"""Web vulnerability engine — passive analysis plus *authorized* safe-active probes.

Every active probe is non-destructive, single-shot and bounded:
* reflection probe with a random marker (XSS candidate, never a weaponised payload)
* error-signature probe for SQL injection (one quote, no stacked queries, no time delays)
* a short, fixed list of commonly exposed files (read-only GET)
* CORS origin reflection check
* redirect-parameter probe — netguard blocks the out-of-scope hop, which *is* the signal

Active probes only run when the scan profile requires authorization AND the scope
entry allows active testing.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..core.netguard import authorize_target, guarded_fetch
from ..services.assets import upsert_asset
from .base import ENGINE_NAME, ENGINE_VERSION, EngineContext, EngineResult, target_url
from .http_engine import analyze_cookies, analyze_security_headers, parse_html

log = logging.getLogger("nexus.engine.webvuln")

SQL_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate[",
    "pg_query()",
    "postgresql query failed",
    "ora-01756",
    "ora-00933",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sqlite3.operationalerror",
    "sqlite error",
    "syntax error at or near",
    "mysql_fetch",
    "mysqli_",
    "jdbc.sqlexception",
    "system.data.sqlclient",
)

REFLECTION_CONTEXT_HINTS = ("<script", "javascript:", "onerror=", "onload=", "srcdoc=")

EXPOSED_FILE_PROBES: tuple[tuple[str, str, str, str], ...] = (
    ("/.env", "APP_KEY=|DB_PASSWORD=|APP_SECRET=|DATABASE_URL=", "high", "Environment file exposed"),
    ("/.env.local", "APP_KEY=|DB_PASSWORD=|DATABASE_URL=", "high", "Environment file exposed"),
    ("/.git/HEAD", "ref: refs/", "high", "Git metadata exposed"),
    ("/.git/config", "[core]", "high", "Git configuration exposed"),
    ("/.svn/entries", "dir", "medium", "Subversion metadata exposed"),
    ("/backup.zip", "PK\\x03\\x04", "high", "Backup archive exposed"),
    ("/db.sql", "INSERT INTO|CREATE TABLE", "high", "Database dump exposed"),
    ("/dump.sql", "INSERT INTO|CREATE TABLE", "high", "Database dump exposed"),
    ("/.DS_Store", "Bud1", "low", "macOS metadata file exposed"),
    ("/server-status", "Apache Server Status|Server Version:", "medium", "Apache server-status exposed"),
    ("/phpinfo.php", "phpinfo()|PHP Version", "high", "phpinfo() exposed"),
    ("/web.config", "<configuration", "medium", "IIS configuration exposed"),
    ("/package.json", '"dependencies"|"name"', "low", "Node.js manifest exposed"),
    ("/composer.json", '"require"', "low", "Composer manifest exposed"),
    ("/Dockerfile", "^FROM ", "medium", "Dockerfile exposed"),
    ("/.well-known/security.txt.bak", "Contact:", "low", "Backup of security.txt exposed"),
)

REDIRECT_PARAM_NAMES = ("redirect", "redirect_uri", "url", "next", "return", "returnurl", "continue", "dest", "destination", "goto", "target", "r", "u", "to")

SENSITIVE_PARAM_NAMES = ("password", "passwd", "pwd", "token", "api_key", "apikey", "secret", "session", "sessionid", "auth", "access_token")


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    params[name] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), ""))


def _collect_parameter_urls(base_url: str, html_links: list[tuple[str, str]], forms: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
    """Return [(url, param_name, extra_values)] for GET parameters worth probing."""
    origin = f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}"
    found: dict[str, set[str]] = {}
    ordered: list[str] = []

    candidates: list[str] = [base_url]
    for _tag, link in html_links:
        if not link or link.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        absolute = urljoin(base_url, link)
        if absolute.startswith(origin) and "?" in absolute:
            candidates.append(absolute)

    for candidate in candidates:
        parts = urlsplit(candidate)
        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            if name.lower() in SENSITIVE_PARAM_NAMES:
                continue
            key = f"{parts.scheme}://{parts.netloc}{parts.path}"
            found.setdefault(key, set())
            if name not in found[key]:
                found[key].add(name)
                ordered.append(f"{key}|{name}|{value[:60]}")

    for form in forms:
        if form.get("method") != "get":
            continue
        action = urljoin(base_url, form.get("action") or base_url)
        for field in form.get("inputs", []):
            name = field.get("name") or ""
            if not name or field.get("type") in ("submit", "button", "file", "password") or name.lower() in SENSITIVE_PARAM_NAMES:
                continue
            key = f"{urlsplit(action).scheme}://{urlsplit(action).netloc}{urlsplit(action).path}"
            if name not in found.setdefault(key, set()):
                found[key].add(name)
                ordered.append(f"{key}|{name}|form")

    result: list[tuple[str, str, str]] = []
    for item in ordered[:12]:
        page, name, value = item.split("|", 2)
        result.append((page, name, value))
    return result


async def _probe_reflection(ctx: EngineContext, page: str, param: str, baseline_body: str) -> dict[str, Any] | None:
    marker = "nxq" + secrets.token_hex(4)
    probe_url = _with_param(page, param, f"1{marker}7")
    fetch = await guarded_fetch(ctx.db, ctx.project.id, probe_url, method="GET", timeout=10, max_body_bytes=200_000)
    if not fetch.ok or fetch.response is None:
        return None
    text = fetch.body.decode("utf-8", errors="replace")
    if marker not in text:
        return None
    index = text.find(marker)
    window = text[max(0, index - 60) : index + len(marker) + 60].lower()
    dangerous = any(hint in window for hint in REFLECTION_CONTEXT_HINTS)
    return {
        "url": probe_url,
        "marker": marker,
        "context": text[max(0, index - 120) : index + len(marker) + 120],
        "dangerous_context": dangerous,
        "status": fetch.status,
        "baseline_len": len(baseline_body),
        "probe_len": len(text),
    }


async def _probe_sql_error(ctx: EngineContext, page: str, param: str, baseline_status: int) -> dict[str, Any] | None:
    for payload in ("'", '"', "'\""):
        probe_url = _with_param(page, param, payload)
        fetch = await guarded_fetch(ctx.db, ctx.project.id, probe_url, method="GET", timeout=10, max_body_bytes=120_000)
        if not fetch.ok or fetch.response is None:
            continue
        text = fetch.body.decode("utf-8", errors="replace").lower()
        for signature in SQL_ERROR_SIGNATURES:
            if signature in text:
                index = text.find(signature)
                return {
                    "url": probe_url,
                    "payload": payload,
                    "signature": signature,
                    "status": fetch.status,
                    "excerpt": fetch.body.decode("utf-8", errors="replace")[max(0, index - 160) : index + 240],
                    "baseline_status": baseline_status,
                }
        await asyncio.sleep(0.1)
    return None


async def _probe_exposed_file(ctx: EngineContext, origin: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for path, signature, severity, title in EXPOSED_FILE_PROBES:
        ctx.check_cancel()
        fetch = await guarded_fetch(
            ctx.db, ctx.project.id, origin + path, method="GET", timeout=8, max_body_bytes=30_000
        )
        if not fetch.ok or fetch.response is None or fetch.status != 200:
            await asyncio.sleep(0.08)
            continue
        text = fetch.body.decode("utf-8", errors="replace")
        if re.search(signature, text[:6000], re.IGNORECASE | re.MULTILINE):
            hits.append(
                {
                    "path": path,
                    "severity": severity,
                    "title": title,
                    "status": fetch.status,
                    "size": len(fetch.body),
                    "excerpt": text[:900],
                    "content_type": fetch.response.headers.get("content-type", ""),
                }
            )
        await asyncio.sleep(0.08)
    return hits


async def _probe_cors(ctx: EngineContext, url: str) -> dict[str, Any] | None:
    probe_origin = "https://nexus-cors-probe.example"
    fetch = await guarded_fetch(
        ctx.db,
        ctx.project.id,
        url,
        method="GET",
        timeout=8,
        max_body_bytes=4000,
        headers={"Origin": probe_origin},
    )
    if not fetch.ok or fetch.response is None:
        return None
    headers = {k.lower(): v for k, v in fetch.response.headers.items()}
    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    if allow_origin in (probe_origin, "*"):
        return {
            "allow_origin": allow_origin,
            "allow_credentials": allow_credentials,
            "status": fetch.status,
            "headers": {k: v for k, v in headers.items() if k.startswith("access-control")},
        }
    return None


async def _probe_open_redirect(ctx: EngineContext, page: str, param: str) -> dict[str, Any] | None:
    """Uses netguard's own out-of-scope block as a *safe* open-redirect detector."""
    probe_value = "https://nexus-redirect-probe.example/landing"
    probe_url = _with_param(page, param, probe_value)
    fetch = await guarded_fetch(ctx.db, ctx.project.id, probe_url, method="GET", timeout=9, max_body_bytes=4000)
    if fetch.ok:
        return None
    if fetch.error == "out_of_scope":
        first = fetch.hops[0] if fetch.hops else None
        location = ""
        if first and first.status in (301, 302, 303, 307, 308):
            location = first.location
        return {
            "url": probe_url,
            "param": param,
            "status": first.status if first else None,
            "location": location,
        }
    return None


def _is_same_origin(candidate: str, origin: str) -> bool:
    try:
        return bool(candidate) and candidate.startswith(origin)
    except Exception:
        return False


async def run(ctx: EngineContext, targets: list[dict[str, Any]]) -> EngineResult:
    result = EngineResult(data={"targets": []})
    active_allowed = ctx.require_active
    if active_allowed and not any_scope_allows_active(ctx):
        ctx.emit(
            "Active testing was requested but no matching scope entry allows active checks — running passive checks only.",
            level="warn",
            phase="scope_check",
        )
        active_allowed = False

    for target in targets:
        ctx.check_cancel()
        url = target_url(target)
        parts = urlsplit(url)
        host = parts.hostname or ""
        if not host:
            continue
        decision = authorize_target(ctx.db, ctx.project.id, host, port=parts.port, require_active=active_allowed)
        if not decision.allowed:
            ctx.emit(f"Skipping {url} — {decision.reason}: {decision.detail}", level="warn", phase="scope_check")
            continue

        asset, created = upsert_asset(
            ctx.db,
            project_id=ctx.project.id,
            asset_type="subdomain" if host.count(".") > 1 else "domain",
            value=host,
            scope_id=decision.scope_id,
            source="scan",
            scan_id=ctx.scan.id,
        )
        if created:
            result.assets += 1
        ctx.db.commit()

        # ------------------------------------------------------------ baseline
        ctx.phase("baseline", "running", progress=15)
        fetch = await guarded_fetch(ctx.db, ctx.project.id, url, method="GET", timeout=10, max_body_bytes=400_000)
        if not fetch.ok or fetch.response is None:
            ctx.emit(f"Baseline request failed for {url}: {fetch.error}", level="error", phase="baseline")
            ctx.phase("baseline", "failed", progress=100)
            continue
        body = fetch.body.decode("utf-8", errors="replace")
        origin = f"{parts.scheme}://{parts.netloc}"
        html = parse_html(body)
        tls_port = parts.port or (443 if parts.scheme == "https" else 80)
        service_port = tls_port
        from ..services.assets import upsert_service

        service, service_created, _ = upsert_service(
            ctx.db,
            project_id=ctx.project.id,
            asset=asset,
            port=service_port,
            protocol="tcp",
            state="open",
            name="https" if parts.scheme == "https" else "http",
            product=fetch.response.headers.get("server", "")[:80] if fetch.response else "",
            source=ENGINE_NAME,
        )
        if service_created:
            result.services += 1
        ctx.emit(f"Baseline: HTTP {fetch.status}, {len(body)} bytes from {fetch.final_url}.", phase="baseline")
        ctx.phase("baseline", "done", progress=100)

        # ------------------------------------------------------------- passive
        ctx.phase("passive", "running", progress=20)
        headers = {k.lower(): v for k, v in fetch.response.headers.items()}
        header_snapshot, header_issues = analyze_security_headers(headers, is_https=parts.scheme == "https")
        set_cookie_values: list[str] = []
        try:
            set_cookie_values = fetch.response.headers.get_list("set-cookie")
        except Exception:
            pass
        cookies, cookie_issues = analyze_cookies(set_cookie_values, is_https=parts.scheme == "https")
        for issue in list(header_issues) + list(cookie_issues):
            ctx.save(
                check_id=issue["check_id"],
                category="headers" if issue in header_issues else "cookie",
                title=issue["title"],
                severity=issue["severity"],
                confidence=issue.get("confidence", "firm"),
                target=host,
                location=issue["location"],
                description=issue["description"],
                impact=issue["impact"],
                remediation=issue["remediation"],
                references=issue.get("references", []),
                cwe=issue.get("cwe", ""),
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset.id,
                service_id=service.id,
                evidence={
                    "kind": "header_dump",
                    "label": f"{issue['location']} on {fetch.final_url}",
                    "headers": headers,
                    "response": "\n".join(set_cookie_values) if issue in cookie_issues else "",
                    "source": ENGINE_NAME,
                },
                tags=["webvuln", "passive"],
            )
            result.findings += 1

        server_banner = headers.get("server", "").lower()
        if any(token in server_banner for token in ("iis/6", "iis/7", "apache/1", "apache/2.0", "apache/2.2", "nginx/0.", "nginx/1.0", "nginx/1.2", "nginx/1.4", "php/5", "php/7.0", "php/7.1", "php/7.2", "php/7.3")):
            ctx.save(
                check_id="outdated_server_banner",
                category="outdated_component",
                title="End-of-life server software advertised",
                severity="medium",
                confidence="tentative",
                target=host,
                location="Server",
                description=f"The banner indicates an unsupported version: {headers.get('server')}. The banner alone does not prove the actual version.",
                impact="End-of-life versions no longer receive security fixes and are targeted by automated exploitation.",
                remediation="Upgrade to a supported version and remove version details from banners.",
                references=["https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"],
                cwe="CWE-1104",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset.id,
                tags=["components"],
            )
            result.findings += 1
        ctx.phase("passive", "done", progress=100)

        # -------------------------------------------------------------- active
        active_summary: dict[str, Any] = {"enabled": active_allowed, "reflections": 0, "sql_errors": 0, "exposed_files": 0, "cors": 0, "redirects": 0}
        if active_allowed:
            ctx.phase("active", "running", progress=10)

            cors = await _probe_cors(ctx, url)
            if cors:
                active_summary["cors"] = 1
                ctx.save(
                    check_id="cors_origin_reflection",
                    category="misconfig",
                    title="CORS reflects arbitrary origins",
                    severity="high" if cors["allow_credentials"] else "medium",
                    confidence="certain",
                    target=host,
                    location="Access-Control-Allow-Origin",
                    description=(
                        f"Origin https://nexus-cors-probe.example was reflected as {cors['allow_origin']}"
                        + (" with credentials allowed." if cors["allow_credentials"] else ".")
                    ),
                    impact=(
                        "With credentials enabled, any website can read authenticated responses from this host on behalf of a logged-in victim."
                        if cors["allow_credentials"]
                        else "Any website can read responses from this host, leaking data that was not meant to be cross-origin readable."
                    ),
                    remediation="Validate Origin against a strict allow-list; never reflect arbitrary origins, and never combine a wildcard/reflection with credentials.",
                    references=["https://portswigger.net/web-security/cors", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/08-Testing_for_Cross_Origin_Resource_Sharing"],
                    cwe="CWE-346",
                    detected_by=ENGINE_NAME,
                    engine_version=ENGINE_VERSION,
                    asset_id=asset.id,
                    service_id=service.id,
                    verified=True,
                    active_check=True,
                    evidence={
                        "kind": "http_response",
                        "label": "CORS probe",
                        "request": f"GET {url}\nOrigin: https://nexus-cors-probe.example",
                        "response": "\n".join(f"{k}: {v}" for k, v in cors["headers"].items()),
                        "source": ENGINE_NAME,
                    },
                    tags=["cors", "active"],
                )
                result.findings += 1

            parameters = _collect_parameter_urls(url, html.links, html.forms)
            ctx.emit(
                f"Exploring {len(parameters)} GET parameter(s) for reflection and injection signatures (authorized active testing).",
                phase="active",
                kind="metric",
            )
            for page, param, _value in parameters:
                ctx.check_cancel()
                if not _is_same_origin(page, origin):
                    continue
                reflection = await _probe_reflection(ctx, page, param, body)
                if reflection:
                    active_summary["reflections"] += 1
                    severity = "high" if reflection["dangerous_context"] else "medium"
                    ctx.save(
                        check_id="xss_reflected_input",
                        category="xss",
                        title=f"Input is reflected without encoding in parameter '{param}'",
                        severity=severity,
                        confidence="tentative",
                        target=host,
                        location=f"{urlsplit(page).path}?{param}",
                        description=(
                            "A unique marker sent in this parameter came back in the HTML response"
                            + (" inside a script/attribute context, which is directly exploitable." if reflection["dangerous_context"] else " in the response body.")
                            + " No exploit payload was used — this is a reflection signal that requires manual confirmation."
                        ),
                        impact="If the reflection is not encoded, an attacker can craft a link that executes JavaScript in the victim's browser and steals session data.",
                        remediation="Context-aware output encoding, plus a strict Content-Security-Policy; validate and allow-list input where possible.",
                        references=["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                        cwe="CWE-79",
                        detected_by=ENGINE_NAME,
                        engine_version=ENGINE_VERSION,
                        asset_id=asset.id,
                        service_id=service.id,
                        verified=False,
                        active_check=True,
                        evidence={
                            "kind": "http_request",
                            "label": f"Reflection probe on {param}",
                            "request": f"GET {reflection['url']}",
                            "response": reflection["context"],
                            "source": ENGINE_NAME,
                        },
                        tags=["xss", "reflection", "active", "requires-manual-confirmation"],
                    )
                    result.findings += 1

                sql_error = await _probe_sql_error(ctx, page, param, fetch.status or 0)
                if sql_error:
                    active_summary["sql_errors"] += 1
                    ctx.save(
                        check_id="sqli_error_based",
                        category="sqli",
                        title=f"Database error triggered by parameter '{param}'",
                        severity="high",
                        confidence="firm",
                        target=host,
                        location=f"{urlsplit(page).path}?{param}",
                        description=f"A single quote character caused the application to return a database error ({sql_error['signature']}).",
                        impact="User input reaches a SQL query; a determined attacker can read or modify data and in many stacks take over the database server.",
                        remediation="Use parameterised queries/ORM bindings everywhere, validate input types, and disable detailed database errors in production responses.",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
                        cwe="CWE-89",
                        detected_by=ENGINE_NAME,
                        engine_version=ENGINE_VERSION,
                        asset_id=asset.id,
                        service_id=service.id,
                        verified=False,
                        active_check=True,
                        evidence={
                            "kind": "http_response",
                            "label": f"Error-based probe on {param}",
                            "request": f"GET {sql_error['url']}\n(payload: {sql_error['payload']})",
                            "response": sql_error["excerpt"],
                            "source": ENGINE_NAME,
                        },
                        tags=["sqli", "active", "requires-manual-confirmation"],
                    )
                    result.findings += 1
                await asyncio.sleep(0.15)

            for param in [name for _page, name, _v in parameters if name.lower() in REDIRECT_PARAM_NAMES][:4]:
                redirect = await _probe_open_redirect(ctx, url, param)
                if redirect:
                    active_summary["redirects"] += 1
                    ctx.save(
                        check_id="open_redirect",
                        category="misconfig",
                        title=f"Open redirect via parameter '{param}'",
                        severity="medium",
                        confidence="firm",
                        target=host,
                        location=f"{urlsplit(url).path}?{param}",
                        description="The application redirected to an external URL supplied by the user (the hop was blocked by the out-of-scope guard, which confirms the redirect).",
                        impact="Attackers use your domain in phishing links that appear trustworthy to victims, bypassing URL-based filters.",
                        remediation="Allow-list redirect destinations (relative paths or an explicit host list) and never redirect to raw user input.",
                        references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                        cwe="CWE-601",
                        detected_by=ENGINE_NAME,
                        engine_version=ENGINE_VERSION,
                        asset_id=asset.id,
                        verified=True,
                        active_check=True,
                        evidence={
                            "kind": "http_response",
                            "label": f"Redirect probe on {param}",
                            "request": f"GET {redirect['url']}",
                            "response": f"HTTP {redirect['status']} -> Location: {redirect['location']}",
                            "source": ENGINE_NAME,
                        },
                        tags=["redirect", "active"],
                    )
                    result.findings += 1

            exposed = await _probe_exposed_file(ctx, origin)
            for hit in exposed:
                active_summary["exposed_files"] += 1
                ctx.save(
                    check_id=f"exposed_file_{hit['path'].strip('/').replace('/', '_').replace('.', '_')}",
                    category="exposure",
                    title=f"{hit['title']} at {hit['path']}",
                    severity=hit["severity"],
                    confidence="certain",
                    target=host,
                    location=hit["path"],
                    description=f"The file was served publicly (HTTP 200, {hit['size']} bytes) with the expected content shape.",
                    impact="Attackers download source, credentials or database dumps directly, which often ends the engagement in minutes.",
                    remediation="Block these paths at the web server, remove the files from the document root, rotate any exposed credential, and verify with a re-scan.",
                    references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
                    cwe="CWE-538",
                    detected_by=ENGINE_NAME,
                    engine_version=ENGINE_VERSION,
                    asset_id=asset.id,
                    service_id=service.id,
                    verified=True,
                    active_check=True,
                    evidence={
                        "kind": "http_response",
                        "label": f"GET {hit['path']}",
                        "request": f"GET {origin}{hit['path']}",
                        "response": f"HTTP {hit['status']} ({hit['content_type']})\n{hit['excerpt']}",
                        "source": ENGINE_NAME,
                    },
                    tags=["exposure", "active"],
                )
                result.findings += 1

            # HTTP method surface (read-only OPTIONS request)
            options_fetch = await guarded_fetch(ctx.db, ctx.project.id, url, method="OPTIONS", timeout=8, max_body_bytes=2000)
            if options_fetch.ok and options_fetch.response is not None:
                allow = options_fetch.response.headers.get("allow", "")
                if allow:
                    methods = [m.strip().upper() for m in allow.split(",")]
                    risky = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT")]
                    result.data.setdefault("methods", {})[host] = methods
                    if risky:
                        ctx.save(
                            check_id="http_risky_methods",
                            category="misconfig",
                            title=f"Risky HTTP methods advertised: {', '.join(risky)}",
                            severity="low" if "TRACE" in risky else "medium",
                            confidence="firm",
                            target=host,
                            location="Allow",
                            description=f"OPTIONS returned Allow: {allow}. Advertising the method does not prove it is unauthenticated, but it widens the attack surface.",
                            impact="If these verbs are not authenticated and validated, attackers can modify or delete resources and use TRACE for cross-site tracing.",
                            remediation="Disable unused verbs at the web server; require authentication and authorization for PUT/DELETE; turn TRACE off.",
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"],
                            cwe="CWE-749",
                            detected_by=ENGINE_NAME,
                            engine_version=ENGINE_VERSION,
                            asset_id=asset.id,
                            verified=True,
                            active_check=True,
                            evidence={
                                "kind": "header_dump",
                                "label": "OPTIONS response",
                                "request": f"OPTIONS {url}",
                                "response": f"Allow: {allow}",
                                "source": ENGINE_NAME,
                            },
                            tags=["methods", "active"],
                        )
                        result.findings += 1
            ctx.phase("active", "done", progress=100)
        else:
            ctx.emit(
                "Active checks skipped: scan profile is passive. Choose the 'safe_active' profile with an active-authorized scope entry to enable them.",
                phase="active",
            )

        # ----------------------------------------------------------- correlate
        ctx.phase("correlate", "running", progress=50)
        ctx.emit(
            f"Active summary for {host}: reflections={active_summary['reflections']}, sql_signatures={active_summary['sql_errors']}, "
            f"exposed_files={active_summary['exposed_files']}, cors={active_summary['cors']}, redirects={active_summary['redirects']}.",
            kind="metric",
            phase="correlate",
        )
        ctx.phase("correlate", "done", progress=100)

        result.data["targets"].append(
            {
                "host": host,
                "url": fetch.final_url,
                "parameters_probed": len(parameters) if active_allowed else 0,
                "active": active_summary,
                "passive_findings": len(header_issues) + len(cookie_issues),
            }
        )

    ctx.scan.stats = {**(ctx.scan.stats or {}), "webvuln": result.data}
    ctx.db.commit()
    return result


def any_scope_allows_active(ctx: EngineContext) -> bool:
    from ..core.netguard import _active_scopes

    return any(scope.allow_active for scope in _active_scopes(ctx.db, ctx.project.id))
