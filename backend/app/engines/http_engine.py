"""HTTP analysis engine — headers, cookies, redirects, TLS status, well-known files.

All requests go through netguard's `guarded_fetch` (pinned to validated IPs, redirect
hops re-authorized one by one, environment proxies ignored).
"""

from __future__ import annotations

import logging
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from ..core.netguard import authorize_target, guarded_fetch
from ..services.assets import detect_http_changes, recompute_asset_risk, upsert_asset, upsert_service
from .base import ENGINE_NAME, ENGINE_VERSION, EngineContext, EngineResult, target_url

log = logging.getLogger("nexus.engine.http")

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "x-permitted-cross-domain-policies",
)

WELL_KNOWN_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/humans.txt",
)

BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache", "via")

TRACEBACK_MARKERS = (
    "traceback (most recent call last)",
    "stack trace:",
    "at java.",
    "system.nullreferenceexception",
    "whoops, looks like something went wrong",
    "sqlstate[",
    "you have an error in your sql syntax",
    "ora-0",
    "postgresql query failed",
    "warning: mysql",
    "undefined index:",
    "notice: undefined",
    "fatal error:",
    "microsoft ole db provider",
)

CSRF_TOKEN_HINTS = ("csrf", "_token", "authenticity_token", "xsrf", "nonce", "__requestverificationtoken", "anticsrf")


# ---------------------------------------------------------------------------
# Minimal, dependency-free HTML analysis
# ---------------------------------------------------------------------------
class _HtmlAnalyzer(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.generator = ""
        self.links: list[tuple[str, str]] = []  # (tag, url)
        self.forms: list[dict[str, Any]] = []
        self.comments: list[str] = []
        self.has_password_field = False
        self._in_title = False
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "meta" and attributes.get("name", "").lower() == "generator":
            self.generator = attributes.get("content", "")
        elif tag in ("a", "img", "script", "link", "iframe", "source") and (
            attributes.get("href") or attributes.get("src")
        ):
            self.links.append((tag, attributes.get("href") or attributes.get("src") or ""))
        if tag == "form":
            self._current_form = {
                "action": attributes.get("action", ""),
                "method": (attributes.get("method") or "get").lower(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            name = attributes.get("name", "")
            input_type = (attributes.get("type") or "text").lower()
            self._current_form["inputs"].append({"name": name, "type": input_type})
            if input_type == "password":
                self.has_password_field = True
        elif tag == "input" and attributes.get("type", "").lower() == "password":
            self.has_password_field = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()

    def handle_comment(self, data: str) -> None:
        self.comments.append(data.strip()[:200])


def parse_html(html: str) -> _HtmlAnalyzer:
    analyzer = _HtmlAnalyzer()
    try:
        analyzer.feed(html[:400_000])
    except Exception:  # pragma: no cover - malformed HTML must never break a scan
        pass
    return analyzer


# ---------------------------------------------------------------------------
# Header / cookie analysis
# ---------------------------------------------------------------------------
def analyze_security_headers(headers: dict[str, str], *, is_https: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    snapshot: dict[str, Any] = {}
    issues: list[dict[str, Any]] = []

    for name in SECURITY_HEADERS:
        snapshot[name] = headers.get(name, "")

    hsts = headers.get("strict-transport-security", "")
    if is_https:
        if not hsts:
            issues.append(
                {
                    "check_id": "http_hsts_missing",
                    "severity": "medium",
                    "confidence": "certain",
                    "location": "Strict-Transport-Security",
                    "title": "HSTS header is missing",
                    "description": "The site never instructs browsers to require HTTPS, so the first request (and any link a user clicks) can be downgraded to plain HTTP.",
                    "impact": "An attacker on the same network can strip TLS and read or modify the session (SSL-stripping).",
                    "remediation": "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload — after confirming every subdomain works over HTTPS.",
                    "references": ["https://datatracker.ietf.org/doc/html/rfc6797", "https://hstspreload.org/"],
                    "cwe": "CWE-319",
                }
            )
        else:
            match = re.search(r"max-age\s*=\s*(\d+)", hsts)
            max_age = int(match.group(1)) if match else 0
            if max_age < 15_552_000:
                issues.append(
                    {
                        "check_id": "http_hsts_short_max_age",
                        "severity": "low",
                        "confidence": "certain",
                        "location": "Strict-Transport-Security",
                        "title": f"HSTS max-age is too short ({max_age}s)",
                        "description": "A short max-age gives browsers only brief protection and is not eligible for preload.",
                        "impact": "Users remain exposed to downgrade attacks outside the short window.",
                        "remediation": "Use max-age of at least 15552000 (180 days); 31536000 (1 year) is recommended.",
                        "references": ["https://hstspreload.org/#opt-in"],
                        "cwe": "CWE-319",
                    }
                )
            if "includesubdomains" not in hsts.lower():
                issues.append(
                    {
                        "check_id": "http_hsts_no_subdomains",
                        "severity": "info",
                        "confidence": "certain",
                        "location": "Strict-Transport-Security",
                        "title": "HSTS does not cover subdomains",
                        "description": "includeSubDomains is absent, so subdomains can still be downgraded.",
                        "impact": "A single misconfigured subdomain can be used to hijack cookies scoped to the parent domain.",
                        "remediation": "Add includeSubDomains once all subdomains serve HTTPS.",
                        "references": ["https://datatracker.ietf.org/doc/html/rfc6797#section-6.1.2"],
                        "cwe": "CWE-319",
                    }
                )

    csp = headers.get("content-security-policy", "")
    if not csp:
        if not headers.get("content-security-policy-report-only"):
            issues.append(
                {
                    "check_id": "http_csp_missing",
                    "severity": "medium",
                    "confidence": "certain",
                    "location": "Content-Security-Policy",
                    "title": "No Content-Security-Policy",
                    "description": "Without CSP the browser will execute any script the page loads, whatever its origin.",
                    "impact": "Any content injection (XSS) becomes directly exploitable; there is no second line of defence.",
                    "remediation": "Start with a report-only policy, then enforce one such as: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://csp-evaluator.withgoogle.com/"],
                    "cwe": "CWE-693",
                }
            )
    else:
        lowered = csp.lower()
        if "unsafe-inline" in lowered:
            issues.append(
                {
                    "check_id": "http_csp_unsafe_inline",
                    "severity": "medium",
                    "confidence": "certain",
                    "location": "Content-Security-Policy",
                    "title": "CSP allows 'unsafe-inline'",
                    "description": "Inline scripts are permitted, which is the exact vector CSP exists to block.",
                    "impact": "Reflected or stored HTML injection can execute JavaScript despite the policy.",
                    "remediation": "Replace inline handlers with external scripts and use nonces or hashes.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"],
                    "cwe": "CWE-693",
                }
            )
        if "unsafe-eval" in lowered:
            issues.append(
                {
                    "check_id": "http_csp_unsafe_eval",
                    "severity": "low",
                    "confidence": "certain",
                    "location": "Content-Security-Policy",
                    "title": "CSP allows 'unsafe-eval'",
                    "description": "Dynamic code evaluation is enabled in the browser.",
                    "impact": "Injected strings can be turned into executable code.",
                    "remediation": "Remove unsafe-eval and refactor code that relies on eval/Function constructor.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"],
                    "cwe": "CWE-693",
                }
            )
        if re.search(r"(script-src|default-src)[^;]*\*", lowered):
            issues.append(
                {
                    "check_id": "http_csp_wildcard",
                    "severity": "low",
                    "confidence": "certain",
                    "location": "Content-Security-Policy",
                    "title": "CSP uses a wildcard source",
                    "description": "A wildcard allows scripts from any origin, weakening the policy to near-zero value.",
                    "impact": "An attacker who can host a script anywhere can load it in the victim page.",
                    "remediation": "List explicit origins instead of *.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
                    "cwe": "CWE-693",
                }
            )
        if "frame-ancestors" not in lowered and not headers.get("x-frame-options"):
            issues.append(
                {
                    "check_id": "http_clickjacking",
                    "severity": "medium",
                    "confidence": "certain",
                    "location": "Content-Security-Policy",
                    "title": "Page can be framed (no frame-ancestors, no X-Frame-Options)",
                    "description": "Neither CSP frame-ancestors nor X-Frame-Options is present.",
                    "impact": "The site can be embedded in an attacker page and used for clickjacking against authenticated users.",
                    "remediation": "Add frame-ancestors 'none' (or X-Frame-Options: DENY) to every HTML response.",
                    "references": ["https://owasp.org/www-community/attacks/Clickjacking"],
                    "cwe": "CWE-1021",
                }
            )

    if not headers.get("x-content-type-options"):
        issues.append(
            {
                "check_id": "http_no_nosniff",
                "severity": "low",
                "confidence": "certain",
                "location": "X-Content-Type-Options",
                "title": "X-Content-Type-Options is missing",
                "description": "Browsers may MIME-sniff responses and treat, for example, an uploaded image as script.",
                "impact": "Uploaded content can become an XSS vector.",
                "remediation": "Send X-Content-Type-Options: nosniff on every response.",
                "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                "cwe": "CWE-436",
            }
        )

    if not headers.get("referrer-policy"):
        issues.append(
            {
                "check_id": "http_referrer_policy_missing",
                "severity": "low",
                "confidence": "certain",
                "location": "Referrer-Policy",
                "title": "Referrer-Policy is missing",
                "description": "Full URLs (which may contain tokens or identifiers) are sent to third-party sites.",
                "impact": "Sensitive path or parameter data leaks to external hosts through the Referer header.",
                "remediation": "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
                "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                "cwe": "CWE-200",
            }
        )

    for header in BANNER_HEADERS:
        value = headers.get(header, "")
        if not value:
            continue
        if re.search(r"\d+\.\d+", value) or header in ("x-powered-by", "x-aspnet-version"):
            issues.append(
                {
                    "check_id": f"http_banner_{header.replace('-', '_')}",
                    "severity": "low" if header == "server" else "info",
                    "confidence": "certain",
                    "location": header.title(),
                    "title": f"Technology disclosure via {header.title()} header",
                    "description": f"The response advertises: {value[:120]}",
                    "impact": "Version banners let an attacker skip straight to exploits matching your stack instead of probing blindly.",
                    "remediation": f"Remove or generalize the {header} header at the web server / framework level.",
                    "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
                    "cwe": "CWE-200",
                }
            )

    return snapshot, issues


def analyze_cookies(set_cookie_headers: list[str], *, is_https: bool) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cookies: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []

    for raw in set_cookie_headers:
        if not raw:
            continue
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attributes = {}
        for attribute in parts[1:]:
            key, _, value = attribute.partition("=")
            attributes[key.strip().lower()] = value.strip()

        lower_names = {k.lower() for k in attributes}
        cookie = {
            "name": name,
            "secure": "secure" in lower_names,
            "httponly": "httponly" in lower_names,
            "samesite": attributes.get("samesite", ""),
            "domain": attributes.get("domain", ""),
            "path": attributes.get("path", ""),
            "max_age": attributes.get("max-age", ""),
            "expires": attributes.get("expires", ""),
            "prefix": name.split("__")[0] + "__" if name.startswith(("__Host-", "__Secure-")) else "",
            "size": len(raw),
        }
        cookies.append(cookie)

        if is_https and not cookie["secure"]:
            issues.append(
                {
                    "check_id": f"cookie_insecure_{name}",
                    "severity": "medium",
                    "confidence": "certain",
                    "location": f"Set-Cookie: {name}",
                    "title": f"Cookie '{name}' is missing the Secure attribute",
                    "description": "The cookie may be transmitted over plain HTTP.",
                    "impact": "A network attacker can capture or fixate the session cookie and hijack the account.",
                    "remediation": "Set the Secure attribute on every cookie; keep cookies on HTTPS only.",
                    "references": ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    "cwe": "CWE-614",
                }
            )
        if not cookie["httponly"]:
            issues.append(
                {
                    "check_id": f"cookie_no_httponly_{name}",
                    "severity": "medium",
                    "confidence": "certain",
                    "location": f"Set-Cookie: {name}",
                    "title": f"Cookie '{name}' is readable by JavaScript (no HttpOnly)",
                    "description": "The cookie is exposed to document.cookie.",
                    "impact": "Any XSS on the site can steal this cookie and impersonate the user.",
                    "remediation": "Add HttpOnly to every cookie that the JavaScript does not strictly need.",
                    "references": ["https://owasp.org/www-community/HttpOnly"],
                    "cwe": "CWE-1004",
                }
            )
        if not cookie["samesite"]:
            issues.append(
                {
                    "check_id": f"cookie_no_samesite_{name}",
                    "severity": "low",
                    "confidence": "certain",
                    "location": f"Set-Cookie: {name}",
                    "title": f"Cookie '{name}' has no SameSite attribute",
                    "description": "Modern browsers apply Lax by default, but the intent is not explicit and older clients may send it cross-site.",
                    "impact": "Increases exposure to cross-site request forgery.",
                    "remediation": "Set SameSite=Lax (or Strict for sensitive cookies); use None only with Secure when cross-site use is required.",
                    "references": ["https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis"],
                    "cwe": "CWE-1275",
                }
            )
        if cookie["samesite"].lower() == "none" and not cookie["secure"]:
            issues.append(
                {
                    "check_id": f"cookie_samesite_none_insecure_{name}",
                    "severity": "medium",
                    "confidence": "certain",
                    "location": f"Set-Cookie: {name}",
                    "title": f"Cookie '{name}' uses SameSite=None without Secure",
                    "description": "Browsers reject or drop such cookies, and any that are accepted travel cross-site in the clear.",
                    "impact": "Session breakage plus exposure to cross-site attacks.",
                    "remediation": "Add Secure whenever SameSite=None is used.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                    "cwe": "CWE-1275",
                }
            )
        if name.startswith("__Host-") and (cookie["domain"] or cookie["path"] not in ("", "/")):
            issues.append(
                {
                    "check_id": f"cookie_host_prefix_misuse_{name}",
                    "severity": "low",
                    "confidence": "certain",
                    "location": f"Set-Cookie: {name}",
                    "title": f"Cookie '{name}' uses the __Host- prefix incorrectly",
                    "description": "__Host- requires Secure, path=/ and no Domain attribute.",
                    "impact": "Browsers silently reject the cookie, or the intended scoping guarantee is lost.",
                    "remediation": "Remove the Domain attribute and set Path=/ with Secure.",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes"],
                    "cwe": "CWE-16",
                }
            )
        if cookie["domain"].startswith(".") and cookie["domain"].count(".") <= 1:
            issues.append(
                {
                    "check_id": f"cookie_broad_domain_{name}",
                    "severity": "low",
                    "confidence": "firm",
                    "location": f"Set-Cookie: {name}",
                    "title": f"Cookie '{name}' is scoped to the whole registrable domain",
                    "description": f"Domain={cookie['domain']} shares the cookie with every subdomain.",
                    "impact": "Any compromised subdomain (including a marketing or legacy host) can read or overwrite the session cookie.",
                    "remediation": "Omit the Domain attribute so the cookie stays host-only, unless sharing is truly required.",
                    "references": ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    "cwe": "CWE-16",
                }
            )

    return cookies, issues


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------
async def run(ctx: EngineContext, targets: list[dict[str, Any]]) -> EngineResult:
    result = EngineResult(data={"targets": []})
    timeout = float((ctx.scan.options or {}).get("http_timeout", 10))

    for target in targets:
        ctx.check_cancel()
        url = target_url(target)
        parts = urlsplit(url)
        host = parts.hostname or ""
        if not host:
            continue

        decision = authorize_target(
            ctx.db, ctx.project.id, host, port=parts.port, require_active=False
        )
        if not decision.allowed:
            ctx.emit(f"Skipping {url} — {decision.reason}: {decision.detail}", level="warn", phase="scope_check")
            continue
        ctx.emit(f"Authorized {url} (scope: {decision.scope_value}).", phase="scope_check")

        asset, asset_created = upsert_asset(
            ctx.db,
            project_id=ctx.project.id,
            asset_type="subdomain" if (host.count(".") > 1) else "domain",
            value=host,
            scope_id=decision.scope_id,
            source="scan",
            scan_id=ctx.scan.id,
        )
        if asset_created:
            result.assets += 1
        ctx.db.commit()

        # ------------------------------------------------------------- request
        ctx.phase("connect", "running", progress=10)
        fetch = await guarded_fetch(
            ctx.db,
            ctx.project.id,
            url,
            method="GET",
            timeout=timeout,
            read_body=True,
            max_body_bytes=400_000,
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        if not fetch.ok or fetch.response is None:
            ctx.emit(f"Request to {url} failed: {fetch.error}", level="error", phase="connect")
            if fetch.error in ("out_of_scope", "dns_resolution_failed", "loopback_address", "private_address_not_authorized"):
                ctx.phase("connect", "failed", progress=100)
                continue
            ctx.phase("connect", "done", progress=100)
            continue

        response = fetch.response
        headers = {k.lower(): v for k, v in response.headers.items()}
        body_text = fetch.body.decode("utf-8", errors="replace")
        html = parse_html(body_text)
        is_https = parts.scheme == "https"
        redirect_chain = [{"url": hop.url, "status": hop.status, "allowed": hop.allowed, "ms": hop.elapsed_ms} for hop in fetch.hops]

        ctx.emit(
            f"HTTP {response.status_code} in {fetch.hops[-1].elapsed_ms if fetch.hops else 0} ms — final URL {fetch.final_url}",
            phase="connect",
            data={"status": response.status_code, "redirects": len(fetch.hops) - 1},
        )
        ctx.phase("connect", "done", progress=100)

        # --------------------------------------------------------- HTTP service
        service, service_created, changed = upsert_service(
            ctx.db,
            project_id=ctx.project.id,
            asset=asset,
            port=parts.port or (443 if is_https else 80),
            protocol="tcp",
            state="open",
            name="https" if is_https else "http",
            product=headers.get("server", "")[:80],
            version="",
            banner=headers.get("server", ""),
            source=ENGINE_NAME,
        )
        if service_created:
            result.services += 1

        # ------------------------------------------------------------- headers
        ctx.phase("headers", "running", progress=20)
        header_snapshot, header_issues = analyze_security_headers(headers, is_https=is_https)
        for issue in header_issues:
            ctx.save(
                check_id=issue["check_id"],
                category="headers",
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
                    "label": f"Response headers for {fetch.final_url}",
                    "headers": headers,
                    "request": f"GET {parts.path or '/'} HTTP/1.1\nHost: {host}",
                    "response": f"HTTP/{response.http_version} {response.status_code}",
                    "source": ENGINE_NAME,
                },
                tags=["headers"],
            )
            result.findings += 1
        ctx.emit(f"Security header analysis produced {len(header_issues)} finding(s).", phase="headers")
        ctx.phase("headers", "done", progress=100)

        # ------------------------------------------------------------- cookies
        ctx.phase("cookies", "running", progress=20)
        set_cookie_values: list[str] = []
        try:
            set_cookie_values = response.headers.get_list("set-cookie")
        except Exception:
            set_cookie_values = [headers.get("set-cookie", "")] if headers.get("set-cookie") else []
        cookies, cookie_issues = analyze_cookies(set_cookie_values, is_https=is_https)
        for issue in cookie_issues:
            ctx.save(
                check_id=issue["check_id"],
                category="cookie",
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
                    "kind": "cookie_dump",
                    "label": f"Set-Cookie headers from {fetch.final_url}",
                    "response": "\n".join(set_cookie_values),
                    "headers": {"set-cookie": "[REDACTED]"} if set_cookie_values else {},
                    "source": ENGINE_NAME,
                },
                tags=["cookies"],
            )
            result.findings += 1
        ctx.emit(f"Cookie analysis: {len(cookies)} cookie(s), {len(cookie_issues)} finding(s).", phase="cookies")
        ctx.phase("cookies", "done", progress=100)

        # ----------------------------------------------------------- redirects
        ctx.phase("redirects", "running", progress=30)
        if not is_https:
            upgraded = any(str(hop.get("url", "")).startswith("https://") for hop in redirect_chain)
            if not upgraded:
                ctx.save(
                    check_id="http_no_https_redirect",
                    category="tls",
                    title=f"{host} serves content over plain HTTP without redirecting to HTTPS",
                    severity="high",
                    confidence="certain",
                    target=host,
                    location=url,
                    description="The HTTP endpoint returned content instead of a 301/308 redirect to the HTTPS URL.",
                    impact="Every request, including credentials and session cookies, can be read or modified in transit.",
                    remediation="Redirect all HTTP traffic to HTTPS with a 301/308 and enable HSTS.",
                    references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
                    cwe="CWE-319",
                    detected_by=ENGINE_NAME,
                    engine_version=ENGINE_VERSION,
                    asset_id=asset.id,
                    service_id=service.id,
                    evidence={
                        "kind": "http_response",
                        "label": "Plain HTTP response",
                        "request": f"GET {url}",
                        "response": f"HTTP {response.status_code}",
                        "headers": headers,
                        "source": ENGINE_NAME,
                    },
                    tags=["tls"],
                )
                result.findings += 1
        for hop in fetch.hops:
            if hop.allowed is False:
                ctx.save(
                    check_id="http_redirect_out_of_scope",
                    category="misconfig",
                    title="Redirect target is outside the authorized scope",
                    severity="info",
                    confidence="certain",
                    target=hop.url,
                    location=str(hop.url),
                    description=f"The redirect was not followed: {hop.error}",
                    impact="Out-of-scope redirects are a classic SSRF pivot and were correctly blocked — no data was retrieved.",
                    remediation="Confirm the redirect is intentional; external redirects should point to a domain you control.",
                    detected_by=ENGINE_NAME,
                    engine_version=ENGINE_VERSION,
                    asset_id=asset.id,
                    tags=["redirects", "scope"],
                )
                result.findings += 1
        ctx.phase("redirects", "done", progress=100)

        # ------------------------------------------------------------- TLS link
        ctx.phase("tls", "running", progress=30)
        tls_summary: dict[str, Any] = {}
        if is_https:
            from . import tls_engine

            port = parts.port or 443
            tls_decision = authorize_target(ctx.db, ctx.project.id, host, port=port)
            if tls_decision.allowed:
                import asyncio as _asyncio

                report = await _asyncio.to_thread(
                    tls_engine.inspect_tls, host, port, 8.0, allow_private=ctx.allow_private
                )
                if report.get("connected"):
                    tls_summary = {
                        "protocol": report.get("protocol"),
                        "issuer": (report.get("cert") or {}).get("issuer_cn", ""),
                        "days_until_expiry": (report.get("cert") or {}).get("days_until_expiry"),
                        "verified": report.get("verified"),
                        "protocols_supported": report.get("protocols_supported", {}),
                    }
                    created_findings = tls_engine.evaluate(ctx, host, report, asset_id=asset.id, service_id=service.id)
                    result.findings += created_findings
                    merged_tls = dict(service.tls or {})
                    merged_tls.update(
                        {
                            "protocol": report.get("protocol"),
                            "cipher": report.get("cipher"),
                            "issuer": (report.get("cert") or {}).get("issuer_cn", ""),
                            "not_after": (report.get("cert") or {}).get("not_after", ""),
                            "fingerprint_sha256": (report.get("cert") or {}).get("fingerprint_sha256", ""),
                            "verified": report.get("verified"),
                            "protocols_supported": report.get("protocols_supported", {}),
                        }
                    )
                    service.tls = merged_tls
                    ctx.db.commit()
                else:
                    ctx.emit(f"TLS inspection unavailable: {report.get('error')}", level="warn", phase="tls")
        ctx.phase("tls", "done", progress=100)

        # -------------------------------------------------------- well-known
        ctx.phase("wellknown", "running", progress=40)
        well_known: dict[str, Any] = {}
        base = f"{parts.scheme}://{host}" + (f":{parts.port}" if parts.port and parts.port not in (80, 443) else "")
        for path in WELL_KNOWN_PATHS:
            ctx.check_cancel()
            probe = await guarded_fetch(
                ctx.db,
                ctx.project.id,
                base + path,
                method="GET",
                timeout=min(timeout, 8),
                read_body=True,
                max_body_bytes=20_000,
            )
            status = probe.status if probe.ok else None
            well_known[path] = {"status": status, "error": probe.error}
            if probe.ok:
                well_known[path]["content_type"] = (probe.response.headers.get("content-type", "") if probe.response else "")
                well_known[path]["size"] = len(probe.body)
                if path == "/.well-known/security.txt" and status == 200:
                    ctx.emit("security.txt is published (RFC 9116) — responsible disclosure is documented.", phase="wellknown")
            await _sleep_ms(120)

        if well_known.get("/robots.txt", {}).get("status") == 200:
            content = ""
            probe = await guarded_fetch(
                ctx.db, ctx.project.id, base + "/robots.txt", method="GET", timeout=8, read_body=True, max_body_bytes=20_000
            )
            if probe.ok:
                content = probe.body.decode("utf-8", errors="replace")
                well_known["/robots.txt"]["content"] = content[:4000]
                disallowed = re.findall(r"(?im)^\s*disallow:\s*(\S+)", content)
                sensitive = [d for d in disallowed if any(token in d.lower() for token in ("admin", "backup", "private", "internal", "config", "db", "sql", "old", "test", "api/"))]
                if sensitive:
                    ctx.save(
                        check_id="http_robots_sensitive_paths",
                        category="info_disclosure",
                        title="robots.txt discloses sensitive paths",
                        severity="low",
                        confidence="tentative",
                        target=host,
                        location="/robots.txt",
                        description=f"Disallowed entries hint at sensitive locations: {', '.join(sensitive[:8])}",
                        impact="Robots.txt is public; listing private areas hands attackers a starting map (it is not an access control).",
                        remediation="Rely on real authentication instead of robots.txt, and keep sensitive paths out of it.",
                        references=["https://www.rfc-editor.org/rfc/rfc9309"],
                        cwe="CWE-200",
                        detected_by=ENGINE_NAME,
                        engine_version=ENGINE_VERSION,
                        asset_id=asset.id,
                        evidence={
                            "kind": "http_response",
                            "label": "/robots.txt",
                            "response": content[:2000],
                            "source": ENGINE_NAME,
                        },
                        tags=["disclosure"],
                    )
                    result.findings += 1
        ctx.phase("wellknown", "done", progress=100)

        # ------------------------------------------------------- HTML analysis
        mixed_content = [
            url_value
            for tag, url_value in html.links
            if url_value.lower().startswith("http://") and is_https
        ]
        if mixed_content:
            ctx.save(
                check_id="http_mixed_content",
                category="misconfig",
                title="Page loads resources over plain HTTP (mixed content)",
                severity="medium",
                confidence="certain",
                target=host,
                location=mixed_content[0][:200],
                description=f"{len(mixed_content)} resource(s) are referenced over http:// on an HTTPS page.",
                impact="Browsers block or run these resources insecurely, allowing content injection into a protected page.",
                remediation="Reference every resource with https:// (or a protocol-relative/root-relative URL).",
                references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
                cwe="CWE-319",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset.id,
                evidence={
                    "kind": "http_response",
                    "label": "Insecure resource references",
                    "response": "\n".join(mixed_content[:15]),
                    "source": ENGINE_NAME,
                },
                tags=["html", "tls"],
            )
            result.findings += 1

        if html.generator:
            ctx.save(
                check_id="http_generator_meta",
                category="info_disclosure",
                title="CMS/platform disclosed in page metadata",
                severity="info",
                confidence="certain",
                target=host,
                location="meta[name=generator]",
                description=f"<meta name=\"generator\"> reveals: {html.generator[:120]}",
                impact="Version information guides attackers toward known CVEs for that platform.",
                remediation="Remove the generator meta tag or strip version numbers.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
                cwe="CWE-200",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset.id,
                tags=["disclosure"],
            )
            result.findings += 1

        if "index of /" in html.title.lower() or re.search(r"<h1>\s*index of", body_text[:4000], re.IGNORECASE):
            ctx.save(
                check_id="http_directory_listing",
                category="exposure",
                title="Directory listing is enabled",
                severity="medium",
                confidence="firm",
                target=host,
                location=parts.path or "/",
                description="The server returned an auto-generated index of files for this path.",
                impact="Attackers browse the structure and download files that were never meant to be public.",
                remediation="Disable autoindex (nginx: autoindex off; Apache: Options -Indexes) and review the exposed directory.",
                references=["https://owasp.org/www-community/attacks/Directory_traversal"],
                cwe="CWE-548",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset.id,
                evidence={
                    "kind": "http_response",
                    "label": "Directory index response",
                    "response": body_text[:1500],
                    "source": ENGINE_NAME,
                },
                tags=["exposure"],
            )
            result.findings += 1

        traceback_hit = next((marker for marker in TRACEBACK_MARKERS if marker in body_text.lower()), "")
        if traceback_hit and response.status_code >= 400:
            ctx.save(
                check_id="http_verbose_error",
                category="info_disclosure",
                title="Verbose error page leaks internals",
                severity="high" if response.status_code >= 500 else "medium",
                confidence="firm",
                target=host,
                location=parts.path or "/",
                description=f"The {response.status_code} response contains framework/database error output (matched '{traceback_hit}').",
                impact="Stack traces, SQL fragments and file paths reveal the technology stack and often the exact vulnerable query.",
                remediation="Disable debug mode in production and return a generic error page with a correlation id.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/"],
                cwe="CWE-209",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset.id,
                evidence={
                    "kind": "http_response",
                    "label": f"HTTP {response.status_code} body excerpt",
                    "response": body_text[:2000],
                    "source": ENGINE_NAME,
                },
                tags=["errors"],
            )
            result.findings += 1

        # --------------------------------------------------------------- CSRF
        csrf_findings = 0
        for form in html.forms:
            if form["method"] != "post":
                continue
            has_token = any(
                any(hint in (field.get("name") or "").lower() for hint in CSRF_TOKEN_HINTS)
                for field in form["inputs"]
            )
            if has_token:
                continue
            action = form.get("action") or (parts.path or "/")
            if any(
                token in action.lower() for token in ("search", "login", "signin", "newsletter", "subscribe", "contact")
            ) and not html.has_password_field:
                # Low-impact forms: report once as informational instead of alarming the client
                severity, confidence = "info", "tentative"
            else:
                severity, confidence = "medium", "firm"
            ctx.save(
                check_id="csrf_missing_token_post_form",
                category="csrf",
                title="POST form without an anti-CSRF token",
                severity=severity,
                confidence=confidence,
                target=host,
                location=action[:200],
                description="The form posts state-changing data without any token-like field (csrf/_token/authenticity_token/XSRF).",
                impact="If the session cookie is sent automatically (SameSite=Lax still permits top-level POST navigation in some flows), an attacker page can submit this form on behalf of a logged-in user.",
                remediation="Add a per-session anti-CSRF token validated server-side, and/or require SameSite=Strict cookies plus re-authentication for sensitive actions.",
                references=["https://owasp.org/www-community/attacks/csrf", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
                cwe="CWE-352",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset.id,
                evidence={
                    "kind": "http_request",
                    "label": f"Form at {action[:120]}",
                    "request": f"POST {action}\nmethod={form['method']}\nfields={', '.join(f.get('name', '') for f in form['inputs'][:12])}",
                    "source": ENGINE_NAME,
                },
                tags=["csrf"],
            )
            csrf_findings += 1
        result.findings += csrf_findings
        if csrf_findings:
            ctx.emit(f"{csrf_findings} POST form(s) without an anti-CSRF token (heuristic, review manually).", level="warn")

        # ------------------------------------------------------------ snapshot
        snapshot = {
            "url": fetch.final_url,
            "status_code": response.status_code,
            "title": html.title[:200],
            "server": headers.get("server", ""),
            "security_headers": header_snapshot,
            "cookies": cookies,
            "redirects": redirect_chain,
            "tls": tls_summary,
            "well_known": {k: {kk: vv for kk, vv in v.items() if kk != "content"} for k, v in well_known.items()},
            "forms": [{"action": f.get("action", ""), "method": f.get("method", ""), "fields": len(f["inputs"])} for f in html.forms][:20],
            "links_found": len(html.links),
            "mixed_content": mixed_content[:10],
            "generator": html.generator[:120],
            "captured_at": _now_iso(),
        }
        changed_keys = detect_http_changes(
            ctx.db, project_id=ctx.project.id, asset=asset, scan_id=ctx.scan.id, new_snapshot=snapshot
        )
        if changed_keys:
            ctx.emit(f"Attack-surface changes detected: {', '.join(changed_keys)}", level="warn", kind="metric")

        asset.last_scanned_at = _now()
        recompute_asset_risk(ctx.db, asset)
        ctx.db.commit()

        result.data["targets"].append(
            {
                "host": host,
                "url": fetch.final_url,
                "status": response.status_code,
                "findings": len(header_issues) + len(cookie_issues) + csrf_findings,
                "cookies": len(cookies),
                "tls": tls_summary,
            }
        )

    ctx.scan.stats = {**(ctx.scan.stats or {}), "http": result.data}
    ctx.db.commit()
    return result


async def _sleep_ms(milliseconds: int) -> None:
    import asyncio

    await asyncio.sleep(milliseconds / 1000.0)


def _now():
    from ..core.utils import utcnow

    return utcnow()


def _now_iso() -> str:
    from ..core.utils import utcnow_iso

    return utcnow_iso()
