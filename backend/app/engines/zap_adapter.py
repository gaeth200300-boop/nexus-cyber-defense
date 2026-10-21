"""OWASP ZAP integration — real scans driven through the ZAP daemon REST API.

How this stays honest and safe:
* the ZAP endpoint is taken from server configuration only (NEXUS_ZAP_URL /
  NEXUS_ZAP_API_KEY); it is never user-supplied, which is why talking to a local
  daemon on 127.0.0.1 is acceptable here (scan *targets* remain RoE-gated);
* every target URL is authorized against the project scope with netguard BEFORE
  it is handed to ZAP, because ZAP performs its own HTTP requests and our
  connection pinning cannot cover them;
* active scanning requires an active-authorized scope entry, the `zap_active`
  profile, and NEXUS_ACTIVE_SCANNING_ENABLED=true;
* alerts are stored with ZAP's own risk/confidence values mapped into our
  severity/confidence vocabulary — nothing is upgraded or invented.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from ..config import settings
from ..core.netguard import ScopeViolation, authorize_target
from ..models import Project, Scan
from .base import EngineContext, EngineResult

log = logging.getLogger("nexus.engine.zap")

ENGINE_NAME = "nexus-zap-adapter"
ENGINE_VERSION = "zap-adapter-0.1"

POLL_INTERVAL = 3.0
MAX_POLL_SECONDS = 900


class ZapError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Low-level REST client for the ZAP daemon
# ---------------------------------------------------------------------------
class ZapClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, *, timeout: float = 20.0) -> None:
        self.base_url = (base_url or settings.zap_url).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.zap_api_key
        if not self.base_url:
            raise ZapError("ZAP is not configured (NEXUS_ZAP_URL is empty)")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout, connect=6.0),
            trust_env=False,
            headers={"Accept": "application/json", "User-Agent": "NEXUS-CyberDefense-ZAP-Adapter/0.1"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _request(self, component: str, view: str, params: dict[str, Any] | None = None) -> Any:
        query = {k: v for k, v in (params or {}).items() if v not in (None, "")}
        if self.api_key:
            query["apikey"] = self.api_key
        url = f"/JSON/{component}/{view}/"
        try:
            response = await self._client.get(url, params=query)
        except httpx.HTTPError as exc:
            raise ZapError(f"ZAP API unreachable at {self.base_url}: {exc}") from exc
        if response.status_code != 200:
            raise ZapError(f"ZAP API returned HTTP {response.status_code} for {url}")
        try:
            payload = response.json()
        except Exception as exc:
            raise ZapError(f"ZAP API returned non-JSON for {url}: {exc}") from exc
        # ZAP signals API errors as {"code": 400, "message": "..."} with HTTP 200
        if isinstance(payload, dict) and payload.get("code") and int(payload.get("code", 200)) >= 400:
            raise ZapError(f"ZAP error: {payload.get('message', 'unknown')}")
        return payload

    async def version(self) -> str:
        payload = await self._request("core", "view/version")
        return str(payload.get("version", "unknown"))

    async def spider_start(self, url: str, *, max_children: int = 20) -> str:
        payload = await self._request("spider", "action/scan", {"url": url, "maxChildren": max_children, "recurse": "true"})
        return str(payload.get("scan", "0"))

    async def spider_status(self, scan_id: str) -> int:
        payload = await self._request("spider", "view/status", {"scanId": scan_id})
        return int(payload.get("status", 0))

    async def spider_results(self, scan_id: str) -> list[str]:
        payload = await self._request("spider", "view/results", {"scanId": scan_id})
        return [str(u) for u in payload.get("results", [])]

    async def ascan_start(self, url: str) -> str:
        payload = await self._request("ascan", "action/scan", {"url": url, "recurse": "true", "inScopeOnly": "false"})
        return str(payload.get("scan", "0"))

    async def ascan_status(self, scan_id: str) -> int:
        payload = await self._request("ascan", "view/status", {"scanId": scan_id})
        return int(payload.get("status", 0))

    async def alerts(self, base_url: str, *, start: int = 0, count: int = 500) -> list[dict[str, Any]]:
        payload = await self._request("alert", "view/alerts", {"baseurl": base_url, "start": start, "count": count})
        return list(payload.get("alerts", []))


# ---------------------------------------------------------------------------
# Mapping ZAP vocabulary -> NEXUS vocabulary
# ---------------------------------------------------------------------------
def zap_severity(riskcode: Any) -> str:
    return {"3": "high", "2": "medium", "1": "low", "0": "info"}.get(str(riskcode), "info")


def zap_confidence(confidence: Any) -> str:
    code = str(confidence)
    if code == "4":  # user confirmed
        return "certain"
    if code in ("2", "3"):  # medium / high confidence
        return "firm"
    return "tentative"


def zap_category(name: str, cweid: Any) -> str:
    lowered = (name or "").lower()
    rules: list[tuple[tuple[str, ...], str]] = [
        (("cross site scripting", "xss"), "xss"),
        (("sql injection", "sqli"), "sqli"),
        (("csrf",), "csrf"),
        (("access control", "authorization", "idor"), "access_control"),
        (("authentication", "session"), "auth"),
        (("cookie",), "cookie"),
        (("cors",), "misconfig"),
        (("header",), "headers"),
        (("ssl", "tls", "certificate"), "tls"),
        (("information disclosure", "information leak", "information exposure"), "info_disclosure"),
        (("path traversal", "directory browsing", "backup file", "exposed"), "exposure"),
        (("server", "banner", "obsolete", "outdated"), "outdated_component"),
        (("traversal", "injection", "remote os"), "injection_other"),
        (("cryptograph", "weak", "hash"), "crypto"),
    ]
    for keywords, category in rules:
        if any(keyword in lowered for keyword in keywords):
            return category
    try:
        cwe = int(cweid or 0)
    except (TypeError, ValueError):
        cwe = 0
    if cwe:
        if cwe in (79, 80, 83, 87):
            return "xss"
        if cwe == 89:
            return "sqli"
        if cwe == 352:
            return "csrf"
        if cwe in (22, 98, 552):
            return "exposure"
        if cwe in (16, 693, 284):
            return "misconfig"
    return "other"


def _alert_to_evidence(alert: dict[str, Any], instance: dict[str, Any]) -> dict[str, Any]:
    request_line = f"{instance.get('method', 'GET')} {instance.get('uri', '')}"
    return {
        "kind": "http_response",
        "label": f"ZAP {alert.get('alertRef', alert.get('pluginId', ''))} — {instance.get('uri', '')[:120]}",
        "request": request_line,
        "response": str(instance.get("evidence", ""))[:2000],
        "source": ENGINE_NAME,
    }


# ---------------------------------------------------------------------------
# Engine entry point
# ---------------------------------------------------------------------------
async def _authorize_targets(db, project: Project, urls: list[str], *, require_active: bool) -> tuple[list[str], list[str]]:
    """Return (authorized, blocked_reasons). Every URL is RoE-checked first."""
    from urllib.parse import urlsplit

    authorized: list[str] = []
    blocked: list[str] = []
    for url in urls:
        parts = urlsplit(url)
        try:
            decision = authorize_target(
                db,
                project.id,
                parts.hostname or "",
                require_active=require_active,
                port=parts.port,
            )
        except ScopeViolation as exc:
            blocked.append(f"{url}: {exc.reason}")
            continue
        if not decision.allowed:
            blocked.append(f"{url}: {decision.reason}")
            continue
        authorized.append(url)
    return authorized, blocked


async def run(ctx: EngineContext, targets: list[dict[str, Any]]) -> EngineResult:
    from .base import target_url

    result = EngineResult()
    db = ctx.db
    scan: Scan = ctx.scan

    if not settings.zap_url.strip():
        raise ZapError(
            "ZAP integration is not configured. Start the ZAP daemon and set NEXUS_ZAP_URL "
            "(e.g. http://127.0.0.1:8080) plus NEXUS_ZAP_API_KEY in backend\\.env."
        )

    active_scan = scan.profile == "zap_active"
    require_active = active_scan or scan.profile in ("safe_active",)

    urls = [target_url(t, default_scheme="https") for t in targets]
    authorized, blocked = await _authorize_targets(db, ctx.project, urls, require_active=require_active)
    for reason in blocked:
        ctx.emit(f"Target blocked by scope policy: {reason}", level="warn", phase="scope_check")
    if not authorized:
        raise ZapError("No target passed the authorization check — nothing was sent to ZAP.")

    if active_scan and not settings.active_scanning_enabled:
        raise ZapError("Active scanning is disabled platform-wide (NEXUS_ACTIVE_SCANNING_ENABLED=false).")

    client = ZapClient()
    try:
        version = await client.version()
        ctx.emit(f"Connected to OWASP ZAP {version} at {settings.zap_url}", phase="connect")
        ctx.phase("connect", "done", progress=100)
    except ZapError:
        await client.close()
        raise

    stats: dict[str, Any] = {"spider_urls": 0, "alerts": 0, "findings": 0, "targets": len(authorized)}
    try:
        for url in authorized:
            ctx.check_cancel()
            # ---------------------------------------------------------- spider
            ctx.phase("baseline", "running", progress=10)
            ctx.emit(f"Spidering {url} with ZAP…", phase="baseline")
            try:
                spider_id = await client.spider_start(url)
            except ZapError as exc:
                ctx.emit(f"ZAP spider failed for {url}: {exc}", level="error", phase="baseline")
                continue
            waited = 0.0
            while True:
                ctx.check_cancel()
                await asyncio.sleep(POLL_INTERVAL)
                waited += POLL_INTERVAL
                try:
                    status = await client.spider_status(spider_id)
                except ZapError as exc:
                    ctx.emit(f"ZAP spider status failed: {exc}", level="warn", phase="baseline")
                    break
                if status >= 100:
                    break
                if waited >= MAX_POLL_SECONDS:
                    ctx.emit("ZAP spider reached the time limit; continuing with what was crawled.", level="warn", phase="baseline")
                    break
            try:
                crawled = await client.spider_results(spider_id)
                stats["spider_urls"] += len(crawled)
                ctx.emit(f"ZAP spider found {len(crawled)} URL(s) under {url}.", phase="baseline")
            except ZapError:
                pass
            ctx.phase("baseline", "done", progress=100)

            # ------------------------------------------------------- active scan
            if active_scan:
                ctx.phase("active", "running", progress=5)
                ctx.emit(f"Running authorized ZAP active scan on {url}…", phase="active")
                try:
                    ascan_id = await client.ascan_start(url)
                except ZapError as exc:
                    ctx.emit(f"ZAP active scan failed for {url}: {exc}", level="error", phase="active")
                    ascan_id = ""
                waited = 0.0
                while ascan_id:
                    ctx.check_cancel()
                    await asyncio.sleep(POLL_INTERVAL)
                    waited += POLL_INTERVAL
                    try:
                        status = await client.ascan_status(ascan_id)
                    except ZapError as exc:
                        ctx.emit(f"ZAP active scan status failed: {exc}", level="warn", phase="active")
                        break
                    ctx.phase("active", "running", progress=min(95, 5 + status))
                    if status >= 100:
                        break
                    if waited >= MAX_POLL_SECONDS * 2:
                        ctx.emit("ZAP active scan reached the time limit.", level="warn", phase="active")
                        break
                ctx.phase("active", "done", progress=100)
            else:
                ctx.emit("Passive profile: no active attacks were sent by ZAP.", phase="passive")

        # ------------------------------------------------------------- alerts
        ctx.phase("correlate", "running", progress=30)
        async with ctx.sem:
            for url in authorized:
                ctx.check_cancel()
                try:
                    alerts = await client.alerts(url)
                except ZapError as exc:
                    ctx.emit(f"Fetching ZAP alerts failed: {exc}", level="error", phase="correlate")
                    continue
                for alert in alerts:
                    instances = alert.get("instances") or [{}]
                    instance = instances[0]
                    name = str(alert.get("alert") or alert.get("name") or "ZAP alert")
                    severity = zap_severity(alert.get("riskcode"))
                    confidence = zap_confidence(alert.get("confidence"))
                    location = str(instance.get("param") or "") or str(instance.get("uri") or "")
                    references = [r.strip() for r in str(alert.get("reference", "")).split("\n") if r.strip()]
                    _, created = ctx.save(
                        check_id=f"zap_{alert.get('pluginId', 'unknown')}",
                        category=zap_category(name, alert.get("cweid")),
                        title=name[:300],
                        severity=severity,
                        confidence=confidence,
                        target=url,
                        location=location[:512],
                        description=str(alert.get("desc", ""))[:4000],
                        impact=str(alert.get("otherinfo", ""))[:4000] or "See the ZAP alert description for the impact of this issue.",
                        remediation=str(alert.get("solution", ""))[:4000],
                        references=references[:10],
                        cwe=f"CWE-{alert.get('cweid')}" if str(alert.get("cweid", "0")) not in ("0", "", "None") else "",
                        detected_by=ENGINE_NAME,
                        engine_version=ENGINE_VERSION,
                        active_check=active_scan,
                        verified=confidence == "certain",
                        evidence=_alert_to_evidence(alert, instance),
                        tags=["zap", f"zap-plugin-{alert.get('pluginId', '')}"[:60]],
                    )
                    stats["alerts"] += 1
                    if created:
                        stats["findings"] += 1
        ctx.phase("correlate", "done", progress=100)
    finally:
        await client.close()

    ctx.phase("store", "running", progress=50)
    result.data = stats
    result.findings = stats["findings"]
    result.notes.append(
        f"ZAP {('active' if active_scan else 'passive')} scan finished: {stats['alerts']} alert(s) across {len(authorized)} target(s), "
        f"{stats['spider_urls']} URL(s) discovered."
    )
    ctx.phase("store", "done", progress=100)
    return result


async def healthcheck() -> dict[str, Any]:
    """Used by the system health endpoint — never raises."""
    if not settings.zap_url.strip():
        return {"configured": False, "reachable": False, "detail": "NEXUS_ZAP_URL is empty"}
    client = ZapClient(timeout=6.0)
    try:
        version = await client.version()
        return {"configured": True, "reachable": True, "detail": f"ZAP {version}"}
    except ZapError as exc:
        return {"configured": True, "reachable": False, "detail": str(exc)}
    finally:
        await client.close()


def build_scan_url(base: str, path: str) -> str:  # small helper reused by tests
    return f"{base.rstrip('/')}{path}"
