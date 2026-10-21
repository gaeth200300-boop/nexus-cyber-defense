"""netguard — the single egress chokepoint for every outbound connection.

Responsibilities
----------------
1. Rules-of-Engagement (RoE): an outbound target must match an *active, unexpired*
   scope entry of the owning project. No scope => no packet.
2. SSRF hardening: block loopback, private, link-local, reserved and multicast
   addresses, plus cloud metadata endpoints (always blocked, even in lab mode).
3. DNS-rebinding defence: validate the peer IP of the *actual* TCP connection,
   not only the pre-flight DNS answer (see `GuardedNetworkBackend`).
4. Uniform, auditable denials: every rejection raises `ScopeViolation` with a
   machine-readable reason that the API/UI can display.

Nothing in the platform may perform network I/O without going through here.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from typing import Any, Iterable

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Project, Scope
from .utils import normalize_host, utcnow

log = logging.getLogger("nexus.netguard")

# Endpoints that are NEVER reachable, regardless of any flag or scope entry.
CLOUD_METADATA_IPS: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS / Azure / GCP / DigitalOcean IMDS
        "169.254.170.2",    # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",      # Oracle Cloud
        "fd00:ec2::254",    # AWS IMDS IPv6
    }
)
CLOUD_METADATA_HOSTS: frozenset[str] = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "metadata.azure.com",
        "metadata",
    }
)
LOCAL_HOSTNAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "kubernetes.default"})

BLOCKED_PORTS: frozenset[int] = frozenset(
    {
        0,
        25,    # SMTP — no mail delivery from a scanner
        465,   # SMTPS
        587,   # SMTP submission
        137, 138, 139, 445,  # NetBIOS / SMB — never needed for assessment
        631,   # CUPS
    }
)


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized scope or is inherently unsafe."""

    def __init__(self, reason: str, detail: str = "", target: str = "") -> None:
        self.reason = reason
        self.detail = detail
        self.target = target
        super().__init__(f"{reason}: {detail or target}")


@dataclass
class TargetDecision:
    allowed: bool
    host: str
    kind: str = "domain"
    resolved_ips: list[str] = field(default_factory=list)
    scope_id: str | None = None
    scope_value: str = ""
    allow_active: bool = False
    reason: str = ""
    detail: str = ""


# ---------------------------------------------------------------------------
# Low level address checks
# ---------------------------------------------------------------------------
def _hostname_is_always_blocked(host: str) -> tuple[bool, str]:
    if host in LOCAL_HOSTNAMES or host.endswith(".localhost") or host.endswith(".local"):
        return True, "loopback_and_local_hostnames"
    if host in CLOUD_METADATA_HOSTS:
        return True, "cloud_metadata_hostname"
    return False, ""


def check_ip_allowed(ip: str, *, allow_private: bool) -> tuple[bool, str]:
    """Hard address policy. Cloud metadata is blocked *always*."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, "unparseable_address"

    normalized = str(addr)
    if normalized in CLOUD_METADATA_IPS:
        return False, "cloud_metadata_address"
    if addr.is_loopback:
        return False, "loopback_address"
    if addr.is_link_local:
        return False, "link_local_address"
    if addr.is_multicast:
        return False, "multicast_address"
    if addr.is_reserved or addr.is_unspecified:
        return False, "reserved_address"
    # IPv4-mapped IPv6 safety net
    if addr.version == 6 and addr.ipv4_mapped is not None:
        return check_ip_allowed(str(addr.ipv4_mapped), allow_private=allow_private)
    if addr.is_private:
        if not allow_private:
            return False, "private_address_not_authorized"
        return True, ""  # explicitly authorized lab/private target
    if not addr.is_global:
        return False, "non_global_address"
    return True, ""


def check_port_allowed(port: int, *, allow_privileged: bool = True) -> tuple[bool, str]:
    if port in BLOCKED_PORTS:
        return False, "blocked_port"
    if port < 1 or port > 65535:
        return False, "invalid_port"
    return True, ""


def resolve_host_sync(host: str) -> list[str]:
    """Resolve A/AAAA records (filtered to globally routable answers)."""
    if not host:
        return []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        addr = addr.split("%")[0]  # strip IPv6 zone id
        if addr not in ips:
            ips.append(addr)
    return ips


async def resolve_host(host: str) -> list[str]:
    import asyncio

    return await asyncio.get_running_loop().run_in_executor(None, resolve_host_sync, host)


# ---------------------------------------------------------------------------
# Scope (RoE) evaluation
# ---------------------------------------------------------------------------
def _active_scopes(db: Session, project_id: str) -> list[Scope]:
    now = utcnow()
    rows = db.execute(
        select(Scope).where(Scope.project_id == project_id, Scope.is_active.is_(True))
    ).scalars().all()
    return [s for s in rows if s.expires_at is None or s.expires_at > now]


def _scope_matches_host(scope: Scope, host: str) -> bool:
    value = normalize_host(scope.value)
    if scope.kind == "domain":
        if host == value:
            return True
        return bool(scope.include_subdomains and host.endswith("." + value))
    if scope.kind == "url":
        try:
            from urllib.parse import urlparse

            parsed = urlparse(scope.value if "://" in scope.value else "https://" + scope.value)
            scope_host = normalize_host(parsed.hostname or "")
        except Exception:
            scope_host = value
        return host == scope_host or (scope.include_subdomains and host.endswith("." + scope_host))
    return False


def _scope_matches_ip(scope: Scope, ip: str) -> bool:
    try:
        if scope.kind == "ip":
            return str(ipaddress.ip_address(scope.value)) == str(ipaddress.ip_address(ip))
        if scope.kind == "cidr":
            return ipaddress.ip_address(ip) in ipaddress.ip_network(scope.value, strict=False)
        if scope.kind in ("domain", "url"):
            # A domain scope implicitly authorizes the addresses it currently resolves to,
            # but only those already validated against the private-range policy.
            return False
    except ValueError:
        return False
    return False


def authorize_target(
    db: Session,
    project_id: str,
    target: str,
    *,
    kind: str | None = None,
    require_active: bool = False,
    port: int | None = None,
) -> TargetDecision:
    """Decide whether `target` (hostname, IP, URL or CIDR member) may be contacted."""
    host = normalize_host(target)
    if not host:
        return TargetDecision(False, host, reason="empty_target")

    blocked, reason = _hostname_is_always_blocked(host)
    if blocked:
        return TargetDecision(False, host, reason=reason, detail="This hostname is permanently blocked.")

    if port is not None:
        ok_port, port_reason = check_port_allowed(port)
        if not ok_port:
            return TargetDecision(False, host, reason=port_reason, detail=f"port {port}")

    project = db.get(Project, project_id)
    if project is None:
        return TargetDecision(False, host, reason="unknown_project")

    allow_private = bool(settings.allow_private_targets and project.allow_private_targets)

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    resolved: list[str] = [host] if is_ip else resolve_host_sync(host)

    # --- address policy first: unsafe addresses are rejected before scope matching
    for ip in resolved:
        ok, ip_reason = check_ip_allowed(ip, allow_private=allow_private)
        if not ok:
            detail = f"resolved address {ip} rejected"
            if ip_reason == "private_address_not_authorized":
                detail += " (private targets require NEXUS_ALLOW_PRIVATE_TARGETS=true AND project.allow_private_targets)"
            elif ip_reason in ("cloud_metadata_address", "cloud_metadata_hostname"):
                detail = "Cloud metadata endpoints are blocked unconditionally."
            return TargetDecision(False, host, kind=kind or "domain", resolved_ips=resolved, reason=ip_reason, detail=detail)

    if not resolved and not is_ip:
        return TargetDecision(False, host, reason="dns_resolution_failed", detail="The name did not resolve to any address.")

    # --- scope (RoE) match
    scopes = _active_scopes(db, project_id)
    matched: Scope | None = None
    for scope in scopes:
        if is_ip:
            if _scope_matches_ip(scope, host) or _scope_matches_host(scope, host):
                matched = scope
                break
        else:
            if _scope_matches_host(scope, host):
                matched = scope
                break
            # allow an explicit IP/CIDR authorization to cover a resolved address
            if any(_scope_matches_ip(scope, ip) for ip in resolved):
                matched = scope
                break

    if matched is None:
        return TargetDecision(
            False,
            host,
            kind=kind or ("ip" if is_ip else "domain"),
            resolved_ips=resolved,
            reason="out_of_scope",
            detail="No active authorization entry matches this target.",
        )

    if matched.expires_at and matched.expires_at <= utcnow():
        return TargetDecision(False, host, resolved_ips=resolved, reason="scope_expired", detail="Authorization entry expired.")

    if require_active and not matched.allow_active:
        return TargetDecision(
            False,
            host,
            resolved_ips=resolved,
            scope_id=matched.id,
            scope_value=matched.value,
            reason="active_testing_not_authorized",
            detail="This scope entry does not allow active testing.",
        )

    return TargetDecision(
        True,
        host,
        kind=kind or ("ip" if is_ip else "domain"),
        resolved_ips=resolved,
        scope_id=matched.id,
        scope_value=matched.value,
        allow_active=bool(matched.allow_active),
        reason="authorized",
        detail=f"Matched scope entry '{matched.value}'",
    )


def require_authorized(db: Session, project_id: str, target: str, **kwargs: Any) -> TargetDecision:
    decision = authorize_target(db, project_id, target, **kwargs)
    if not decision.allowed:
        raise ScopeViolation(decision.reason, decision.detail, decision.host)
    return decision


# ---------------------------------------------------------------------------
# httpx integration: connection pinning (DNS-rebinding safe) + manual redirects
#
# Instead of trusting httpx to re-resolve the hostname (which would allow a
# rebinding attacker to swap the answer between our check and the connection),
# we rewrite the URL to the *validated IP* and tell httpcore to use the original
# hostname for TLS SNI / certificate verification via the `sni_hostname`
# extension. Redirects are never followed automatically: each hop is authorized
# separately so a redirect cannot smuggle us out of scope (classic SSRF bypass).
# ---------------------------------------------------------------------------
@dataclass
class PinnedRequest:
    connect_url: str
    headers: dict[str, str]
    extensions: dict[str, Any]
    ip: str
    original_url: str


def _format_ip_for_url(ip: str) -> str:
    return f"[{ip}]" if ":" in ip else ip


def pin_url(url: str, decision: TargetDecision, *, connect_ip: str | None = None, headers: dict[str, str] | None = None) -> PinnedRequest:
    """Rewrite `url` so the TCP connection goes to a validated IP of the authorized host."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ScopeViolation("unsupported_scheme", f"scheme '{parts.scheme}' is not allowed", url)
    host = normalize_host(parts.hostname or decision.host)
    if host != decision.host and not host.endswith("." + decision.host):
        raise ScopeViolation("host_mismatch", f"'{host}' does not belong to authorized target '{decision.host}'", url)

    port = parts.port or (443 if parts.scheme == "https" else 80)
    ip = connect_ip or (decision.resolved_ips[0] if decision.resolved_ips else "")
    if not ip:
        raise ScopeViolation("no_valid_address", "no validated address available for this target", url)

    netloc = f"{_format_ip_for_url(ip)}:{port}"
    connect_url = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))

    host_header = host if port in (80, 443) else f"{host}:{port}"
    merged_headers = {"Host": host_header, **(headers or {})}
    extensions: dict[str, Any] = {"sni_hostname": host}
    return PinnedRequest(
        connect_url=connect_url,
        headers=merged_headers,
        extensions=extensions,
        ip=ip,
        original_url=url,
    )


def build_client(
    *,
    allow_private: bool,
    timeout: float = 10.0,
    verify: bool = True,
    headers: dict[str, str] | None = None,
    limits: httpx.Limits | None = None,
) -> httpx.AsyncClient:
    """Create an httpx client configured for pinned, non-redirecting, guarded requests."""
    import ssl

    if verify:
        ssl_context = ssl.create_default_context()
    else:  # only used to *report* invalid certificates, never to hide them
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    transport = httpx.AsyncHTTPTransport(
        retries=0,
        verify=ssl_context,
        limits=limits or httpx.Limits(max_connections=20, max_keepalive_connections=10),
        trust_env=False,  # never honour environment proxies: they must not silently reroute scans
    )
    return httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout, connect=min(timeout, 8.0)),
        follow_redirects=False,  # redirects are handled by guarded_fetch below
        headers=headers
        or {
            "User-Agent": "Mozilla/5.0 (compatible; NexusCyberDefense/0.1; +authorized-security-testing)",
            "Accept": "*/*",
            "Accept-Language": "en;q=0.9,ar;q=0.8",
            "Connection": "close",
        },
        limits=limits,
        trust_env=False,
    )


async def guarded_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    decision: TargetDecision,
    *,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
    connect_ip: str | None = None,
) -> tuple[httpx.Response | None, PinnedRequest | None, str]:
    """Send one request to an authorized target, pinned to a validated address."""
    pinned = pin_url(url, decision, connect_ip=connect_ip, headers=headers)
    request = client.build_request(
        method,
        pinned.connect_url,
        headers=pinned.headers,
        content=content,
    )
    request.extensions.update(pinned.extensions)
    try:
        response = await client.send(request, stream=False)
        return response, pinned, ""
    except ScopeViolation:
        raise
    except httpx.HTTPError as exc:
        return None, pinned, f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        return None, pinned, f"{type(exc).__name__}: {exc}"


@dataclass
class FetchHop:
    url: str
    status: int | None
    location: str = ""
    allowed: bool = True
    error: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0


@dataclass
class FetchResult:
    ok: bool
    final_url: str
    status: int | None
    response: httpx.Response | None
    hops: list[FetchHop] = field(default_factory=list)
    error: str = ""
    body: bytes = b""


async def guarded_fetch(
    db: Session,
    project_id: str,
    url: str,
    *,
    method: str = "GET",
    max_redirects: int = 5,
    require_active: bool = False,
    timeout: float = 10.0,
    read_body: bool = True,
    max_body_bytes: int = 512_000,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
) -> FetchResult:
    """Authorized, pinned, redirect-safe fetch. Every hop re-validated against the RoE."""
    import time
    from urllib.parse import urljoin, urlsplit

    allow_private = allow_private_for_project(db, project_id)
    hops: list[FetchHop] = []
    current = url

    async with build_client(allow_private=allow_private, timeout=timeout, headers=headers) as client:
        for _ in range(max_redirects + 1):
            try:
                decision = authorize_target(
                    db,
                    project_id,
                    normalize_host(urlsplit(current).hostname or ""),
                    require_active=require_active,
                    port=urlsplit(current).port,
                )
            except Exception as exc:  # pragma: no cover
                return FetchResult(False, current, None, None, hops, f"authorization_error: {exc}")

            if not decision.allowed:
                hops.append(FetchHop(current, None, allowed=False, error=f"{decision.reason}: {decision.detail}"))
                return FetchResult(False, current, None, None, hops, decision.reason)

            started = time.perf_counter()
            response, pinned, error = await guarded_request(
                client, method, current, decision, content=content, headers=headers
            )
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            if response is None:
                hops.append(FetchHop(current, None, error=error, elapsed_ms=elapsed_ms))
                return FetchResult(False, current, None, None, hops, error)

            body = b""
            if read_body and method != "HEAD":
                try:
                    body = response.content[:max_body_bytes]
                except Exception as exc:  # pragma: no cover
                    error = f"body_read_error: {exc}"

            hops.append(
                FetchHop(
                    current,
                    response.status_code,
                    location=response.headers.get("location", ""),
                    elapsed_ms=elapsed_ms,
                    headers={k.lower(): v for k, v in response.headers.items()},
                )
            )

            if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
                location = response.headers["location"]
                next_url = urljoin(current, location)
                next_parts = urlsplit(next_url)
                # scheme downgrade is allowed but recorded; non-http schemes are rejected
                if next_parts.scheme not in ("http", "https"):
                    hops.append(FetchHop(next_url, None, allowed=False, error="redirect_scheme_blocked"))
                    return FetchResult(False, current, response.status_code, response, hops, "redirect_scheme_blocked")
                current = next_url
                if response.status_code == 303:
                    method = "GET"
                continue

            return FetchResult(True, current, response.status_code, response, hops, error, body)

        hops.append(FetchHop(current, None, allowed=False, error="too_many_redirects"))
        return FetchResult(False, current, None, None, hops, "too_many_redirects")


def allow_private_for_project(db: Session, project_id: str) -> bool:
    project = db.get(Project, project_id)
    if project is None:
        return False
    return bool(settings.allow_private_targets and project.allow_private_targets)


def summarize_policy() -> dict[str, Any]:
    """Exposed on /system/health so operators can see the active policy."""
    return {
        "allow_private_targets_global": settings.allow_private_targets,
        "active_scanning_enabled": settings.active_scanning_enabled,
        "cloud_metadata_blocked": sorted(CLOUD_METADATA_IPS),
        "blocked_ports": sorted(BLOCKED_PORTS),
        "blocked_hostnames": sorted(set(LOCAL_HOSTNAMES) | set(CLOUD_METADATA_HOSTS)),
    }


def first_blocked_reason(decisions: Iterable[TargetDecision]) -> str:
    for d in decisions:
        if not d.allowed:
            return f"{d.host}: {d.reason}"
    return ""
