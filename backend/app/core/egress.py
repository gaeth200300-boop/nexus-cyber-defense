"""Guarded egress for outbound *integrations* (NVD, CISA KEV, AI providers).

Scan targets go through netguard's RoE authorization because they are the
customer's infrastructure. Integration endpoints are different: they are public
data services, so they are not scope-checked — but they still must be reached
safely. This module guarantees that, no matter what DNS answers:

* loopback / private / link-local / cloud-metadata addresses are refused;
* the TCP connection is pinned to a validated public IP (the URL is rewritten to
  that IP and the original hostname is sent via SNI + Host header);
* redirects are followed manually, one hop at a time, each hop re-validated and
  optionally restricted to an allow-list of hostnames;
* environment proxies are never honoured.

Every outbound integration call in NEXUS goes through `fetch_public`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any


from .netguard import TargetDecision, build_client, check_ip_allowed, guarded_request, resolve_host_sync
from .utils import normalize_host

log = logging.getLogger("nexus.egress")

# Integration hosts that are always refused even if DNS says otherwise.
_ALWAYS_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".localdomain")


class EgressBlocked(Exception):
    """Raised when an integration endpoint resolves somewhere unsafe."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")


@dataclass
class PublicResponse:
    ok: bool
    status: int | None = None
    body: bytes = b""
    final_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""

    def json(self) -> Any:
        import json

        return json.loads(self.body.decode("utf-8", errors="replace"))

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def _host_allowed(host: str, allowed_hosts: list[str] | None) -> bool:
    if not allowed_hosts:
        return True
    return any(host == h or host.endswith("." + h) for h in allowed_hosts)


def resolve_public_ips(host: str) -> list[str]:
    """Resolve `host` and keep only globally routable addresses.

    Raises EgressBlocked when nothing safe remains — we refuse rather than
    falling back to an unchecked connection.
    """
    host = normalize_host(host)
    if not host:
        raise EgressBlocked("empty_host", "integration URL has no host")
    if host in ("localhost", "localhost.localdomain") or host.endswith(_ALWAYS_BLOCKED_SUFFIXES):
        raise EgressBlocked("local_hostname", f"'{host}' is a local hostname")
    ips = resolve_host_sync(host)
    if not ips:
        raise EgressBlocked("dns_failure", f"could not resolve '{host}'")
    safe: list[str] = []
    for ip in ips:
        allowed, reason = check_ip_allowed(ip, allow_private=False)
        if allowed:
            safe.append(ip)
    if not safe:
        raise EgressBlocked("unsafe_address", f"'{host}' resolved only to unsafe addresses ({', '.join(ips)})")
    return safe


async def fetch_public(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
    timeout: float = 20.0,
    max_bytes: int = 8_000_000,
    max_redirects: int = 2,
    allowed_hosts: list[str] | None = None,
) -> PublicResponse:
    """Fetch a public integration endpoint with pinned, validated connections."""
    from urllib.parse import urljoin, urlsplit

    current = url
    async with build_client(allow_private=False, timeout=timeout, headers=headers) as client:
        for _hop in range(max_redirects + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https"):
                return PublicResponse(False, error=f"unsupported_scheme: {parts.scheme}", final_url=current)
            host = normalize_host(parts.hostname or "")
            if not _host_allowed(host, allowed_hosts):
                return PublicResponse(False, error=f"host_not_allowed: {host}", final_url=current)
            try:
                ips = resolve_public_ips(host)
            except EgressBlocked as exc:
                return PublicResponse(False, error=f"{exc.reason}: {exc.detail}", final_url=current)

            decision = TargetDecision(allowed=True, host=host, kind="domain", resolved_ips=ips, reason="integration_endpoint")
            response, _pinned, error = await guarded_request(client, method, current, decision, headers=headers, content=content)
            if response is None:
                return PublicResponse(False, error=error, final_url=current)

            if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
                next_url = urljoin(current, response.headers["location"])
                if method == "POST" and response.status_code == 303:
                    method, content = "GET", None
                current = next_url
                continue

            body = b""
            try:
                body = response.content[:max_bytes]
            except Exception as exc:  # pragma: no cover - streaming quirks
                log.debug("body read failed for %s: %s", current, exc)

            if response.status_code >= 400:
                return PublicResponse(
                    False,
                    status=response.status_code,
                    body=body,
                    final_url=current,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    error=f"http_{response.status_code}",
                )
            return PublicResponse(
                True,
                status=response.status_code,
                body=body,
                final_url=current,
                headers={k.lower(): v for k, v in response.headers.items()},
            )
        return PublicResponse(False, error="too_many_redirects", final_url=current)


async def fetch_public_json(url: str, **kwargs: Any) -> tuple[Any | None, PublicResponse]:
    """Convenience wrapper returning (parsed_json, raw_response)."""
    response = await fetch_public(url, **kwargs)
    if not response.ok:
        return None, response
    try:
        return response.json(), response
    except Exception as exc:
        return None, PublicResponse(
            False,
            status=response.status,
            body=response.body,
            final_url=response.final_url,
            headers=response.headers,
            error=f"invalid_json: {exc}",
        )
