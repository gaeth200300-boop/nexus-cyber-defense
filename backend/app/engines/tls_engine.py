"""TLS / certificate engine — real handshakes and X.509 parsing.

Produces verifiable evidence: certificate subject/issuer/SANs, validity, key size,
signature algorithm, negotiated protocol/cipher and which protocol versions the
server still accepts.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from ..core.netguard import authorize_target, check_ip_allowed, resolve_host_sync
from ..core.utils import sha256_hex
from ..services.assets import record_change, upsert_asset, upsert_service
from .base import ENGINE_NAME, ENGINE_VERSION, EngineContext, EngineResult

log = logging.getLogger("nexus.engine.tls")

WEAK_SIGNATURE_ALGORITHMS = ("md5", "sha1")
MIN_RSA_BITS = 2048
EXPIRY_WARNING_DAYS = 21


def _key_details(cert: x509.Certificate) -> dict[str, Any]:
    public_key = cert.public_key()
    details: dict[str, Any] = {"type": type(public_key).__name__, "size": None}
    if isinstance(public_key, rsa.RSAPublicKey):
        details.update(type="RSA", size=public_key.key_size)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        details.update(type="ECDSA", size=public_key.curve.key_size, curve=public_key.curve.name)
    elif isinstance(public_key, dsa.DSAPublicKey):
        details.update(type="DSA", size=public_key.key_size)
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed25519PublicKey)):
        details.update(type="EdDSA", size=256)
    return details


def _probe_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool | None:
    """Return True/False if the protocol is accepted, or None when the client refuses to test it."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
    except (ValueError, ssl.SSLError):
        return None
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        message = str(exc).lower()
        if "unsupported protocol" in message or "no protocols available" in message:
            return None
        return False
    except OSError:
        return False


def inspect_tls(host: str, port: int = 443, timeout: float = 8.0, *, allow_private: bool = False) -> dict[str, Any]:
    """Perform a real TLS inspection. Never raises — returns a report with `error` set instead."""
    report: dict[str, Any] = {
        "host": host,
        "port": port,
        "connected": False,
        "error": "",
        "protocol": "",
        "cipher": "",
        "cert": {},
        "chain": [],
        "protocols_supported": {},
        "verified": False,
        "verification_error": "",
    }

    # Validate the resolved address before connecting (netguard, address-level).
    addresses = resolve_host_sync(host)
    if not addresses:
        report["error"] = "dns_resolution_failed"
        return report
    target_ip = addresses[0]
    ok, reason = check_ip_allowed(target_ip, allow_private=allow_private)
    if not ok:
        report["error"] = f"address_blocked:{reason}"
        return report

    # 1) verification handshake (does the chain validate for this hostname?)
    verification_error = ""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target_ip if _is_ip(host) else host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=None if _is_ip(host) else host) as tls:
                report["verified"] = True
                report["protocol"] = tls.version() or ""
                cipher = tls.cipher()
                report["cipher"] = cipher[0] if cipher else ""
                report["cert"] = _certificate_to_dict(tls.getpeercert(binary_form=True))
                report["chain"] = _chain_to_list(tls)
    except ssl.SSLCertVerificationError as exc:
        verification_error = str(getattr(exc, "verify_message", "") or exc)
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        report["error"] = f"tls_handshake_failed: {type(exc).__name__}"
        return report

    # 2) unverified handshake to obtain the certificate even when validation failed
    if not report["verified"]:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target_ip if _is_ip(host) else host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=None if _is_ip(host) else host) as tls:
                    report["connected"] = True
                    report["protocol"] = tls.version() or ""
                    cipher = tls.cipher()
                    report["cipher"] = cipher[0] if cipher else ""
                    report["cert"] = _certificate_to_dict(tls.getpeercert(binary_form=True))
                    report["chain"] = _chain_to_list(tls)
        except (ssl.SSLError, OSError, socket.timeout) as exc:
            report["error"] = f"tls_handshake_failed: {type(exc).__name__}"
            return report
        report["verification_error"] = verification_error
    report["connected"] = True

    # 3) protocol version support
    for name, version in (
        ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ):
        if version is None:
            continue
        report["protocols_supported"][name] = _probe_protocol(target_ip if _is_ip(host) else host, port, version, timeout)

    # 4) computed helpers
    cert = report.get("cert") or {}
    if cert:
        report["cert"]["hostname_matches"] = _hostname_matches(host, cert)
        try:
            expires = datetime.fromisoformat(cert["not_after"].replace("Z", "+00:00"))
            report["cert"]["days_until_expiry"] = (expires - datetime.now(timezone.utc)).days
        except Exception:
            report["cert"]["days_until_expiry"] = None
    return report


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _certificate_to_dict(der: bytes | None) -> dict[str, Any]:
    if not der:
        return {}
    cert = x509.load_der_x509_certificate(der)
    try:
        san_names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName
        )
    except x509.ExtensionNotFound:
        san_names = []

    return {
        "subject": cert.subject.rfc4514_string(),
        "common_name": (cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME) or [{}])[0].value
        if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        else "",
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_cn": (cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME) or [{}])[0].value
        if cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        else "",
        "san": san_names[:50],
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name or str(cert.signature_algorithm_oid.dotted_string),
        "key": _key_details(cert),
        "fingerprint_sha256": sha256_hex(der),
        "self_signed": cert.subject == cert.issuer,
        "is_ca": bool(
            (cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            if _has_extension(cert, x509.BasicConstraints)
            else False
        ),
    }


def _has_extension(cert: x509.Certificate, ext_class) -> bool:
    try:
        cert.extensions.get_extension_for_class(ext_class)
        return True
    except x509.ExtensionNotFound:
        return False


def _chain_to_list(tls_socket: ssl.SSLSocket) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    try:
        certificates = tls_socket.get_unverified_chain()  # type: ignore[attr-defined]
    except Exception:
        return chain
    for der in certificates or []:
        try:
            cert = x509.load_der_x509_certificate(der)
            chain.append(
                {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_after": cert.not_valid_after_utc.isoformat(),
                    "is_ca": bool(
                        (
                            cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                            if _has_extension(cert, x509.BasicConstraints)
                            else False
                        )
                    ),
                }
            )
        except Exception:
            continue
    return chain


def _hostname_matches(host: str, cert: dict[str, Any]) -> bool:
    names = [n.lower() for n in (cert.get("san") or [])]
    if not names and cert.get("common_name"):
        names = [str(cert["common_name"]).lower()]
    host = host.lower().rstrip(".")
    for name in names:
        if name == host:
            return True
        if name.startswith("*.") and host.endswith(name[1:]) and host.count(".") == name.count("."):
            return True
    return False


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def evaluate(ctx: EngineContext, host: str, report: dict[str, Any], *, asset_id: str | None, service_id: str | None) -> int:
    """Turn a TLS report into findings. Returns the number of findings created."""
    if not report.get("connected"):
        return 0
    created = 0
    cert = report.get("cert") or {}
    evidence_base = {
        "kind": "tls_chain",
        "label": f"TLS handshake with {host}:{report.get('port')}",
        "response": (
            f"protocol={report.get('protocol')} cipher={report.get('cipher')}\n"
            f"subject={cert.get('subject')}\nissuer={cert.get('issuer')}\n"
            f"valid: {cert.get('not_before')} -> {cert.get('not_after')}\n"
            f"SAN: {', '.join(cert.get('san') or []) or '(none)'}\n"
            f"verification: {'OK' if report.get('verified') else report.get('verification_error') or 'failed'}"
        ),
        "source": ENGINE_NAME,
    }

    days_left = cert.get("days_until_expiry")
    if isinstance(days_left, int) and days_left < 0:
        ctx.save(
            check_id="tls_cert_expired",
            category="tls",
            title=f"TLS certificate for {host} expired {abs(days_left)} day(s) ago",
            severity="high",
            confidence="certain",
            target=host,
            location=f"{host}:{report.get('port')}",
            description=f"The certificate is not valid after {cert.get('not_after')}.",
            impact="Browsers and API clients show trust errors and may refuse to connect; users are trained to click through warnings.",
            remediation="Renew the certificate and automate renewal with ACME (e.g. Let's Encrypt / your CA).",
            references=["https://www.rfc-editor.org/rfc/rfc5280"],
            cwe="CWE-298",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            asset_id=asset_id,
            service_id=service_id,
            verified=True,
            evidence=evidence_base,
            tags=["tls", "certificate", "expiry"],
        )
        created += 1
    elif isinstance(days_left, int) and days_left <= EXPIRY_WARNING_DAYS:
        ctx.save(
            check_id="tls_cert_expiring_soon",
            category="tls",
            title=f"TLS certificate for {host} expires in {days_left} day(s)",
            severity="medium",
            confidence="certain",
            target=host,
            location=f"{host}:{report.get('port')}",
            description=f"The certificate expires on {cert.get('not_after')}.",
            impact="An unnoticed expiry causes an immediate outage for every TLS client.",
            remediation="Renew now and set a monitoring alert at least 14 days before expiry.",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            asset_id=asset_id,
            service_id=service_id,
            verified=True,
            evidence=evidence_base,
            tags=["tls", "certificate", "expiry"],
        )
        created += 1

    if cert.get("self_signed"):
        ctx.save(
            check_id="tls_self_signed",
            category="tls",
            title=f"{host} uses a self-signed certificate",
            severity="high",
            confidence="certain",
            target=host,
            location=f"{host}:{report.get('port')}",
            description="The certificate issuer equals its subject, so no public trust anchor validates it.",
            impact="Clients cannot distinguish the service from an attacker performing a man-in-the-middle; trust warnings train users to ignore real attacks.",
            remediation="Issue a certificate from a publicly trusted CA or deploy your internal CA into the client trust store.",
            references=["https://www.rfc-editor.org/rfc/rfc5280#section-6"],
            cwe="CWE-295",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            asset_id=asset_id,
            service_id=service_id,
            verified=True,
            evidence=evidence_base,
            tags=["tls", "certificate"],
        )
        created += 1
    elif not report.get("verified"):
        error_text = (report.get("verification_error") or "").lower()
        if "hostname" in error_text or (cert and cert.get("hostname_matches") is False):
            ctx.save(
                check_id="tls_hostname_mismatch",
                category="tls",
                title=f"Certificate name does not match {host}",
                severity="high",
                confidence="certain",
                target=host,
                location=f"{host}:{report.get('port')}",
                description=f"The certificate is valid for {', '.join(cert.get('san') or [cert.get('common_name', '')])} but not for the requested host.",
                impact="Clients cannot establish a trusted session with this name; automated integrations will fail or be forced to disable verification.",
                remediation="Reissue the certificate including this hostname in the SAN list.",
                references=["https://www.rfc-editor.org/rfc/rfc6125"],
                cwe="CWE-297",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset_id,
                service_id=service_id,
                verified=True,
                evidence=evidence_base,
                tags=["tls", "certificate"],
            )
            created += 1
        elif report.get("verification_error"):
            ctx.save(
                check_id="tls_untrusted_chain",
                category="tls",
                title=f"Certificate chain for {host} is not trusted",
                severity="medium",
                confidence="certain",
                target=host,
                location=f"{host}:{report.get('port')}",
                description=f"Validation failed: {report.get('verification_error')}",
                impact="Clients may reject the connection or require manual trust exceptions.",
                remediation="Install the full intermediate chain on the server and verify with an independent TLS scanner.",
                references=["https://www.rfc-editor.org/rfc/rfc5280"],
                cwe="CWE-295",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=asset_id,
                service_id=service_id,
                evidence=evidence_base,
                tags=["tls", "certificate"],
            )
            created += 1

    signature = str(cert.get("signature_algorithm", "")).lower()
    if any(weak in signature for weak in WEAK_SIGNATURE_ALGORITHMS):
        ctx.save(
            check_id="tls_weak_signature",
            category="tls",
            title=f"Certificate signed with a weak algorithm ({cert.get('signature_algorithm')})",
            severity="medium",
            confidence="certain",
            target=host,
            location=f"{host}:{report.get('port')}",
            description="MD5/SHA-1 signatures are considered broken for certificate issuance.",
            impact="An attacker with significant resources may forge a certificate that some clients still accept.",
            remediation="Reissue the certificate using SHA-256 or stronger.",
            references=["https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"],
            cwe="CWE-327",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            asset_id=asset_id,
            service_id=service_id,
            evidence=evidence_base,
            tags=["tls", "crypto"],
        )
        created += 1

    key = cert.get("key") or {}
    if key.get("type") == "RSA" and isinstance(key.get("size"), int) and key["size"] < MIN_RSA_BITS:
        ctx.save(
            check_id="tls_weak_key",
            category="tls",
            title=f"RSA key is only {key.get('size')} bits",
            severity="high",
            confidence="certain",
            target=host,
            location=f"{host}:{report.get('port')}",
            description=f"The certificate uses an RSA key of {key.get('size')} bits, below the 2048-bit minimum.",
            impact="Keys of this size can be factored with academic-scale resources, allowing traffic decryption and impersonation.",
            remediation="Generate a 2048-bit (preferably 3072-bit) RSA key or an ECDSA P-256 key, then reissue.",
            references=["https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final"],
            cwe="CWE-326",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            asset_id=asset_id,
            service_id=service_id,
            evidence=evidence_base,
            tags=["tls", "crypto"],
        )
        created += 1

    legacy = [name for name in ("TLSv1.0", "TLSv1.1") if report.get("protocols_supported", {}).get(name) is True]
    if legacy:
        ctx.save(
            check_id="tls_legacy_protocols",
            category="tls",
            title=f"Legacy TLS protocol still accepted ({', '.join(legacy)})",
            severity="medium",
            confidence="certain",
            target=host,
            location=f"{host}:{report.get('port')}",
            description=f"The server completed a handshake using {', '.join(legacy)}.",
            impact="Legacy protocols permit downgrade attacks and use deprecated cryptography (BEAST, POODLE class issues).",
            remediation="Disable TLS 1.0/1.1 and require TLS 1.2+ (ideally TLS 1.3) with modern cipher suites.",
            references=["https://datatracker.ietf.org/doc/rfc8996/", "https://www.rfc-editor.org/rfc/rfc7525"],
            cwe="CWE-327",
            detected_by=ENGINE_NAME,
            engine_version=ENGINE_VERSION,
            asset_id=asset_id,
            service_id=service_id,
            verified=True,
            active_check=True,
            evidence={
                **evidence_base,
                "response": evidence_base["response"]
                + f"\nprotocols accepted: {', '.join(k for k, v in report.get('protocols_supported', {}).items() if v)}",
            },
            tags=["tls", "protocol"],
        )
        created += 1

    return created


async def run(ctx: EngineContext, targets: list[dict[str, Any]]) -> EngineResult:
    result = EngineResult(data={"hosts": []})
    for target in targets:
        ctx.check_cancel()
        host = str(target.get("host") or target.get("value") or "").strip()
        port = int(target.get("port") or 443)
        if not host:
            continue

        decision = authorize_target(ctx.db, ctx.project.id, host, port=port, require_active=False)
        if not decision.allowed:
            ctx.emit(f"TLS inspection skipped for {host} — {decision.reason}", level="warn", phase="scope_check")
            continue

        ctx.phase("tls", "running", progress=20)
        ctx.emit(f"Inspecting TLS on {host}:{port} …", phase="tls")
        report = await asyncio.to_thread(inspect_tls, host, port, 8.0, allow_private=ctx.allow_private)
        if not report.get("connected"):
            ctx.emit(f"TLS inspection failed for {host}:{port} — {report.get('error')}", level="warn", phase="tls")
            ctx.phase("tls", "done", progress=100)
            continue

        asset, created = upsert_asset(
            ctx.db,
            project_id=ctx.project.id,
            asset_type="host" if not _is_ip(host) else "ip",
            value=host,
            scope_id=decision.scope_id,
            source="scan",
            scan_id=ctx.scan.id,
        )
        if created:
            result.assets += 1

        service, service_created, changed = upsert_service(
            ctx.db,
            project_id=ctx.project.id,
            asset=asset,
            port=port,
            protocol="tcp",
            state="open",
            name="https" if port == 443 else "tls",
            product=(report.get("cert") or {}).get("issuer_cn", ""),
            version=report.get("protocol", ""),
            tls={
                "protocol": report.get("protocol"),
                "cipher": report.get("cipher"),
                "issuer": (report.get("cert") or {}).get("issuer_cn", ""),
                "subject": (report.get("cert") or {}).get("common_name", ""),
                "not_after": (report.get("cert") or {}).get("not_after", ""),
                "fingerprint_sha256": (report.get("cert") or {}).get("fingerprint_sha256", ""),
                "protocols_supported": report.get("protocols_supported", {}),
                "verified": report.get("verified"),
            },
            source=ENGINE_NAME,
        )
        if service_created:
            result.services += 1
        if "tls_certificate" in changed:
            record_change(
                ctx.db,
                project_id=ctx.project.id,
                asset_id=asset.id,
                service_id=service.id,
                scan_id=ctx.scan.id,
                kind="tls_change",
                severity="medium",
                summary=f"TLS certificate on {host}:{port} changed",
                before={"fingerprint": (service.tls or {}).get("fingerprint_sha256", "")},
                after={"fingerprint": (report.get("cert") or {}).get("fingerprint_sha256", "")},
            )

        created_findings = evaluate(ctx, host, report, asset_id=asset.id, service_id=service.id)
        result.findings += created_findings
        result.data["hosts"].append(
            {
                "host": host,
                "port": port,
                "protocol": report.get("protocol"),
                "issuer": (report.get("cert") or {}).get("issuer_cn"),
                "days_until_expiry": (report.get("cert") or {}).get("days_until_expiry"),
                "verified": report.get("verified"),
            }
        )
        ctx.db.commit()
        ctx.phase("tls", "done", progress=100)

    return result
