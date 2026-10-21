"""Engine & integration availability detection.

The UI must never imply a capability the machine does not have, so this module is
the single source of truth for "what can actually run here".
"""

from __future__ import annotations

import importlib.metadata
import shutil
import socket
from dataclasses import asdict, dataclass

from ..config import settings


@dataclass
class Capability:
    key: str
    name_en: str
    name_ar: str
    kind: str  # builtin | integration | optional
    available: bool
    version: str = ""
    detail: str = ""
    setup_hint: str = ""


def _pkg_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return ""


def find_nmap() -> str | None:
    if settings.nmap_path:
        import os

        if os.path.isfile(settings.nmap_path):
            return settings.nmap_path
    return shutil.which("nmap")


def zap_configured() -> bool:
    return bool(settings.zap_url.strip())


def zap_reachable() -> tuple[bool, str]:
    if not zap_configured():
        return False, "not_configured"
    from urllib.parse import urlparse

    parsed = urlparse(settings.zap_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 8080)
    try:
        with socket.create_connection((host, port), timeout=2.0):
            return True, "reachable"
    except OSError as exc:
        return False, f"unreachable: {exc}"


def ai_status() -> dict[str, object]:
    provider = settings.ai_provider
    if provider == "none" or not settings.ai_model:
        return {
            "configured": False,
            "provider": provider,
            "model": settings.ai_model,
            "detail": "AI Copilot is not configured. Analysis features stay deterministic; no AI output is fabricated.",
        }
    key_required = provider in ("openai", "openrouter", "azure", "custom")
    if key_required and not settings.ai_api_key:
        return {
            "configured": False,
            "provider": provider,
            "model": settings.ai_model,
            "detail": "Provider selected but NEXUS_AI_API_KEY is empty.",
        }
    if provider == "ollama":
        from urllib.parse import urlparse

        base = settings.ai_base_url or "http://127.0.0.1:11434/v1"
        parsed = urlparse(base)
        try:
            with socket.create_connection((parsed.hostname or "127.0.0.1", parsed.port or 11434), timeout=2.0):
                return {"configured": True, "provider": provider, "model": settings.ai_model, "detail": "Ollama reachable."}
        except OSError as exc:
            return {
                "configured": False,
                "provider": provider,
                "model": settings.ai_model,
                "detail": f"Ollama not reachable at {base}: {exc}",
            }
    return {"configured": True, "provider": provider, "model": settings.ai_model, "detail": "AI Copilot ready."}


def detect_capabilities() -> list[Capability]:
    nmap_path = find_nmap()
    zap_ok, zap_detail = zap_reachable()
    ai = ai_status()

    caps: list[Capability] = [
        Capability(
            "dns",
            "DNS engine (records, SPF/DMARC, subdomain discovery)",
            "محرك DNS (السجلات، SPF/DMARC، اكتشاف النطاقات الفرعية)",
            "builtin",
            available=bool(_pkg_version("dnspython")),
            version=_pkg_version("dnspython"),
            detail="dnspython",
        ),
        Capability(
            "tls",
            "TLS / certificate engine",
            "محرك TLS والشهادات",
            "builtin",
            available=bool(_pkg_version("cryptography")),
            version=_pkg_version("cryptography"),
            detail="stdlib ssl + cryptography",
        ),
        Capability(
            "http",
            "HTTP analysis engine",
            "محرك تحليل HTTP",
            "builtin",
            available=bool(_pkg_version("httpx")),
            version=_pkg_version("httpx"),
            detail="httpx with pinned connections",
        ),
        Capability(
            "webvuln",
            "Built-in web vulnerability engine (passive + safe active)",
            "محرك ثغرات الويب المدمج (سلبي + نشط آمن)",
            "builtin",
            available=True,
            version=_pkg_version("httpx"),
            detail="Deterministic checks: headers, cookies, TLS, reflection, error signatures, exposed files",
        ),
        Capability(
            "tcp_scan",
            "Built-in TCP connect scanner",
            "ماسح TCP المدمج",
            "builtin",
            available=True,
            version="asyncio",
            detail="No root/admin required, connect scan only",
        ),
        Capability(
            "pcap",
            "PCAP analyzer",
            "محلل ملفات PCAP",
            "builtin",
            available=bool(_pkg_version("dpkt")),
            version=_pkg_version("dpkt"),
            detail="dpkt",
        ),
        Capability(
            "logs",
            "Log analysis & detection engine",
            "محرك تحليل السجلات والكشف",
            "builtin",
            available=True,
            version="0.1.0",
            detail="nginx / apache / syslog / JSON / CSV with rule DSL",
        ),
        Capability(
            "intel_nvd",
            "NVD 2.0 vulnerability intelligence",
            "استخبارات الثغرات NVD 2.0",
            "builtin",
            available=True,
            version="2.0",
            detail=("API key configured" if settings.nvd_api_key else "No API key — rate limited to 5 requests/30s"),
            setup_hint="" if settings.nvd_api_key else "Optional: request a free key at nvd.nist.gov and set NEXUS_NVD_API_KEY",
        ),
        Capability(
            "intel_kev",
            "CISA Known Exploited Vulnerabilities feed",
            "قائمة CISA للثغرات المستغَلة فعليًا",
            "builtin",
            available=True,
            version="feed",
            detail=settings.kev_feed_url,
        ),
        Capability(
            "nmap",
            "Nmap integration",
            "تكامل Nmap",
            "integration",
            available=bool(nmap_path),
            version="",
            detail=nmap_path or "nmap not found on PATH",
            setup_hint="" if nmap_path else "Install Nmap from nmap.org, then set NEXUS_NMAP_PATH or add it to PATH.",
        ),
        Capability(
            "zap",
            "OWASP ZAP integration",
            "تكامل OWASP ZAP",
            "integration",
            available=zap_ok,
            version="",
            detail=f"{settings.zap_url or 'not configured'} ({zap_detail})",
            setup_hint=""
            if zap_ok
            else "Run ZAP (e.g. docker run -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -config api.key=...) and set NEXUS_ZAP_URL + NEXUS_ZAP_API_KEY.",
        ),
        Capability(
            "ai_copilot",
            "AI Security Copilot",
            "مساعد الأمن الذكي",
            "optional",
            available=bool(ai["configured"]),
            version=str(settings.ai_model or ""),
            detail=str(ai["detail"]),
            setup_hint="Set NEXUS_AI_PROVIDER (openrouter/openai/ollama) + NEXUS_AI_API_KEY + NEXUS_AI_MODEL in backend\\.env, then restart.",
        ),
        Capability(
            "reports_pdf",
            "PDF report generation",
            "توليد تقارير PDF",
            "builtin",
            available=bool(_pkg_version("reportlab")),
            version=_pkg_version("reportlab"),
            detail="ReportLab + arabic-reshaper/python-bidi for Arabic shaping",
        ),
    ]
    return caps


def capabilities_dict() -> dict[str, object]:
    caps = detect_capabilities()
    by_key = {c.key: asdict(c) for c in caps}
    return {
        "capabilities": by_key,
        "summary": {
            "total": len(caps),
            "available": sum(1 for c in caps if c.available),
            "missing_integrations": [c.key for c in caps if c.kind == "integration" and not c.available],
        },
    }
