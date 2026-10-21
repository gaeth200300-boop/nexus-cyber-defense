"""Scan event emission + per-scan-kind phase plans (drives the live UI progress)."""

from __future__ import annotations

import copy
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, attributes

from ..models import Scan, ScanEvent
from .utils import utcnow

# ---------------------------------------------------------------------------
# Phase plans — each scan kind declares the ordered phases the UI will show.
# ---------------------------------------------------------------------------
PHASE_PLANS: dict[str, list[dict[str, str]]] = {
    "asset_discovery": [
        {"key": "scope_check", "en": "Scope verification", "ar": "التحقق من نطاق التفويض"},
        {"key": "dns", "en": "DNS records", "ar": "سجلات DNS"},
        {"key": "ct", "en": "Certificate Transparency", "ar": "شفافية الشهادات"},
        {"key": "wordlist", "en": "Subdomain wordlist", "ar": "قائمة النطاقات الفرعية"},
        {"key": "tls", "en": "TLS inspection", "ar": "فحص شهادات TLS"},
        {"key": "store", "en": "Persist assets", "ar": "حفظ الأصول"},
    ],
    "dns_diagnostics": [
        {"key": "scope_check", "en": "Scope verification", "ar": "التحقق من نطاق التفويض"},
        {"key": "resolve", "en": "Resolution", "ar": "تحليل الاسم"},
        {"key": "records", "en": "Record types", "ar": "أنواع السجلات"},
        {"key": "mail_security", "en": "Mail security (SPF/DMARC/DKIM)", "ar": "أمن البريد"},
        {"key": "hygiene", "en": "DNS hygiene (CAA/NS/SOA)", "ar": "نظافة DNS"},
        {"key": "store", "en": "Store findings", "ar": "حفظ النتائج"},
    ],
    "http_analysis": [
        {"key": "scope_check", "en": "Scope verification", "ar": "التحقق من نطاق التفويض"},
        {"key": "connect", "en": "Connectivity", "ar": "الاتصال"},
        {"key": "headers", "en": "Security headers", "ar": "الرؤوس الأمنية"},
        {"key": "cookies", "en": "Cookie attributes", "ar": "سمات الكوكيز"},
        {"key": "redirects", "en": "Redirect chain", "ar": "سلسلة التحويلات"},
        {"key": "tls", "en": "TLS / certificate", "ar": "TLS والشهادة"},
        {"key": "wellknown", "en": "Well-known files", "ar": "ملفات معيارية"},
        {"key": "store", "en": "Store findings", "ar": "حفظ النتائج"},
    ],
    "web_vuln": [
        {"key": "scope_check", "en": "Scope verification", "ar": "التحقق من نطاق التفويض"},
        {"key": "baseline", "en": "Baseline crawl", "ar": "الزحف الأساسي"},
        {"key": "passive", "en": "Passive analysis", "ar": "تحليل سلبي"},
        {"key": "active", "en": "Authorized active checks", "ar": "فحوص نشطة مصرّح بها"},
        {"key": "correlate", "en": "Deduplicate & correlate", "ar": "إزالة التكرار والربط"},
        {"key": "store", "en": "Store findings", "ar": "حفظ النتائج"},
    ],
    "network_scan": [
        {"key": "scope_check", "en": "Scope verification", "ar": "التحقق من نطاق التفويض"},
        {"key": "resolve", "en": "Host discovery", "ar": "اكتشاف المضيف"},
        {"key": "ports", "en": "Port scanning", "ar": "فحص المنافذ"},
        {"key": "fingerprint", "en": "Service fingerprint", "ar": "بصمة الخدمات"},
        {"key": "store", "en": "Store services", "ar": "حفظ الخدمات"},
    ],
    "pcap_analysis": [
        {"key": "parse", "en": "Parse capture", "ar": "تحليل الملف"},
        {"key": "protocols", "en": "Protocol statistics", "ar": "إحصاءات البروتوكولات"},
        {"key": "conversations", "en": "Conversations", "ar": "الاتصالات"},
        {"key": "dns", "en": "DNS activity", "ar": "نشاط DNS"},
        {"key": "http", "en": "HTTP activity", "ar": "نشاط HTTP"},
        {"key": "tls", "en": "TLS/SNI", "ar": "TLS و SNI"},
        {"key": "iocs", "en": "Indicator extraction", "ar": "استخراج المؤشرات"},
        {"key": "store", "en": "Store report", "ar": "حفظ التقرير"},
    ],
    "log_analysis": [
        {"key": "parse", "en": "Parse upload", "ar": "تحليل الملف"},
        {"key": "normalize", "en": "Normalize events", "ar": "توحيد الأحداث"},
        {"key": "rules", "en": "Detection rules", "ar": "قواعد الكشف"},
        {"key": "alerts", "en": "Group into alerts", "ar": "تجميع التنبيهات"},
        {"key": "store", "en": "Store results", "ar": "حفظ النتائج"},
    ],
    "intel_correlation": [
        {"key": "collect", "en": "Collect findings", "ar": "جمع النتائج"},
        {"key": "query", "en": "Query NVD / KEV", "ar": "الاستعلام من NVD وKEV"},
        {"key": "link", "en": "Create links", "ar": "إنشاء الروابط"},
        {"key": "store", "en": "Store links", "ar": "حفظ الروابط"},
    ],
}


def build_phases(kind: str) -> list[dict[str, Any]]:
    plan = PHASE_PLANS.get(kind, [{"key": "run", "en": "Run", "ar": "التنفيذ"}])
    return [{**p, "status": "pending", "progress": 0} for p in plan]


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------
def emit(
    db: Session,
    *,
    project_id: str,
    scan_id: str | None = None,
    level: str = "info",
    kind: str = "log",
    message: str = "",
    phase: str = "",
    data: dict[str, Any] | None = None,
    commit: bool = False,
) -> ScanEvent:
    event = ScanEvent(
        scan_id=scan_id,
        project_id=project_id,
        ts=utcnow(),
        level=level[:10],
        kind=kind[:20],
        phase=phase[:60],
        message=message[:4000],
        data=data or {},
    )
    db.add(event)
    if commit:
        db.commit()
    return event


def set_phase(
    db: Session,
    scan: Scan,
    phase_key: str,
    status: str,
    *,
    progress: int | None = None,
    commit: bool = False,
) -> None:
    """Update the phase plan stored on the scan and recompute overall progress."""
    # Deep-copy: a shallow list() shares the dict objects with the value loaded
    # from the DB, so in-place edits would make SQLAlchemy's equality check see
    # "no change" and silently skip the UPDATE.
    phases = copy.deepcopy(list(scan.phases or []))
    for index, phase in enumerate(phases):
        if phase.get("key") == phase_key:
            phase["status"] = status
            if progress is not None:
                phase["progress"] = progress
            break
    else:
        phases.append({"key": phase_key, "en": phase_key, "ar": phase_key, "status": status, "progress": progress or 0})
    scan.phases = phases
    attributes.flag_modified(scan, "phases")

    if phases:
        scan.progress = int(sum(int(p.get("progress", 0)) for p in phases) / len(phases))
    scan.heartbeat_at = utcnow()
    if status == "running" and scan.status in ("queued",):
        scan.status = "running"
        scan.started_at = scan.started_at or utcnow()
    if commit:
        db.commit()


def latest_event_id(db: Session, scan_id: str) -> int:
    return int(db.execute(select(func.max(ScanEvent.id)).where(ScanEvent.scan_id == scan_id)).scalar() or 0)


def events_since(db: Session, *, scan_id: str | None, project_id: str, after_id: int, limit: int = 200) -> list[ScanEvent]:
    query = select(ScanEvent).where(ScanEvent.project_id == project_id, ScanEvent.id > after_id)
    if scan_id:
        query = query.where(ScanEvent.scan_id == scan_id)
    return list(db.execute(query.order_by(ScanEvent.id.asc()).limit(limit)).scalars().all())


def event_to_dict(event: ScanEvent) -> dict[str, Any]:
    from .utils import to_iso_z

    return {
        "id": event.id,
        "scan_id": event.scan_id,
        "ts": to_iso_z(event.ts),
        "level": event.level,
        "kind": event.kind,
        "phase": event.phase,
        "message": event.message,
        "data": event.data or {},
    }
