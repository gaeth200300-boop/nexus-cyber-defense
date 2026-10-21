"""Report data assembly + rendering dispatch.

A report is built from the database only — findings, evidence, scans, assets and
scope records that actually exist. Nothing is synthesized: if a project has no
findings, the report says so, and every count is computed from stored rows.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..core.utils import to_iso_z, utcnow
from ..models import Asset, CveRecord, Evidence, Finding, KevEntry, Report, Scan, Scope, Service
from ..services.findings import severity_counts

log = logging.getLogger("nexus.reports")

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


# ---------------------------------------------------------------------------
# Data assembly
# ---------------------------------------------------------------------------
def _finding_rows(db: Session, report: Report) -> list[Finding]:
    kind = report.kind
    project_id = report.project_id
    base = select(Finding).where(Finding.project_id == project_id)

    if kind == "scan_summary" and report.scan_ids:
        base = base.where(Finding.scan_id.in_(report.scan_ids))
    elif kind == "comparison":
        scan_a = (report.options or {}).get("scan_a")
        scan_b = (report.options or {}).get("scan_b")
        if scan_b:
            base = base.where(Finding.scan_id == scan_b)
        elif scan_a:
            base = base.where(Finding.scan_id == scan_a)
    elif kind == "executive":
        base = base.where(Finding.status.in_(("open", "confirmed", "in_progress")), Finding.severity.in_(("critical", "high", "medium")))

    rows = list(db.execute(base.order_by(Finding.last_seen_at.desc()).limit(600)).scalars().all())
    rows.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 5, -f.occurrence_count))
    return rows


def _comparison_sets(db: Session, report: Report) -> dict[str, list[Finding]]:
    options = report.options or {}
    scan_a, scan_b = options.get("scan_a"), options.get("scan_b")
    if not (scan_a and scan_b):
        return {"new": [], "resolved": [], "persistent": [], "error": ["comparison requires options.scan_a and options.scan_b"]}

    def of_scan(scan_id: str) -> dict[str, Finding]:
        rows = db.execute(
            select(Finding).where(Finding.project_id == report.project_id, Finding.scan_id == scan_id)
        ).scalars().all()
        return {f.fingerprint: f for f in rows}

    a, b = of_scan(scan_a), of_scan(scan_b)
    new = [f for key, f in b.items() if key not in a]
    resolved = [f for key, f in a.items() if key not in b]
    persistent = [f for key, f in b.items() if key in a]
    for group in (new, resolved, persistent):
        group.sort(key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 5)
    return {"new": new, "resolved": resolved, "persistent": persistent, "error": []}


def _evidence_for(db: Session, finding: Finding) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Evidence).where(Evidence.finding_id == finding.id).order_by(Evidence.created_at.desc()).limit(2)
    ).scalars().all()
    return [
        {
            "kind": e.kind,
            "label": e.label,
            "request": e.request_snippet,
            "response": e.response_snippet[:1500],
            "redactions": len(e.redactions or []),
            "sha256": e.raw_sha256,
        }
        for e in rows
    ]


def _intel_for(db: Session, finding_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    from ..models import FindingIntelLink

    if not finding_ids:
        return {}
    links = db.execute(
        select(FindingIntelLink).where(FindingIntelLink.finding_id.in_(finding_ids[:300]))
    ).scalars().all()
    out: dict[str, list[dict[str, Any]]] = {}
    for link in links:
        out.setdefault(link.finding_id, []).append(
            {"cve": link.cve_id, "match_type": link.match_type, "confidence": link.confidence}
        )
    return out


def collect_report_data(db: Session, report: Report) -> dict[str, Any]:
    from ..models import Project

    project = db.get(Project, report.project_id)
    findings = _finding_rows(db, report)
    finding_ids = [f.id for f in findings]
    intel = _intel_for(db, finding_ids)

    scopes = db.execute(select(Scope).where(Scope.project_id == report.project_id, Scope.is_active.is_(True))).scalars().all()
    asset_count = int(db.execute(select(func.count(Asset.id)).where(Asset.project_id == report.project_id)).scalar_one() or 0)
    service_count = int(db.execute(select(func.count(Service.id)).where(Service.project_id == report.project_id)).scalar_one() or 0)

    scan_rows: list[dict[str, Any]] = []
    if report.scan_ids:
        scans = db.execute(select(Scan).where(Scan.id.in_(report.scan_ids))).scalars().all()
        scan_rows = [
            {
                "id": s.id,
                "name": s.name,
                "kind": s.kind,
                "profile": s.profile,
                "status": s.status,
                "progress": s.progress,
                "engine": s.engine,
                "engine_version": s.engine_version,
                "started_at": to_iso_z(s.started_at),
                "finished_at": to_iso_z(s.finished_at),
                "targets": [t.get("value") or t.get("host") for t in (s.targets or [])][:20],
                "authorization": s.authorization_snapshot or {},
                "stats": s.stats or {},
                "error": s.error,
            }
            for s in scans
        ]

    kev_ids: list[str] = []
    for items in intel.values():
        kev_ids.extend(i["cve"] for i in items)
    kev_rows: dict[str, dict[str, Any]] = {}
    if kev_ids:
        for entry in db.execute(select(KevEntry).where(KevEntry.cve_id.in_(set(kev_ids)))).scalars().all():
            kev_rows[entry.cve_id] = {
                "vendor": entry.vendor_project,
                "product": entry.product,
                "ransomware": entry.known_ransomware,
                "due_date": to_iso_z(entry.due_date),
                "action": entry.required_action,
            }
    cve_rows: dict[str, dict[str, Any]] = {}
    if kev_ids:
        for record in db.execute(select(CveRecord).where(CveRecord.id.in_(set(kev_ids)))).scalars().all():
            cve_rows[record.id] = {
                "score": record.cvss_v3_score,
                "severity": record.cvss_severity,
                "vector": record.cvss_v3_vector,
                "description": record.description[:600],
                "url": record.source_url,
            }

    include_evidence = bool((report.options or {}).get("include_evidence", True))
    include_remediation = bool((report.options or {}).get("include_remediation", True))

    items: list[dict[str, Any]] = []
    for f in findings:
        items.append(
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "status": f.status,
                "verified": f.verified,
                "active_check": f.active_check,
                "target": f.target,
                "location": f.location,
                "description": f.description,
                "impact": f.impact,
                "remediation": f.remediation if include_remediation else "",
                "references": (f.references or [])[:6],
                "cwe": f.cwe,
                "cve": f.cve,
                "owasp": f.owasp,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "detected_by": f.detected_by,
                "engine_version": f.engine_version,
                "occurrence_count": f.occurrence_count,
                "first_seen_at": to_iso_z(f.first_seen_at),
                "last_seen_at": to_iso_z(f.last_seen_at),
                "tags": f.tags or [],
                "intel": [
                    {**link, "nvd": cve_rows.get(link["cve"]), "kev": kev_rows.get(link["cve"])}
                    for link in intel.get(f.id, [])
                ],
                "evidence": _evidence_for(db, f) if include_evidence else [],
            }
        )

    status_counts: dict[str, int] = {}
    for f in findings:
        status_counts[f.status] = status_counts.get(f.status, 0) + 1
    category_counts: dict[str, int] = {}
    for f in findings:
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    comparison = _comparison_sets(db, report) if report.kind == "comparison" else None

    return {
        "report": {
            "id": report.id,
            "kind": report.kind,
            "format": report.format,
            "title": report.title,
            "version": report.version,
            "generated_at": to_iso_z(utcnow()),
            "period_from": to_iso_z(report.period_from),
            "period_to": to_iso_z(report.period_to),
            "options": report.options or {},
        },
        "platform": {
            "name": settings.app_name,
            "version": settings.version,
            "classification": "CONFIDENTIAL — authorized security assessment output",
        },
        "project": {
            "id": project.id if project else "",
            "name": project.name if project else "",
            "kind": project.kind if project else "",
            "description": (project.description if project else "")[:600],
        },
        "summary": {
            "severity_counts": severity_counts(db, report.project_id),
            "status_counts": status_counts,
            "category_counts": category_counts,
            "findings_in_report": len(items),
            "assets": asset_count,
            "services": service_count,
            "scans": len(scan_rows),
            "verified_findings": sum(1 for f in findings if f.verified),
            "critical_high": sum(1 for f in findings if f.severity in ("critical", "high")),
        },
        "scopes": [
            {
                "kind": s.kind,
                "value": s.value,
                "include_subdomains": s.include_subdomains,
                "allow_active": s.allow_active,
                "authorization_ref": s.authorization_ref,
                "authorized_by": s.authorized_by,
                "verified_method": s.verified_method,
                "verified_at": to_iso_z(s.verified_at),
                "expires_at": to_iso_z(s.expires_at),
            }
            for s in scopes
        ],
        "scans": scan_rows,
        "findings": items,
        "comparison": (
            {
                "error": comparison["error"],
                "new": [f.fingerprint for f in comparison["new"]],
                "resolved": [f.fingerprint for f in comparison["resolved"]],
                "persistent": [f.fingerprint for f in comparison["persistent"]],
                "counts": {
                    "new": len(comparison["new"]),
                    "resolved": len(comparison["resolved"]),
                    "persistent": len(comparison["persistent"]),
                },
                "detail": {
                    "new": [f.title for f in comparison["new"][:50]],
                    "resolved": [f.title for f in comparison["resolved"][:50]],
                    "persistent": [f.title for f in comparison["persistent"][:50]],
                },
            }
            if comparison
            else None
        ),
        "methodology": [
            "All findings were produced by deterministic engines running on this platform; each one carries a confidence level and the engine that detected it.",
            "Items marked confidence=tentative are indicators that require validation; they are never presented as confirmed vulnerabilities.",
            "CVE links are marked exact (the CVE id came from the detection source) or inferred (keyword correlation) — inferred links are not asserted as real exposure.",
            "Evidence is stored redacted: secrets, tokens and personal data are removed before storage.",
            "The authorization snapshot recorded at scan creation time proves the exact scope that was approved when the scan ran.",
        ],
        "limitations": [
            "Findings represent the state of the targets at scan time; the platform does not claim continuous coverage between scans.",
            "Absence of findings is not proof of absence of vulnerabilities.",
            "Active checks run only where the scope explicitly allows active testing.",
        ],
    }


# ---------------------------------------------------------------------------
# Rendering dispatch
# ---------------------------------------------------------------------------
async def generate_report(db: Session, report_id: str) -> dict[str, Any]:
    """Render a stored Report row to its file. Returns a small result summary."""
    report = db.get(Report, report_id)
    if report is None:
        raise RuntimeError(f"report {report_id} not found")

    report.status = "generating"
    db.commit()

    try:
        data = collect_report_data(db, report)
        settings.ensure_dirs()
        fmt = (report.format or "html").lower()
        path = settings.reports_dir / f"{report.id}.{fmt}"

        if fmt == "json":
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        elif fmt == "pdf":
            from .render_pdf import render_pdf

            render_pdf(data, path)
        else:
            from .render_html import render_html

            path.write_text(render_html(data), encoding="utf-8")

        report.status = "ready"
        report.file_path = str(path)
        report.size_bytes = path.stat().st_size if path.exists() else 0
        if path.exists():
            from ..core.utils import sha256_hex

            report.sha256 = sha256_hex(path.read_bytes())
        report.summary = {
            "severity_counts": data["summary"]["severity_counts"],
            "findings": data["summary"]["findings_in_report"],
            "critical_high": data["summary"]["critical_high"],
            "assets": data["summary"]["assets"],
        }
        report.completed_at = utcnow()
        report.error = ""
        db.commit()
        log.info("report %s rendered to %s (%s bytes)", report.id, path.name, report.size_bytes)
        return {"report_id": report.id, "format": fmt, "size_bytes": report.size_bytes, "path": str(path)}
    except Exception as exc:
        report.status = "failed"
        report.error = f"{type(exc).__name__}: {exc}"
        report.completed_at = utcnow()
        db.commit()
        log.exception("report %s failed", report_id)
        raise


def default_report_title(kind: str, project_name: str, lang: str = "en") -> str:
    labels = {
        "executive": ("Executive Security Report", "التقرير الأمني التنفيذي"),
        "technical": ("Technical Security Report", "التقرير الأمني التقني"),
        "comparison": ("Scan Comparison Report", "تقرير مقارنة الفحوصات"),
        "scan_summary": ("Scan Summary Report", "ملخص الفحص"),
    }
    en, ar = labels.get(kind, ("Security Report", "تقرير أمني"))
    stamp = datetime.utcnow().strftime("%Y-%m-%d")
    return f"{en if lang == 'en' else ar} — {project_name} — {stamp}"
