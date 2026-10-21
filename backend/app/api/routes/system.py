"""Platform endpoints: health, metadata, capabilities, dashboard, jobs, settings.

Everything here is derived from the database or from real process/integration
probing. The notification centre is a *view* over actual alerts, findings, failed
scans and unreviewed surface changes — never generated placeholder text.
"""

from __future__ import annotations

import logging
import time
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...config import settings
from ...core.constants import (
    ALERT_STATUSES,
    ALERT_STATUS_LABELS,
    ASSET_CHANGE_KINDS,
    ASSET_TYPES,
    CONFIDENCES,
    CONFIDENCE_LABELS,
    EVIDENCE_KINDS,
    FINDING_CATEGORIES,
    FINDING_STATUSES,
    FINDING_STATUS_LABELS,
    GLOBAL_ROLES,
    INCIDENT_STATUSES,
    INCIDENT_STATUS_LABELS,
    JOB_STATUSES,
    LAB_CATEGORIES,
    LAB_LEVELS,
    LOG_FORMATS,
    PROJECT_KINDS,
    PROJECT_ROLES,
    REPORT_KINDS,
    ROLE_LABELS,
    SCAN_KINDS,
    SCAN_PROFILES,
    SCAN_STATUSES,
    SCAN_STATUS_LABELS,
    SCOPE_KINDS,
    SCOPE_VERIFICATION_METHODS,
    SERVICE_STATES,
    SEVERITIES,
    SEVERITY_COLORS,
    SEVERITY_LABELS,
    SEVERITY_RANK,
)
from ...core.netguard import summarize_policy
from ...core.queue import ALL_JOB_TYPES, JOB_MAINTENANCE, JobQueue
from ...core.redaction import redact_text
from ...core.utils import to_iso_z, utcnow
from ...db import get_db, ping
from ...engines.registry import ai_status, capabilities_dict, find_nmap, zap_configured
from ...models import (
    Alert,
    Asset,
    AssetChange,
    CveRecord,
    Finding,
    Incident,
    Job,
    Lab,
    LogEvent,
    LogSource,
    Project,
    Report,
    Scan,
    Service,
    SettingKV,
)
from ...services.labs import user_lab_stats
from ...worker import worker_status
from ..deps import AuthContext, api_error, audit, get_auth, require_global_role, require_scope, write_scope_guard
from .common import accessible_project_ids, paged

log = logging.getLogger("nexus.api.system")

router = APIRouter(prefix="/system", tags=["system"])

PROCESS_STARTED_AT = utcnow()
SETTINGS_KEY = "system_settings"
NOTIFICATIONS_WINDOW_DEFAULT = 14
JOB_RESULT_KEYS = ("findings", "assets", "services", "notes")

_capability_cache: tuple[float, dict[str, Any]] | None = None


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _labeled(mapping: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    return [{"key": key, "labels": labels} for key, labels in mapping.items()]


def _status_meta(keys: tuple[str, ...], labels: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    return [{"key": key, "labels": labels.get(key, {"en": key, "ar": key})} for key in keys]


def _runtime_settings(db: Session) -> dict[str, Any]:
    row = db.get(SettingKV, SETTINGS_KEY)
    stored = dict(row.value or {}) if row else {}
    return {
        "event_retention_days": int(stored.get("event_retention_days", 30)),
        "notification_window_days": int(stored.get("notification_window_days", NOTIFICATIONS_WINDOW_DEFAULT)),
        "project_retention_days_default": int(stored.get("project_retention_days_default", 180)),
        "updated_at": to_iso_z(row.updated_at) if row else None,
        "updated_by": row.updated_by if row else None,
    }


def _cached_capabilities() -> dict[str, Any]:
    global _capability_cache
    now = time.monotonic()
    if _capability_cache and now - _capability_cache[0] < 30:
        return _capability_cache[1]
    data = capabilities_dict()
    _capability_cache = (now, data)
    return data


def _job_public(job: Job) -> dict[str, Any]:
    error, _ = redact_text(job.last_error or "", limit=1200)
    result = {key: (job.result or {}).get(key) for key in JOB_RESULT_KEYS if key in (job.result or {})}
    return {
        "id": job.id,
        "project_id": job.project_id,
        "scan_id": job.scan_id,
        "type": job.type,
        "status": job.status,
        "priority": job.priority,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "progress": job.progress,
        "phase": job.phase,
        "locked_by": job.locked_by,
        "run_after": to_iso_z(job.run_after),
        "created_at": to_iso_z(job.created_at),
        "started_at": to_iso_z(job.started_at),
        "finished_at": to_iso_z(job.finished_at),
        "lease_expires_at": to_iso_z(job.lease_expires_at),
        "last_error": error,
        "result": result,
    }


def _project_names(db: Session, ids: list[str]) -> dict[str, str]:
    if not ids:
        return {}
    return {
        pid: name
        for pid, name in db.execute(select(Project.id, Project.name).where(Project.id.in_(ids))).all()
    }


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# ---------------------------------------------------------------------------
# Health (public)
# ---------------------------------------------------------------------------
@router.get("/health")
def health() -> JSONResponse:
    started = time.perf_counter()
    db_ok, dialect = ping()
    latency_ms = round((time.perf_counter() - started) * 1000, 1)
    payload: dict[str, Any] = {
        "status": "ok" if db_ok else "degraded",
        "app": settings.app_name,
        "version": settings.version,
        "environment": settings.env,
        # Flat field kept stable for scripts/load balancers.
        "database": dialect if db_ok else "unreachable",
        "database_ok": db_ok,
        "database_latency_ms": latency_ms,
        "worker": worker_status(),
        "server_time": to_iso_z(utcnow()),
        "uptime_seconds": max(0, int((utcnow() - PROCESS_STARTED_AT).total_seconds())),
        "policy": summarize_policy(),
    }
    return JSONResponse(payload, status_code=200 if db_ok else 503)


# ---------------------------------------------------------------------------
# Metadata for the UI (single source of truth for constants)
# ---------------------------------------------------------------------------
@router.get("/meta")
def meta(auth: AuthContext = Depends(get_auth)) -> dict[str, Any]:
    ai = ai_status()
    nmap = find_nmap()
    return {
        "app": {
            "name": settings.app_name,
            "version": settings.version,
            "environment": settings.env,
            "api_version": "v1",
        },
        "user": {
            "id": auth.user.id,
            "email": auth.user.email,
            "full_name": auth.user.full_name,
            "role": auth.user.role,
            "mfa_enabled": auth.user.mfa_enabled,
            "auth_method": auth.method,
            "scopes": auth.scopes,
        },
        "server_time": to_iso_z(utcnow()),
        "locale": {"default": "ar", "supported": ["ar", "en"], "directions": {"ar": "rtl", "en": "ltr"}},
        "features": {
            "ai_configured": bool(ai.get("configured")),
            "ai_provider": ai.get("provider"),
            "zap_configured": zap_configured(),
            "nmap_available": bool(nmap),
            "inprocess_worker": bool(settings.inprocess_worker),
            "allow_private_targets_global": bool(settings.allow_private_targets),
            "active_scanning_enabled": bool(settings.active_scanning_enabled),
        },
        "limits": {
            "max_upload_mb": settings.max_upload_mb,
            "rate_limit_per_minute": settings.rate_limit_per_minute,
            "access_token_minutes": settings.access_token_minutes,
            "refresh_token_days": settings.refresh_token_days,
            "max_concurrent_scans": settings.max_concurrent_scans,
        },
        "constants": {
            "severities": [
                {"key": key, "labels": SEVERITY_LABELS[key], "color": SEVERITY_COLORS[key], "rank": SEVERITY_RANK[key]}
                for key in SEVERITIES
            ],
            "confidences": _status_meta(CONFIDENCES, CONFIDENCE_LABELS),
            "finding_statuses": _status_meta(FINDING_STATUSES, FINDING_STATUS_LABELS),
            "finding_categories": _labeled(FINDING_CATEGORIES),
            "scan_statuses": _status_meta(SCAN_STATUSES, SCAN_STATUS_LABELS),
            "scan_kinds": _labeled(SCAN_KINDS),
            "scan_profiles": _labeled(SCAN_PROFILES),
            "job_types": list(ALL_JOB_TYPES),
            "job_statuses": list(JOB_STATUSES),
            "project_kinds": _labeled(PROJECT_KINDS),
            "global_roles": list(GLOBAL_ROLES),
            "project_roles": list(PROJECT_ROLES),
            "role_labels": _labeled(ROLE_LABELS),
            "scope_kinds": list(SCOPE_KINDS),
            "scope_verification_methods": list(SCOPE_VERIFICATION_METHODS),
            "asset_types": list(ASSET_TYPES),
            "service_states": list(SERVICE_STATES),
            "asset_change_kinds": _labeled(ASSET_CHANGE_KINDS),
            "alert_statuses": _status_meta(ALERT_STATUSES, ALERT_STATUS_LABELS),
            "incident_statuses": _status_meta(INCIDENT_STATUSES, INCIDENT_STATUS_LABELS),
            "log_formats": list(LOG_FORMATS),
            "lab_levels": _labeled(LAB_LEVELS),
            "lab_categories": _labeled(LAB_CATEGORIES),
            "report_kinds": _labeled(REPORT_KINDS),
            "evidence_kinds": list(EVIDENCE_KINDS),
        },
        "policy": summarize_policy(),
    }


@router.get("/capabilities")
def capabilities(auth: AuthContext = Depends(require_scope("read:system"))) -> dict[str, Any]:
    data = _cached_capabilities()
    return {
        **data,
        "detected_at": to_iso_z(utcnow()),
        "note": "Unavailable integrations are reported as unavailable and are never simulated.",
    }


# ---------------------------------------------------------------------------
# Global dashboard (all values from stored rows, scoped to accessible projects)
# ---------------------------------------------------------------------------
def _series(db: Session, query) -> dict[str, int]:
    return {str(key): int(value) for key, value in db.execute(query).all()}


@router.get("/dashboard")
def dashboard(
    auth: AuthContext = Depends(require_scope("read:system")),
    db: Session = Depends(get_db),
    days: int = Query(default=14, ge=7, le=90),
) -> dict[str, Any]:
    ids = accessible_project_ids(db, auth)
    since = (utcnow() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    empty = {
        "scope": {"projects": 0, "project_ids": []},
        "assets": {"total": 0, "active": 0, "monitored": 0, "by_type": {}, "by_risk": {}},
        "services": {"open": 0},
        "findings": {
            "open_total": 0,
            "by_severity": {key: 0 for key in SEVERITIES},
            "by_status": {},
            "verified_open": 0,
            "new_7d": 0,
            "resolved_7d": 0,
        },
        "scans": {"total": 0, "active": 0, "by_status": {}, "completed_7d": 0, "failed_7d": 0},
        "soc": {
            "alerts_open": 0,
            "open_by_severity": {},
            "incidents_open": 0,
            "events_24h": 0,
            "sources": 0,
        },
        "reports": {"total": 0, "ready": 0},
        "jobs": {key: 0 for key in JOB_STATUSES} | {"total": 0},
        "labs": {"runs": 0, "labs_passed": 0, "total_score": 0, "achievements": 0},
        "risk": {"top_assets": []},
        "recent": {"findings": [], "scans": [], "alerts": []},
        "trend": {"days": [], "findings_created": [], "findings_resolved": []},
        "generated_at": to_iso_z(utcnow()),
    }
    if not ids:
        return empty

    def count(query) -> int:
        return int(db.execute(query).scalar_one() or 0)

    now = utcnow()
    week_ago = now - timedelta(days=7)
    day_ago = now - timedelta(hours=24)

    assets_total = count(select(func.count(Asset.id)).where(Asset.project_id.in_(ids)))
    assets_active = count(select(func.count(Asset.id)).where(Asset.project_id.in_(ids), Asset.state == "active"))
    assets_monitored = count(select(func.count(Asset.id)).where(Asset.project_id.in_(ids), Asset.is_monitored.is_(True)))
    assets_by_type = _series(
        db, select(Asset.type, func.count(Asset.id)).where(Asset.project_id.in_(ids)).group_by(Asset.type)
    )
    assets_by_risk = _series(
        db, select(Asset.risk_severity, func.count(Asset.id)).where(Asset.project_id.in_(ids)).group_by(Asset.risk_severity)
    )
    services_open = count(select(func.count(Service.id)).where(Service.project_id.in_(ids), Service.state == "open"))

    finding_counts = {key: 0 for key in SEVERITIES}
    for sev, cnt in db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.project_id.in_(ids), Finding.status.in_(("open", "confirmed")))
        .group_by(Finding.severity)
    ).all():
        finding_counts[str(sev)] = int(cnt)
    findings_open = sum(finding_counts.values())
    by_status = _series(
        db, select(Finding.status, func.count(Finding.id)).where(Finding.project_id.in_(ids)).group_by(Finding.status)
    )
    verified_open = count(
        select(func.count(Finding.id)).where(
            Finding.project_id.in_(ids), Finding.status.in_(("open", "confirmed")), Finding.verified.is_(True)
        )
    )
    new_7d = count(select(func.count(Finding.id)).where(Finding.project_id.in_(ids), Finding.created_at >= week_ago))
    resolved_7d = count(
        select(func.count(Finding.id)).where(Finding.project_id.in_(ids), Finding.resolved_at.is_not(None), Finding.resolved_at >= week_ago)
    )

    scans_by_status = _series(
        db, select(Scan.status, func.count(Scan.id)).where(Scan.project_id.in_(ids)).group_by(Scan.status)
    )
    scans_total = sum(scans_by_status.values())
    scans_active = sum(scans_by_status.get(s, 0) for s in ("queued", "running"))
    completed_7d = count(
        select(func.count(Scan.id)).where(Scan.project_id.in_(ids), Scan.status == "completed", Scan.finished_at >= week_ago)
    )
    failed_7d = count(
        select(func.count(Scan.id)).where(Scan.project_id.in_(ids), Scan.status.in_(("failed", "partial")), Scan.finished_at >= week_ago)
    )

    alert_open_states = ("new", "acknowledged", "investigating")
    alerts_open = count(
        select(func.count(Alert.id)).where(Alert.project_id.in_(ids), Alert.status.in_(alert_open_states))
    )
    alerts_by_severity = {key: 0 for key in SEVERITIES}
    for sev, cnt in db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.project_id.in_(ids), Alert.status.in_(alert_open_states))
        .group_by(Alert.severity)
    ).all():
        alerts_by_severity[str(sev)] = int(cnt)
    incidents_open = count(
        select(func.count(Incident.id)).where(Incident.project_id.in_(ids), Incident.status != "closed")
    )
    events_24h = count(
        select(func.count(LogEvent.id)).where(LogEvent.project_id.in_(ids), LogEvent.ingested_at >= day_ago)
    )
    sources_total = count(select(func.count(LogSource.id)).where(LogSource.project_id.in_(ids)))

    reports_total = count(select(func.count(Report.id)).where(Report.project_id.in_(ids)))
    reports_ready = count(
        select(func.count(Report.id)).where(Report.project_id.in_(ids), Report.status == "ready")
    )

    jobs_by_status = {key: 0 for key in JOB_STATUSES}
    for state, cnt in db.execute(
        select(Job.status, func.count(Job.id)).where(Job.project_id.in_(ids)).group_by(Job.status)
    ).all():
        jobs_by_status[str(state)] = int(cnt)
    jobs_by_status["total"] = sum(jobs_by_status.values())

    names = _project_names(db, ids)
    top_assets = db.execute(
        select(Asset)
        .where(Asset.project_id.in_(ids), Asset.risk_severity.in_(("critical", "high", "medium")))
        .order_by(Asset.risk_score.desc(), Asset.last_seen_at.desc())
        .limit(8)
    ).scalars().all()

    finding_rows = db.execute(
        select(Finding, Project.name)
        .join(Project, Project.id == Finding.project_id)
        .where(Finding.project_id.in_(ids), Finding.status.in_(("open", "confirmed")))
        .order_by(Finding.last_seen_at.desc())
        .limit(8)
    ).all()
    scan_rows = db.execute(
        select(Scan, Project.name)
        .join(Project, Project.id == Scan.project_id)
        .where(Scan.project_id.in_(ids))
        .order_by(Scan.created_at.desc())
        .limit(8)
    ).all()
    alert_rows = db.execute(
        select(Alert, Project.name)
        .join(Project, Project.id == Alert.project_id)
        .where(Alert.project_id.in_(ids), Alert.status.in_(alert_open_states))
        .order_by(Alert.last_seen_at.desc())
        .limit(8)
    ).all()

    days_list: list[str] = []
    cursor = since
    for _ in range(days):
        days_list.append(cursor.date().isoformat())
        cursor = cursor + timedelta(days=1)
    created = _series(
        db,
        select(func.date(Finding.created_at), func.count(Finding.id))
        .where(Finding.project_id.in_(ids), Finding.created_at >= since)
        .group_by(func.date(Finding.created_at)),
    )
    resolved = _series(
        db,
        select(func.date(Finding.resolved_at), func.count(Finding.id))
        .where(Finding.project_id.in_(ids), Finding.resolved_at.is_not(None), Finding.resolved_at >= since)
        .group_by(func.date(Finding.resolved_at)),
    )

    lab_stats = user_lab_stats(db, auth.user_id)
    return {
        "scope": {"projects": len(ids), "project_ids": ids},
        "assets": {
            "total": assets_total,
            "active": assets_active,
            "monitored": assets_monitored,
            "by_type": assets_by_type,
            "by_risk": assets_by_risk,
        },
        "services": {"open": services_open},
        "findings": {
            "open_total": findings_open,
            "by_severity": finding_counts,
            "by_status": by_status,
            "verified_open": verified_open,
            "new_7d": new_7d,
            "resolved_7d": resolved_7d,
        },
        "scans": {
            "total": scans_total,
            "active": scans_active,
            "by_status": scans_by_status,
            "completed_7d": completed_7d,
            "failed_7d": failed_7d,
        },
        "soc": {
            "alerts_open": alerts_open,
            "open_by_severity": alerts_by_severity,
            "incidents_open": incidents_open,
            "events_24h": events_24h,
            "sources": sources_total,
        },
        "reports": {"total": reports_total, "ready": reports_ready},
        "jobs": jobs_by_status,
        "labs": {
            "runs": lab_stats["runs"],
            "labs_passed": lab_stats["labs_passed"],
            "total_score": lab_stats["total_score"],
            "achievements": len(lab_stats["achievements"]),
        },
        "risk": {
            "top_assets": [
                {
                    "id": asset.id,
                    "project_id": asset.project_id,
                    "project_name": names.get(asset.project_id, ""),
                    "value": asset.value,
                    "type": asset.type,
                    "risk_severity": asset.risk_severity,
                    "risk_score": asset.risk_score,
                    "state": asset.state,
                    "last_seen_at": to_iso_z(asset.last_seen_at),
                }
                for asset in top_assets
            ]
        },
        "recent": {
            "findings": [
                {
                    "id": finding.id,
                    "project_id": finding.project_id,
                    "project_name": project_name,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "confidence": finding.confidence,
                    "target": finding.target,
                    "last_seen_at": to_iso_z(finding.last_seen_at),
                }
                for finding, project_name in finding_rows
            ],
            "scans": [
                {
                    "id": scan.id,
                    "project_id": scan.project_id,
                    "project_name": project_name,
                    "name": scan.name,
                    "kind": scan.kind,
                    "status": scan.status,
                    "progress": scan.progress,
                    "created_at": to_iso_z(scan.created_at),
                }
                for scan, project_name in scan_rows
            ],
            "alerts": [
                {
                    "id": alert.id,
                    "project_id": alert.project_id,
                    "project_name": project_name,
                    "title": alert.title,
                    "severity": alert.severity,
                    "status": alert.status,
                    "last_seen_at": to_iso_z(alert.last_seen_at),
                }
                for alert, project_name in alert_rows
            ],
        },
        "trend": {
            "days": days_list,
            "findings_created": [created.get(day, 0) for day in days_list],
            "findings_resolved": [resolved.get(day, 0) for day in days_list],
        },
        "generated_at": to_iso_z(utcnow()),
    }


# ---------------------------------------------------------------------------
# Global search
# ---------------------------------------------------------------------------
@router.get("/search")
def global_search(
    auth: AuthContext = Depends(require_scope("read:system")),
    db: Session = Depends(get_db),
    q: str = Query(default="", min_length=2, max_length=120),
    limit: int = Query(default=5, ge=1, le=20),
) -> dict[str, Any]:
    term = q.strip()
    pattern = _like(term)
    ids = accessible_project_ids(db, auth)
    names = _project_names(db, ids)

    def project_item(row: dict[str, Any]) -> dict[str, Any]:
        row["project_name"] = names.get(row.get("project_id") or "", "")
        return row

    groups: dict[str, list[dict[str, Any]]] = {
        "projects": [],
        "assets": [],
        "findings": [],
        "scans": [],
        "alerts": [],
        "reports": [],
        "labs": [],
        "intel": [],
    }

    if ids:
        for project in db.execute(
            select(Project)
            .where(
                Project.id.in_(ids),
                or_(
                    Project.name.ilike(pattern, escape="\\"),
                    Project.slug.ilike(pattern, escape="\\"),
                    Project.description.ilike(pattern, escape="\\"),
                ),
            )
            .order_by(Project.name.asc())
            .limit(limit)
        ).scalars().all():
            groups["projects"].append(
                {
                    "type": "project",
                    "id": project.id,
                    "project_id": project.id,
                    "title": project.name,
                    "subtitle": project.slug,
                    "href": f"/projects/{project.id}",
                }
            )

        for asset in db.execute(
            select(Asset)
            .where(Asset.project_id.in_(ids), Asset.value.ilike(pattern, escape="\\"))
            .order_by(Asset.risk_score.desc())
            .limit(limit)
        ).scalars().all():
            groups["assets"].append(
                project_item(
                    {
                        "type": "asset",
                        "id": asset.id,
                        "project_id": asset.project_id,
                        "title": asset.value,
                        "subtitle": f"{asset.type} · {asset.risk_severity}",
                        "href": f"/projects/{asset.project_id}/assets/{asset.id}",
                    }
                )
            )

        for finding in db.execute(
            select(Finding)
            .where(
                Finding.project_id.in_(ids),
                or_(
                    Finding.title.ilike(pattern, escape="\\"),
                    Finding.target.ilike(pattern, escape="\\"),
                    Finding.cve.ilike(pattern, escape="\\"),
                    Finding.cwe.ilike(pattern, escape="\\"),
                ),
            )
            .order_by(Finding.last_seen_at.desc())
            .limit(limit)
        ).scalars().all():
            groups["findings"].append(
                project_item(
                    {
                        "type": "finding",
                        "id": finding.id,
                        "project_id": finding.project_id,
                        "title": finding.title,
                        "subtitle": f"{finding.severity} · {finding.status}",
                        "href": f"/projects/{finding.project_id}/findings/{finding.id}",
                    }
                )
            )

        for scan in db.execute(
            select(Scan)
            .where(Scan.project_id.in_(ids), Scan.name.ilike(pattern, escape="\\"))
            .order_by(Scan.created_at.desc())
            .limit(limit)
        ).scalars().all():
            groups["scans"].append(
                project_item(
                    {
                        "type": "scan",
                        "id": scan.id,
                        "project_id": scan.project_id,
                        "title": scan.name,
                        "subtitle": f"{scan.kind} · {scan.status}",
                        "href": f"/projects/{scan.project_id}/scans/{scan.id}",
                    }
                )
            )

        for alert in db.execute(
            select(Alert)
            .where(Alert.project_id.in_(ids), Alert.title.ilike(pattern, escape="\\"))
            .order_by(Alert.last_seen_at.desc())
            .limit(limit)
        ).scalars().all():
            groups["alerts"].append(
                project_item(
                    {
                        "type": "alert",
                        "id": alert.id,
                        "project_id": alert.project_id,
                        "title": alert.title,
                        "subtitle": f"{alert.severity} · {alert.status}",
                        "href": f"/projects/{alert.project_id}/soc/alerts/{alert.id}",
                    }
                )
            )

        for report in db.execute(
            select(Report)
            .where(Report.project_id.in_(ids), Report.title.ilike(pattern, escape="\\"))
            .order_by(Report.created_at.desc())
            .limit(limit)
        ).scalars().all():
            groups["reports"].append(
                project_item(
                    {
                        "type": "report",
                        "id": report.id,
                        "project_id": report.project_id,
                        "title": report.title,
                        "subtitle": f"{report.kind} · {report.status}",
                        "href": f"/projects/{report.project_id}/reports/{report.id}",
                    }
                )
            )

    for lab in db.execute(
        select(Lab)
        .where(
            Lab.enabled.is_(True),
            or_(
                Lab.title_en.ilike(pattern, escape="\\"),
                Lab.title_ar.ilike(pattern, escape="\\"),
                Lab.description_en.ilike(pattern, escape="\\"),
                Lab.description_ar.ilike(pattern, escape="\\"),
            ),
        )
        .order_by(Lab.order_index.asc())
        .limit(limit)
    ).scalars().all():
        groups["labs"].append(
            {
                "type": "lab",
                "id": lab.id,
                "project_id": None,
                "title": lab.title_en,
                "subtitle": f"{lab.category} · {lab.level}",
                "href": f"/labs/{lab.id}",
            }
        )

    for cve in db.execute(
        select(CveRecord)
        .where(or_(CveRecord.id.ilike(pattern, escape="\\"), CveRecord.description.ilike(pattern, escape="\\")))
        .order_by(CveRecord.cvss_v3_score.desc())
        .limit(limit)
    ).scalars().all():
        groups["intel"].append(
            {
                "type": "cve",
                "id": cve.id,
                "project_id": None,
                "title": cve.id,
                "subtitle": f"CVSS {cve.cvss_v3_score if cve.cvss_v3_score is not None else 'n/a'} · {cve.cvss_severity}",
                "href": f"/intel/{cve.id}",
            }
        )

    total = sum(len(items) for items in groups.values())
    return {"q": term, "groups": groups, "total": total}


# ---------------------------------------------------------------------------
# Notification centre (derived from real records)
# ---------------------------------------------------------------------------
def _dismiss_key(user_id: str) -> str:
    return f"notifications_dismissed:{user_id}"


def _load_dismissed(db: Session, user_id: str) -> dict[str, str]:
    row = db.get(SettingKV, _dismiss_key(user_id))
    return dict((row.value or {}).get("dismissed") or {}) if row else {}


def _build_notifications(db: Session, auth: AuthContext) -> list[dict[str, Any]]:
    ids = accessible_project_ids(db, auth)
    if not ids:
        return []
    names = _project_names(db, ids)
    window = _runtime_settings(db)["notification_window_days"]
    since = utcnow() - timedelta(days=window)
    items: list[tuple[Any, dict[str, Any]]] = []

    def add(ts, item: dict[str, Any]) -> None:
        item["ts"] = to_iso_z(ts)
        items.append((ts or utcnow(), item))

    for finding in db.execute(
        select(Finding)
        .where(
            Finding.project_id.in_(ids),
            Finding.status.in_(("open", "confirmed")),
            Finding.severity.in_(("critical", "high")),
            Finding.last_seen_at >= since,
        )
        .order_by(Finding.last_seen_at.desc())
        .limit(25)
    ).scalars().all():
        add(
            finding.last_seen_at,
            {
                "id": f"finding:{finding.id}",
                "kind": "finding",
                "severity": finding.severity,
                "title": finding.title,
                "message": f"{finding.target} — {finding.confidence} confidence",
                "project_id": finding.project_id,
                "project_name": names.get(finding.project_id, ""),
                "entity_id": finding.id,
                "href": f"/projects/{finding.project_id}/findings/{finding.id}",
            },
        )

    for alert in db.execute(
        select(Alert)
        .where(
            Alert.project_id.in_(ids),
            Alert.status.in_(("new", "acknowledged", "investigating")),
            Alert.last_seen_at >= since,
        )
        .order_by(Alert.last_seen_at.desc())
        .limit(25)
    ).scalars().all():
        add(
            alert.last_seen_at,
            {
                "id": f"alert:{alert.id}",
                "kind": "alert",
                "severity": alert.severity,
                "title": f"Detection: {alert.title}",
                "message": f"{alert.event_count} event(s) matched · status {alert.status}",
                "project_id": alert.project_id,
                "project_name": names.get(alert.project_id, ""),
                "entity_id": alert.id,
                "href": f"/projects/{alert.project_id}/soc/alerts/{alert.id}",
            },
        )

    for incident in db.execute(
        select(Incident)
        .where(Incident.project_id.in_(ids), Incident.status != "closed", Incident.opened_at >= since)
        .order_by(Incident.opened_at.desc())
        .limit(10)
    ).scalars().all():
        add(
            incident.opened_at,
            {
                "id": f"incident:{incident.id}",
                "kind": "incident",
                "severity": incident.severity,
                "title": f"Incident: {incident.title}",
                "message": f"status {incident.status}",
                "project_id": incident.project_id,
                "project_name": names.get(incident.project_id, ""),
                "entity_id": incident.id,
                "href": f"/projects/{incident.project_id}/soc/incidents/{incident.id}",
            },
        )

    for scan in db.execute(
        select(Scan)
        .where(
            Scan.project_id.in_(ids),
            Scan.status.in_(("failed", "partial")),
            Scan.finished_at.is_not(None),
            Scan.finished_at >= since,
        )
        .order_by(Scan.finished_at.desc())
        .limit(10)
    ).scalars().all():
        add(
            scan.finished_at,
            {
                "id": f"scan:{scan.id}",
                "kind": "scan",
                "severity": "high" if scan.status == "failed" else "medium",
                "title": f"Scan {scan.status}: {scan.name}",
                "message": (scan.error or "The scan did not complete cleanly.")[:300],
                "project_id": scan.project_id,
                "project_name": names.get(scan.project_id, ""),
                "entity_id": scan.id,
                "href": f"/projects/{scan.project_id}/scans/{scan.id}",
            },
        )

    for change in db.execute(
        select(AssetChange)
        .where(
            AssetChange.project_id.in_(ids),
            AssetChange.acknowledged_at.is_(None),
            AssetChange.detected_at >= since,
        )
        .order_by(AssetChange.detected_at.desc())
        .limit(15)
    ).scalars().all():
        add(
            change.detected_at,
            {
                "id": f"asset_change:{change.id}",
                "kind": "asset_change",
                "severity": change.severity,
                "title": f"Surface change: {change.kind.replace('_', ' ')}",
                "message": change.summary,
                "project_id": change.project_id,
                "project_name": names.get(change.project_id, ""),
                "entity_id": change.id,
                "href": f"/projects/{change.project_id}/asm",
            },
        )

    for job in db.execute(
        select(Job)
        .where(
            Job.project_id.in_(ids),
            Job.status.in_(("failed", "dead")),
            Job.finished_at.is_not(None),
            Job.finished_at >= since,
        )
        .order_by(Job.finished_at.desc())
        .limit(10)
    ).scalars().all():
        error, _ = redact_text(job.last_error or "", limit=300)
        add(
            job.finished_at,
            {
                "id": f"job:{job.id}",
                "kind": "job",
                "severity": "high",
                "title": f"Job failed: {job.type}",
                "message": error or "No error detail was recorded.",
                "project_id": job.project_id,
                "project_name": names.get(job.project_id, ""),
                "entity_id": job.id,
                "href": f"/projects/{job.project_id}/scans" if job.scan_id else "/system/jobs",
            },
        )

    dismissed = _load_dismissed(db, auth.user_id)
    visible = [item for _, item in sorted(items, key=lambda pair: pair[0], reverse=True) if item["id"] not in dismissed]
    return visible[:80]


@router.get("/notifications")
def notifications(
    auth: AuthContext = Depends(require_scope("read:system")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    items = _build_notifications(db, auth)
    counts: dict[str, int] = {}
    severities: dict[str, int] = {}
    for item in items:
        counts[item["kind"]] = counts.get(item["kind"], 0) + 1
        severities[item["severity"]] = severities.get(item["severity"], 0) + 1
    return {
        "items": items,
        "unread": len(items),
        "counts": {"by_kind": counts, "by_severity": severities},
        "window_days": _runtime_settings(db)["notification_window_days"],
    }


class DismissBody(BaseModel):
    ids: list[str] = Field(default_factory=list, max_length=200)


@router.post("/notifications/dismiss")
def dismiss_notifications(
    body: DismissBody,
    auth: AuthContext = Depends(require_scope("write:system")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(auth)
    ids = list(dict.fromkeys(body.ids))
    if not ids:
        ids = [item["id"] for item in _build_notifications(db, auth)]
    key = _dismiss_key(auth.user_id)
    row = db.get(SettingKV, key)
    payload = dict(row.value or {}) if row else {}
    dismissed = dict(payload.get("dismissed") or {})
    now = to_iso_z(utcnow())
    for item_id in ids[:200]:
        dismissed[item_id] = now
    # Bound the per-user map without losing the recent dismissals.
    if len(dismissed) > 1000:
        dismissed = dict(list(dismissed.items())[-1000:])
    payload["dismissed"] = dismissed
    if row is None:
        db.add(SettingKV(key=key, value=payload, updated_by=auth.user_id))
    else:
        row.value = payload
        row.updated_by = auth.user_id
    db.commit()
    return {"dismissed": len(ids[:200]), "remaining": len(_build_notifications(db, auth))}


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------
@router.get("/jobs")
def list_jobs(
    auth: AuthContext = Depends(require_scope("read:system")),
    db: Session = Depends(get_db),
    status_filter: str | None = Query(default=None, alias="status"),
    job_type: str | None = Query(default=None, alias="type"),
    project_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=300),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    ids = accessible_project_ids(db, auth)
    if auth.is_admin:
        allowed_ids = [p for p in db.execute(select(Project.id)).scalars().all()]
    else:
        allowed_ids = ids
    if project_id:
        if project_id not in allowed_ids:
            raise api_error("project_not_found", "Project not found.", status.HTTP_404_NOT_FOUND)
        allowed_ids = [project_id]
    if not allowed_ids:
        return {**paged([], 0, limit=limit, offset=offset), "counts": {"by_status": {}}}

    query = select(Job).where(Job.project_id.in_(allowed_ids))
    count_query = select(func.count(Job.id)).where(Job.project_id.in_(allowed_ids))
    if status_filter:
        if status_filter not in JOB_STATUSES:
            raise api_error("invalid_status", f"Job status must be one of {list(JOB_STATUSES)}.")
        query = query.where(Job.status == status_filter)
        count_query = count_query.where(Job.status == status_filter)
    if job_type:
        if job_type not in ALL_JOB_TYPES:
            raise api_error("invalid_job_type", f"Job type must be one of {list(ALL_JOB_TYPES)}.")
        query = query.where(Job.type == job_type)
        count_query = count_query.where(Job.type == job_type)

    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(
        query.order_by(Job.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    stats_query = select(Job.status, func.count(Job.id)).where(Job.project_id.in_(allowed_ids))
    if job_type:
        stats_query = stats_query.where(Job.type == job_type)
    by_status = {key: 0 for key in JOB_STATUSES}
    for state, count in db.execute(stats_query.group_by(Job.status)).all():
        by_status[str(state)] = int(count)
    by_status["total"] = sum(by_status.values())
    return {**paged([_job_public(job) for job in rows], total, limit=limit, offset=offset), "counts": {"by_status": by_status}}


@router.get("/jobs/{job_id}")
def get_job(
    job_id: str,
    auth: AuthContext = Depends(require_scope("read:system")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    job = db.get(Job, job_id)
    if job is None:
        raise api_error("job_not_found", "Job not found.", status.HTTP_404_NOT_FOUND)
    if not auth.is_admin and job.project_id not in accessible_project_ids(db, auth):
        raise api_error("project_not_found", "Job not found.", status.HTTP_404_NOT_FOUND)
    return {"job": _job_public(job), "payload_keys": sorted((job.payload or {}).keys())}


@router.post("/jobs/{job_id}/retry")
def retry_job(
    job_id: str,
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    job = db.get(Job, job_id)
    if job is None:
        raise api_error("job_not_found", "Job not found.", status.HTTP_404_NOT_FOUND)
    if job.status in ("queued", "running"):
        raise api_error("job_active", "This job is already queued or running.", status.HTTP_409_CONFLICT)
    job.status = "queued"
    job.attempts = 0
    job.max_attempts = max(int(job.max_attempts or 1), 1)
    job.run_after = utcnow()
    job.progress = 0
    job.phase = ""
    job.last_error = ""
    job.finished_at = None
    job.locked_by = ""
    job.locked_at = None
    job.lease_expires_at = None
    db.commit()
    audit(db, auth, "system.job_retry", project_id=job.project_id, entity_type="job", entity_id=job.id, meta={"type": job.type})
    return {"job": _job_public(job)}


@router.post("/jobs/{job_id}/cancel")
def cancel_job(
    job_id: str,
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    job = db.get(Job, job_id)
    if job is None:
        raise api_error("job_not_found", "Job not found.", status.HTTP_404_NOT_FOUND)
    if job.status not in ("queued", "running"):
        raise api_error("job_not_active", "Only queued or running jobs can be canceled.", status.HTTP_409_CONFLICT)
    JobQueue.cancel(db, job)
    audit(db, auth, "system.job_cancel", project_id=job.project_id, entity_type="job", entity_id=job.id, meta={"type": job.type})
    return {"job": _job_public(job)}


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------
class MaintenanceBody(BaseModel):
    tasks: list[str] = Field(default_factory=lambda: ["reap", "prune", "kev"], max_length=3)
    force_kev: bool = False


def _system_project(db: Session) -> Project:
    """Hidden, archived project that owns platform-level maintenance jobs."""
    project = db.execute(select(Project).where(Project.slug == "nexus-system")).scalar_one_or_none()
    if project is not None:
        return project
    project = Project(
        name="NEXUS Internal Operations",
        slug="nexus-system",
        description="Internal owner of platform maintenance jobs. Not a customer project.",
        kind="asm",
        settings={"internal": True},
        archived_at=utcnow(),
    )
    db.add(project)
    db.flush()
    return project


@router.post("/maintenance", status_code=status.HTTP_201_CREATED)
def run_maintenance(
    body: MaintenanceBody,
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    allowed = {"reap", "prune", "kev"}
    tasks = [task for task in dict.fromkeys(body.tasks) if task in allowed]
    if not tasks:
        raise api_error("invalid_tasks", f"Tasks must be a non-empty subset of {sorted(allowed)}.")
    runtime = _runtime_settings(db)
    project = _system_project(db)
    job = JobQueue.enqueue(
        db,
        type=JOB_MAINTENANCE,
        project_id=project.id,
        payload={
            "tasks": tasks,
            "force_kev": body.force_kev,
            "event_retention_days": runtime["event_retention_days"],
        },
        priority=200,
        timeout_seconds=1800,
        max_attempts=2,
        dedup_key="system:maintenance",
    )
    db.commit()
    audit(db, auth, "system.maintenance", project_id=project.id, entity_type="job", entity_id=job.id if job else "", meta={"tasks": tasks})
    return {
        "job": _job_public(job) if job else None,
        "enqueued": job is not None,
        "note": "" if job else "A maintenance job is already queued or running.",
    }


# ---------------------------------------------------------------------------
# Effective settings (admin)
# ---------------------------------------------------------------------------
class RuntimeSettingsBody(BaseModel):
    event_retention_days: int | None = Field(default=None, ge=1, le=365)
    notification_window_days: int | None = Field(default=None, ge=1, le=90)
    project_retention_days_default: int | None = Field(default=None, ge=30, le=3650)


@router.get("/settings")
def get_settings(
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ai = ai_status()
    caps = _cached_capabilities()
    return {
        "app": {
            "name": settings.app_name,
            "version": settings.version,
            "environment": settings.env,
            "production": settings.is_production,
        },
        "database": {"dialect": "sqlite" if settings.database_url.startswith("sqlite") else "postgresql"},
        "storage": {
            "managed_directories": ["evidence", "uploads", "reports", "logs", "labs"],
            "max_upload_mb": settings.max_upload_mb,
        },
        "security": {
            "allow_private_targets_global": settings.allow_private_targets,
            "active_scanning_enabled": settings.active_scanning_enabled,
            "rate_limit_per_minute": settings.rate_limit_per_minute,
            "access_token_minutes": settings.access_token_minutes,
            "refresh_token_days": settings.refresh_token_days,
            "allowed_origins": settings.origin_list,
            "policy": summarize_policy(),
        },
        "worker": {
            "inprocess": settings.inprocess_worker,
            "concurrency": settings.worker_concurrency,
            "poll_seconds": settings.job_poll_seconds,
            "lease_seconds": settings.job_lease_seconds,
            "max_concurrent_scans": settings.max_concurrent_scans,
            "status": worker_status(),
        },
        "integrations": {
            "zap_configured": zap_configured(),
            "nmap_path": find_nmap() or "",
            "nmap_available": bool(find_nmap()),
            "nvd_api_key_configured": bool(settings.nvd_api_key),
            "ai": ai,
        },
        "capabilities_summary": caps.get("summary", {}),
        "runtime": _runtime_settings(db),
        "editable": ["event_retention_days", "notification_window_days", "project_retention_days_default"],
        "secret_note": "Secrets (secret key, API keys, provider tokens) are never returned by the API.",
    }


@router.patch("/settings")
def update_settings(
    body: RuntimeSettingsBody,
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = db.get(SettingKV, SETTINGS_KEY)
    current = dict(row.value or {}) if row else {}
    changes: dict[str, Any] = {}
    for field in ("event_retention_days", "notification_window_days", "project_retention_days_default"):
        value = getattr(body, field)
        if value is not None and int(current.get(field, -1)) != value:
            current[field] = value
            changes[field] = value
    if not changes:
        return {"runtime": _runtime_settings(db), "changed": {}}
    if row is None:
        db.add(SettingKV(key=SETTINGS_KEY, value=current, updated_by=auth.user_id))
    else:
        row.value = current
        row.updated_by = auth.user_id
    db.commit()
    audit(db, auth, "system.settings_update", entity_type="setting", entity_id=SETTINGS_KEY, meta=changes)
    return {"runtime": _runtime_settings(db), "changed": changes}
