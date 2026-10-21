"""SOC: log ingestion, events, detection rules, alerts, and incident response."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...core.constants import ALERT_STATUSES, INCIDENT_STATUSES, LOG_FORMATS, SEVERITIES
from ...core.events import build_phases
from ...core.queue import JOB_LOG_ANALYSIS, JobQueue
from ...core.utils import to_iso_z, utcnow
from ...db import get_db
from ...engines.logs_engine import ensure_builtin_rules, validate_rule_definition
from ...models import (
    Alert,
    DetectionRule,
    Incident,
    IncidentEvent,
    LogEvent,
    LogSource,
    ProjectMember,
    Scan,
    User,
)
from ...services.uploads import UploadRejected, store_upload
from ..deps import ProjectAccess, api_error, audit, project_access, write_scope_guard
from .common import paged, parse_dt

log = logging.getLogger("nexus.api.soc")

router = APIRouter(prefix="/projects/{project_id}/soc", tags=["soc"])


def source_public(source: LogSource) -> dict[str, Any]:
    return {
        "id": source.id,
        "name": source.name,
        "kind": source.kind,
        "format": source.format,
        "filename": source.filename,
        "size_bytes": source.size_bytes,
        "sha256": source.sha256,
        "event_count": source.event_count,
        "parse_errors": source.parse_errors,
        "created_at": to_iso_z(source.created_at),
        "last_event_at": to_iso_z(source.last_event_at),
    }


def event_public(event: LogEvent, *, include_raw: bool = False) -> dict[str, Any]:
    data = {
        "id": event.id,
        "source_id": event.source_id,
        "ts": to_iso_z(event.ts),
        "ingested_at": to_iso_z(event.ingested_at),
        "severity": event.severity,
        "event_type": event.event_type,
        "message": event.message,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "method": event.method,
        "url": event.url,
        "status_code": event.status_code,
        "user_agent": event.user_agent,
        "rule_hits": event.rule_hits or [],
    }
    if include_raw:
        data["raw"] = event.raw
        data["meta"] = event.meta or {}
        data["fingerprint"] = event.fingerprint
    return data


def rule_public(rule: DetectionRule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "enabled": rule.enabled,
        "is_builtin": rule.is_builtin,
        "definition": rule.definition or {},
        "trigger_count": rule.trigger_count,
        "last_triggered_at": to_iso_z(rule.last_triggered_at),
        "created_at": to_iso_z(rule.created_at),
    }


def alert_public(alert: Alert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "event_count": alert.event_count,
        "group_key": alert.group_key,
        "first_seen_at": to_iso_z(alert.first_seen_at),
        "last_seen_at": to_iso_z(alert.last_seen_at),
        "assignee_id": alert.assignee_id,
        "incident_id": alert.incident_id,
        "evidence_event_ids": alert.evidence_event_ids or [],
        "meta": alert.meta or {},
    }


def incident_public(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "summary": incident.summary,
        "owner_id": incident.owner_id,
        "opened_at": to_iso_z(incident.opened_at),
        "closed_at": to_iso_z(incident.closed_at),
        "created_at": to_iso_z(incident.created_at),
    }


def incident_event_public(event: IncidentEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "ts": to_iso_z(event.ts),
        "kind": event.kind,
        "actor": event.actor_label,
        "body": event.body,
        "meta": event.meta or {},
    }


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------
@router.post("/sources", status_code=status.HTTP_201_CREATED)
async def upload_log_source(
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
    file: UploadFile = File(...),
    name: str = Form(default=""),
    format: str = Form(default="auto"),
) -> dict[str, Any]:
    """Upload a log file and queue real parsing + rule evaluation."""
    write_scope_guard(access.auth)
    if format not in LOG_FORMATS:
        raise api_error("invalid_format", f"Log format must be one of {list(LOG_FORMATS)}.")
    try:
        stored = await store_upload(file, kind="log")
    except UploadRejected as exc:
        raise api_error(exc.code, exc.message, exc.status_code)

    source_name = name.strip() or stored["source_name"]
    scan = Scan(
        project_id=access.project.id,
        name=f"Log analysis — {source_name}"[:200],
        kind="log_analysis",
        profile="passive",
        status="queued",
        progress=0,
        phases=build_phases("log_analysis"),
        targets=[],
        options={
            "upload_path": stored["upload_path"],
            "source_name": source_name[:200],
            "format": format,
        },
        authorization_snapshot={
            "created_at": to_iso_z(utcnow()),
            "created_by": access.user_id,
            "profile": "passive",
            "require_active": False,
            "scopes": [],
            "note": "Offline analysis of an uploaded log file — no network targets.",
        },
        requested_by=access.user_id,
    )
    db.add(scan)
    db.flush()
    job = JobQueue.enqueue(
        db,
        type=JOB_LOG_ANALYSIS,
        project_id=access.project.id,
        scan_id=scan.id,
        priority=90,
        timeout_seconds=900,
        max_attempts=2,
        dedup_key=f"scan:{scan.id}",
    )
    db.commit()
    audit(
        db,
        access.auth,
        "soc.source_upload",
        project_id=access.project.id,
        entity_type="scan",
        entity_id=scan.id,
        meta={"name": source_name, "size": stored["size_bytes"], "sha256": stored["sha256"], "format": format},
    )
    return {
        "scan_id": scan.id,
        "job_id": job.id if job else None,
        "upload": {k: stored[k] for k in ("source_name", "size_bytes", "sha256", "max_mb")},
        "note": "The log source appears here once the worker finishes parsing. Watch the scan stream for progress.",
    }


@router.get("/sources")
def list_sources(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = db.execute(
        select(LogSource).where(LogSource.project_id == access.project.id).order_by(LogSource.created_at.desc()).limit(200)
    ).scalars().all()
    return {"items": [source_public(s) for s in rows], "total": len(rows)}


@router.delete("/sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_source(
    source_id: str,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> None:
    source = db.get(LogSource, source_id)
    if source is None or source.project_id != access.project.id:
        raise api_error("source_not_found", "Log source not found.", status.HTTP_404_NOT_FOUND)
    db.delete(source)  # events cascade
    db.commit()
    audit(db, access.auth, "soc.source_delete", project_id=access.project.id, entity_type="log_source", entity_id=source_id)
    return None


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
@router.get("/events")
def list_events(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    q: str = Query(default="", max_length=200),
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    source_id: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    method: str | None = Query(default=None),
    status_code: int | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    query = select(LogEvent).where(LogEvent.project_id == access.project.id)
    count_query = select(func.count(LogEvent.id)).where(LogEvent.project_id == access.project.id)
    if q:
        pattern = f"%{q.strip()}%"
        condition = LogEvent.message.like(pattern) | LogEvent.url.like(pattern) | LogEvent.src_ip.like(pattern)
        query = query.where(condition)
        count_query = count_query.where(condition)
    if severity:
        query = query.where(LogEvent.severity == severity)
        count_query = count_query.where(LogEvent.severity == severity)
    if event_type:
        query = query.where(LogEvent.event_type == event_type)
        count_query = count_query.where(LogEvent.event_type == event_type)
    if source_id:
        query = query.where(LogEvent.source_id == source_id)
        count_query = count_query.where(LogEvent.source_id == source_id)
    if src_ip:
        query = query.where(LogEvent.src_ip == src_ip)
        count_query = count_query.where(LogEvent.src_ip == src_ip)
    if method:
        query = query.where(LogEvent.method == method.upper())
        count_query = count_query.where(LogEvent.method == method.upper())
    if status_code is not None:
        query = query.where(LogEvent.status_code == status_code)
        count_query = count_query.where(LogEvent.status_code == status_code)
    since = parse_dt(date_from, field="date_from") if date_from else None
    until = parse_dt(date_to, field="date_to") if date_to else None
    if since:
        query = query.where(LogEvent.ingested_at >= since)
        count_query = count_query.where(LogEvent.ingested_at >= since)
    if until:
        query = query.where(LogEvent.ingested_at <= until)
        count_query = count_query.where(LogEvent.ingested_at <= until)

    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(query.order_by(LogEvent.ts.desc().nullslast(), LogEvent.id.desc()).limit(limit).offset(offset)).scalars().all()
    severity_counts = {
        sev: int(cnt)
        for sev, cnt in db.execute(
            select(LogEvent.severity, func.count(LogEvent.id))
            .where(LogEvent.project_id == access.project.id)
            .group_by(LogEvent.severity)
        ).all()
    }
    return {**paged([event_public(e) for e in rows], total, limit=limit, offset=offset), "counts": {"by_severity": severity_counts}}


@router.get("/events/{event_id}")
def get_event(
    event_id: int,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    event = db.get(LogEvent, event_id)
    if event is None or event.project_id != access.project.id:
        raise api_error("event_not_found", "Log event not found.", status.HTTP_404_NOT_FOUND)
    return {"event": event_public(event, include_raw=True)}


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------
class RuleBody(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=2000)
    severity: str = Field(default="medium")
    enabled: bool = True
    definition: dict[str, Any]


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    severity: str | None = None
    enabled: bool | None = None
    definition: dict[str, Any] | None = None


def _validate_rule(body_severity: str, definition: dict[str, Any]) -> None:
    if body_severity not in SEVERITIES:
        raise api_error("invalid_severity", f"Severity must be one of {list(SEVERITIES)}.")
    errors = validate_rule_definition(definition or {})
    if errors:
        raise api_error("invalid_rule", "The rule definition is invalid.", status.HTTP_422_UNPROCESSABLE_ENTITY, errors=errors)


@router.get("/rules")
def list_rules(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_builtin_rules(db, access.project.id)
    rows = db.execute(
        select(DetectionRule)
        .where(DetectionRule.project_id == access.project.id)
        .order_by(DetectionRule.is_builtin.desc(), DetectionRule.created_at.asc())
    ).scalars().all()
    return {"items": [rule_public(r) for r in rows]}


@router.post("/rules", status_code=status.HTTP_201_CREATED)
def create_rule(
    body: RuleBody,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _validate_rule(body.severity, body.definition)
    rule = DetectionRule(
        project_id=access.project.id,
        name=body.name.strip(),
        description=body.description.strip(),
        severity=body.severity,
        enabled=body.enabled,
        is_builtin=False,
        definition=body.definition,
        created_by=access.user_id,
    )
    db.add(rule)
    db.commit()
    audit(db, access.auth, "soc.rule_create", project_id=access.project.id, entity_type="detection_rule", entity_id=rule.id, meta={"name": rule.name})
    return {"rule": rule_public(rule)}


@router.patch("/rules/{rule_id}")
def update_rule(
    rule_id: str,
    body: RuleUpdate,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rule = db.get(DetectionRule, rule_id)
    if rule is None or rule.project_id != access.project.id:
        raise api_error("rule_not_found", "Rule not found.", status.HTTP_404_NOT_FOUND)
    if body.severity is not None or body.definition is not None:
        _validate_rule(body.severity or rule.severity, body.definition if body.definition is not None else rule.definition)
    if body.name is not None:
        rule.name = body.name.strip()
    if body.description is not None:
        rule.description = body.description.strip()
    if body.severity is not None:
        rule.severity = body.severity
    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.definition is not None:
        if rule.is_builtin:
            raise api_error("builtin_rule", "Built-in rule logic is immutable — duplicate it as a custom rule instead.")
        rule.definition = body.definition
    db.commit()
    audit(db, access.auth, "soc.rule_update", project_id=access.project.id, entity_type="detection_rule", entity_id=rule.id)
    return {"rule": rule_public(rule)}


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: str,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> None:
    rule = db.get(DetectionRule, rule_id)
    if rule is None or rule.project_id != access.project.id:
        raise api_error("rule_not_found", "Rule not found.", status.HTTP_404_NOT_FOUND)
    if rule.is_builtin:
        raise api_error("builtin_rule", "Built-in rules can only be disabled, not deleted.", status.HTTP_409_CONFLICT)
    db.delete(rule)
    db.commit()
    audit(db, access.auth, "soc.rule_delete", project_id=access.project.id, entity_type="detection_rule", entity_id=rule_id)
    return None


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
@router.get("/alerts")
def list_alerts(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    query = select(Alert).where(Alert.project_id == access.project.id)
    count_query = select(func.count(Alert.id)).where(Alert.project_id == access.project.id)
    if status_filter:
        query = query.where(Alert.status == status_filter)
        count_query = count_query.where(Alert.status == status_filter)
    if severity:
        query = query.where(Alert.severity == severity)
        count_query = count_query.where(Alert.severity == severity)
    if rule_id:
        query = query.where(Alert.rule_id == rule_id)
        count_query = count_query.where(Alert.rule_id == rule_id)
    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(query.order_by(Alert.last_seen_at.desc()).limit(limit).offset(offset)).scalars().all()
    by_status = {
        state: int(cnt)
        for state, cnt in db.execute(
            select(Alert.status, func.count(Alert.id)).where(Alert.project_id == access.project.id).group_by(Alert.status)
        ).all()
    }
    by_severity = {
        sev: int(cnt)
        for sev, cnt in db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.project_id == access.project.id, Alert.status.notin_(("closed", "false_positive")))
            .group_by(Alert.severity)
        ).all()
    }
    return {
        **paged([alert_public(a) for a in rows], total, limit=limit, offset=offset),
        "counts": {"by_status": by_status, "open_by_severity": by_severity},
    }


@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: str,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.project_id != access.project.id:
        raise api_error("alert_not_found", "Alert not found.", status.HTTP_404_NOT_FOUND)
    ids = [int(i) for i in (alert.evidence_event_ids or []) if str(i).isdigit()]
    events = db.execute(select(LogEvent).where(LogEvent.id.in_(ids or [0]))).scalars().all()
    rule = db.get(DetectionRule, alert.rule_id) if alert.rule_id else None
    return {
        "alert": alert_public(alert),
        "rule": rule_public(rule) if rule else None,
        "events": [event_public(e) for e in events],
    }


class AlertUpdate(BaseModel):
    status: str | None = None
    assignee_id: str | None = None
    note: str = Field(default="", max_length=1000)


def _validate_member(db: Session, project_id: str, user_id: str | None) -> None:
    if user_id in (None, ""):
        return
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise api_error("assignee_not_found", "The assignee account does not exist.")
    if user.role in ("owner", "admin"):
        return
    member = db.execute(
        select(ProjectMember).where(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id)
    ).scalar_one_or_none()
    if member is None:
        raise api_error("assignee_not_member", "The assignee is not a member of this project.")


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: str,
    body: AlertUpdate,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.project_id != access.project.id:
        raise api_error("alert_not_found", "Alert not found.", status.HTTP_404_NOT_FOUND)
    if body.status is not None:
        if body.status not in ALERT_STATUSES:
            raise api_error("invalid_status", f"Alert status must be one of {list(ALERT_STATUSES)}.")
        alert.status = body.status
    if body.assignee_id is not None:
        _validate_member(db, access.project.id, body.assignee_id or None)
        alert.assignee_id = body.assignee_id or None
    if body.note:
        meta = dict(alert.meta or {})
        notes = list(meta.get("notes") or [])
        notes.append({"at": to_iso_z(utcnow()), "by": access.auth.label, "note": body.note.strip()[:1000]})
        meta["notes"] = notes[-50:]
        alert.meta = meta
    db.commit()
    audit(db, access.auth, "soc.alert_update", project_id=access.project.id, entity_type="alert", entity_id=alert.id, meta={"status": alert.status})
    return {"alert": alert_public(alert)}


@router.post("/alerts/{alert_id}/promote", status_code=status.HTTP_201_CREATED)
def promote_alert(
    alert_id: str,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.project_id != access.project.id:
        raise api_error("alert_not_found", "Alert not found.", status.HTTP_404_NOT_FOUND)
    if alert.incident_id:
        raise api_error("already_promoted", "This alert is already linked to an incident.", status.HTTP_409_CONFLICT)
    incident = Incident(
        project_id=access.project.id,
        title=alert.title[:300],
        severity=alert.severity,
        status="open",
        summary=alert.description,
        owner_id=None,
        created_by=access.user_id,
    )
    db.add(incident)
    db.flush()
    alert.incident_id = incident.id
    if alert.status == "new":
        alert.status = "investigating"
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_user_id=access.user_id,
            actor_label=access.auth.label,
            kind="action",
            body=f"Incident opened from alert: {alert.title}",
            meta={"alert_id": alert.id},
        )
    )
    db.commit()
    audit(db, access.auth, "soc.alert_promote", project_id=access.project.id, entity_type="incident", entity_id=incident.id, meta={"alert_id": alert.id})
    return {"incident": incident_public(incident), "alert": alert_public(alert)}


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    severity: str = Field(default="medium")
    summary: str = Field(default="", max_length=8000)
    alert_ids: list[str] = Field(default_factory=list, max_length=100)
    owner_id: str | None = None


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    severity: str | None = None
    status: str | None = None
    summary: str | None = Field(default=None, max_length=8000)
    owner_id: str | None = None


class IncidentNote(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


@router.get("/incidents")
def list_incidents(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    query = select(Incident).where(Incident.project_id == access.project.id)
    count_query = select(func.count(Incident.id)).where(Incident.project_id == access.project.id)
    if status_filter:
        query = query.where(Incident.status == status_filter)
        count_query = count_query.where(Incident.status == status_filter)
    if severity:
        query = query.where(Incident.severity == severity)
        count_query = count_query.where(Incident.severity == severity)
    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(query.order_by(Incident.opened_at.desc()).limit(limit).offset(offset)).scalars().all()
    by_status = {
        state: int(cnt)
        for state, cnt in db.execute(
            select(Incident.status, func.count(Incident.id)).where(Incident.project_id == access.project.id).group_by(Incident.status)
        ).all()
    }
    return {**paged([incident_public(i) for i in rows], total, limit=limit, offset=offset), "counts": {"by_status": by_status}}


@router.post("/incidents", status_code=status.HTTP_201_CREATED)
def create_incident(
    body: IncidentCreate,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if body.severity not in SEVERITIES:
        raise api_error("invalid_severity", f"Severity must be one of {list(SEVERITIES)}.")
    _validate_member(db, access.project.id, body.owner_id)
    incident = Incident(
        project_id=access.project.id,
        title=body.title.strip(),
        severity=body.severity,
        status="open",
        summary=body.summary.strip(),
        owner_id=body.owner_id or access.user_id,
        created_by=access.user_id,
    )
    db.add(incident)
    db.flush()
    linked = 0
    for alert_id in body.alert_ids:
        alert = db.get(Alert, alert_id)
        if alert and alert.project_id == access.project.id and not alert.incident_id:
            alert.incident_id = incident.id
            if alert.status == "new":
                alert.status = "investigating"
            linked += 1
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_user_id=access.user_id,
            actor_label=access.auth.label,
            kind="status_change",
            body=f"Incident opened ({linked} alert(s) linked).",
            meta={"alert_ids": body.alert_ids},
        )
    )
    db.commit()
    audit(db, access.auth, "soc.incident_create", project_id=access.project.id, entity_type="incident", entity_id=incident.id, meta={"severity": incident.severity, "alerts": linked})
    return {"incident": incident_public(incident), "linked_alerts": linked}


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.project_id != access.project.id:
        raise api_error("incident_not_found", "Incident not found.", status.HTTP_404_NOT_FOUND)
    events = db.execute(
        select(IncidentEvent).where(IncidentEvent.incident_id == incident.id).order_by(IncidentEvent.ts.desc()).limit(200)
    ).scalars().all()
    alerts = db.execute(select(Alert).where(Alert.incident_id == incident.id)).scalars().all()
    return {
        "incident": incident_public(incident),
        "timeline": [incident_event_public(e) for e in events],
        "alerts": [alert_public(a) for a in alerts],
    }


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.project_id != access.project.id:
        raise api_error("incident_not_found", "Incident not found.", status.HTTP_404_NOT_FOUND)
    changes: list[str] = []
    if body.title is not None:
        incident.title = body.title.strip()
    if body.severity is not None:
        if body.severity not in SEVERITIES:
            raise api_error("invalid_severity", f"Severity must be one of {list(SEVERITIES)}.")
        changes.append(f"severity {incident.severity} → {body.severity}")
        incident.severity = body.severity
    if body.status is not None:
        if body.status not in INCIDENT_STATUSES:
            raise api_error("invalid_status", f"Incident status must be one of {list(INCIDENT_STATUSES)}.")
        changes.append(f"status {incident.status} → {body.status}")
        incident.status = body.status
        incident.closed_at = utcnow() if body.status == "closed" else None
    if body.summary is not None:
        incident.summary = body.summary.strip()
    if body.owner_id is not None:
        _validate_member(db, access.project.id, body.owner_id or None)
        incident.owner_id = body.owner_id or None
    if changes:
        db.add(
            IncidentEvent(
                incident_id=incident.id,
                actor_user_id=access.user_id,
                actor_label=access.auth.label,
                kind="status_change",
                body="; ".join(changes),
            )
        )
    db.commit()
    audit(db, access.auth, "soc.incident_update", project_id=access.project.id, entity_type="incident", entity_id=incident.id, meta={"changes": changes})
    return {"incident": incident_public(incident)}


@router.post("/incidents/{incident_id}/notes", status_code=status.HTTP_201_CREATED)
def add_incident_note(
    incident_id: str,
    body: IncidentNote,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.project_id != access.project.id:
        raise api_error("incident_not_found", "Incident not found.", status.HTTP_404_NOT_FOUND)
    event = IncidentEvent(
        incident_id=incident.id,
        actor_user_id=access.user_id,
        actor_label=access.auth.label,
        kind="note",
        body=body.body.strip(),
    )
    db.add(event)
    db.commit()
    audit(db, access.auth, "soc.incident_note", project_id=access.project.id, entity_type="incident", entity_id=incident.id)
    return {"event": incident_event_public(event)}
