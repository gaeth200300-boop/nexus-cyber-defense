"""Findings: filtering, evidence, lifecycle, triage, bulk actions, export."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...copilot.service import priority_score
from ...core.constants import FINDING_STATUSES, SEVERITIES
from ...core.utils import to_iso_z
from ...db import get_db
from ...models import (
    Asset,
    CveRecord,
    Finding,
    FindingEvent,
    FindingIntelLink,
    KevEntry,
    ProjectMember,
    Scan,
    Service,
    User,
)
from ...services.findings import add_note, change_status, evidence_summary, severity_counts
from ..deps import ProjectAccess, api_error, audit, project_access
from .common import csv_list, paged

router = APIRouter(prefix="/projects/{project_id}", tags=["findings"])

SORT_OPTIONS = {
    "severity": None,  # handled in Python (portable across SQLite/PostgreSQL)
    "last_seen": Finding.last_seen_at.desc(),
    "first_seen": Finding.first_seen_at.desc(),
    "cvss": Finding.cvss_score.desc(),
    "created": Finding.created_at.desc(),
}


def finding_public(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "project_id": finding.project_id,
        "scan_id": finding.scan_id,
        "asset_id": finding.asset_id,
        "service_id": finding.service_id,
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": finding.status,
        "verified": finding.verified,
        "active_check": finding.active_check,
        "cwe": finding.cwe,
        "cve": finding.cve,
        "owasp": finding.owasp,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "target": finding.target,
        "location": finding.location,
        "description": finding.description,
        "impact": finding.impact,
        "remediation": finding.remediation,
        "references": finding.references or [],
        "tags": finding.tags or [],
        "detected_by": finding.detected_by,
        "engine_version": finding.engine_version,
        "occurrence_count": finding.occurrence_count,
        "duplicate_of": finding.duplicate_of,
        "triage_note": finding.triage_note,
        "assigned_to": finding.assigned_to,
        "first_seen_at": to_iso_z(finding.first_seen_at),
        "last_seen_at": to_iso_z(finding.last_seen_at),
        "resolved_at": to_iso_z(finding.resolved_at),
        "created_at": to_iso_z(finding.created_at),
    }


def event_public(event: FindingEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "ts": to_iso_z(event.ts),
        "kind": event.kind,
        "actor": event.actor_label,
        "from_status": event.from_status,
        "to_status": event.to_status,
        "note": event.note,
    }


def _filtered_query(project_id: str, params: dict[str, Any]):
    query = select(Finding).where(Finding.project_id == project_id)
    count_query = select(func.count(Finding.id)).where(Finding.project_id == project_id)

    severities = csv_list(params.get("severity"))
    if severities:
        query = query.where(Finding.severity.in_(severities))
        count_query = count_query.where(Finding.severity.in_(severities))
    statuses = csv_list(params.get("status"))
    if statuses:
        query = query.where(Finding.status.in_(statuses))
        count_query = count_query.where(Finding.status.in_(statuses))
    if params.get("category"):
        query = query.where(Finding.category == params["category"])
        count_query = count_query.where(Finding.category == params["category"])
    if params.get("confidence"):
        query = query.where(Finding.confidence == params["confidence"])
        count_query = count_query.where(Finding.confidence == params["confidence"])
    if params.get("asset_id"):
        query = query.where(Finding.asset_id == params["asset_id"])
        count_query = count_query.where(Finding.asset_id == params["asset_id"])
    if params.get("scan_id"):
        query = query.where(Finding.scan_id == params["scan_id"])
        count_query = count_query.where(Finding.scan_id == params["scan_id"])
    if params.get("detected_by"):
        query = query.where(Finding.detected_by == params["detected_by"])
        count_query = count_query.where(Finding.detected_by == params["detected_by"])
    if params.get("verified") is not None:
        query = query.where(Finding.verified.is_(params["verified"]))
        count_query = count_query.where(Finding.verified.is_(params["verified"]))
    if params.get("q"):
        pattern = f"%{str(params['q']).strip()}%"
        condition = or_(
            Finding.title.like(pattern),
            Finding.target.like(pattern),
            Finding.cve.like(pattern),
            Finding.location.like(pattern),
            Finding.description.like(pattern),
        )
        query = query.where(condition)
        count_query = count_query.where(condition)
    if params.get("since"):
        query = query.where(Finding.last_seen_at >= params["since"])
        count_query = count_query.where(Finding.last_seen_at >= params["since"])
    return query, count_query


@router.get("/findings")
def list_findings(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    q: str = Query(default="", max_length=200),
    severity: str = Query(default="", description="Comma-separated severities"),
    status_filter: str = Query(default="", alias="status", description="Comma-separated statuses"),
    category: str | None = Query(default=None),
    confidence: str | None = Query(default=None),
    asset_id: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    detected_by: str | None = Query(default=None),
    verified: bool | None = Query(default=None),
    sort: str = Query(default="severity"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    params = {
        "q": q,
        "severity": severity,
        "status": status_filter,
        "category": category,
        "confidence": confidence,
        "asset_id": asset_id,
        "scan_id": scan_id,
        "detected_by": detected_by,
        "verified": verified,
    }
    query, count_query = _filtered_query(access.project.id, params)
    total = int(db.execute(count_query).scalar_one())

    if sort == "severity":
        # Portable severity ordering: fetch a bounded window then sort in Python.
        rows = db.execute(query.order_by(Finding.last_seen_at.desc()).limit(min(total, 5000))).scalars().all()
        order = {name: index for index, name in enumerate(SEVERITIES)}
        rows.sort(key=lambda f: (order.get(f.severity, 99), f.last_seen_at))
        items = rows[offset : offset + limit]
    else:
        order_clause = SORT_OPTIONS.get(sort)
        if order_clause is None:
            order_clause = Finding.last_seen_at.desc()
        statement = query.order_by(order_clause).limit(limit).offset(offset)
        items = db.execute(statement).scalars().all()

    return {
        **paged([finding_public(f) for f in items], total, limit=limit, offset=offset),
        "counts": {
            "by_severity": severity_counts(db, access.project.id),
            "by_status": {
                state: int(cnt)
                for state, cnt in db.execute(
                    select(Finding.status, func.count(Finding.id))
                    .where(Finding.project_id == access.project.id)
                    .group_by(Finding.status)
                ).all()
            },
        },
    }


@router.get("/findings/export")
def export_findings(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    format: str = Query(default="csv"),
    q: str = Query(default=""),
    severity: str = Query(default=""),
    status_filter: str = Query(default="", alias="status"),
    category: str | None = Query(default=None),
    asset_id: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
) -> Response:
    if format not in ("csv", "json"):
        raise api_error("invalid_format", "Export format must be csv or json.")
    query, _count = _filtered_query(
        access.project.id,
        {
            "q": q,
            "severity": severity,
            "status": status_filter,
            "category": category,
            "asset_id": asset_id,
            "scan_id": scan_id,
        },
    )
    rows = db.execute(query.order_by(Finding.last_seen_at.desc()).limit(5000)).scalars().all()
    audit(db, access.auth, "finding.export", project_id=access.project.id, meta={"format": format, "rows": len(rows)})

    if format == "json":
        body = json.dumps([finding_public(f) for f in rows], ensure_ascii=False, indent=2)
        return Response(
            content=body,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="nexus-findings.json"'},
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "id", "severity", "confidence", "status", "title", "category", "target", "location",
            "cve", "cwe", "cvss_score", "detected_by", "verified", "occurrence_count", "first_seen", "last_seen",
        ]
    )
    for f in rows:
        writer.writerow(
            [
                f.id, f.severity, f.confidence, f.status, f.title, f.category, f.target, f.location,
                f.cve, f.cwe, f.cvss_score or "", f.detected_by, "yes" if f.verified else "no",
                f.occurrence_count, to_iso_z(f.first_seen_at), to_iso_z(f.last_seen_at),
            ]
        )
    return Response(
        content="\ufeff" + buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="nexus-findings.csv"'},
    )


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: str,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.project_id != access.project.id:
        raise api_error("finding_not_found", "Finding not found.", status.HTTP_404_NOT_FOUND)

    events = db.execute(
        select(FindingEvent).where(FindingEvent.finding_id == finding.id).order_by(FindingEvent.ts.desc()).limit(100)
    ).scalars().all()
    asset = db.get(Asset, finding.asset_id) if finding.asset_id else None
    service = db.get(Service, finding.service_id) if finding.service_id else None
    scan = db.get(Scan, finding.scan_id) if finding.scan_id else None
    assignee = db.get(User, finding.assigned_to) if finding.assigned_to else None

    links = db.execute(
        select(FindingIntelLink, CveRecord)
        .join(CveRecord, CveRecord.id == FindingIntelLink.cve_id, isouter=True)
        .where(FindingIntelLink.finding_id == finding.id)
    ).all()
    cve_ids = [link.cve_id for link, _record in links]
    kev = {
        row.cve_id: row
        for row in db.execute(select(KevEntry).where(KevEntry.cve_id.in_(cve_ids or [""]))).scalars().all()
    }
    intel_links = []
    for link, record in links:
        intel_links.append(
            {
                "cve_id": link.cve_id,
                "match_type": link.match_type,
                "confidence": link.confidence,
                "rationale": link.rationale,
                "cve": {
                    "description": record.description if record else "",
                    "cvss_v3_score": record.cvss_v3_score if record else None,
                    "cvss_severity": record.cvss_severity if record else "",
                    "published_at": to_iso_z(record.published_at) if record else None,
                },
                "kev": bool(link.cve_id in kev),
                "kev_ransomware": bool(kev[link.cve_id].known_ransomware) if link.cve_id in kev else False,
            }
        )

    score, reasons = priority_score(finding, kev=bool(cve_ids and any(c in kev for c in cve_ids)), intel_links=len(links))

    return {
        "finding": finding_public(finding),
        "priority": {"score": score, "reasons": reasons, "method": "deterministic"},
        "evidence": evidence_summary(db, finding.id),
        "timeline": [event_public(e) for e in events],
        "intel": intel_links,
        "asset": {"id": asset.id, "value": asset.value, "type": asset.type} if asset else None,
        "service": {"id": service.id, "port": service.port, "protocol": service.protocol, "name": service.name} if service else None,
        "scan": {"id": scan.id, "name": scan.name, "kind": scan.kind, "status": scan.status} if scan else None,
        "assignee": {"id": assignee.id, "name": assignee.full_name or assignee.email} if assignee else None,
    }


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------
class FindingUpdate(BaseModel):
    status: str | None = None
    note: str = Field(default="", max_length=4000)
    triage_note: str | None = Field(default=None, max_length=4000)
    assigned_to: str | None = None
    tags: list[str] | None = None


class NoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=4000)


class BulkAction(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=200)
    action: str
    status: str | None = None
    assigned_to: str | None = None
    tag: str | None = Field(default=None, max_length=60)
    note: str = Field(default="", max_length=1000)


def _validate_assignee(db: Session, project_id: str, user_id: str | None) -> None:
    if user_id in (None, ""):
        return
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise api_error("assignee_not_found", "The assignee account does not exist or is disabled.")
    if user.role in ("owner", "admin"):
        return
    member = db.execute(
        select(ProjectMember).where(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id)
    ).scalar_one_or_none()
    if member is None:
        raise api_error("assignee_not_member", "The assignee is not a member of this project.")


@router.patch("/findings/{finding_id}")
def update_finding(
    finding_id: str,
    body: FindingUpdate,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.project_id != access.project.id:
        raise api_error("finding_not_found", "Finding not found.", status.HTTP_404_NOT_FOUND)

    if body.status is not None:
        if body.status not in FINDING_STATUSES:
            raise api_error("invalid_status", f"Status must be one of {list(FINDING_STATUSES)}.")
        change_status(
            db,
            finding,
            body.status,
            actor_user_id=access.user_id,
            actor_label=access.auth.label,
            note=body.note or f"Status set to {body.status}.",
        )
    if body.triage_note is not None:
        finding.triage_note = body.triage_note.strip()
    if body.assigned_to is not None:
        _validate_assignee(db, access.project.id, body.assigned_to or None)
        finding.assigned_to = body.assigned_to or None
        db.add(
            FindingEvent(
                finding_id=finding.id,
                actor_user_id=access.user_id,
                actor_label=access.auth.label[:200],
                kind="note",
                note=f"Assigned to {body.assigned_to}" if body.assigned_to else "Unassigned",
            )
        )
    if body.tags is not None:
        finding.tags = sorted({t.strip()[:60] for t in body.tags if t.strip()})[:30]
    db.commit()
    audit(db, access.auth, "finding.update", project_id=access.project.id, entity_type="finding", entity_id=finding.id, meta={"status": finding.status})
    return {"finding": finding_public(finding)}


@router.post("/findings/{finding_id}/notes", status_code=status.HTTP_201_CREATED)
def add_finding_note(
    finding_id: str,
    body: NoteCreate,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.project_id != access.project.id:
        raise api_error("finding_not_found", "Finding not found.", status.HTTP_404_NOT_FOUND)
    event = add_note(db, finding, actor_user_id=access.user_id, actor_label=access.auth.label, note=body.note.strip())
    audit(db, access.auth, "finding.note", project_id=access.project.id, entity_type="finding", entity_id=finding.id)
    return {"event": event_public(event)}


@router.post("/findings/bulk")
def bulk_update(
    body: BulkAction,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = db.execute(
        select(Finding).where(Finding.project_id == access.project.id, Finding.id.in_(body.ids))
    ).scalars().all()
    if not rows:
        raise api_error("findings_not_found", "None of the selected findings belong to this project.")
    if body.action == "status":
        if body.status not in FINDING_STATUSES:
            raise api_error("invalid_status", f"Status must be one of {list(FINDING_STATUSES)}.")
        for finding in rows:
            change_status(
                db,
                finding,
                body.status,
                actor_user_id=access.user_id,
                actor_label=access.auth.label,
                note=body.note or "Bulk status update.",
            )
    elif body.action == "assign":
        _validate_assignee(db, access.project.id, body.assigned_to or None)
        for finding in rows:
            finding.assigned_to = body.assigned_to or None
        db.commit()
    elif body.action == "tag":
        tag = (body.tag or "").strip()
        if not tag:
            raise api_error("invalid_tag", "A tag is required for the tag action.")
        for finding in rows:
            finding.tags = sorted({*(finding.tags or []), tag[:60]})
        db.commit()
    else:
        raise api_error("invalid_action", "Action must be status, assign or tag.")

    audit(db, access.auth, f"finding.bulk_{body.action}", project_id=access.project.id, meta={"count": len(rows)})
    return {"updated": len(rows), "action": body.action}
