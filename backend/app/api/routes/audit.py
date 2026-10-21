"""Audit trail: append-only, hash-chained activity log.

Global audit is restricted to platform admins; project audit to project admins.
Entries can be filtered for investigations and the chain can be verified to
prove that no row was modified or deleted outside the application.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...core.audit import verify_chain
from ...core.utils import to_iso_z
from ...db import get_db
from ...models import AuditLog
from ..deps import AuthContext, ProjectAccess, api_error, project_access, require_global_role
from .common import paged, parse_dt

log = logging.getLogger("nexus.api.audit")

router = APIRouter(prefix="/audit", tags=["audit"])
project_router = APIRouter(prefix="/projects/{project_id}/audit", tags=["audit"])

OUTCOMES = ("success", "denied", "error")


def audit_public(entry: AuditLog) -> dict[str, Any]:
    return {
        "id": entry.id,
        "ts": to_iso_z(entry.ts),
        "actor_user_id": entry.actor_user_id,
        "actor_label": entry.actor_label,
        "actor_api_key_id": entry.actor_api_key_id,
        "project_id": entry.project_id,
        "action": entry.action,
        "entity_type": entry.entity_type,
        "entity_id": entry.entity_id,
        "outcome": entry.outcome,
        "ip": entry.ip,
        "user_agent": entry.user_agent,
        "meta": entry.meta or {},
        "prev_hash": entry.prev_hash,
        "entry_hash": entry.entry_hash,
    }


def _filtered(
    db: Session,
    *,
    project_id: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    actor_user_id: str | None = None,
    entity_type: str | None = None,
    q: str = "",
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    query = select(AuditLog)
    count_query = select(func.count(AuditLog.id))

    def apply(*conditions):
        nonlocal query, count_query
        for condition in conditions:
            query = query.where(condition)
            count_query = count_query.where(condition)

    if project_id:
        apply(AuditLog.project_id == project_id)
    if action:
        apply(AuditLog.action == action)
    if outcome:
        apply(AuditLog.outcome == outcome)
    if actor_user_id:
        apply(AuditLog.actor_user_id == actor_user_id)
    if entity_type:
        apply(AuditLog.entity_type == entity_type)
    if q:
        pattern = f"%{q.strip()}%"
        apply(
            or_(
                AuditLog.action.ilike(pattern),
                AuditLog.actor_label.ilike(pattern),
                AuditLog.entity_id.ilike(pattern),
                AuditLog.entity_type.ilike(pattern),
                AuditLog.ip.ilike(pattern),
            )
        )
    since = parse_dt(date_from, field="date_from") if date_from else None
    until = parse_dt(date_to, field="date_to") if date_to else None
    if since:
        apply(AuditLog.ts >= since)
    if until:
        apply(AuditLog.ts <= until)

    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(
        query.order_by(AuditLog.ts.desc(), AuditLog.id.desc()).limit(limit).offset(offset)
    ).scalars().all()

    base = select(AuditLog.outcome, func.count(AuditLog.id))
    if project_id:
        base = base.where(AuditLog.project_id == project_id)
    by_outcome = {str(k): int(v) for k, v in db.execute(base.group_by(AuditLog.outcome)).all()}

    top_actions_query = select(AuditLog.action, func.count(AuditLog.id))
    if project_id:
        top_actions_query = top_actions_query.where(AuditLog.project_id == project_id)
    top_actions = [
        {"action": action_name, "count": int(count)}
        for action_name, count in db.execute(
            top_actions_query.group_by(AuditLog.action).order_by(func.count(AuditLog.id).desc()).limit(15)
        ).all()
    ]

    result = paged([audit_public(row) for row in rows], total, limit=limit, offset=offset)
    result["counts"] = {"by_outcome": by_outcome, "top_actions": top_actions}
    return result


# ---------------------------------------------------------------------------
# Global (admin only)
# ---------------------------------------------------------------------------
@router.get("")
def list_audit(
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
    project_id: str | None = Query(default=None),
    action: str | None = Query(default=None, max_length=80),
    outcome: str | None = Query(default=None),
    actor_user_id: str | None = Query(default=None),
    entity_type: str | None = Query(default=None, max_length=60),
    q: str = Query(default="", max_length=160),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    if outcome and outcome not in OUTCOMES:
        raise api_error("invalid_outcome", f"Outcome must be one of {list(OUTCOMES)}.")
    return _filtered(
        db,
        project_id=project_id,
        action=action,
        outcome=outcome,
        actor_user_id=actor_user_id,
        entity_type=entity_type,
        q=q,
        date_from=date_from,
        date_to=date_to,
        limit=limit,
        offset=offset,
    )


@router.get("/actions")
def audit_actions(
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = db.execute(
        select(AuditLog.action, func.count(AuditLog.id))
        .group_by(AuditLog.action)
        .order_by(func.count(AuditLog.id).desc())
    ).all()
    return {"items": [{"action": action, "count": int(count)} for action, count in rows]}


@router.get("/verify")
def verify(
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
    limit: int = Query(default=5000, ge=1, le=20000),
) -> dict[str, Any]:
    result = verify_chain(db, limit=limit)
    result["scope"] = f"first {limit} entries in chronological order"
    return result


@router.get("/export")
def export_audit(
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
    project_id: str | None = Query(default=None),
    action: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
) -> StreamingResponse:
    result = _filtered(
        db,
        project_id=project_id,
        action=action,
        outcome=outcome,
        date_from=date_from,
        date_to=date_to,
        limit=5000,
        offset=0,
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["id", "ts", "actor", "actor_user_id", "action", "entity_type", "entity_id", "outcome", "project_id", "ip", "meta", "entry_hash"]
    )
    for item in result["items"]:
        writer.writerow(
            [
                item["id"],
                item["ts"],
                item["actor_label"],
                item["actor_user_id"] or "",
                item["action"],
                item["entity_type"],
                item["entity_id"],
                item["outcome"],
                item["project_id"] or "",
                item["ip"],
                json.dumps(item["meta"], ensure_ascii=False, sort_keys=True),
                item["entry_hash"],
            ]
        )
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="nexus-audit.csv"'},
    )


@router.get("/{entry_id}")
def get_audit_entry(
    entry_id: str,
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    entry = db.get(AuditLog, entry_id)
    if entry is None:
        raise api_error("audit_not_found", "Audit entry not found.", status.HTTP_404_NOT_FOUND)
    return {"entry": audit_public(entry)}


# ---------------------------------------------------------------------------
# Project-scoped (project admin)
# ---------------------------------------------------------------------------
@project_router.get("")
def list_project_audit(
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
    action: str | None = Query(default=None, max_length=80),
    outcome: str | None = Query(default=None),
    actor_user_id: str | None = Query(default=None),
    entity_type: str | None = Query(default=None, max_length=60),
    q: str = Query(default="", max_length=160),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    if outcome and outcome not in OUTCOMES:
        raise api_error("invalid_outcome", f"Outcome must be one of {list(OUTCOMES)}.")
    return _filtered(
        db,
        project_id=access.project.id,
        action=action,
        outcome=outcome,
        actor_user_id=actor_user_id,
        entity_type=entity_type,
        q=q,
        date_from=date_from,
        date_to=date_to,
        limit=limit,
        offset=offset,
    )
