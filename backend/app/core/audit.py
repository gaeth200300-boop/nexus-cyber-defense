"""Append-only, hash-chained audit trail.

Every state-changing API call and every scan lifecycle step writes one row here.
The API deliberately exposes *no* update/delete endpoint for this table, and each
entry carries a SHA-256 chain hash so silent tampering is detectable.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AuditLog
from .utils import canonical_json, sha256_hex, utcnow

log = logging.getLogger("nexus.audit")

GENESIS_HASH = "0" * 64


def _last_hash(db: Session) -> str:
    row = db.execute(
        select(AuditLog.entry_hash).order_by(AuditLog.ts.desc(), AuditLog.id.desc()).limit(1)
    ).scalar_one_or_none()
    return row or GENESIS_HASH


def record(
    db: Session,
    action: str,
    *,
    actor_user_id: str | None = None,
    actor_label: str = "system",
    actor_api_key_id: str | None = None,
    project_id: str | None = None,
    entity_type: str = "",
    entity_id: str = "",
    outcome: str = "success",
    ip: str = "",
    user_agent: str = "",
    meta: dict[str, Any] | None = None,
    commit: bool = False,
) -> AuditLog:
    """Append one audit entry (does not commit unless commit=True)."""
    prev_hash = _last_hash(db)
    ts = utcnow()
    payload = canonical_json(
        {
            "ts": ts.isoformat(),
            "action": action,
            "actor_user_id": actor_user_id,
            "actor_api_key_id": actor_api_key_id,
            "project_id": project_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "outcome": outcome,
            "meta": meta or {},
        }
    )
    entry = AuditLog(
        ts=ts,
        actor_user_id=actor_user_id,
        actor_label=actor_label[:200],
        actor_api_key_id=actor_api_key_id,
        project_id=project_id,
        action=action[:80],
        entity_type=entity_type[:60],
        entity_id=str(entity_id)[:64],
        outcome=outcome[:20],
        ip=ip[:64],
        user_agent=user_agent[:300],
        meta=meta or {},
        prev_hash=prev_hash,
        entry_hash=sha256_hex(prev_hash + payload),
    )
    db.add(entry)
    if commit:
        db.commit()
    return entry


def verify_chain(db: Session, limit: int = 5000) -> dict[str, Any]:
    """Recompute the chain and report the first broken link (admin-only endpoint)."""
    rows = db.execute(
        select(AuditLog).order_by(AuditLog.ts.asc(), AuditLog.id.asc()).limit(limit)
    ).scalars().all()
    prev = GENESIS_HASH
    checked = 0
    for row in rows:
        payload = canonical_json(
            {
                "ts": row.ts.isoformat(),
                "action": row.action,
                "actor_user_id": row.actor_user_id,
                "actor_api_key_id": row.actor_api_key_id,
                "project_id": row.project_id,
                "entity_type": row.entity_type,
                "entity_id": row.entity_id,
                "outcome": row.outcome,
                "meta": row.meta or {},
            }
        )
        expected = sha256_hex(prev + payload)
        if row.prev_hash != prev or row.entry_hash != expected:
            return {
                "ok": False,
                "checked": checked,
                "broken_at": {"id": row.id, "ts": row.ts.isoformat(), "action": row.action},
                "detail": "Chain mismatch — the log may have been modified outside the application.",
            }
        prev = row.entry_hash
        checked += 1
    return {"ok": True, "checked": checked, "last_hash": prev}
