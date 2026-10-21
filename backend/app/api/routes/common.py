"""Shared helpers for route modules: query parsing, pagination, path safety."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.utils import to_iso_z, utcnow
from ...models import Project, ProjectMember
from ..deps import AuthContext, api_error

TERMINAL_SCAN_STATUSES = ("completed", "failed", "canceled", "partial")
ACTIVE_SCAN_STATUSES = ("queued", "running", "paused")


def parse_dt(value: Any, *, field: str = "date") -> datetime | None:
    """Parse an ISO-8601 string (or pass a datetime through). Naive UTC out."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            raise api_error("invalid_datetime", f"'{value}' is not a valid ISO-8601 {field}.")
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def csv_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in str(value).split(",") if part.strip()]


def paged(items: list[Any], total: int, *, limit: int, offset: int) -> dict[str, Any]:
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(items) < total,
    }


def safe_child_path(parent: Path, candidate: str, *, must_exist: bool = False) -> Path:
    """Resolve `candidate` and refuse anything outside `parent` (path traversal guard)."""
    raw = Path(candidate)
    path = raw if raw.is_absolute() else (parent / raw)
    resolved = path.resolve()
    parent_resolved = parent.resolve()
    try:
        resolved.relative_to(parent_resolved)
    except ValueError:
        raise api_error(
            "unsafe_path",
            "The requested file is outside the managed storage directory.",
            status.HTTP_400_BAD_REQUEST,
        )
    if must_exist and not resolved.exists():
        raise api_error("file_missing", "The file no longer exists on disk.", status.HTTP_410_GONE)
    return resolved


def now_iso() -> str:
    return to_iso_z(utcnow()) or ""


def accessible_project_ids(db: Session, auth: AuthContext) -> list[str]:
    """Project ids the caller may read (archived projects excluded).

    Owners and admins see every project; everyone else sees only explicit
    memberships. This is the single scope helper for cross-project views such as
    the dashboard, global search and the notification centre.
    """
    statement = select(Project.id).where(Project.archived_at.is_(None))
    if auth.user.role in ("owner", "admin"):
        return list(db.execute(statement).scalars().all())
    return list(
        db.execute(
            statement.join(ProjectMember, ProjectMember.project_id == Project.id).where(
                ProjectMember.user_id == auth.user_id
            )
        ).scalars().all()
    )
