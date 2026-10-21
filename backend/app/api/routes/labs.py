"""Training labs: catalogue, run lifecycle, progressive hints, auto-grading.

Labs are graded against real artefacts and the user's own project data (see
`app/labs/verify.py`). Quiz answer keys and full hint text are never serialized
before they are due: the catalogue exposes only the question and its options,
and hints are released one at a time.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...core.constants import LAB_CATEGORIES, LAB_LEVELS
from ...core.utils import to_iso_z
from ...db import get_db
from ...labs.content import sync_labs
from ...labs.files import labs_dir
from ...models import Lab, LabRun, Project, ProjectMember
from ...services.labs import (
    leaderboard,
    request_hint,
    reset_lab_run,
    start_lab_run,
    submit_answers,
    user_lab_stats,
    verify_lab_run,
)
from ..deps import AuthContext, api_error, audit, require_scope, write_scope_guard
from .common import paged, safe_child_path

log = logging.getLogger("nexus.api.labs")

router = APIRouter(prefix="/labs", tags=["labs"])

FIXTURE_MEDIA_TYPES = {
    ".pcap": "application/vnd.tcpdump.pcap",
    ".pem": "application/x-pem-file",
    ".log": "text/plain; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".json": "application/json",
}


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------
def _public_checks(lab: Lab, *, passed: bool = False) -> list[dict[str, Any]]:
    """Strip everything that would let a caller grade itself."""
    out: list[dict[str, Any]] = []
    for check in lab.checks or []:
        kind = check.get("type", "quiz")
        spec = check.get("spec") or {}
        item: dict[str, Any] = {
            "key": check.get("key", ""),
            "type": kind,
            "points": int(check.get("points", 0) or 0),
            "label_en": check.get("label_en", ""),
            "label_ar": check.get("label_ar", ""),
        }
        if kind == "quiz":
            item["question_en"] = spec.get("question_en", "")
            item["question_ar"] = spec.get("question_ar", "")
            item["options"] = spec.get("options") or []
            if passed:
                item["explanation_en"] = spec.get("explanation_en", "")
                item["explanation_ar"] = spec.get("explanation_ar", "")
        elif kind in ("file_analysis", "project_state"):
            item["spec"] = {
                key: spec.get(key)
                for key in ("kind", "file", "assert", "value", "rule", "min")
                if key in spec
            }
        out.append(item)
    return out


def _fixture_available(lab: Lab) -> bool:
    if lab.target_kind != "file" or not lab.target_ref:
        return False
    try:
        path = safe_child_path(labs_dir(), Path(lab.target_ref).name)
    except Exception:  # noqa: BLE001 - a bad reference must not break the catalogue
        return False
    return path.exists()


def lab_public(
    lab: Lab,
    *,
    best_score: int = 0,
    passed: bool = False,
    attempts: int = 0,
    active_run_id: str | None = None,
    last_run_at=None,
) -> dict[str, Any]:
    checks = list(lab.checks or [])
    max_points = sum(int(c.get("points", 0) or 0) for c in checks if c.get("type") != "manual")
    return {
        "id": lab.id,
        "slug": lab.slug,
        "title_en": lab.title_en,
        "title_ar": lab.title_ar,
        "category": lab.category,
        "category_label": LAB_CATEGORIES.get(lab.category),
        "level": lab.level,
        "level_label": LAB_LEVELS.get(lab.level),
        "points": lab.points,
        "description_en": lab.description_en,
        "description_ar": lab.description_ar,
        "objectives": lab.objectives or [],
        "checks": _public_checks(lab, passed=passed),
        "check_count": len(checks),
        "max_points": max_points,
        "hints_total": len(lab.hints or []),
        "target_kind": lab.target_kind,
        "fixture_available": _fixture_available(lab),
        "requires_private_access": bool(lab.requires_private_access),
        "enabled": bool(lab.enabled),
        "order_index": lab.order_index,
        "user_state": {
            "best_score": int(best_score or 0),
            "passed": bool(passed),
            "attempts": int(attempts or 0),
            "active_run_id": active_run_id,
            "last_run_at": to_iso_z(last_run_at),
        },
    }


def run_public(run: LabRun, lab: Lab | None = None) -> dict[str, Any]:
    data = {
        "id": run.id,
        "lab_id": run.lab_id,
        "project_id": run.project_id,
        "status": run.status,
        "score": run.score,
        "attempts": run.attempts,
        "hints_used": run.hints_used or [],
        "checks_result": run.checks_result or [],
        "answers": (run.evidence or {}).get("answers") or {},
        "reset_count": run.reset_count,
        "started_at": to_iso_z(run.started_at),
        "finished_at": to_iso_z(run.finished_at),
    }
    if lab is not None:
        data["lab"] = {
            "id": lab.id,
            "slug": lab.slug,
            "title_en": lab.title_en,
            "title_ar": lab.title_ar,
            "category": lab.category,
            "level": lab.level,
            "points": lab.points,
            "target_kind": lab.target_kind,
        }
    return data


def _runs_for_user(db: Session, user_id: str) -> list[LabRun]:
    return db.execute(
        select(LabRun).where(LabRun.user_id == user_id).order_by(LabRun.started_at.desc())
    ).scalars().all()


def _state_for_labs(runs: list[LabRun]) -> dict[str, dict[str, Any]]:
    state: dict[str, dict[str, Any]] = {}
    for run in runs:
        entry = state.setdefault(
            run.lab_id,
            {"best_score": 0, "passed": False, "attempts": 0, "active_run_id": None, "last_run_at": None},
        )
        entry["attempts"] += 1
        if run.status == "passed":
            entry["passed"] = True
            entry["best_score"] = max(int(entry["best_score"]), int(run.score or 0))
        if run.status == "started":
            entry["active_run_id"] = run.id
        if entry["last_run_at"] is None:
            entry["last_run_at"] = run.started_at
    return state


def _lab_or_404(db: Session, lab_id: str) -> Lab:
    lab = db.execute(
        select(Lab).where(or_(Lab.id == lab_id, Lab.slug == lab_id))
    ).scalar_one_or_none()
    if lab is None:
        raise api_error("lab_not_found", "Lab not found.", status.HTTP_404_NOT_FOUND)
    return lab


def _run_or_404(db: Session, run_id: str, auth: AuthContext) -> tuple[LabRun, Lab]:
    run = db.get(LabRun, run_id)
    if run is None:
        raise api_error("run_not_found", "Lab run not found.", status.HTTP_404_NOT_FOUND)
    if run.user_id != auth.user_id:
        raise api_error("run_not_yours", "This lab run belongs to another user.", status.HTTP_403_FORBIDDEN)
    lab = db.get(Lab, run.lab_id)
    if lab is None:
        raise api_error("lab_not_found", "The lab for this run no longer exists.", status.HTTP_404_NOT_FOUND)
    return run, lab


def _project_role(db: Session, auth: AuthContext, project_id: str) -> tuple[Project, str]:
    project = db.get(Project, project_id)
    if project is None or project.archived_at is not None:
        raise api_error("project_not_found", "Project not found.", status.HTTP_404_NOT_FOUND)
    if auth.user.role == "owner":
        return project, "owner"
    if auth.user.role == "admin":
        return project, "admin"
    member = db.execute(
        select(ProjectMember).where(
            ProjectMember.project_id == project.id, ProjectMember.user_id == auth.user_id
        )
    ).scalar_one_or_none()
    if member is None:
        raise api_error("not_a_member", "You are not a member of this project.", status.HTTP_403_FORBIDDEN)
    return project, member.role


# ---------------------------------------------------------------------------
# Catalogue & stats
# ---------------------------------------------------------------------------
@router.get("")
def list_labs(
    auth: AuthContext = Depends(require_scope("read:labs")),
    db: Session = Depends(get_db),
    category: str | None = Query(default=None),
    level: str | None = Query(default=None),
    q: str = Query(default="", max_length=160),
    include_disabled: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    if db.execute(select(func.count(Lab.id))).scalar_one() == 0:
        sync_labs(db)

    query = select(Lab)
    count_query = select(func.count(Lab.id))
    if not include_disabled:
        query = query.where(Lab.enabled.is_(True))
        count_query = count_query.where(Lab.enabled.is_(True))
    if category:
        query = query.where(Lab.category == category)
        count_query = count_query.where(Lab.category == category)
    if level:
        query = query.where(Lab.level == level)
        count_query = count_query.where(Lab.level == level)
    if q:
        pattern = f"%{q.strip()}%"
        condition = (
            Lab.title_en.ilike(pattern)
            | Lab.title_ar.ilike(pattern)
            | Lab.description_en.ilike(pattern)
            | Lab.description_ar.ilike(pattern)
        )
        query = query.where(condition)
        count_query = count_query.where(condition)

    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(
        query.order_by(Lab.order_index.asc(), Lab.created_at.asc()).limit(limit).offset(offset)
    ).scalars().all()
    state = _state_for_labs(_runs_for_user(db, auth.user_id))
    items = [
        lab_public(lab, **state.get(lab.id, {}))
        for lab in rows
    ]
    categories = [
        {
            "key": key,
            "labels": labels,
            "count": int(
                db.execute(select(func.count(Lab.id)).where(Lab.category == key, Lab.enabled.is_(True))).scalar_one()
            ),
        }
        for key, labels in LAB_CATEGORIES.items()
        if int(db.execute(select(func.count(Lab.id)).where(Lab.category == key, Lab.enabled.is_(True))).scalar_one()) > 0
    ]
    return {
        **paged(items, total, limit=limit, offset=offset),
        "categories": categories,
        "levels": [{"key": key, "labels": labels} for key, labels in LAB_LEVELS.items()],
    }


@router.get("/leaderboard")
def lab_leaderboard(
    auth: AuthContext = Depends(require_scope("read:labs")),
    db: Session = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    rows = leaderboard(db, limit=limit)
    for row in rows:
        row["last_pass_at"] = to_iso_z(row.get("last_pass_at"))
        row["is_me"] = row["user_id"] == auth.user_id
    return {"items": rows, "total": len(rows)}


@router.get("/me/stats")
def my_stats(
    auth: AuthContext = Depends(require_scope("read:labs")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    stats = user_lab_stats(db, auth.user_id)
    for achievement in stats["achievements"]:
        achievement["earned_at"] = to_iso_z(achievement.get("earned_at"))
    runs = db.execute(
        select(LabRun)
        .where(LabRun.user_id == auth.user_id)
        .order_by(LabRun.started_at.desc())
        .limit(30)
    ).scalars().all()
    labs = {
        lab.id: lab
        for lab in db.execute(select(Lab).where(Lab.id.in_({r.lab_id for r in runs} or {""}))).scalars().all()
    }
    return {
        **stats,
        "recent_runs": [run_public(run, labs.get(run.lab_id)) for run in runs],
    }


# ---------------------------------------------------------------------------
# Lab detail & fixture
# ---------------------------------------------------------------------------
@router.get("/{lab_id}")
def get_lab(
    lab_id: str,
    auth: AuthContext = Depends(require_scope("read:labs")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    lab = _lab_or_404(db, lab_id)
    if not lab.enabled and auth.user.role not in ("owner", "admin"):
        raise api_error("lab_disabled", "This lab is disabled.", status.HTTP_404_NOT_FOUND)
    # Best/passed state only depends on graded runs from this user.
    state = _state_for_labs([r for r in _runs_for_user(db, auth.user_id) if r.lab_id == lab.id]).get(lab.id, {})
    run = None
    if state.get("active_run_id"):
        run = db.get(LabRun, state["active_run_id"])
    data = lab_public(lab, **state)
    data["hints"] = [
        (lab.hints or [])[i]
        for i in (run.hints_used or []) if isinstance(i, int) and 0 <= i < len(lab.hints or [])
    ] if run else []
    data["run"] = run_public(run, lab) if run else None
    return {"lab": data}


@router.get("/{lab_id}/fixture")
def download_fixture(
    lab_id: str,
    auth: AuthContext = Depends(require_scope("read:labs")),
    db: Session = Depends(get_db),
) -> FileResponse:
    lab = _lab_or_404(db, lab_id)
    if lab.target_kind != "file" or not lab.target_ref:
        raise api_error("no_fixture", "This lab has no downloadable fixture.", status.HTTP_404_NOT_FOUND)
    filename = Path(lab.target_ref).name
    path = safe_child_path(labs_dir(), filename, must_exist=True)
    return FileResponse(
        path,
        filename=filename,
        media_type=FIXTURE_MEDIA_TYPES.get(path.suffix.lower(), "application/octet-stream"),
    )


# ---------------------------------------------------------------------------
# Run lifecycle
# ---------------------------------------------------------------------------
class StartBody(BaseModel):
    project_id: str | None = Field(default=None, max_length=36)


class AnswerBody(BaseModel):
    answers: dict[str, str] = Field(default_factory=dict)


@router.post("/{lab_id}/start", status_code=status.HTTP_201_CREATED)
def start_lab(
    lab_id: str,
    body: StartBody | None = None,
    auth: AuthContext = Depends(require_scope("write:labs")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(auth)
    lab = _lab_or_404(db, lab_id)
    if not lab.enabled:
        raise api_error("lab_disabled", "This lab is disabled.", status.HTTP_409_CONFLICT)

    project_id = (body.project_id if body else None) or None
    if project_id:
        project, role = _project_role(db, auth, project_id)
        if role == "viewer":
            raise api_error(
                "insufficient_project_role",
                "Starting a lab in this project requires the analyst role or higher.",
                status.HTTP_403_FORBIDDEN,
            )

    run = start_lab_run(db, lab=lab, user_id=auth.user_id, project_id=project_id)
    audit(
        db,
        auth,
        "lab.start",
        project_id=project_id,
        entity_type="lab_run",
        entity_id=run.id,
        meta={"lab": lab.slug, "attempt": run.attempts},
    )
    return {"run": run_public(run, lab)}


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    auth: AuthContext = Depends(require_scope("read:labs")),
    db: Session = Depends(get_db),
    refresh: bool = Query(default=True),
) -> dict[str, Any]:
    run, lab = _run_or_404(db, run_id, auth)
    # Project-state checks become passable after the user performs the action in
    # their project; refreshing keeps the UI honest without faking progress.
    if refresh and run.status == "started" and run.checks_result:
        await verify_lab_run(db, run.id)
        db.refresh(run)
    return {"run": run_public(run, lab)}


@router.post("/runs/{run_id}/hint")
def unlock_hint(
    run_id: str,
    auth: AuthContext = Depends(require_scope("write:labs")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(auth)
    run, lab = _run_or_404(db, run_id, auth)
    if run.status == "passed":
        raise api_error("lab_already_passed", "This lab is already passed.", status.HTTP_409_CONFLICT)
    result = request_hint(db, lab=lab, run=run)
    audit(db, auth, "lab.hint", project_id=run.project_id, entity_type="lab_run", entity_id=run.id, meta={"lab": lab.slug})
    return {**result, "run": run_public(run, lab)}


@router.post("/runs/{run_id}/submit")
async def submit_lab(
    run_id: str,
    body: AnswerBody,
    auth: AuthContext = Depends(require_scope("write:labs")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(auth)
    run, lab = _run_or_404(db, run_id, auth)
    if run.status == "reset":
        raise api_error("run_reset", "This run was reset — start the lab again.", status.HTTP_409_CONFLICT)
    submit_answers(db, lab=lab, run=run, answers=body.answers)
    result = await verify_lab_run(db, run.id)
    db.refresh(run)
    explanations = {}
    if not result["pending"]:
        for check in _public_checks(lab, passed=result["passed"]):
            if check["type"] == "quiz":
                explanations[check["key"]] = {
                    "explanation_en": check.get("explanation_en", ""),
                    "explanation_ar": check.get("explanation_ar", ""),
                }
    audit(
        db,
        auth,
        "lab.submit",
        project_id=run.project_id,
        entity_type="lab_run",
        entity_id=run.id,
        meta={"lab": lab.slug, "passed": result["passed"], "score": result["score"]},
    )
    return {**result, "run": run_public(run, lab), "explanations": explanations}


@router.post("/runs/{run_id}/reset")
def reset_run(
    run_id: str,
    auth: AuthContext = Depends(require_scope("write:labs")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(auth)
    run, lab = _run_or_404(db, run_id, auth)
    reset_lab_run(db, run=run)
    audit(db, auth, "lab.reset", project_id=run.project_id, entity_type="lab_run", entity_id=run.id, meta={"lab": lab.slug})
    return {"run": run_public(run, lab)}
