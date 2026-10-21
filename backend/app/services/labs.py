"""Lab run lifecycle: start, hint, submit, reset, leaderboard, achievements.

The heavy lifting (grading) lives in `app/labs/verify.py` and is shared with the
worker; this service is the API-facing layer.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.utils import utcnow
from ..labs.verify import verify_lab_run  # re-exported for the worker
from ..models import Achievement, Lab, LabRun, User

log = logging.getLogger("nexus.services.labs")

__all__ = [
    "start_lab_run",
    "request_hint",
    "submit_answers",
    "reset_lab_run",
    "leaderboard",
    "user_lab_stats",
    "verify_lab_run",
]


def start_lab_run(db: Session, *, lab: Lab, user_id: str, project_id: str | None = None) -> LabRun:
    """Open a (or return the active) run for this user and lab."""
    existing = db.execute(
        select(LabRun)
        .where(LabRun.lab_id == lab.id, LabRun.user_id == user_id, LabRun.status == "started")
        .order_by(LabRun.started_at.desc())
    ).scalars().first()
    if existing:
        if project_id and existing.project_id != project_id:
            existing.project_id = project_id
            db.commit()
        return existing

    attempts = int(
        db.execute(select(func.count(LabRun.id)).where(LabRun.lab_id == lab.id, LabRun.user_id == user_id)).scalar_one() or 0
    )
    run = LabRun(
        lab_id=lab.id,
        user_id=user_id,
        project_id=project_id,
        status="started",
        attempts=attempts + 1,
    )
    db.add(run)
    db.commit()
    log.info("lab run started: user=%s lab=%s attempt=%s", user_id, lab.slug, run.attempts)
    return run


def request_hint(db: Session, *, lab: Lab, run: LabRun) -> dict[str, Any]:
    """Unlock the next hint (progressive). Idempotent once all hints are used."""
    hints = list(lab.hints or [])
    used = list(run.hints_used or [])
    if len(used) >= len(hints):
        return {"hint": None, "used": len(used), "total": len(hints), "message": "All hints are already unlocked."}
    index = len(used)
    used.append(index)
    run.hints_used = used
    db.commit()
    return {
        "hint": hints[index],
        "index": index,
        "used": len(used),
        "total": len(hints),
    }


def submit_answers(db: Session, *, lab: Lab, run: LabRun, answers: dict[str, str]) -> dict[str, Any]:
    """Store quiz answers and grade the run."""
    evidence = dict(run.evidence or {})
    stored = dict(evidence.get("answers") or {})
    valid_keys = {c.get("key") for c in (lab.checks or []) if c.get("type") == "quiz"}
    for key, value in (answers or {}).items():
        if key in valid_keys:
            stored[key] = str(value)[:80]
    evidence["answers"] = stored
    run.evidence = evidence
    db.commit()
    return {"answers": stored}


def reset_lab_run(db: Session, *, run: LabRun) -> LabRun:
    """Reset progress (keeps attempt history, clears answers and hints)."""
    run.status = "reset"
    run.reset_count = int(run.reset_count or 0) + 1
    run.score = 0
    run.hints_used = []
    run.checks_result = []
    run.evidence = {}
    run.finished_at = utcnow()
    db.commit()
    return run


def leaderboard(db: Session, *, limit: int = 20) -> list[dict[str, Any]]:
    """Total best-score per user across labs (each user's best run per lab counts)."""
    best = (
        select(LabRun.user_id, LabRun.lab_id, func.max(LabRun.score).label("best"), func.max(LabRun.finished_at).label("last_at"))
        .where(LabRun.status == "passed")
        .group_by(LabRun.user_id, LabRun.lab_id)
        .subquery()
    )
    rows = db.execute(
        select(User.id, User.full_name, User.email, func.sum(best.c.best).label("score"), func.count(best.c.lab_id).label("labs"), func.max(best.c.last_at))
        .join(best, best.c.user_id == User.id)
        .group_by(User.id)
        .order_by(func.sum(best.c.best).desc())
        .limit(limit)
    ).all()
    return [
        {
            "user_id": user_id,
            "name": full_name or email,
            "score": int(score or 0),
            "labs_passed": int(labs or 0),
            "last_pass_at": last_at,
        }
        for user_id, full_name, email, score, labs, last_at in rows
    ]


def user_lab_stats(db: Session, user_id: str) -> dict[str, Any]:
    runs = db.execute(select(LabRun).where(LabRun.user_id == user_id)).scalars().all()
    passed = [r for r in runs if r.status == "passed"]
    best_by_lab: dict[str, int] = {}
    for run in passed:
        best_by_lab[run.lab_id] = max(best_by_lab.get(run.lab_id, 0), int(run.score or 0))
    achievements = db.execute(select(Achievement).where(Achievement.user_id == user_id).order_by(Achievement.earned_at.desc())).scalars().all()
    return {
        "runs": len(runs),
        "labs_passed": len(best_by_lab),
        "total_score": sum(best_by_lab.values()),
        "achievements": [
            {"code": a.code, "title_en": a.title_en, "title_ar": a.title_ar, "points": a.points, "earned_at": a.earned_at}
            for a in achievements
        ],
    }
