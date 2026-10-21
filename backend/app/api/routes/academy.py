"""Academy API: division catalogue, lesson detail, and private progress.

The curriculum is public to authenticated users.  Progress, notes, bookmarks
and quiz results are always filtered by ``auth.user_id``; there is no route that
accepts a user id from the caller.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session

from ...academy.content import DIVISIONS, DIVISION_KEYS, category_label, public_divisions
from ...core.utils import new_id, sha256_hex, to_iso_z, utcnow
from ...db import get_db
from ...models import Lesson, LessonCertificate, LessonProgress
from ..deps import AuthContext, api_error, audit, get_auth, write_scope_guard
from .common import paged

router = APIRouter(prefix="/academy", tags=["academy"])

PROGRESS_STATUSES = ("not_started", "in_progress", "completed")
QUIZ_PASS_PERCENT = 70


class ProgressUpdate(BaseModel):
    status: str | None = None
    progress_percent: int | None = Field(default=None, ge=0, le=100)


class BookmarkUpdate(BaseModel):
    bookmarked: bool


class NotesUpdate(BaseModel):
    notes: str = Field(default="", max_length=20000)


class QuizSubmit(BaseModel):
    answers: dict[str, str] = Field(default_factory=dict)


class CertificateRequest(BaseModel):
    display_name: str = Field(default="", max_length=160)


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------
def _public_quiz(lesson: Lesson) -> list[dict[str, Any]]:
    """Never serialize answer keys or explanations before grading."""
    return [
        {
            "id": question.get("id", ""),
            "question_en": question.get("question_en", ""),
            "question_ar": question.get("question_ar", ""),
            "options": question.get("options", []),
        }
        for question in (lesson.quiz or [])
    ]


def _user_state(progress: LessonProgress | None) -> dict[str, Any]:
    if progress is None:
        return {
            "status": "not_started",
            "progress_percent": 0,
            "quiz_score": None,
            "quiz_attempts": 0,
            "bookmarked": False,
            "has_notes": False,
            "started_at": None,
            "completed_at": None,
            "updated_at": None,
        }
    return {
        "status": progress.status,
        "progress_percent": int(progress.progress_percent or 0),
        "quiz_score": progress.quiz_score,
        "quiz_attempts": int(progress.quiz_attempts or 0),
        "bookmarked": bool(progress.bookmarked),
        "has_notes": bool((progress.notes or "").strip()),
        "started_at": to_iso_z(progress.started_at),
        "completed_at": to_iso_z(progress.completed_at),
        "updated_at": to_iso_z(progress.updated_at),
    }


def _public_lesson(lesson: Lesson, progress: LessonProgress | None, *, detail: bool = False) -> dict[str, Any]:
    division = DIVISIONS.get(lesson.division, {})
    state = _user_state(progress)
    payload: dict[str, Any] = {
        "id": lesson.id,
        "slug": lesson.slug,
        "division": lesson.division,
        "division_title_en": division.get("title_en", lesson.division),
        "division_title_ar": division.get("title_ar", lesson.division),
        "category": lesson.category,
        "category_label": category_label(lesson.division, lesson.category),
        "difficulty": lesson.difficulty,
        "order_index": lesson.order_index,
        "title_en": lesson.title_en,
        "title_ar": lesson.title_ar,
        "summary_en": lesson.summary_en,
        "summary_ar": lesson.summary_ar,
        "duration_minutes": lesson.duration_minutes,
        "objectives": lesson.objectives or [],
        "tags": lesson.tags or [],
        "video": {
            "url": lesson.video_url or "",
            "status": lesson.video_status,
            "available": bool(lesson.video_url) and lesson.video_status == "verified",
        },
        "video_url": lesson.video_url or "",
        "video_status": lesson.video_status,
        "resource": {
            "url": lesson.resource_url or "",
            "label_en": lesson.resource_label_en,
            "label_ar": lesson.resource_label_ar,
            "kind": "official_documentation",
        },
        "resource_url": lesson.resource_url or "",
        "resource_label_en": lesson.resource_label_en,
        "resource_label_ar": lesson.resource_label_ar,
        "quiz_count": len(lesson.quiz or []),
        "user_state": state,
        # Flattened learner state so a list row can be rendered without
        # reaching into `user_state`.
        "status": state["status"],
        "progress_percent": state["progress_percent"],
        "quiz_score": state["quiz_score"],
        "quiz_attempts": state["quiz_attempts"],
        "bookmarked": state["bookmarked"],
        "completed_at": state["completed_at"],
    }
    if detail:
        payload.update(
            {
                "description_en": lesson.description_en,
                "description_ar": lesson.description_ar,
                "exercise_en": lesson.exercise_en,
                "exercise_ar": lesson.exercise_ar,
                "quiz": _public_quiz(lesson),
                "notes": (progress.notes if progress else "") or "",
                "prerequisites": list(lesson.prerequisites or []),
                "related": list(lesson.related or []),
            }
        )
    return payload


def _lesson_refs(db: Session, slugs: list[str]) -> list[dict[str, Any]]:
    if not slugs:
        return []
    rows = db.execute(select(Lesson).where(Lesson.slug.in_(slugs), Lesson.is_published.is_(True))).scalars().all()
    by_slug = {lesson.slug: lesson for lesson in rows}
    result: list[dict[str, Any]] = []
    for slug in slugs:
        lesson = by_slug.get(slug)
        if lesson is None:
            continue
        result.append(
            {
                "id": lesson.id,
                "slug": lesson.slug,
                "title_en": lesson.title_en,
                "title_ar": lesson.title_ar,
                "division": lesson.division,
                "difficulty": lesson.difficulty,
                "duration_minutes": lesson.duration_minutes,
            }
        )
    return result


def _lesson_or_404(db: Session, lesson_id: str) -> Lesson:
    lesson = db.execute(
        select(Lesson).where(
            or_(Lesson.id == lesson_id, Lesson.slug == lesson_id),
            Lesson.is_published.is_(True),
        )
    ).scalar_one_or_none()
    if lesson is None:
        raise api_error("lesson_not_found", "Lesson not found.", status.HTTP_404_NOT_FOUND)
    return lesson


def _progress_for(db: Session, user_id: str, lesson_id: str) -> LessonProgress | None:
    return db.execute(
        select(LessonProgress).where(
            LessonProgress.user_id == user_id,
            LessonProgress.lesson_id == lesson_id,
        )
    ).scalar_one_or_none()


def _ensure_progress(db: Session, user_id: str, lesson: Lesson) -> LessonProgress:
    progress = _progress_for(db, user_id, lesson.id)
    if progress is None:
        progress = LessonProgress(user_id=user_id, lesson_id=lesson.id, status="not_started", progress_percent=0)
        db.add(progress)
        db.flush()
    return progress


def _validate_division(division: str | None) -> None:
    if division and division not in DIVISION_KEYS:
        raise api_error(
            "invalid_division",
            f"Unknown division. Use one of: {', '.join(DIVISION_KEYS)}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------
@router.get("/divisions")
def list_divisions(
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    divisions = public_divisions()

    total_by_division: dict[str, int] = {}
    completed_by_division: dict[str, int] = {}
    in_progress_by_division: dict[str, int] = {}
    bookmarked_by_division: dict[str, int] = {}
    category_total: dict[tuple[str, str], int] = {}
    category_completed: dict[tuple[str, str], int] = {}

    for division, category, count in db.execute(
        select(Lesson.division, Lesson.category, func.count(Lesson.id))
        .where(Lesson.is_published.is_(True))
        .group_by(Lesson.division, Lesson.category)
    ).all():
        category_total[(division, category)] = int(count)
        total_by_division[division] = total_by_division.get(division, 0) + int(count)

    for division, status_value, count in db.execute(
        select(Lesson.division, LessonProgress.status, func.count(LessonProgress.id))
        .join(Lesson, Lesson.id == LessonProgress.lesson_id)
        .where(LessonProgress.user_id == auth.user_id, Lesson.is_published.is_(True))
        .group_by(Lesson.division, LessonProgress.status)
    ).all():
        if status_value == "completed":
            completed_by_division[division] = int(count)
        elif status_value == "in_progress":
            in_progress_by_division[division] = int(count)

    for division, category, count in db.execute(
        select(Lesson.division, Lesson.category, func.count(LessonProgress.id))
        .join(Lesson, Lesson.id == LessonProgress.lesson_id)
        .where(
            LessonProgress.user_id == auth.user_id,
            LessonProgress.status == "completed",
            Lesson.is_published.is_(True),
        )
        .group_by(Lesson.division, Lesson.category)
    ).all():
        category_completed[(division, category)] = int(count)

    for division, count in db.execute(
        select(Lesson.division, func.count(LessonProgress.id))
        .join(Lesson, Lesson.id == LessonProgress.lesson_id)
        .where(
            LessonProgress.user_id == auth.user_id,
            LessonProgress.bookmarked.is_(True),
            Lesson.is_published.is_(True),
        )
        .group_by(Lesson.division)
    ).all():
        bookmarked_by_division[division] = int(count)

    for division in divisions:
        key = division["key"]
        total = total_by_division.get(key, division["lesson_count"])
        completed = completed_by_division.get(key, 0)
        division["lesson_count"] = total
        division["completed"] = completed
        division["in_progress"] = in_progress_by_division.get(key, 0)
        division["bookmarked"] = bookmarked_by_division.get(key, 0)
        division["progress_percent"] = round((completed / total) * 100, 1) if total else 0.0
        division["video_verified"] = 0
        division["video_pending"] = total
        for category in division["categories"]:
            category["lesson_count"] = category_total.get((key, category["key"]), 0)
            category["completed"] = category_completed.get((key, category["key"]), 0)

    total_lessons = sum(item["lesson_count"] for item in divisions)
    completed = sum(item["completed"] for item in divisions)
    return {
        "divisions": divisions,
        "totals": {
            "lesson_count": total_lessons,
            "completed": completed,
            "in_progress": sum(item["in_progress"] for item in divisions),
            "bookmarked": sum(item["bookmarked"] for item in divisions),
            "progress_percent": round((completed / total_lessons) * 100, 1) if total_lessons else 0.0,
            "video_verified": 0,
            "video_pending": total_lessons,
        },
        "video_note": "Video links are only shown after independent verification; pending lessons use official documentation and exercises.",
    }


@router.get("/lessons")
def list_lessons(
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
    division: str | None = Query(default=None),
    category: str | None = Query(default=None),
    difficulty: str | None = Query(default=None),
    q: str = Query(default="", max_length=160),
    progress_status: str | None = Query(default=None, alias="status"),
    bookmarked: bool | None = Query(default=None),
    limit: int = Query(default=24, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    _validate_division(division)
    if progress_status and progress_status not in PROGRESS_STATUSES:
        raise api_error("invalid_status", "Unknown progress status.", status.HTTP_422_UNPROCESSABLE_ENTITY)
    if difficulty and difficulty not in ("beginner", "intermediate", "advanced"):
        raise api_error("invalid_difficulty", "Unknown difficulty.", status.HTTP_422_UNPROCESSABLE_ENTITY)

    conditions: list[Any] = [Lesson.is_published.is_(True)]
    if division:
        conditions.append(Lesson.division == division)
    if category:
        conditions.append(Lesson.category == category)
    if difficulty:
        conditions.append(Lesson.difficulty == difficulty)
    if q.strip():
        term = f"%{q.strip()}%"
        conditions.append(
            or_(
                Lesson.title_en.ilike(term),
                Lesson.title_ar.ilike(term),
                Lesson.summary_en.ilike(term),
                Lesson.summary_ar.ilike(term),
                Lesson.slug.ilike(term),
            )
        )
    if progress_status == "not_started":
        conditions.append(or_(LessonProgress.id.is_(None), LessonProgress.status == "not_started"))
    elif progress_status:
        conditions.append(LessonProgress.status == progress_status)
    if bookmarked is True:
        conditions.append(LessonProgress.bookmarked.is_(True))

    total = int(
        db.execute(
            select(func.count(Lesson.id)).outerjoin(
                LessonProgress,
                and_(LessonProgress.lesson_id == Lesson.id, LessonProgress.user_id == auth.user_id),
            ).where(*conditions)
        ).scalar_one()
    )

    division_order = case(
        (Lesson.division == "defense", 0),
        (Lesson.division == "offense", 1),
        (Lesson.division == "forensics", 2),
        else_=3,
    )
    rows = db.execute(
        select(Lesson, LessonProgress)
        .outerjoin(
            LessonProgress,
            and_(LessonProgress.lesson_id == Lesson.id, LessonProgress.user_id == auth.user_id),
        )
        .where(*conditions)
        .order_by(division_order, Lesson.order_index, Lesson.slug)
        .limit(limit)
        .offset(offset)
    ).all()

    return paged(
        [_public_lesson(lesson, progress) for lesson, progress in rows],
        total,
        limit=limit,
        offset=offset,
    )


@router.get("/lessons/{lesson_id}")
def get_lesson(
    lesson_id: str,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    lesson = _lesson_or_404(db, lesson_id)
    progress = _progress_for(db, auth.user_id, lesson.id)
    payload = _public_lesson(lesson, progress, detail=True)
    return {
        "lesson": payload,
        "prerequisites": _lesson_refs(db, list(lesson.prerequisites or [])),
        "related": _lesson_refs(db, list(lesson.related or [])),
    }


# ---------------------------------------------------------------------------
# Private learning state
# ---------------------------------------------------------------------------
@router.put("/lessons/{lesson_id}/progress")
def update_progress(
    lesson_id: str,
    body: ProgressUpdate,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(auth)
    lesson = _lesson_or_404(db, lesson_id)
    if body.status is not None and body.status not in PROGRESS_STATUSES:
        raise api_error("invalid_status", "Unknown progress status.", status.HTTP_422_UNPROCESSABLE_ENTITY)

    progress = _ensure_progress(db, auth.user_id, lesson)
    now = utcnow()
    requested_status = body.status

    if requested_status == "not_started":
        progress.status = "not_started"
        progress.progress_percent = 0
        progress.started_at = None
        progress.completed_at = None
    else:
        if requested_status is not None:
            progress.status = requested_status
        if progress.status == "not_started":
            progress.status = "in_progress"
        if progress.started_at is None:
            progress.started_at = now

        if progress.status == "completed":
            progress.progress_percent = 100
            progress.completed_at = progress.completed_at or now
        elif body.progress_percent is not None:
            progress.progress_percent = body.progress_percent
            if progress.progress_percent >= 100:
                progress.status = "completed"
                progress.progress_percent = 100
                progress.completed_at = now
            elif progress.progress_percent <= 0:
                progress.progress_percent = 0
                progress.status = "not_started"
                progress.started_at = None
                progress.completed_at = None
            else:
                progress.progress_percent = max(progress.progress_percent, 1)
        elif progress.progress_percent <= 0:
            progress.progress_percent = 10

    progress.updated_at = now
    db.commit()
    audit(
        db,
        auth,
        "academy.progress",
        entity_type="lesson",
        entity_id=lesson.id,
        meta={
            "slug": lesson.slug,
            "status": progress.status,
            "progress_percent": progress.progress_percent,
        },
    )
    return {"user_state": _user_state(progress)}


@router.post("/lessons/{lesson_id}/bookmark")
def set_bookmark(
    lesson_id: str,
    body: BookmarkUpdate,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(auth)
    lesson = _lesson_or_404(db, lesson_id)
    progress = _ensure_progress(db, auth.user_id, lesson)
    progress.bookmarked = bool(body.bookmarked)
    progress.updated_at = utcnow()
    db.commit()
    audit(
        db,
        auth,
        "academy.bookmark",
        entity_type="lesson",
        entity_id=lesson.id,
        meta={"slug": lesson.slug, "bookmarked": progress.bookmarked},
    )
    return {"user_state": _user_state(progress)}


@router.put("/lessons/{lesson_id}/notes")
def update_notes(
    lesson_id: str,
    body: NotesUpdate,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(auth)
    lesson = _lesson_or_404(db, lesson_id)
    progress = _ensure_progress(db, auth.user_id, lesson)
    progress.notes = body.notes
    progress.updated_at = utcnow()
    db.commit()
    audit(
        db,
        auth,
        "academy.note",
        entity_type="lesson",
        entity_id=lesson.id,
        meta={"slug": lesson.slug, "chars": len(body.notes)},
    )
    return {"notes": progress.notes, "user_state": _user_state(progress)}


@router.post("/lessons/{lesson_id}/quiz")
def submit_quiz(
    lesson_id: str,
    body: QuizSubmit,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(auth)
    lesson = _lesson_or_404(db, lesson_id)
    quiz = list(lesson.quiz or [])
    if not quiz:
        raise api_error("quiz_unavailable", "This lesson has no knowledge check yet.", status.HTTP_409_CONFLICT)

    details: list[dict[str, Any]] = []
    correct_count = 0
    for question in quiz:
        question_id = question.get("id", "")
        selected = body.answers.get(question_id)
        answer = question.get("answer")
        is_correct = selected == answer
        if is_correct:
            correct_count += 1
        details.append(
            {
                "id": question_id,
                "selected": selected,
                "correct": is_correct,
                "answer": answer,
                "explanation_en": question.get("explanation_en", ""),
                "explanation_ar": question.get("explanation_ar", ""),
            }
        )

    total = len(quiz)
    score = round((correct_count / total) * 100) if total else 0
    passed = score >= QUIZ_PASS_PERCENT
    progress = _ensure_progress(db, auth.user_id, lesson)
    now = utcnow()
    progress.quiz_score = max(int(progress.quiz_score or 0), score)
    progress.quiz_answers = body.answers
    progress.quiz_attempts = int(progress.quiz_attempts or 0) + 1
    if progress.started_at is None:
        progress.started_at = now
    if passed:
        progress.status = "completed"
        progress.progress_percent = 100
        progress.completed_at = progress.completed_at or now
    elif progress.status != "completed":
        progress.status = "in_progress"
        progress.progress_percent = max(int(progress.progress_percent or 0), 50)
    progress.updated_at = now
    db.commit()
    audit(
        db,
        auth,
        "academy.quiz",
        entity_type="lesson",
        entity_id=lesson.id,
        meta={
            "slug": lesson.slug,
            "score": score,
            "passed": passed,
            "attempt": progress.quiz_attempts,
        },
    )
    return {
        "score": score,
        "passed": passed,
        "correct": correct_count,
        "total": total,
        "pass_percent": QUIZ_PASS_PERCENT,
        "best_score": progress.quiz_score,
        "details": details,
        "user_state": _user_state(progress),
    }


@router.get("/me/stats")
def my_stats(
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = db.execute(
        select(Lesson.division, LessonProgress.status, func.count(LessonProgress.id))
        .join(Lesson, Lesson.id == LessonProgress.lesson_id)
        .where(LessonProgress.user_id == auth.user_id, Lesson.is_published.is_(True))
        .group_by(Lesson.division, LessonProgress.status)
    ).all()
    by_division: dict[str, dict[str, int]] = {
        key: {"completed": 0, "in_progress": 0, "not_started": 0} for key in DIVISION_KEYS
    }
    for division, status_value, count in rows:
        if division in by_division and status_value in by_division[division]:
            by_division[division][status_value] = int(count)

    total = int(
        db.execute(select(func.count(Lesson.id)).where(Lesson.is_published.is_(True))).scalar_one()
    )
    completed = int(
        db.execute(
            select(func.count(LessonProgress.id))
            .join(Lesson, Lesson.id == LessonProgress.lesson_id)
            .where(LessonProgress.user_id == auth.user_id, LessonProgress.status == "completed", Lesson.is_published.is_(True))
        ).scalar_one()
    )
    in_progress = int(
        db.execute(
            select(func.count(LessonProgress.id))
            .join(Lesson, Lesson.id == LessonProgress.lesson_id)
            .where(LessonProgress.user_id == auth.user_id, LessonProgress.status == "in_progress", Lesson.is_published.is_(True))
        ).scalar_one()
    )
    bookmarked = int(
        db.execute(
            select(func.count(LessonProgress.id))
            .join(Lesson, Lesson.id == LessonProgress.lesson_id)
            .where(LessonProgress.user_id == auth.user_id, LessonProgress.bookmarked.is_(True), Lesson.is_published.is_(True))
        ).scalar_one()
    )
    average_score = db.execute(
        select(func.avg(LessonProgress.quiz_score))
        .join(Lesson, Lesson.id == LessonProgress.lesson_id)
        .where(LessonProgress.user_id == auth.user_id, LessonProgress.quiz_score.is_not(None))
    ).scalar_one()
    minutes_completed = int(
        db.execute(
            select(func.coalesce(func.sum(Lesson.duration_minutes), 0))
            .join(LessonProgress, LessonProgress.lesson_id == Lesson.id)
            .where(LessonProgress.user_id == auth.user_id, LessonProgress.status == "completed")
        ).scalar_one()
        or 0
    )
    continue_row = db.execute(
        select(Lesson, LessonProgress)
        .join(LessonProgress, LessonProgress.lesson_id == Lesson.id)
        .where(
            LessonProgress.user_id == auth.user_id,
            LessonProgress.status == "in_progress",
            Lesson.is_published.is_(True),
        )
        .order_by(LessonProgress.updated_at.desc())
        .limit(1)
    ).first()

    return {
        "totals": {
            "lesson_count": total,
            "completed": completed,
            "in_progress": in_progress,
            "bookmarked": bookmarked,
            "progress_percent": round((completed / total) * 100, 1) if total else 0.0,
            "average_quiz_score": round(float(average_score), 1) if average_score is not None else None,
            "minutes_completed": minutes_completed,
        },
        "by_division": by_division,
        "continue_learning": _public_lesson(continue_row[0], continue_row[1]) if continue_row else None,
    }


# ---------------------------------------------------------------------------
# Overview, personalised learning path and training records
# ---------------------------------------------------------------------------
def _division_progress(db: Session, user_id: str) -> dict[str, dict[str, Any]]:
    """Per-division learner counters derived from the caller's own progress."""
    lessons = db.execute(select(Lesson).where(Lesson.is_published.is_(True))).scalars().all()
    progress_rows = db.execute(
        select(LessonProgress).where(LessonProgress.user_id == user_id)
    ).scalars().all()
    by_lesson = {row.lesson_id: row for row in progress_rows}

    buckets: dict[str, dict[str, Any]] = {}
    for lesson in lessons:
        bucket = buckets.setdefault(
            lesson.division,
            {
                "total": 0,
                "completed": 0,
                "in_progress": 0,
                "not_started": 0,
                "bookmarked": 0,
                "minutes_total": 0,
                "minutes_completed": 0,
                "_scores": [],
            },
        )
        bucket["total"] += 1
        bucket["minutes_total"] += int(lesson.duration_minutes or 0)
        row = by_lesson.get(lesson.id)
        if row is None:
            bucket["not_started"] += 1
            continue
        if row.status == "completed":
            bucket["completed"] += 1
            bucket["minutes_completed"] += int(lesson.duration_minutes or 0)
        elif row.status == "in_progress":
            bucket["in_progress"] += 1
        else:
            bucket["not_started"] += 1
        if row.bookmarked:
            bucket["bookmarked"] += 1
        if row.quiz_score is not None:
            bucket["_scores"].append(int(row.quiz_score))

    for bucket in buckets.values():
        scores = bucket.pop("_scores")
        bucket["average_quiz"] = int(round(sum(scores) / len(scores))) if scores else None
        bucket["percent"] = int(round((bucket["completed"] / bucket["total"]) * 100)) if bucket["total"] else 0
    return buckets


@router.get("/overview")
def overview(
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Division catalogue merged with the caller's own completion counters."""
    buckets = _division_progress(db, auth.user_id)
    divisions = public_divisions()
    for division in divisions:
        stats = buckets.get(division["key"], {})
        division["completed"] = stats.get("completed", 0)
        division["total"] = stats.get("total", division["lesson_count"])
        division["percent"] = stats.get("percent", 0)
        division["average_quiz"] = stats.get("average_quiz")
    return {
        "divisions": divisions,
        "summary": {
            "divisions": buckets,
            "total_lessons": sum(item["total"] for item in buckets.values()),
            "completed": sum(item["completed"] for item in buckets.values()),
            "bookmarked": sum(item["bookmarked"] for item in buckets.values()),
        },
        "generated_at": to_iso_z(utcnow()),
    }


@router.get("/learning-path")
def learning_path(
    division: str = Query(..., min_length=3, max_length=24),
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Recommend the next lessons from real progress and prerequisites."""
    _validate_division(division)
    lessons = db.execute(
        select(Lesson)
        .where(Lesson.division == division, Lesson.is_published.is_(True))
        .order_by(Lesson.order_index)
    ).scalars().all()
    if not lessons:
        return {"division": division, "recommendations": [], "gaps": [], "weakest": [], "percent": 0}

    progress_rows = db.execute(
        select(LessonProgress).where(LessonProgress.user_id == auth.user_id)
    ).scalars().all()
    by_lesson = {row.lesson_id: row for row in progress_rows}
    completed_slugs = {
        lesson.slug for lesson in lessons if by_lesson.get(lesson.id) and by_lesson[lesson.id].status == "completed"
    }

    recommendations: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for lesson in lessons:
        row = by_lesson.get(lesson.id)
        unmet = [slug for slug in (lesson.prerequisites or []) if slug not in completed_slugs]
        record = _public_lesson(lesson, row)
        record["unmet_prerequisites"] = unmet
        if row and row.status == "in_progress":
            record["reason"] = "Continue where you stopped."
        elif row and row.status == "completed":
            record["reason"] = "Reinforce a completed lesson."
        elif unmet:
            record["reason"] = "Finish the prerequisite lesson first."
        else:
            record["reason"] = "Next in this category."
        if row and row.status == "completed":
            continue
        (gaps if unmet else recommendations).append(record)

    weakest = sorted(
        (
            {
                "slug": lesson.slug,
                "title_en": lesson.title_en,
                "title_ar": lesson.title_ar,
                "score": int(by_lesson[lesson.id].quiz_score or 0),
            }
            for lesson in lessons
            if lesson.id in by_lesson and by_lesson[lesson.id].quiz_score is not None
        ),
        key=lambda item: item["score"],
    )[:5]

    return {
        "division": division,
        "recommendations": recommendations[:8],
        "gaps": gaps[:8],
        "weakest": weakest,
        "percent": int(round((len(completed_slugs) / len(lessons)) * 100)) if lessons else 0,
    }


def _certificate_payload(row: LessonCertificate) -> dict[str, Any]:
    return {
        "id": row.id,
        "division": row.division,
        "display_name": row.display_name,
        "lessons_completed": row.lessons_completed,
        "average_quiz": row.average_quiz,
        "serial": row.serial,
        "issued_at": to_iso_z(row.issued_at),
        "disclaimer": (
            "NEXUS platform training record. This is not an external professional certification."
        ),
    }


@router.get("/certificates")
def list_certificates(
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Training records issued to the authenticated user."""
    rows = db.execute(
        select(LessonCertificate).where(LessonCertificate.user_id == auth.user_id)
    ).scalars().all()
    return {"items": [_certificate_payload(row) for row in rows]}


@router.post("/certificates/{division}")
def issue_certificate(
    division: str,
    body: CertificateRequest,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Issue a training record once every lesson in the division is completed."""
    write_scope_guard(auth)
    _validate_division(division)
    lessons = db.execute(
        select(Lesson).where(Lesson.division == division, Lesson.is_published.is_(True))
    ).scalars().all()
    if not lessons:
        raise api_error("no_lessons", "This division has no published lessons.", status.HTTP_404_NOT_FOUND)

    progress_rows = db.execute(
        select(LessonProgress).where(LessonProgress.user_id == auth.user_id)
    ).scalars().all()
    by_lesson = {row.lesson_id: row for row in progress_rows}
    completed = [row for row in progress_rows if row.status == "completed"]
    completed_ids = {row.lesson_id for row in completed}
    if len(completed_ids & {lesson.id for lesson in lessons}) < len(lessons):
        raise api_error(
            "not_complete",
            "Complete every lesson in this division before a training record can be issued.",
            status.HTTP_409_CONFLICT,
        )

    scores = [int(by_lesson[lesson.id].quiz_score or 0) for lesson in lessons if lesson.id in by_lesson]
    average = float(round(sum(scores) / len(scores))) if scores else 0.0
    serial = f"NX-{division.upper()}-{sha256_hex(f'{auth.user_id}:{division}')[:8].upper()}"

    certificate = db.execute(
        select(LessonCertificate).where(
            LessonCertificate.user_id == auth.user_id,
            LessonCertificate.division == division,
        )
    ).scalar_one_or_none()
    if certificate is None:
        certificate = LessonCertificate(
            id=new_id(),
            user_id=auth.user_id,
            division=division,
            display_name=body.display_name or auth.user.full_name or auth.user.email,
            lessons_completed=len(lessons),
            average_quiz=average,
            serial=serial,
        )
        db.add(certificate)
    else:
        certificate.display_name = body.display_name or certificate.display_name
        certificate.lessons_completed = len(lessons)
        certificate.average_quiz = average
    db.commit()
    db.refresh(certificate)
    audit(db, auth, "academy.certificate", entity_type="division", entity_id=division)
    return _certificate_payload(certificate)