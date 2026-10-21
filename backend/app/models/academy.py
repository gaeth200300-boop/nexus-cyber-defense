"""Academy curriculum and per-user learning progress.

The curriculum itself is platform-owned content.  Progress, notes, bookmarks
and quiz results are private to the authenticated user and are always queried
with the user id in the predicate.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..core.utils import new_id, utcnow
from ..db import Base


class Lesson(Base):
    __tablename__ = "academy_lessons"
    __table_args__ = (
        Index("ix_academy_lessons_division_order", "division", "order_index"),
        Index("ix_academy_lessons_division_category", "division", "category"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    division: Mapped[str] = mapped_column(String(20), index=True)  # defense | offense | forensics
    category: Mapped[str] = mapped_column(String(60), index=True)
    difficulty: Mapped[str] = mapped_column(String(20), default="beginner", index=True)  # beginner | intermediate | advanced
    order_index: Mapped[int] = mapped_column(Integer, default=0)

    title_ar: Mapped[str] = mapped_column(String(240))
    title_en: Mapped[str] = mapped_column(String(240), default="")
    summary_ar: Mapped[str] = mapped_column(Text, default="")
    summary_en: Mapped[str] = mapped_column(Text, default="")
    description_ar: Mapped[str] = mapped_column(Text, default="")
    description_en: Mapped[str] = mapped_column(Text, default="")

    objectives: Mapped[list] = mapped_column(JSON, default=list)  # [{en, ar}]
    prerequisites: Mapped[list] = mapped_column(JSON, default=list)  # lesson slugs
    related: Mapped[list] = mapped_column(JSON, default=list)  # lesson slugs

    # Videos are only populated after independent verification.  An empty URL
    # with status=pending_verification is intentionally displayed as unavailable.
    video_url: Mapped[str] = mapped_column(String(500), default="")
    video_status: Mapped[str] = mapped_column(String(30), default="pending_verification")
    resource_url: Mapped[str] = mapped_column(String(500), default="")
    resource_label_ar: Mapped[str] = mapped_column(String(200), default="")
    resource_label_en: Mapped[str] = mapped_column(String(200), default="")

    duration_minutes: Mapped[int] = mapped_column(Integer, default=30)
    exercise_ar: Mapped[str] = mapped_column(Text, default="")
    exercise_en: Mapped[str] = mapped_column(Text, default="")
    quiz: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)

    is_published: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class LessonProgress(Base):
    __tablename__ = "academy_lesson_progress"
    __table_args__ = (
        UniqueConstraint("user_id", "lesson_id", name="uq_lesson_progress_user_lesson"),
        Index("ix_academy_progress_user_status", "user_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    lesson_id: Mapped[str] = mapped_column(ForeignKey("academy_lessons.id", ondelete="CASCADE"), index=True)

    status: Mapped[str] = mapped_column(String(20), default="not_started", index=True)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0)
    quiz_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    quiz_answers: Mapped[dict] = mapped_column(JSON, default=dict)
    quiz_attempts: Mapped[int] = mapped_column(Integer, default=0)
    bookmarked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    notes: Mapped[str] = mapped_column(Text, default="")

    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)