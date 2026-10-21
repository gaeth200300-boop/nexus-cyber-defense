"""Training / CTF lab models. Labs run against isolated, intentionally-weak local apps."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..core.utils import new_id, utcnow
from ..db import Base


class Lab(Base):
    __tablename__ = "labs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    title_ar: Mapped[str] = mapped_column(String(200))
    title_en: Mapped[str] = mapped_column(String(200), default="")
    category: Mapped[str] = mapped_column(String(20), index=True)  # LAB_CATEGORIES
    level: Mapped[str] = mapped_column(String(20), default="beginner", index=True)  # LAB_LEVELS
    points: Mapped[int] = mapped_column(Integer, default=100)

    description_ar: Mapped[str] = mapped_column(Text, default="")
    description_en: Mapped[str] = mapped_column(Text, default="")
    objectives: Mapped[list] = mapped_column(JSON, default=list)  # [{key,label_ar,label_en}]
    hints: Mapped[list] = mapped_column(JSON, default=list)  # ordered, unlocked progressively
    checks: Mapped[list] = mapped_column(JSON, default=list)  # [{key,type,spec,points}] auto-verification

    target_kind: Mapped[str] = mapped_column(String(30), default="none")  # none | internal_app | url | file | dataset
    target_ref: Mapped[str] = mapped_column(String(300), default="")
    resource_limits: Mapped[dict] = mapped_column(JSON, default=dict)  # {cpu, memory_mb, timeout_seconds}
    requires_private_access: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    order_index: Mapped[int] = mapped_column(Integer, default=100)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class LabRun(Base):
    __tablename__ = "lab_runs"
    __table_args__ = (Index("ix_lab_runs_user_lab", "user_id", "lab_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    lab_id: Mapped[str] = mapped_column(ForeignKey("labs.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    status: Mapped[str] = mapped_column(String(16), default="started", index=True)  # started | passed | failed | reset
    score: Mapped[int] = mapped_column(Integer, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    hints_used: Mapped[list] = mapped_column(JSON, default=list)
    checks_result: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    reset_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Achievement(Base):
    __tablename__ = "achievements"
    __table_args__ = (UniqueConstraint("user_id", "code", name="uq_achievements_user_code"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code: Mapped[str] = mapped_column(String(60), index=True)
    title_ar: Mapped[str] = mapped_column(String(160), default="")
    title_en: Mapped[str] = mapped_column(String(160), default="")
    points: Mapped[int] = mapped_column(Integer, default=0)
    earned_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
