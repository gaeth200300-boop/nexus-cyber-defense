"""Command-platform storage: detection rules, cases, evidence custody, posture.

Everything stored here is either written by a user (rules, cases, notes) or is a
derived snapshot whose inputs are recorded alongside it (posture).  Graph and
timeline relationships are *not* stored: they are computed from the real
records that produced them so the provenance of every edge stays verifiable.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..core.utils import new_id, utcnow
from ..db import Base


class SigmaRule(Base):
    """A Sigma detection rule owned by a project (or global when project_id is null)."""

    __tablename__ = "sigma_rules"
    __table_args__ = (
        UniqueConstraint("project_id", "name", name="uq_sigma_rule_project_name"),
        Index("ix_sigma_rules_project_status", "project_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(160), index=True)
    title: Mapped[str] = mapped_column(String(240), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="experimental", index=True)
    author: Mapped[str] = mapped_column(String(120), default="")
    license: Mapped[str] = mapped_column(String(60), default="")
    level: Mapped[str] = mapped_column(String(20), default="medium")
    logsource: Mapped[dict] = mapped_column(JSON, default=dict)
    detection: Mapped[dict] = mapped_column(JSON, default=dict)
    fields: Mapped[list] = mapped_column(JSON, default=list)
    falsepositives: Mapped[list] = mapped_column(JSON, default=list)
    references: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)  # MITRE ATT&CK technique ids
    lessons: Mapped[list] = mapped_column(JSON, default=list)  # related academy lesson slugs
    created_by: Mapped[str] = mapped_column(String(36), default="")
    validation: Mapped[dict] = mapped_column(JSON, default=dict)  # last validation report
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class CaseFile(Base):
    """An investigation case in the analyst workbench."""

    __tablename__ = "case_files"
    __table_args__ = (Index("ix_case_files_project_status", "project_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    reference: Mapped[str] = mapped_column(String(40), index=True)  # e.g. NX-2026-0007
    title: Mapped[str] = mapped_column(String(240))
    summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    classification: Mapped[str] = mapped_column(String(60), default="internal")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    assignee_id: Mapped[str] = mapped_column(String(36), default="")
    created_by: Mapped[str] = mapped_column(String(36), default="")
    opened_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class CaseHypothesis(Base):
    """A competing explanation for a case, with the evidence that supports it."""

    __tablename__ = "case_hypotheses"
    __table_args__ = (Index("ix_case_hypotheses_case", "case_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("case_files.id", ondelete="CASCADE"), index=True)
    statement: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)  # open | supported | refuted | superseded
    confidence: Mapped[str] = mapped_column(String(20), default="tentative")
    rationale: Mapped[str] = mapped_column(Text, default="")
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)  # [{kind, id, label}]
    created_by: Mapped[str] = mapped_column(String(36), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class CaseAnnotation(Base):
    """An analyst note attached to a case and optionally to a specific record."""

    __tablename__ = "case_annotations"
    __table_args__ = (Index("ix_case_annotations_case", "case_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("case_files.id", ondelete="CASCADE"), index=True)
    body: Mapped[str] = mapped_column(Text)
    entity_type: Mapped[str] = mapped_column(String(40), default="")  # finding | alert | asset | evidence | incident
    entity_id: Mapped[str] = mapped_column(String(36), default="")
    author_id: Mapped[str] = mapped_column(String(36), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CaseTask(Base):
    """A unit of investigative work tracked inside a case."""

    __tablename__ = "case_tasks"
    __table_args__ = (Index("ix_case_tasks_case_status", "case_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("case_files.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(240))
    detail: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="todo", index=True)
    assignee_id: Mapped[str] = mapped_column(String(36), default="")
    due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class CustodyEvent(Base):
    """An append-only chain-of-custody entry for a piece of evidence."""

    __tablename__ = "custody_events"
    __table_args__ = (Index("ix_custody_events_evidence", "evidence_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(30), default="received")
    actor_user_id: Mapped[str] = mapped_column(String(36), default="")
    actor_label: Mapped[str] = mapped_column(String(160), default="")
    location: Mapped[str] = mapped_column(String(160), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    sha256_at_action: Mapped[str] = mapped_column(String(64), default="")
    source_path: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class PostureSnapshot(Base):
    """A dated posture score with the exact factors used to compute it."""

    __tablename__ = "posture_snapshots"
    __table_args__ = (Index("ix_posture_snapshots_project_time", "project_id", "computed_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    grade: Mapped[str] = mapped_column(String(6), default="-")
    factors: Mapped[list] = mapped_column(JSON, default=list)  # [{key, label, weight, earned, max, detail}]
    missing_information: Mapped[list] = mapped_column(JSON, default=list)
    coverage: Mapped[dict] = mapped_column(JSON, default=dict)
    computed_by: Mapped[str] = mapped_column(String(36), default="")
    computed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class PurpleSimulation(Base):
    """A recorded purple-team exercise: emulated behaviour vs. expected telemetry."""

    __tablename__ = "purple_simulations"
    __table_args__ = (Index("ix_purple_simulations_project", "project_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scenario_key: Mapped[str] = mapped_column(String(80), index=True)
    scenario_title: Mapped[str] = mapped_column(String(240), default="")
    division: Mapped[str] = mapped_column(String(20), default="offense")
    status: Mapped[str] = mapped_column(String(30), default="completed", index=True)
    expected_telemetry: Mapped[list] = mapped_column(JSON, default=list)
    observed_telemetry: Mapped[list] = mapped_column(JSON, default=list)
    detections: Mapped[list] = mapped_column(JSON, default=list)
    missed: Mapped[list] = mapped_column(JSON, default=list)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    notes: Mapped[str] = mapped_column(Text, default="")
    actor_id: Mapped[str] = mapped_column(String(36), default="")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class LessonCertificate(Base):
    """A record of a learner's completion of a division track.

    This is a platform training record, not an external professional
    certification; the wording of every rendered certificate reflects that.
    """

    __tablename__ = "lesson_certificates"
    __table_args__ = (UniqueConstraint("user_id", "division", name="uq_lesson_certificate_user_division"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    division: Mapped[str] = mapped_column(String(20), index=True)
    display_name: Mapped[str] = mapped_column(String(160), default="")
    lessons_completed: Mapped[int] = mapped_column(Integer, default=0)
    average_quiz: Mapped[float] = mapped_column(Float, default=0.0)
    serial: Mapped[str] = mapped_column(String(40), default="")
    issued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class UserPreference(Base):
    """Persisted per-user interface preferences (theme, locale, dashboard)."""

    __tablename__ = "user_preferences"
    __table_args__ = (UniqueConstraint("user_id", name="uq_user_preferences_user"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    theme: Mapped[str] = mapped_column(String(20), default="dark")
    locale: Mapped[str] = mapped_column(String(10), default="ar")
    dashboard_days: Mapped[int] = mapped_column(Integer, default=14)
    sidebar_collapsed: Mapped[bool] = mapped_column(Boolean, default=False)
    saved_searches: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
