"""Scan orchestration models: scans, jobs (durable queue), events, findings, evidence."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..core.utils import new_id, utcnow
from ..db import Base


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_project_status", "project_id", "status"),
        Index("ix_scans_project_created", "project_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    kind: Mapped[str] = mapped_column(String(30), index=True)  # SCAN_KINDS
    profile: Mapped[str] = mapped_column(String(20), default="passive")  # SCAN_PROFILES
    engine: Mapped[str] = mapped_column(String(40), default="nexus-core")
    engine_version: Mapped[str] = mapped_column(String(40), default="")
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)  # SCAN_STATUSES
    progress: Mapped[int] = mapped_column(Integer, default=0)

    phases: Mapped[list] = mapped_column(JSON, default=list)  # [{key,label_en,label_ar,status,progress}]
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    targets: Mapped[list] = mapped_column(JSON, default=list)  # [{asset_id,type,value,host,port,scheme}]
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    # Exact RoE state captured at creation time — proves what was authorized when it ran.
    authorization_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)

    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    dedup_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    jobs: Mapped[list["Job"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")


class Job(Base):
    """Durable, DB-backed job queue entry (no Redis / no broker required).

    Concurrency safety is achieved with an optimistic compare-and-set UPDATE
    (`UPDATE jobs SET status='running' WHERE id=? AND status='queued'`), which is
    correct on both SQLite and PostgreSQL without relying on row locks.
    """

    __tablename__ = "jobs"
    __table_args__ = (
        Index("ix_jobs_status_run_after", "status", "run_after"),
        Index(
            "uq_jobs_active_dedup",
            "dedup_key",
            unique=True,
            sqlite_where=text("dedup_key IS NOT NULL AND status IN ('queued','running')"),
            postgresql_where=text("dedup_key IS NOT NULL AND status IN ('queued','running')"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    type: Mapped[str] = mapped_column(String(40), index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)  # lower = sooner
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(12), default="queued", index=True)  # JOB_STATUSES

    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    locked_by: Mapped[str] = mapped_column(String(80), default="")
    locked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    run_after: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=900)

    progress: Mapped[int] = mapped_column(Integer, default=0)
    phase: Mapped[str] = mapped_column(String(60), default="")
    dedup_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    scan: Mapped[Scan | None] = relationship(back_populates="jobs")


class ScanEvent(Base):
    """Live stream of scan progress — consumed by the UI through SSE."""

    __tablename__ = "scan_events"
    __table_args__ = (Index("ix_scan_events_scan_id_id", "scan_id", "id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    level: Mapped[str] = mapped_column(String(10), default="info")  # debug|info|warn|error
    kind: Mapped[str] = mapped_column(String(20), default="log")  # phase|log|metric|finding|progress
    phase: Mapped[str] = mapped_column(String(60), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", name="uq_findings_project_fingerprint"),
        Index("ix_findings_project_severity", "project_id", "severity"),
        Index("ix_findings_project_status", "project_id", "status"),
        Index("ix_findings_scan", "scan_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    service_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    fingerprint: Mapped[str] = mapped_column(String(64))  # dedup: category+target+parameter+engine-check
    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(30), index=True)  # FINDING_CATEGORIES
    severity: Mapped[str] = mapped_column(String(12), index=True)  # SEVERITIES
    confidence: Mapped[str] = mapped_column(String(12), default="firm")  # CONFIDENCES
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # FINDING_STATUSES

    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    active_check: Mapped[bool] = mapped_column(Boolean, default=False)  # was this an authorized active probe?

    cwe: Mapped[str] = mapped_column(String(40), default="")
    cve: Mapped[str] = mapped_column(String(30), default="")
    owasp: Mapped[str] = mapped_column(String(80), default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(120), default="")

    target: Mapped[str] = mapped_column(String(512), default="")
    location: Mapped[str] = mapped_column(String(512), default="")  # header name / parameter / file path
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)

    detected_by: Mapped[str] = mapped_column(String(60), default="")  # engine name
    engine_version: Mapped[str] = mapped_column(String(40), default="")
    primary_evidence_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    duplicate_of: Mapped[str | None] = mapped_column(String(36), nullable=True)
    triage_note: Mapped[str] = mapped_column(Text, default="")
    assigned_to: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    scan: Mapped[Scan | None] = relationship(back_populates="findings")


class FindingEvent(Base):
    """Lifecycle trail: who changed a finding status, when, and why."""

    __tablename__ = "finding_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_label: Mapped[str] = mapped_column(String(200), default="system")
    kind: Mapped[str] = mapped_column(String(20), default="status_change")  # status_change|note|verify|rescan
    from_status: Mapped[str] = mapped_column(String(20), default="")
    to_status: Mapped[str] = mapped_column(String(20), default="")
    note: Mapped[str] = mapped_column(Text, default="")


class Evidence(Base):
    """Redacted technical proof attached to a finding or a scan."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True)
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    kind: Mapped[str] = mapped_column(String(24), default="raw")  # EVIDENCE_KINDS
    label: Mapped[str] = mapped_column(String(200), default="")
    request_snippet: Mapped[str] = mapped_column(Text, default="")
    response_snippet: Mapped[str] = mapped_column(Text, default="")
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    body_excerpt: Mapped[str] = mapped_column(Text, default="")
    raw_sha256: Mapped[str] = mapped_column(String(64), default="")
    redacted: Mapped[bool] = mapped_column(Boolean, default=True)
    redactions: Mapped[list] = mapped_column(JSON, default=list)  # [{field, reason}]
    source: Mapped[str] = mapped_column(String(60), default="")  # which engine produced it
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
