"""Asset inventory & attack-surface models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..core.utils import new_id, utcnow
from ..db import Base


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("project_id", "type", "normalized_value", name="uq_assets_project_type_value"),
        Index("ix_assets_project_state", "project_id", "state"),
        Index("ix_assets_project_risk", "project_id", "risk_severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scope_id: Mapped[str | None] = mapped_column(ForeignKey("scopes.id", ondelete="SET NULL"), nullable=True, index=True)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)

    type: Mapped[str] = mapped_column(String(20), index=True)  # ASSET_TYPES
    value: Mapped[str] = mapped_column(String(512))  # as discovered (display)
    normalized_value: Mapped[str] = mapped_column(String(512), index=True)  # lowercase, punycode, no trailing dot
    state: Mapped[str] = mapped_column(String(20), default="unknown", index=True)  # active | inactive | unknown

    source: Mapped[str] = mapped_column(String(40), default="manual")  # manual | discovery | import | lab
    discovered_by_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    tags: Mapped[list] = mapped_column(JSON, default=list)
    risk_severity: Mapped[str] = mapped_column(String(12), default="info", index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    is_monitored: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_services_asset_port_proto"),
        Index("ix_services_project_state", "project_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(12), default="unknown", index=True)  # SERVICE_STATES
    name: Mapped[str] = mapped_column(String(80), default="")  # http, ssh, smtp ...
    product: Mapped[str] = mapped_column(String(120), default="")
    version: Mapped[str] = mapped_column(String(120), default="")
    banner: Mapped[str] = mapped_column(Text, default="")  # truncated, redacted
    tls: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(40), default="scan")  # scan | nmap | discovery | manual
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class AssetChange(Base):
    """Detected drift on the attack surface — powering ASM alerts and comparison reports."""

    __tablename__ = "asset_changes"
    __table_args__ = (Index("ix_asset_changes_project_detected", "project_id", "detected_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)
    service_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    kind: Mapped[str] = mapped_column(String(30), index=True)  # ASSET_CHANGE_KINDS
    severity: Mapped[str] = mapped_column(String(12), default="info", index=True)
    summary: Mapped[str] = mapped_column(String(400), default="")
    before: Mapped[dict] = mapped_column(JSON, default=dict)
    after: Mapped[dict] = mapped_column(JSON, default=dict)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
