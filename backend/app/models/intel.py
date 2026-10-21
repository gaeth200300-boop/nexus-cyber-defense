"""Vulnerability intelligence models (NVD / CISA KEV) and finding↔CVE correlation."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..core.utils import new_id, utcnow
from ..db import Base


class CveRecord(Base):
    __tablename__ = "cve_records"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)  # CVE-2021-44228
    description: Mapped[str] = mapped_column(Text, default="")
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    cvss_v3_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[str] = mapped_column(String(150), default="")
    cvss_v2_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_severity: Mapped[str] = mapped_column(String(12), default="unknown", index=True)

    cwes: Mapped[list] = mapped_column(JSON, default=list)
    references: Mapped[list] = mapped_column(JSON, default=list)
    affected: Mapped[list] = mapped_column(JSON, default=list)  # [{vendor, product, versions}]
    source: Mapped[str] = mapped_column(String(30), default="nvd")
    source_url: Mapped[str] = mapped_column(String(400), default="")
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class KevEntry(Base):
    """CISA Known Exploited Vulnerabilities — the only place we state 'exploited in the wild'."""

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(24), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(String(200), default="")
    product: Mapped[str] = mapped_column(String(200), default="")
    vulnerability_name: Mapped[str] = mapped_column(String(400), default="")
    date_added: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    short_description: Mapped[str] = mapped_column(Text, default="")
    required_action: Mapped[str] = mapped_column(Text, default="")
    due_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    known_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    source_url: Mapped[str] = mapped_column(String(400), default="")
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class FindingIntelLink(Base):
    """Link between a finding and a CVE.

    match_type='exact'      -> the scanner reported the CVE id itself (confirmed evidence)
    match_type='inferred'   -> derived from product/version heuristics (NEVER presented as confirmed)
    """

    __tablename__ = "finding_intel_links"
    __table_args__ = (
        UniqueConstraint("finding_id", "cve_id", "match_type", name="uq_finding_intel_finding_cve_type"),
        Index("ix_finding_intel_cve", "cve_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(String(24), index=True)
    match_type: Mapped[str] = mapped_column(String(12), default="inferred")
    confidence: Mapped[str] = mapped_column(String(12), default="tentative")
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
