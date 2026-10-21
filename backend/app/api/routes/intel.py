"""Vulnerability intelligence: NVD 2.0 lookups, CISA KEV, and finding correlation."""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...config import settings
from ...core.events import build_phases
from ...core.netguard import summarize_policy
from ...core.queue import JOB_INTEL_CORRELATE, JobQueue
from ...core.utils import to_iso_z, utcnow
from ...db import get_db
from ...engines.intel_engine import fetch_cve, fetch_recent, kev_stats, search_nvd, sync_kev
from ...models import CveRecord, Finding, FindingIntelLink, KevEntry, Project, ProjectMember, Scan, SettingKV
from ..deps import AuthContext, ProjectAccess, api_error, audit, project_access, require_scope
from .common import paged

log = logging.getLogger("nexus.api.intel")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

# Global intel routes (/intel/...)
router = APIRouter(prefix="/intel", tags=["intel"])
# Project-scoped correlation routes (/projects/{project_id}/intel/...)
project_router = APIRouter(prefix="/projects/{project_id}/intel", tags=["intel"])


def cve_public(record: CveRecord, *, kev: KevEntry | None = None, linked_findings: int | None = None) -> dict[str, Any]:
    data = {
        "id": record.id,
        "description": record.description,
        "published_at": to_iso_z(record.published_at),
        "modified_at": to_iso_z(record.modified_at),
        "cvss_v3_score": record.cvss_v3_score,
        "cvss_v3_vector": record.cvss_v3_vector,
        "cvss_v2_score": record.cvss_v2_score,
        "cvss_severity": record.cvss_severity,
        "cwes": record.cwes or [],
        "references": record.references or [],
        "affected": record.affected or [],
        "source": record.source,
        "source_url": record.source_url or f"https://nvd.nist.gov/vuln/detail/{record.id}",
        "fetched_at": to_iso_z(record.fetched_at),
        "kev": bool(kev),
    }
    if kev:
        data["kev_detail"] = {
            "vendor_project": kev.vendor_project,
            "product": kev.product,
            "vulnerability_name": kev.vulnerability_name,
            "date_added": to_iso_z(kev.date_added),
            "due_date": to_iso_z(kev.due_date),
            "known_ransomware": kev.known_ransomware,
            "required_action": kev.required_action,
        }
    if linked_findings is not None:
        data["linked_findings"] = linked_findings
    return data


def kev_public(entry: KevEntry) -> dict[str, Any]:
    return {
        "cve_id": entry.cve_id,
        "vendor_project": entry.vendor_project,
        "product": entry.product,
        "vulnerability_name": entry.vulnerability_name,
        "date_added": to_iso_z(entry.date_added),
        "due_date": to_iso_z(entry.due_date),
        "short_description": entry.short_description,
        "required_action": entry.required_action,
        "known_ransomware": entry.known_ransomware,
        "notes": entry.notes,
        "source_url": entry.source_url,
        "fetched_at": to_iso_z(entry.fetched_at),
    }


def _accessible_project_ids(db: Session, auth: AuthContext) -> list[str]:
    if auth.user.role in ("owner", "admin"):
        return list(db.execute(select(Project.id).where(Project.archived_at.is_(None))).scalars().all())
    return list(
        db.execute(select(ProjectMember.project_id).where(ProjectMember.user_id == auth.user_id)).scalars().all()
    )


def _clean_cve_id(raw: str) -> str:
    cve_id = (raw or "").strip().upper()
    if not CVE_RE.match(cve_id):
        raise api_error("invalid_cve_id", "CVE ids look like CVE-2024-12345.")
    return cve_id


# ---------------------------------------------------------------------------
# Global NVD / KEV endpoints
# ---------------------------------------------------------------------------
@router.get("/cve/{cve_id}")
async def get_cve(
    cve_id: str,
    refresh: bool = Query(default=False),
    auth: AuthContext = Depends(require_scope("read:intel")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    cve = _clean_cve_id(cve_id)
    record, error = await fetch_cve(db, cve, force=refresh)
    if record is None:
        if error == "invalid_cve_id":
            raise api_error("invalid_cve_id", "CVE ids look like CVE-2024-12345.")
        if error == "not_found_in_nvd":
            raise api_error("cve_not_found", f"{cve} was not returned by NVD.", status.HTTP_404_NOT_FOUND)
        raise api_error(
            "intel_unavailable",
            f"NVD could not be reached ({error}) and no cached copy exists for {cve}.",
            status.HTTP_502_BAD_GATEWAY,
        )
    kev = db.get(KevEntry, cve)
    project_ids = _accessible_project_ids(db, auth)
    linked = int(
        db.execute(
            select(func.count(func.distinct(FindingIntelLink.finding_id)))
            .select_from(FindingIntelLink)
            .join(Finding, Finding.id == FindingIntelLink.finding_id)
            .where(FindingIntelLink.cve_id == cve, Finding.project_id.in_(project_ids or [""]))
        ).scalar_one()
    )
    return {
        "cve": cve_public(record, kev=kev, linked_findings=linked),
        "cache": {"fresh": (utcnow() - record.fetched_at).total_seconds() < settings.intel_cache_hours * 3600, "hours": settings.intel_cache_hours},
        "error": error or None,
    }


@router.get("/search")
async def search_cves(
    q: str = Query(min_length=2, max_length=120),
    limit: int = Query(default=20, ge=1, le=50),
    auth: AuthContext = Depends(require_scope("read:intel")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    records, error = await search_nvd(db, q, limit=limit)
    if error and not records:
        raise api_error("intel_unavailable", f"NVD search failed: {error}.", status.HTTP_502_BAD_GATEWAY)
    ids = [r.id for r in records]
    kev_map = {
        e.cve_id: e
        for e in db.execute(select(KevEntry).where(KevEntry.cve_id.in_(ids or [""]))).scalars().all()
    }
    return {
        "items": [cve_public(r, kev=kev_map.get(r.id)) for r in records],
        "query": q,
        "error": error or None,
    }


@router.get("/recent")
async def recent_cves(
    days: int = Query(default=7, ge=1, le=30),
    limit: int = Query(default=20, ge=1, le=100),
    auth: AuthContext = Depends(require_scope("read:intel")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    records, error = await fetch_recent(db, days=days, limit=limit)
    if error and not records:
        raise api_error("intel_unavailable", f"NVD recent feed failed: {error}.", status.HTTP_502_BAD_GATEWAY)
    ids = [r.id for r in records]
    kev_map = {
        e.cve_id: e
        for e in db.execute(select(KevEntry).where(KevEntry.cve_id.in_(ids or [""]))).scalars().all()
    }
    return {
        "items": [cve_public(r, kev=kev_map.get(r.id)) for r in records],
        "days": days,
        "error": error or None,
    }


@router.get("/kev")
def list_kev(
    q: str = Query(default="", max_length=200),
    ransomware_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_scope("read:intel")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(KevEntry)
    count_query = select(func.count(KevEntry.cve_id))
    if q:
        pattern = f"%{q.strip().lower()}%"
        condition = (
            func.lower(KevEntry.cve_id).like(pattern)
            | func.lower(KevEntry.vendor_project).like(pattern)
            | func.lower(KevEntry.product).like(pattern)
            | func.lower(KevEntry.vulnerability_name).like(pattern)
        )
        query = query.where(condition)
        count_query = count_query.where(condition)
    if ransomware_only:
        query = query.where(KevEntry.known_ransomware.is_(True))
        count_query = count_query.where(KevEntry.known_ransomware.is_(True))
    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(query.order_by(KevEntry.date_added.desc().nullslast()).limit(limit).offset(offset)).scalars().all()
    return {**paged([kev_public(e) for e in rows], total, limit=limit, offset=offset), "stats": kev_stats(db)}


class KevSyncBody(BaseModel):
    force: bool = False


@router.post("/kev/sync")
async def sync_kev_endpoint(
    body: KevSyncBody | None = None,
    auth: AuthContext = Depends(require_scope("write:intel")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    force = bool(body.force) if body else False
    summary = await sync_kev(db, force=force)
    audit(db, auth, "intel.kev_sync", meta={"force": force, "result": summary})
    return {"result": summary, "stats": kev_stats(db)}


@router.get("/stats")
def intel_stats(
    auth: AuthContext = Depends(require_scope("read:intel")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    state = db.get(SettingKV, "kev_sync")
    cve_total = int(db.execute(select(func.count(CveRecord.id))).scalar_one())
    link_total = int(db.execute(select(func.count(FindingIntelLink.id))).scalar_one())
    return {
        "cve_records_cached": cve_total,
        "finding_links": link_total,
        "kev": kev_stats(db),
        "kev_sync": (state.value or {}) if state else {},
        "cache_hours": settings.intel_cache_hours,
        "nvd_key_configured": bool(settings.nvd_api_key),
        "source": "NVD 2.0 + CISA KEV",
        "fetched_at": to_iso_z(utcnow()),
    }


# ---------------------------------------------------------------------------
# Project-scoped links + correlation runs
# ---------------------------------------------------------------------------
@project_router.get("/links")
def list_links(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    cve_id: str | None = Query(default=None),
    finding_id: str | None = Query(default=None),
    match_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    query = (
        select(FindingIntelLink, Finding, CveRecord)
        .join(Finding, Finding.id == FindingIntelLink.finding_id)
        .join(CveRecord, CveRecord.id == FindingIntelLink.cve_id, isouter=True)
        .where(Finding.project_id == access.project.id)
    )
    count_query = (
        select(func.count(FindingIntelLink.id))
        .select_from(FindingIntelLink)
        .join(Finding, Finding.id == FindingIntelLink.finding_id)
        .where(Finding.project_id == access.project.id)
    )
    if cve_id:
        query = query.where(FindingIntelLink.cve_id == cve_id.upper())
        count_query = count_query.where(FindingIntelLink.cve_id == cve_id.upper())
    if finding_id:
        query = query.where(FindingIntelLink.finding_id == finding_id)
        count_query = count_query.where(FindingIntelLink.finding_id == finding_id)
    if match_type:
        query = query.where(FindingIntelLink.match_type == match_type)
        count_query = count_query.where(FindingIntelLink.match_type == match_type)
    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(query.order_by(FindingIntelLink.created_at.desc()).limit(limit).offset(offset)).all()
    cves = [link.cve_id for link, _finding, _record in rows]
    kev_ids = {k for (k,) in db.execute(select(KevEntry.cve_id).where(KevEntry.cve_id.in_(cves or [""]))).all()}
    items = [
        {
            "id": link.id,
            "cve_id": link.cve_id,
            "match_type": link.match_type,
            "confidence": link.confidence,
            "rationale": link.rationale,
            "created_at": to_iso_z(link.created_at),
            "kev": link.cve_id in kev_ids,
            "finding": {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "target": finding.target,
            },
            "cve": cve_public(record) if record else None,
        }
        for link, finding, record in rows
    ]
    return paged(items, total, limit=limit, offset=offset)


class CorrelateBody(BaseModel):
    max_cves: int = Field(default=40, ge=1, le=100)
    include_kev: bool = True


@project_router.post("/correlate", status_code=status.HTTP_201_CREATED)
def correlate_findings(
    body: CorrelateBody,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    active = db.execute(
        select(Scan).where(
            Scan.project_id == access.project.id,
            Scan.kind == "intel_correlation",
            Scan.status.in_(("queued", "running")),
        )
    ).scalars().first()
    if active:
        raise api_error("correlation_running", "An intel correlation run is already active.", status.HTTP_409_CONFLICT, scan_id=active.id)

    scan = Scan(
        project_id=access.project.id,
        name=f"Intel correlation — {utcnow().strftime('%Y-%m-%d %H:%M')}",
        kind="intel_correlation",
        profile="passive",
        status="queued",
        progress=0,
        phases=build_phases("intel_correlation"),
        targets=[],
        options={"max_cves": body.max_cves, "include_kev": body.include_kev},
        authorization_snapshot={
            "created_at": to_iso_z(utcnow()),
            "created_by": access.user_id,
            "profile": "passive",
            "require_active": False,
            "scopes": [],
            "note": "Read-only correlation of existing findings against public NVD/KEV data.",
            "policy": summarize_policy(),
        },
        requested_by=access.user_id,
    )
    db.add(scan)
    db.flush()
    job = JobQueue.enqueue(
        db,
        type=JOB_INTEL_CORRELATE,
        project_id=access.project.id,
        scan_id=scan.id,
        priority=80,
        timeout_seconds=600,
        max_attempts=2,
        dedup_key=f"scan:{scan.id}",
    )
    db.commit()
    audit(db, access.auth, "intel.correlate", project_id=access.project.id, entity_type="scan", entity_id=scan.id, meta={"job_id": job.id if job else None})
    return {
        "scan_id": scan.id,
        "job_id": job.id if job else None,
        "status": scan.status,
        "note": "Correlation runs in the worker; watch the scan stream for progress.",
    }
