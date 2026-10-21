"""Report generation endpoints (HTML / PDF / JSON) — rendered by a real worker job."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...config import settings
from ...core.constants import REPORT_KINDS
from ...core.queue import JOB_REPORT_GENERATE, JobQueue
from ...core.utils import to_iso_z
from ...db import get_db
from ...models import Report, Scan
from ...reports.generator import default_report_title
from ..deps import ProjectAccess, api_error, audit, project_access, write_scope_guard
from .common import parse_dt, paged, safe_child_path

log = logging.getLogger("nexus.api.reports")

router = APIRouter(prefix="/projects/{project_id}", tags=["reports"])

FORMATS = ("html", "pdf", "json")


def report_public(report: Report) -> dict[str, Any]:
    return {
        "id": report.id,
        "kind": report.kind,
        "format": report.format,
        "title": report.title,
        "version": report.version,
        "status": report.status,
        "period_from": to_iso_z(report.period_from),
        "period_to": to_iso_z(report.period_to),
        "scan_ids": report.scan_ids or [],
        "options": report.options or {},
        "summary": report.summary or {},
        "size_bytes": report.size_bytes,
        "sha256": report.sha256,
        "error": report.error,
        "created_at": to_iso_z(report.created_at),
        "completed_at": to_iso_z(report.completed_at),
        "download_url": f"/projects/{report.project_id}/reports/{report.id}/download" if report.status == "ready" else "",
    }


class ReportCreate(BaseModel):
    kind: str = Field(default="technical")
    format: str = Field(default="html")
    title: str = Field(default="", max_length=250)
    period_from: str | None = None
    period_to: str | None = None
    scan_ids: list[str] = Field(default_factory=list, max_length=50)
    options: dict[str, Any] = Field(default_factory=dict)


@router.post("/reports", status_code=status.HTTP_201_CREATED)
def create_report(
    body: ReportCreate,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    if body.kind not in REPORT_KINDS:
        raise api_error("invalid_kind", f"Report kind must be one of {list(REPORT_KINDS)}.")
    if body.format not in FORMATS:
        raise api_error("invalid_format", f"Format must be one of {list(FORMATS)}.")
    lang = str(body.options.get("lang") or "ar").lower()
    if lang not in ("ar", "en"):
        raise api_error("invalid_lang", "Language must be 'ar' or 'en'.")

    scan_ids: list[str] = []
    for scan_id in body.scan_ids:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.project_id != access.project.id:
            raise api_error("scan_not_found", f"Scan '{scan_id}' does not belong to this project.")
        scan_ids.append(scan.id)

    if body.kind == "comparison" and len(scan_ids) != 2:
        raise api_error("invalid_scans", "A comparison report needs exactly two scan ids (before and after).", status.HTTP_422_UNPROCESSABLE_ENTITY)

    previous = int(
        db.execute(select(func.max(Report.version)).where(Report.project_id == access.project.id, Report.kind == body.kind)).scalar_one()
        or 0
    )
    title = body.title.strip() or default_report_title(body.kind, access.project.name, lang)
    report = Report(
        project_id=access.project.id,
        kind=body.kind,
        format=body.format,
        title=title[:250],
        version=previous + 1,
        period_from=parse_dt(body.period_from, field="period start"),
        period_to=parse_dt(body.period_to, field="period end"),
        scan_ids=scan_ids,
        options={"lang": lang, **body.options},
        status="generating",
        created_by=access.user_id,
    )
    db.add(report)
    db.flush()
    job = JobQueue.enqueue(
        db,
        type=JOB_REPORT_GENERATE,
        project_id=access.project.id,
        payload={"report_id": report.id},
        priority=50,
        timeout_seconds=600,
        max_attempts=2,
        dedup_key=f"report:{report.id}",
    )
    db.commit()
    audit(db, access.auth, "report.create", project_id=access.project.id, entity_type="report", entity_id=report.id, meta={"kind": report.kind, "format": report.format, "job_id": job.id if job else None})
    return {"report": report_public(report), "job_id": job.id if job else None}


@router.get("/reports")
def list_reports(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    status_filter: str | None = Query(default=None, alias="status"),
    kind: str | None = Query(default=None),
    limit: int = Query(default=30, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    query = select(Report).where(Report.project_id == access.project.id)
    count_query = select(func.count(Report.id)).where(Report.project_id == access.project.id)
    if status_filter:
        query = query.where(Report.status == status_filter)
        count_query = count_query.where(Report.status == status_filter)
    if kind:
        query = query.where(Report.kind == kind)
        count_query = count_query.where(Report.kind == kind)
    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(query.order_by(Report.created_at.desc()).limit(limit).offset(offset)).scalars().all()
    return paged([report_public(r) for r in rows], total, limit=limit, offset=offset)


@router.get("/reports/{report_id}")
def get_report(
    report_id: str,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    report = db.get(Report, report_id)
    if report is None or report.project_id != access.project.id:
        raise api_error("report_not_found", "Report not found.", status.HTTP_404_NOT_FOUND)
    file_exists = False
    if report.status == "ready" and report.file_path:
        try:
            file_exists = safe_child_path(settings.reports_dir, report.file_path, must_exist=True).is_file()
        except Exception:
            file_exists = False
    return {"report": report_public(report), "file_exists": file_exists}


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> FileResponse:
    report = db.get(Report, report_id)
    if report is None or report.project_id != access.project.id:
        raise api_error("report_not_found", "Report not found.", status.HTTP_404_NOT_FOUND)
    if report.status != "ready" or not report.file_path:
        raise api_error("report_not_ready", f"The report is '{report.status}', not ready for download.", status.HTTP_409_CONFLICT)
    path = safe_child_path(settings.reports_dir, report.file_path, must_exist=True)
    if not path.is_file():
        raise api_error("report_file_missing", "The report file is missing from storage — regenerate it.", status.HTTP_410_GONE)

    media = {"pdf": "application/pdf", "html": "text/html; charset=utf-8", "json": "application/json"}.get(report.format, "application/octet-stream")
    suffix = "".join(ch for ch in report.title if ch.isascii() and (ch.isalnum() or ch in " -_"))[:60].strip() or report.id
    audit(db, access.auth, "report.download", project_id=access.project.id, entity_type="report", entity_id=report.id)
    return FileResponse(path, media_type=media, filename=f"{suffix}.{report.format}")


@router.post("/reports/{report_id}/regenerate", status_code=status.HTTP_201_CREATED)
def regenerate_report(
    report_id: str,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    report = db.get(Report, report_id)
    if report is None or report.project_id != access.project.id:
        raise api_error("report_not_found", "Report not found.", status.HTTP_404_NOT_FOUND)
    active = db.execute(
        select(func.count(Report.id)).where(Report.id == report.id, Report.status == "generating")
    ).scalar_one()
    if active:
        raise api_error("report_generating", "The report is already being generated.", status.HTTP_409_CONFLICT)
    report.status = "generating"
    report.error = ""
    db.flush()
    job = JobQueue.enqueue(
        db,
        type=JOB_REPORT_GENERATE,
        project_id=access.project.id,
        payload={"report_id": report.id},
        priority=50,
        timeout_seconds=600,
        max_attempts=2,
        dedup_key=f"report:{report.id}",
    )
    db.commit()
    audit(db, access.auth, "report.regenerate", project_id=access.project.id, entity_type="report", entity_id=report.id)
    return {"report": report_public(report), "job_id": job.id if job else None}


@router.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    report_id: str,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> None:
    report = db.get(Report, report_id)
    if report is None or report.project_id != access.project.id:
        raise api_error("report_not_found", "Report not found.", status.HTTP_404_NOT_FOUND)
    if report.file_path:
        try:
            safe_child_path(settings.reports_dir, report.file_path).unlink(missing_ok=True)
        except Exception:
            log.warning("could not remove report file for %s", report.id)
    db.delete(report)
    db.commit()
    audit(db, access.auth, "report.delete", project_id=access.project.id, entity_type="report", entity_id=report_id)
    return None
