"""Scan orchestration: create (with RoE validation), monitor (SSE), cancel, retry.

Creating a scan captures an immutable `authorization_snapshot` of the exact scope
entries that authorized every target at creation time. Engines re-check scope at
run time, so revocation between create and run still blocks the scan.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...config import settings
from ...core.constants import SCAN_KINDS, SCAN_PROFILES
from ...core.events import build_phases, event_to_dict, events_since
from ...core.netguard import authorize_target, summarize_policy
from ...core.queue import SCAN_KIND_TO_JOB, JobQueue
from ...core.utils import normalize_host, parse_target_url, to_iso_z, utcnow
from ...db import SessionLocal, get_db
from ...models import Finding, Job, Scan, Scope
from ...services.uploads import UploadRejected, store_upload
from ..deps import ProjectAccess, api_error, audit, project_access, write_scope_guard
from .common import ACTIVE_SCAN_STATUSES, TERMINAL_SCAN_STATUSES, paged, safe_child_path

log = logging.getLogger("nexus.api.scans")

router = APIRouter(prefix="/projects/{project_id}", tags=["scans"])

ACTIVE_PROFILES = ("safe_active", "zap_active")
ZAP_PROFILES = ("zap_passive", "zap_active")
FILE_KINDS = ("pcap_analysis", "log_analysis")
MAX_TARGETS = 50


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------
def _public_options(options: dict[str, Any] | None) -> dict[str, Any]:
    """Never leak absolute server paths; keep enough for the UI to be honest."""
    out: dict[str, Any] = {}
    for key, value in (options or {}).items():
        if key.endswith("_path") or key in ("upload_path", "source_path"):
            out["has_upload"] = True
            continue
        out[key] = value
    return out


def scan_public(scan: Scan, *, findings: dict[str, int] | None = None) -> dict[str, Any]:
    data = {
        "id": scan.id,
        "project_id": scan.project_id,
        "name": scan.name,
        "kind": scan.kind,
        "profile": scan.profile,
        "engine": scan.engine,
        "engine_version": scan.engine_version,
        "status": scan.status,
        "progress": scan.progress,
        "phases": scan.phases or [],
        "stats": scan.stats or {},
        "targets": scan.targets or [],
        "options": _public_options(scan.options),
        "target_count": len(scan.targets or []),
        "authorization_snapshot": scan.authorization_snapshot or {},
        "requested_by": scan.requested_by,
        "started_at": to_iso_z(scan.started_at),
        "finished_at": to_iso_z(scan.finished_at),
        "heartbeat_at": to_iso_z(scan.heartbeat_at),
        "cancel_requested": scan.cancel_requested,
        "error": scan.error,
        "created_at": to_iso_z(scan.created_at),
    }
    if findings is not None:
        data["findings"] = findings
    return data


def job_public(job: Job) -> dict[str, Any]:
    return {
        "id": job.id,
        "type": job.type,
        "status": job.status,
        "priority": job.priority,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "progress": job.progress,
        "phase": job.phase,
        "last_error": job.last_error,
        "result": job.result or {},
        "created_at": to_iso_z(job.created_at),
        "started_at": to_iso_z(job.started_at),
        "finished_at": to_iso_z(job.finished_at),
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class ScanCreate(BaseModel):
    kind: str
    name: str = Field(default="", max_length=200)
    profile: str = Field(default="passive")
    targets: list[dict[str, Any] | str] = Field(default_factory=list, max_length=MAX_TARGETS)
    options: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=100, ge=1, le=1000)
    idempotency_key: str = Field(default="", max_length=64)


# ---------------------------------------------------------------------------
# Target normalization + authorization
# ---------------------------------------------------------------------------
def _normalize_target(raw: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(raw, str):
        data: dict[str, Any] = {"value": raw}
    elif isinstance(raw, dict):
        data = dict(raw)
    else:
        raise api_error("invalid_target", "Each target must be a string or an object.")

    url = str(data.get("url") or "").strip()
    value = str(data.get("value") or data.get("host") or url or "").strip()
    if not value:
        raise api_error("invalid_target", "A target has no value.")
    if len(value) > 512:
        raise api_error("invalid_target", "A target value exceeds 512 characters.")

    if "://" not in value and url:
        value = url
    scheme = str(data.get("scheme") or "").strip().lower()
    port_raw = data.get("port")

    if "://" in value:
        try:
            host, parsed_scheme, parsed_port = parse_target_url(value)
        except ValueError as exc:
            raise api_error("invalid_target", f"'{value}' is not a valid http(s) target ({exc}).")
        scheme = scheme or parsed_scheme
        port = int(port_raw) if port_raw not in (None, "") else parsed_port
        target = {
            "type": "url",
            "value": value,
            "url": value,
            "host": host,
            "scheme": scheme,
            "port": port,
        }
    else:
        host = normalize_host(value)
        if not host or " " in host or "/" in host:
            raise api_error("invalid_target", f"'{value}' is not a valid hostname or IP.")
        scheme = scheme or "https"
        if scheme not in ("http", "https"):
            raise api_error("invalid_target", f"Unsupported scheme '{scheme}'.")
        port = int(port_raw) if port_raw not in (None, "") else None
        target = {"type": "host", "value": value, "host": host, "scheme": scheme, "port": port}

    if target.get("port") is not None:
        try:
            port = int(target["port"])
        except (TypeError, ValueError):
            raise api_error("invalid_target", "Target port must be a number.")
        if port < 1 or port > 65535:
            raise api_error("invalid_target", f"Port {port} is out of range.")
        target["port"] = port
    return target


def _authorize_targets(
    db: Session,
    project_id: str,
    targets: list[dict[str, Any]],
    *,
    require_active: bool,
) -> list[dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    for target in targets:
        host = str(target.get("host") or target.get("value"))
        decision = authorize_target(
            db,
            project_id,
            host,
            kind="url" if target.get("type") == "url" else None,
            require_active=require_active,
            port=target.get("port"),
        )
        decisions.append(
            {
                "host": decision.host,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "detail": decision.detail,
                "resolved_ips": decision.resolved_ips,
                "scope_id": decision.scope_id,
                "scope_value": decision.scope_value,
                "allow_active": decision.allow_active,
            }
        )
        if not decision.allowed:
            raise api_error(
                "target_not_authorized",
                f"Target '{host}' is not authorized: {decision.detail or decision.reason}.",
                status.HTTP_403_FORBIDDEN,
                target=host,
                reason=decision.reason,
                hint="Add an active, unexpired scope entry that matches this target. Private targets additionally require both the global and project private-target flags.",
            )
    return decisions


def _snapshot_scopes(db: Session, project_id: str, scope_ids: list[str]) -> list[dict[str, Any]]:
    if not scope_ids:
        return []
    rows = db.execute(select(Scope).where(Scope.id.in_(scope_ids))).scalars().all()
    return [
        {
            "id": s.id,
            "kind": s.kind,
            "value": s.value,
            "include_subdomains": s.include_subdomains,
            "allow_active": s.allow_active,
            "authorization_ref": s.authorization_ref,
            "authorized_by": s.authorized_by,
            "verified_method": s.verified_method,
            "verified_at": to_iso_z(s.verified_at),
            "expires_at": to_iso_z(s.expires_at),
        }
        for s in rows
    ]


# ---------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------
@router.post("/scans/uploads", status_code=status.HTTP_201_CREATED)
async def upload_capture(
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
    file: UploadFile = File(...),
    kind: str = Form(...),
) -> dict[str, Any]:
    """Store a PCAP or log file for analysis. Returns the server path to reference in a scan."""
    if kind not in FILE_KINDS:
        raise api_error("invalid_kind", f"Uploads are supported for {list(FILE_KINDS)}.")
    try:
        stored = await store_upload(file, kind="pcap" if kind == "pcap_analysis" else "log")
    except UploadRejected as exc:
        raise api_error(exc.code, exc.message, exc.status_code)

    audit(
        db,
        access.auth,
        "scan.upload",
        project_id=access.project.id,
        entity_type="upload",
        entity_id=Path(stored["upload_path"]).name,
        meta={"kind": kind, "size": stored["size_bytes"], "sha256": stored["sha256"]},
    )
    return {
        **stored,
        "note": "Pass upload_path and source_name inside scan options. Files are never executed.",
    }


# ---------------------------------------------------------------------------
# Create / list / detail
# ---------------------------------------------------------------------------
@router.post("/scans", status_code=status.HTTP_201_CREATED)
def create_scan(
    body: ScanCreate,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    if body.kind not in SCAN_KINDS:
        raise api_error("invalid_kind", f"Scan kind must be one of {list(SCAN_KINDS)}.")
    if body.profile not in SCAN_PROFILES:
        raise api_error("invalid_profile", f"Profile must be one of {list(SCAN_PROFILES)}.")
    if body.kind in FILE_KINDS and body.profile != "passive":
        raise api_error("invalid_profile", f"{body.kind} runs offline and only supports the passive profile.")
    if body.kind == "intel_correlation" and body.profile != "passive":
        raise api_error("invalid_profile", "Intel correlation is read-only and only supports the passive profile.")
    if body.kind == "web_vuln" and body.profile in ZAP_PROFILES and not settings.zap_url.strip():
        raise api_error(
            "zap_not_configured",
            "OWASP ZAP is not configured. Set NEXUS_ZAP_URL (and NEXUS_ZAP_API_KEY) in backend\\.env, or use the built-in web engine profile.",
            status.HTTP_409_CONFLICT,
        )
    if body.profile in ACTIVE_PROFILES and not settings.active_scanning_enabled:
        raise api_error("active_scanning_disabled", "Active scanning is disabled platform-wide.", status.HTTP_409_CONFLICT)

    if body.idempotency_key:
        existing = db.execute(
            select(Scan).where(
                Scan.project_id == access.project.id,
                Scan.dedup_key == body.idempotency_key,
                Scan.status.in_(ACTIVE_SCAN_STATUSES),
            )
        ).scalars().first()
        if existing:
            raise api_error("duplicate_scan", "A scan with this idempotency key is already active.", status.HTTP_409_CONFLICT, scan_id=existing.id)

    options = dict(body.options or {})
    targets: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    require_active = body.kind == "network_scan" or body.profile in ACTIVE_PROFILES

    if body.kind in FILE_KINDS:
        upload_path = str(options.get("upload_path") or "")
        if not upload_path:
            raise api_error("upload_required", "Upload the file first (POST /scans/uploads) and pass upload_path in options.")
        resolved = safe_child_path(settings.uploads_dir, upload_path, must_exist=True)
        options["upload_path"] = str(resolved)
        options.setdefault("source_name", Path(resolved).name[:200])
        if body.kind == "pcap_analysis" and resolved.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
            raise api_error("invalid_file_type", "The referenced file is not a PCAP capture.")
        options.setdefault("format", "auto")
    elif body.kind == "intel_correlation":
        pass  # correlates existing findings; no network target
    else:
        if not body.targets:
            raise api_error("targets_required", "At least one authorized target is required for this scan kind.")
        if len(body.targets) > MAX_TARGETS:
            raise api_error("too_many_targets", f"A single scan is limited to {MAX_TARGETS} targets.")
        seen: set[str] = set()
        for raw in body.targets:
            target = _normalize_target(raw)
            key = f"{target.get('host')}|{target.get('port')}|{target.get('url','')}"
            if key in seen:
                continue
            seen.add(key)
            targets.append(target)
        decisions = _authorize_targets(db, access.project.id, targets, require_active=require_active)
        if body.kind == "web_vuln":
            for target in targets:
                if not target.get("url"):
                    scheme = target.get("scheme") or "https"
                    port = target.get("port")
                    host = target.get("host")
                    target["url"] = f"{scheme}://{host}" + (f":{port}" if port and port not in (80, 443) else "")

    scope_ids = sorted({str(d["scope_id"]) for d in decisions if d.get("scope_id")})
    snapshot = {
        "created_at": to_iso_z(utcnow()),
        "created_by": access.user_id,
        "profile": body.profile,
        "require_active": require_active,
        "scopes": _snapshot_scopes(db, access.project.id, scope_ids),
        "decisions": decisions,
        "global_private_targets": settings.allow_private_targets,
        "project_private_targets": access.project.allow_private_targets,
        "active_scanning_enabled": settings.active_scanning_enabled,
        "policy": summarize_policy(),
    }

    scan_name = body.name.strip() or f"{SCAN_KINDS[body.kind]['en']} — {utcnow().strftime('%Y-%m-%d %H:%M')}"
    scan = Scan(
        project_id=access.project.id,
        name=scan_name[:200],
        kind=body.kind,
        profile=body.profile,
        status="queued",
        progress=0,
        phases=build_phases(body.kind),
        targets=targets,
        options=options,
        authorization_snapshot=snapshot,
        requested_by=access.user_id,
        dedup_key=body.idempotency_key or None,
    )
    db.add(scan)
    db.flush()

    timeout = 2400 if body.profile in ZAP_PROFILES else 900
    job = JobQueue.enqueue(
        db,
        type=SCAN_KIND_TO_JOB[body.kind],
        project_id=access.project.id,
        scan_id=scan.id,
        payload={},
        priority=body.priority,
        timeout_seconds=timeout,
        max_attempts=2,
        dedup_key=f"scan:{scan.id}",
    )
    db.commit()

    audit(
        db,
        access.auth,
        "scan.create",
        project_id=access.project.id,
        entity_type="scan",
        entity_id=scan.id,
        meta={
            "kind": scan.kind,
            "profile": scan.profile,
            "targets": [t.get("host") for t in targets][:20],
            "job_id": job.id if job else None,
        },
    )
    return {
        "scan": scan_public(scan),
        "job": job_public(job) if job else None,
        "authorization": {
            "require_active": require_active,
            "targets": decisions,
            "note": "Authorization was captured at creation time. Scope is re-checked when the scan runs.",
        },
    }


@router.get("/scans")
def list_scans(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    status_filter: str | None = Query(default=None, alias="status"),
    kind: str | None = Query(default=None),
    limit: int = Query(default=30, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    query = select(Scan).where(Scan.project_id == access.project.id)
    count_query = select(func.count(Scan.id)).where(Scan.project_id == access.project.id)
    if status_filter:
        query = query.where(Scan.status == status_filter)
        count_query = count_query.where(Scan.status == status_filter)
    if kind:
        query = query.where(Scan.kind == kind)
        count_query = count_query.where(Scan.kind == kind)
    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(query.order_by(Scan.created_at.desc()).limit(limit).offset(offset)).scalars().all()
    counts = {
        state: int(cnt)
        for state, cnt in db.execute(
            select(Scan.status, func.count(Scan.id)).where(Scan.project_id == access.project.id).group_by(Scan.status)
        ).all()
    }
    return {**paged([scan_public(s) for s in rows], total, limit=limit, offset=offset), "counts": counts}


@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: str,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.project_id != access.project.id:
        raise api_error("scan_not_found", "Scan not found.", status.HTTP_404_NOT_FOUND)
    jobs = db.execute(select(Job).where(Job.scan_id == scan.id).order_by(Job.created_at.desc())).scalars().all()
    findings_by_severity = {
        severity: int(cnt)
        for severity, cnt in db.execute(
            select(Finding.severity, func.count(Finding.id)).where(Finding.scan_id == scan.id).group_by(Finding.severity)
        ).all()
    }
    return {
        "scan": scan_public(scan, findings=findings_by_severity),
        "jobs": [job_public(j) for j in jobs],
    }


# ---------------------------------------------------------------------------
# Live events (poll + SSE)
# ---------------------------------------------------------------------------
@router.get("/scans/{scan_id}/events")
def scan_events_poll(
    scan_id: str,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    after_id: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.project_id != access.project.id:
        raise api_error("scan_not_found", "Scan not found.", status.HTTP_404_NOT_FOUND)
    rows = events_since(db, scan_id=scan.id, project_id=access.project.id, after_id=after_id, limit=limit)
    return {
        "items": [event_to_dict(e) for e in rows],
        "last_id": rows[-1].id if rows else after_id,
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "progress": scan.progress,
            "phases": scan.phases or [],
            "error": scan.error,
        },
    }


@router.get("/scans/{scan_id}/stream")
def scan_events_stream(
    scan_id: str,
    access: ProjectAccess = Depends(project_access("viewer")),
    after_id: int = Query(default=0, ge=0),
) -> StreamingResponse:
    """Server-Sent Events stream of scan progress and logs."""
    scan = None
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.project_id != access.project.id:
            raise api_error("scan_not_found", "Scan not found.", status.HTTP_404_NOT_FOUND)
        project_id = scan.project_id

    def event_stream():
        last_id = after_id
        idle_ticks = 0
        started = time.monotonic()
        yield "retry: 3000\n\n"
        while time.monotonic() - started < 1800:  # absolute cap: 30 minutes per connection
            try:
                with SessionLocal() as session:
                    rows = events_since(session, scan_id=scan_id, project_id=project_id, after_id=last_id, limit=200)
                    current = session.get(Scan, scan_id)
                    status_value = current.status if current else "failed"
                    progress = current.progress if current else 0
                if rows:
                    idle_ticks = 0
                    for event in rows:
                        last_id = event.id
                        payload = json.dumps(event_to_dict(event), ensure_ascii=False)
                        yield f"id: {event.id}\nevent: {event.kind or 'log'}\ndata: {payload}\n\n"
                else:
                    idle_ticks += 1
                    if idle_ticks % 15 == 0:
                        yield f": keep-alive {int(time.monotonic())}\n\n"
                if status_value in TERMINAL_SCAN_STATUSES and not rows and idle_ticks >= 2:
                    final = json.dumps({"scan_id": scan_id, "status": status_value, "progress": progress})
                    yield f"event: done\ndata: {final}\n\n"
                    return
            except GeneratorExit:  # client disconnected
                return
            except Exception as exc:  # never let one bad tick kill the stream silently
                log.debug("SSE tick failed for %s: %s", scan_id, exc)
                yield f"event: error\ndata: {json.dumps({'message': 'stream hiccup'})}\n\n"
            time.sleep(1.0)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# Lifecycle actions
# ---------------------------------------------------------------------------
@router.post("/scans/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.project_id != access.project.id:
        raise api_error("scan_not_found", "Scan not found.", status.HTTP_404_NOT_FOUND)
    if scan.status in TERMINAL_SCAN_STATUSES:
        raise api_error("scan_finished", f"The scan is already {scan.status}.", status.HTTP_409_CONFLICT)
    scan.cancel_requested = True
    canceled = JobQueue.cancel_scan_jobs(db, scan.id)
    db.commit()
    audit(db, access.auth, "scan.cancel", project_id=access.project.id, entity_type="scan", entity_id=scan.id, meta={"jobs": canceled})
    return {"canceled_jobs": canceled, "scan": scan_public(scan)}


@router.post("/scans/{scan_id}/retry", status_code=status.HTTP_201_CREATED)
def retry_scan(
    scan_id: str,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.project_id != access.project.id:
        raise api_error("scan_not_found", "Scan not found.", status.HTTP_404_NOT_FOUND)
    active = db.execute(
        select(Job).where(Job.scan_id == scan.id, Job.status.in_(("queued", "running"))).limit(1)
    ).scalar_one_or_none()
    if active is not None:
        raise api_error("scan_active", "This scan still has an active job.", status.HTTP_409_CONFLICT)
    if scan.kind == "web_vuln" and scan.profile in ZAP_PROFILES and not settings.zap_url.strip():
        raise api_error("zap_not_configured", "OWASP ZAP is not configured on this server.", status.HTTP_409_CONFLICT)

    # Re-validate authorization before re-running: scope entries may have expired,
    # been deactivated, or lost their active-testing permission since creation.
    require_active = scan.kind == "network_scan" or scan.profile in ACTIVE_PROFILES
    if scan.kind != "intel_correlation" and scan.targets:
        decisions = _authorize_targets(db, access.project.id, list(scan.targets), require_active=require_active)
        scope_ids = sorted({str(d["scope_id"]) for d in decisions if d.get("scope_id")})
        scan.authorization_snapshot = {
            **(scan.authorization_snapshot or {}),
            "refreshed_at": to_iso_z(utcnow()),
            "refreshed_by": access.user_id,
            "require_active": require_active,
            "scopes": _snapshot_scopes(db, access.project.id, scope_ids),
            "decisions": decisions,
        }

    scan.status = "queued"
    scan.progress = 0
    scan.phases = build_phases(scan.kind)
    scan.cancel_requested = False
    scan.error = ""
    scan.started_at = None
    scan.finished_at = None
    scan.stats = {}
    db.flush()
    job = JobQueue.enqueue(
        db,
        type=SCAN_KIND_TO_JOB[scan.kind],
        project_id=access.project.id,
        scan_id=scan.id,
        priority=100,
        timeout_seconds=2400 if scan.profile in ZAP_PROFILES else 900,
        max_attempts=2,
        dedup_key=f"scan:{scan.id}",
    )
    db.commit()
    audit(db, access.auth, "scan.retry", project_id=access.project.id, entity_type="scan", entity_id=scan.id, meta={"job_id": job.id if job else None})
    return {"scan": scan_public(scan), "job": job_public(job) if job else None}


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: str,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> None:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.project_id != access.project.id:
        raise api_error("scan_not_found", "Scan not found.", status.HTTP_404_NOT_FOUND)
    if scan.status in ("queued", "running", "paused"):
        raise api_error("scan_active", "Cancel the scan before deleting it.", status.HTTP_409_CONFLICT)
    db.delete(scan)
    db.commit()
    audit(db, access.auth, "scan.delete", project_id=access.project.id, entity_type="scan", entity_id=scan_id)
    return None
