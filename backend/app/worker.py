"""NEXUS worker — executes queued jobs (scans, reports, labs, maintenance).

Runs in a dedicated background thread (dev-lite) or as its own process
(production: `python -m app.worker`). The job contract:

* claim → one job per call (optimistic CAS in `core.queue`),
* execute with a hard timeout (`job.timeout_seconds`),
* heartbeat the lease while running so a crashed worker is detected,
* honor operator cancellation cooperatively (`scan.cancel_requested`),
* retries with backoff are decided by `JobQueue.fail` — this module only
  classifies errors as retryable or not.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import os
import socket
import threading
from datetime import timedelta
from typing import Any, Callable

from sqlalchemy import select, update

from .config import settings
from .core.queue import (
    JOB_LAB_VERIFY,
    JOB_MAINTENANCE,
    JOB_REPORT_GENERATE,
    JobQueue,
)
from .core.utils import new_id, utcnow
from .db import SessionLocal, session_scope
from .engines.base import EngineContext, EngineResult, ScanCanceled
from .models import Job, Project, Scan, ScanEvent

log = logging.getLogger("nexus.worker")

HEARTBEAT_INTERVAL = 20.0
MAINTENANCE_INTERVAL = 60.0


# ---------------------------------------------------------------------------
# Engine selection
# ---------------------------------------------------------------------------
def _select_engine(scan: Scan):
    from .engines import dns_engine, http_engine, intel_engine, logs_engine, network_engine, pcap_engine, webvuln_engine

    if scan.kind == "web_vuln" and scan.profile in ("zap_passive", "zap_active"):
        from .engines import zap_adapter

        return zap_adapter.run
    mapping: dict[str, Callable[..., Any]] = {
        "asset_discovery": dns_engine.run,
        "dns_diagnostics": dns_engine.run,
        "http_analysis": http_engine.run,
        "web_vuln": webvuln_engine.run,
        "network_scan": network_engine.run,
        "pcap_analysis": pcap_engine.run,
        "log_analysis": logs_engine.run,
        "intel_correlation": intel_engine.run,
    }
    return mapping.get(scan.kind)


# ---------------------------------------------------------------------------
# Job handlers
# ---------------------------------------------------------------------------
async def _handle_scan_job(db, job: Job) -> dict[str, Any]:
    scan = db.get(Scan, job.scan_id) if job.scan_id else None
    if scan is None:
        raise RuntimeError(f"scan {job.scan_id} no longer exists")
    project = db.get(Project, scan.project_id)
    if project is None:
        raise RuntimeError(f"project {scan.project_id} no longer exists")

    engine = _select_engine(scan)
    if engine is None:
        raise RuntimeError(f"no engine registered for scan kind '{scan.kind}'")

    ctx = EngineContext(db, scan, project, worker_id=job.locked_by or "worker")
    for key, value in (job.payload or {}).items():
        scan.options = {**(scan.options or {}), key: value}  # merge runtime payload (upload paths, flags)
    db.commit()

    result: EngineResult = await engine(ctx, list(scan.targets or []))
    return {
        "findings": result.findings,
        "assets": result.assets,
        "services": result.services,
        "notes": result.notes,
        "data": result.data,
    }


async def _handle_report_job(db, job: Job) -> dict[str, Any]:
    from .reports.generator import generate_report

    report_id = (job.payload or {}).get("report_id") or ""
    if not report_id:
        raise RuntimeError("report.generate job is missing payload.report_id")
    return await generate_report(db, report_id)


async def _handle_lab_job(db, job: Job) -> dict[str, Any]:
    from .services.labs import verify_lab_run

    payload = job.payload or {}
    run_id = payload.get("run_id") or ""
    if not run_id:
        raise RuntimeError("lab.verify job is missing payload.run_id")
    return await verify_lab_run(db, run_id)


async def _handle_maintenance(db, job: Job) -> dict[str, Any]:
    from .engines.intel_engine import sync_kev

    payload = job.payload or {}
    tasks = payload.get("tasks") or ["reap", "kev", "prune"]
    summary: dict[str, Any] = {}

    if "reap" in tasks:
        summary["requeued"] = JobQueue.reap_stale(db)
    if "kev" in tasks:
        summary["kev"] = await sync_kev(db, force=bool(payload.get("force_kev")))
    if "prune" in tasks:
        summary["pruned_events"] = _prune_scan_events(db, days=int(payload.get("event_retention_days", 30)))
    return summary


def _prune_scan_events(db, *, days: int) -> int:
    """Trim the live scan log so the database stays small (findings are kept)."""
    from sqlalchemy import delete

    cutoff = utcnow() - timedelta(days=max(days, 1))
    result = db.execute(delete(ScanEvent).where(ScanEvent.ts < cutoff))
    db.commit()
    return int(result.rowcount or 0)


_HANDLERS: dict[str, Callable[[Any, Job], Any]] = {
    "scan.discovery": _handle_scan_job,
    "scan.http_analysis": _handle_scan_job,
    "scan.web_vuln": _handle_scan_job,
    "scan.network": _handle_scan_job,
    "scan.pcap": _handle_scan_job,
    "scan.logs": _handle_scan_job,
    "scan.intel": _handle_scan_job,
    JOB_REPORT_GENERATE: _handle_report_job,
    JOB_LAB_VERIFY: _handle_lab_job,
    JOB_MAINTENANCE: _handle_maintenance,
}


# ---------------------------------------------------------------------------
# Execution wrapper
# ---------------------------------------------------------------------------
def _is_retryable(exc: BaseException) -> bool:
    from .engines.zap_adapter import ZapError

    if isinstance(exc, (ScanCanceled, ValueError)):
        return False
    if isinstance(exc, ZapError):
        return True  # the daemon may be starting up / briefly busy
    return True


async def _heartbeat_loop(job_id: str, stop: asyncio.Event) -> None:
    """Keep the lease alive and mirror operator cancellation onto the scan."""
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=HEARTBEAT_INTERVAL)
            return
        except asyncio.TimeoutError:
            pass
        try:
            with SessionLocal() as db:
                row = db.execute(select(Job.status, Job.scan_id).where(Job.id == job_id)).first()
                if row is None:
                    return
                status, scan_id = row
                if status == "canceled" and scan_id:
                    db.execute(update(Scan).where(Scan.id == scan_id, Scan.cancel_requested.is_(False)).values(cancel_requested=True))
                db.execute(
                    update(Job)
                    .where(Job.id == job_id)
                    .values(lease_expires_at=utcnow() + timedelta(seconds=settings.job_lease_seconds))
                )
                if scan_id:
                    db.execute(update(Scan).where(Scan.id == scan_id).values(heartbeat_at=utcnow()))
                db.commit()
        except Exception as exc:  # never let the heartbeat kill a job
            log.debug("heartbeat tick failed for job %s: %s", job_id, exc)


async def execute_job(job_id: str, worker_id: str) -> str:
    """Run one claimed job. Returns the final job status string."""
    with session_scope() as db:
        job = db.get(Job, job_id)
        if job is None or job.status != "running" or job.locked_by != worker_id:
            return "skipped"
        job_type = job.type
        scan_id = job.scan_id
        timeout = max(int(job.timeout_seconds or 900), 30)

    handler = _HANDLERS.get(job_type)
    if handler is None:
        with session_scope() as db:
            job = db.get(Job, job_id)
            if job:
                JobQueue.fail(db, job, f"no handler for job type '{job_type}'", retryable=False)
        return "failed"

    stop = asyncio.Event()
    heartbeat = asyncio.create_task(_heartbeat_loop(job_id, stop))
    status = "succeeded"
    try:
        with session_scope() as db:
            job = db.get(Job, job_id)
            if job is None:
                return "skipped"
            if scan_id:
                scan = db.get(Scan, scan_id)
                if scan and scan.status == "queued":
                    scan.status = "running"
                    scan.started_at = scan.started_at or utcnow()
                    db.commit()
            result = await asyncio.wait_for(handler(db, job), timeout=timeout)

        with session_scope() as db:
            job = db.get(Job, job_id)
            if job is None:
                return "skipped"
            JobQueue.succeed(db, job, result or {})
            log.info("job %s (%s) succeeded", job_id, job_type)
            _apply_scan_result(db, scan_id, result or {})
    except asyncio.TimeoutError:
        with session_scope() as db:
            job = db.get(Job, job_id)
            if job:
                job.last_error = f"job exceeded its {timeout}s time limit"
                status = JobQueue.fail(db, job, job.last_error, retryable=False)
                _emit_scan_event(db, scan_id, f"Job exceeded its {timeout}s time limit.", level="error")
            _apply_scan_result(db, scan_id, {})
        log.warning("job %s timed out after %ss", job_id, timeout)
    except ScanCanceled as exc:
        with session_scope() as db:
            job = db.get(Job, job_id)
            if job and job.status not in ("canceled",):
                JobQueue.cancel(db, job)
            if scan_id:
                scan = db.get(Scan, scan_id)
                if scan:
                    scan.cancel_requested = True
                    db.commit()
            _emit_scan_event(db, scan_id, f"Scan canceled: {exc}", level="warn")
            _apply_scan_result(db, scan_id, {})
        status = "canceled"
        log.info("job %s canceled by operator", job_id)
    except Exception as exc:  # noqa: BLE001 - the queue records the failure
        with session_scope() as db:
            job = db.get(Job, job_id)
            if job:
                status = JobQueue.fail(db, job, f"{type(exc).__name__}: {exc}", retryable=_is_retryable(exc))
            _emit_scan_event(db, scan_id, f"Job failed: {type(exc).__name__}: {exc}", level="error")
            _apply_scan_result(db, scan_id, {})
        log.exception("job %s failed", job_id)
    finally:
        stop.set()
        heartbeat.cancel()
        try:
            await heartbeat
        except (asyncio.CancelledError, Exception):
            pass
    return status


def _apply_scan_result(db, scan_id: str | None, result: dict[str, Any]) -> None:
    if not scan_id:
        return
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    if result:
        stats = dict(scan.stats or {})
        stats.update({k: v for k, v in result.items() if k != "data"})
        if isinstance(result.get("data"), dict):
            stats["last_run"] = result["data"]
        scan.stats = stats
    JobQueue.mark_scan_state(db, scan_id)
    if scan.status == "completed":
        _finalize_phases(scan)


def _finalize_phases(scan: Scan) -> None:
    """Mark any phases the engine finished without closing as done.

    Engines report phases as they go. Offline analyzers intentionally stop after
    their last real step, so the trailing "store" phase would otherwise sit at
    "pending" forever even though the scan completed and committed its data.
    Failed phases are preserved so the UI can still see what broke.
    """
    from sqlalchemy.orm import attributes

    phases = copy.deepcopy(list(scan.phases or []))
    changed = False
    for phase in phases:
        if phase.get("status") in ("pending", "running"):
            phase["status"] = "done"
            phase["progress"] = 100
            changed = True
    if changed:
        scan.phases = phases
        attributes.flag_modified(scan, "phases")
    if scan.progress != 100:
        scan.progress = 100


def _emit_scan_event(db, scan_id: str | None, message: str, *, level: str = "info") -> None:
    if not scan_id:
        return
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    from .core.events import emit

    emit(db, project_id=scan.project_id, scan_id=scan_id, level=level, kind="log", message=message, phase="")


# ---------------------------------------------------------------------------
# Worker loop
# ---------------------------------------------------------------------------
class Worker:
    def __init__(self, worker_id: str | None = None) -> None:
        self.worker_id = worker_id or f"worker-{socket.gethostname()}-{os.getpid()}-{new_id()[:4]}"
        self._stop = threading.Event()
        self._last_maintenance = 0.0
        self.jobs_done = 0

    def request_stop(self) -> None:
        self._stop.set()

    async def loop(self) -> None:
        log.info("worker %s started (poll every %.1fs)", self.worker_id, settings.job_poll_seconds)
        while not self._stop.is_set():
            processed = False
            try:
                with SessionLocal() as db:
                    job = JobQueue.claim(db, self.worker_id)
                if job is not None:
                    processed = True
                    await execute_job(job.id, self.worker_id)
                    self.jobs_done += 1
                else:
                    await self._maybe_maintenance()
            except Exception:  # noqa: BLE001 - the loop must survive anything
                log.exception("worker loop error")
                await asyncio.sleep(2.0)
            if not processed:
                await asyncio.sleep(settings.job_poll_seconds)

    async def _maybe_maintenance(self) -> None:
        loop_time = asyncio.get_running_loop().time()
        if loop_time - self._last_maintenance < MAINTENANCE_INTERVAL:
            return
        self._last_maintenance = loop_time
        try:
            with SessionLocal() as db:
                JobQueue.reap_stale(db)
        except Exception as exc:  # pragma: no cover
            log.debug("maintenance tick failed: %s", exc)


# ---------------------------------------------------------------------------
# Background thread control (used by the API when NEXUS_INPROCESS_WORKER=true)
# ---------------------------------------------------------------------------
_worker: Worker | None = None
_thread: threading.Thread | None = None


def _thread_main(worker: Worker) -> None:
    try:
        asyncio.run(worker.loop())
    except Exception:  # pragma: no cover
        log.exception("background worker terminated")
    finally:
        log.info("worker thread stopped")


def start_background_worker() -> Worker | None:
    global _worker, _thread
    if _thread and _thread.is_alive():
        return _worker
    _worker = Worker()
    _thread = threading.Thread(target=_thread_main, args=(_worker,), name="nexus-worker", daemon=True)
    _thread.start()
    return _worker


def stop_background_worker(timeout: float = 5.0) -> None:
    global _worker, _thread
    if _worker:
        _worker.request_stop()
    if _thread and _thread.is_alive():
        _thread.join(timeout=timeout)
    _thread = None


def worker_status() -> dict[str, Any]:
    running = bool(_thread and _thread.is_alive())
    return {
        "in_process": running,
        "worker_id": _worker.worker_id if _worker else "",
        "jobs_done": _worker.jobs_done if _worker else 0,
    }


# ---------------------------------------------------------------------------
# Standalone entry point: python -m app.worker
# ---------------------------------------------------------------------------
def run_forever() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    worker = Worker()
    log.info("NEXUS worker starting standalone — Ctrl+C to stop")
    try:
        asyncio.run(worker.loop())
    except KeyboardInterrupt:
        log.info("worker interrupted — shutting down")


if __name__ == "__main__":  # pragma: no cover
    run_forever()
