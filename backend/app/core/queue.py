"""Durable DB-backed job queue.

Why not Celery/RQ: this platform must run on a plain Windows 10 laptop with SQLite
and no Docker, while still being correct under concurrency. A queue stored in the
same database as the results can never lose a job on crash, needs no extra
service, and gives us priorities, leases, retries, deduplication and full history
for free.

Claiming uses an optimistic compare-and-set (`UPDATE ... WHERE id=? AND
status='queued'`), which is safe on SQLite (single writer) and PostgreSQL alike.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Sequence

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Job, Scan
from .utils import utcnow

log = logging.getLogger("nexus.queue")

# Job type registry — workers resolve these names to engine callables.
JOB_DISCOVERY = "scan.discovery"
JOB_HTTP_ANALYSIS = "scan.http_analysis"
JOB_WEB_VULN = "scan.web_vuln"
JOB_NETWORK_SCAN = "scan.network"
JOB_PCAP_ANALYSIS = "scan.pcap"
JOB_LOG_ANALYSIS = "scan.logs"
JOB_INTEL_CORRELATE = "scan.intel"
JOB_REPORT_GENERATE = "report.generate"
JOB_LAB_VERIFY = "lab.verify"
JOB_MAINTENANCE = "system.maintenance"

ALL_JOB_TYPES = (
    JOB_DISCOVERY,
    JOB_HTTP_ANALYSIS,
    JOB_WEB_VULN,
    JOB_NETWORK_SCAN,
    JOB_PCAP_ANALYSIS,
    JOB_LOG_ANALYSIS,
    JOB_INTEL_CORRELATE,
    JOB_REPORT_GENERATE,
    JOB_LAB_VERIFY,
    JOB_MAINTENANCE,
)

# Scan kind -> job type
SCAN_KIND_TO_JOB = {
    "asset_discovery": JOB_DISCOVERY,
    "dns_diagnostics": JOB_DISCOVERY,
    "http_analysis": JOB_HTTP_ANALYSIS,
    "web_vuln": JOB_WEB_VULN,
    "network_scan": JOB_NETWORK_SCAN,
    "pcap_analysis": JOB_PCAP_ANALYSIS,
    "log_analysis": JOB_LOG_ANALYSIS,
    "intel_correlation": JOB_INTEL_CORRELATE,
}

ACTIVE_JOB_STATUSES = ("queued", "running")


class JobQueue:
    # ------------------------------------------------------------------ enqueue
    @staticmethod
    def enqueue(
        db: Session,
        *,
        type: str,
        project_id: str,
        payload: dict[str, Any] | None = None,
        scan_id: str | None = None,
        priority: int = 100,
        timeout_seconds: int = 900,
        max_attempts: int = 3,
        dedup_key: str | None = None,
        run_after=None,
        commit: bool = False,
    ) -> Job | None:
        """Enqueue a job. Returns None when an identical active job already exists."""
        if type not in ALL_JOB_TYPES:
            raise ValueError(f"unknown job type: {type}")
        if dedup_key:
            existing = db.execute(
                select(Job.id).where(Job.dedup_key == dedup_key, Job.status.in_(ACTIVE_JOB_STATUSES)).limit(1)
            ).scalar_one_or_none()
            if existing:
                log.info("job deduplicated (dedup_key=%s)", dedup_key)
                return None
        job = Job(
            scan_id=scan_id,
            project_id=project_id,
            type=type,
            payload=payload or {},
            priority=priority,
            timeout_seconds=timeout_seconds,
            max_attempts=max_attempts,
            dedup_key=dedup_key,
            run_after=run_after or utcnow(),
            status="queued",
        )
        db.add(job)
        try:
            if commit:
                db.commit()
            else:
                db.flush()
        except IntegrityError:
            db.rollback()
            log.info("job deduplicated by unique index (dedup_key=%s)", dedup_key)
            return None
        return job

    # -------------------------------------------------------------------- claim
    @staticmethod
    def claim(db: Session, worker_id: str, *, max_concurrent_scans: int | None = None) -> Job | None:
        """Atomically claim the highest-priority runnable job (or None)."""
        now = utcnow()
        limit = max_concurrent_scans if max_concurrent_scans is not None else settings.max_concurrent_scans

        running_scan_ids = set(
            db.execute(
                select(Job.scan_id).where(Job.status == "running", Job.scan_id.is_not(None)).distinct()
            ).scalars().all()
        )
        scan_slots_full = len(running_scan_ids) >= limit

        candidates = db.execute(
            select(Job.id, Job.scan_id)
            .where(Job.status == "queued", Job.run_after <= now)
            .order_by(Job.priority.asc(), Job.created_at.asc())
            .limit(25)
        ).all()

        for job_id, scan_id in candidates:
            if scan_slots_full and scan_id is not None and scan_id not in running_scan_ids:
                continue  # keep the queue fair: don't start a new scan while the limit is reached
            result = db.execute(
                update(Job)
                .where(Job.id == job_id, Job.status == "queued")
                .values(
                    status="running",
                    locked_by=worker_id,
                    locked_at=now,
                    started_at=now,
                    lease_expires_at=now + timedelta(seconds=settings.job_lease_seconds),
                    attempts=Job.attempts + 1,
                )
            )
            db.commit()
            if result.rowcount == 1:
                return db.get(Job, job_id)
        return None

    # ---------------------------------------------------------------- lifecycle
    @staticmethod
    def heartbeat(db: Session, job_id: str, *, progress: int | None = None, phase: str | None = None) -> None:
        values: dict[str, Any] = {"lease_expires_at": utcnow() + timedelta(seconds=settings.job_lease_seconds)}
        if progress is not None:
            values["progress"] = max(0, min(100, int(progress)))
        if phase is not None:
            values["phase"] = phase
        db.execute(update(Job).where(Job.id == job_id).values(**values))
        db.commit()

    @staticmethod
    def succeed(db: Session, job: Job, result: dict[str, Any] | None = None) -> None:
        job.status = "succeeded"
        job.progress = 100
        job.result = result or {}
        job.finished_at = utcnow()
        job.locked_by = ""
        job.lease_expires_at = None
        db.commit()

    @staticmethod
    def fail(db: Session, job: Job, error: str, *, retryable: bool = True) -> str:
        """Mark a job failed; requeue with exponential backoff when retries remain."""
        job.last_error = (error or "unknown error")[:2000]
        job.locked_by = ""
        job.lease_expires_at = None
        if retryable and job.attempts < job.max_attempts:
            backoff = min(300, 5 * (2 ** max(job.attempts - 1, 0)))
            job.status = "queued"
            job.run_after = utcnow() + timedelta(seconds=backoff)
            job.progress = 0
            db.commit()
            log.warning("job %s failed (attempt %s/%s) — retrying in %ss: %s", job.id, job.attempts, job.max_attempts, backoff, job.last_error)
            return job.status
        job.status = "dead" if retryable else "failed"
        job.finished_at = utcnow()
        db.commit()
        log.error("job %s failed permanently: %s", job.id, job.last_error)
        return job.status

    @staticmethod
    def cancel(db: Session, job: Job) -> None:
        if job.status in ACTIVE_JOB_STATUSES:
            job.status = "canceled"
            job.finished_at = utcnow()
            job.locked_by = ""
            job.lease_expires_at = None
            db.commit()

    @staticmethod
    def cancel_scan_jobs(db: Session, scan_id: str) -> int:
        rows = db.execute(select(Job).where(Job.scan_id == scan_id, Job.status.in_(ACTIVE_JOB_STATUSES))).scalars().all()
        for job in rows:
            job.status = "canceled"
            job.finished_at = utcnow()
            job.locked_by = ""
            job.lease_expires_at = None
        db.commit()
        return len(rows)

    # ------------------------------------------------------------------ upkeep
    @staticmethod
    def reap_stale(db: Session) -> int:
        """Requeue jobs whose worker died (lease expired)."""
        now = utcnow()
        stale = db.execute(
            select(Job).where(Job.status == "running", Job.lease_expires_at.is_not(None), Job.lease_expires_at < now)
        ).scalars().all()
        requeued = 0
        for job in stale:
            job.last_error = (job.last_error + "\n[lease expired — worker presumed dead]").strip()
            if job.attempts < job.max_attempts:
                job.status = "queued"
                job.run_after = now
                job.progress = 0
                requeued += 1
            else:
                job.status = "dead"
                job.finished_at = now
            job.locked_by = ""
            job.lease_expires_at = None
        if stale:
            db.commit()
            log.warning("reaped %s stale job(s), requeued %s", len(stale), requeued)
        return len(stale)

    @staticmethod
    def stats(db: Session, project_id: str | None = None) -> dict[str, int]:
        query = select(Job.status, func.count(Job.id)).group_by(Job.status)
        if project_id:
            query = query.where(Job.project_id == project_id)
        rows = db.execute(query).all()
        stats = {status: 0 for status in ("queued", "running", "succeeded", "failed", "canceled", "dead")}
        for status, count in rows:
            stats[status] = count
        stats["total"] = sum(stats.values())
        return stats

    @staticmethod
    def active_for_project(db: Session, project_id: str) -> int:
        return int(
            db.execute(
                select(func.count(Job.id)).where(Job.project_id == project_id, Job.status.in_(ACTIVE_JOB_STATUSES))
            ).scalar_one()
        )

    @staticmethod
    def recent(db: Session, project_id: str, *, limit: int = 50) -> Sequence[Job]:
        return db.execute(
            select(Job).where(Job.project_id == project_id).order_by(Job.created_at.desc()).limit(limit)
        ).scalars().all()

    @staticmethod
    def mark_scan_state(db: Session, scan_id: str) -> Scan | None:
        """Recompute a scan's aggregate status from its jobs."""
        scan = db.get(Scan, scan_id)
        if scan is None:
            return None
        jobs = db.execute(select(Job).where(Job.scan_id == scan_id)).scalars().all()
        if not jobs:
            return scan
        statuses = {j.status for j in jobs}
        if statuses <= {"succeeded"}:
            scan.status = "completed"
            scan.progress = 100
        elif "running" in statuses or "queued" in statuses:
            scan.status = "running"
            scan.progress = int(sum(j.progress for j in jobs) / max(len(jobs), 1))
        elif "canceled" in statuses and statuses <= {"canceled", "succeeded"}:
            scan.status = "canceled"
        elif "dead" in statuses or "failed" in statuses:
            successes = sum(1 for j in jobs if j.status == "succeeded")
            scan.status = "partial" if successes else "failed"
            scan.error = next((j.last_error for j in jobs if j.status in ("dead", "failed")), "")
        if scan.status in ("completed", "failed", "canceled", "partial"):
            scan.finished_at = scan.finished_at or utcnow()
        db.commit()
        return scan
