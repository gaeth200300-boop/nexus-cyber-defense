"""Durable queue contract: ordering, dedup, retries and scan-state rollups."""

from __future__ import annotations

from app.core.queue import JobQueue
from app.db import SessionLocal


def test_priority_order_and_claim_cas(project):
    with SessionLocal() as db:
        low = JobQueue.enqueue(db, type="system.maintenance", project_id=project["id"], priority=900, dedup_key="pytest-low")
        high = JobQueue.enqueue(db, type="system.maintenance", project_id=project["id"], priority=5, dedup_key="pytest-high")
        db.commit()
        claimed = JobQueue.claim(db, "pytest-worker", max_concurrent_scans=99)
        assert claimed is not None
        assert claimed.id == high.id
        assert claimed.status == "running"
        assert claimed.locked_by == "pytest-worker"

        # A second claim must not hand out the same job.
        second = JobQueue.claim(db, "pytest-worker-2", max_concurrent_scans=99)
        assert second is not None and second.id == low.id
        assert JobQueue.claim(db, "pytest-worker-3", max_concurrent_scans=99) is None

        JobQueue.succeed(db, claimed, {"ok": True})
        db.refresh(claimed)
        assert claimed.status == "succeeded"


def test_dedup_returns_none_for_active_duplicate(project):
    with SessionLocal() as db:
        first = JobQueue.enqueue(db, type="system.maintenance", project_id=project["id"], dedup_key="pytest-dedup")
        second = JobQueue.enqueue(db, type="system.maintenance", project_id=project["id"], dedup_key="pytest-dedup")
        db.commit()
        assert first is not None
        assert second is None


def test_unknown_job_type_is_rejected(project):
    import pytest

    with SessionLocal() as db:
        with pytest.raises(ValueError):
            JobQueue.enqueue(db, type="not.a.job", project_id=project["id"])


def test_retryable_failure_requeues_then_dies(project):
    with SessionLocal() as db:
        job = JobQueue.enqueue(db, type="system.maintenance", project_id=project["id"], max_attempts=2, dedup_key="pytest-retry")
        db.commit()
        claimed = JobQueue.claim(db, "pytest-retry-worker", max_concurrent_scans=99)
        assert claimed is not None and claimed.id == job.id
        state = JobQueue.fail(db, claimed, "boom", retryable=True)
        db.refresh(claimed)
        assert state == "queued"
        assert claimed.attempts == 1
        assert claimed.last_error == "boom"

        # Make the retry runnable immediately instead of waiting for backoff.
        claimed.run_after = claimed.created_at
        db.commit()
        again = JobQueue.claim(db, "pytest-retry-worker", max_concurrent_scans=99)
        assert again is not None and again.id == job.id
        state = JobQueue.fail(db, again, "boom again", retryable=True)
        db.refresh(again)
        assert state == "dead"
        assert again.status == "dead"
