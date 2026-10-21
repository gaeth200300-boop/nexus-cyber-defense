"""Shared test fixtures.

The test suite runs against a throwaway SQLite database and a deterministic
secret, so no developer data is touched and tokens are reproducible across
restarts. The in-process worker is disabled: tests that need a scan executed
claim and run the queued job synchronously via ``run_next_job``.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

TEST_DB = BACKEND_DIR / "storage" / "test_nexus.db"
TEST_DB.parent.mkdir(parents=True, exist_ok=True)
if TEST_DB.exists():
    TEST_DB.unlink()
for leftover in (TEST_DB.with_suffix(".db-wal"), TEST_DB.with_suffix(".db-shm")):
    if leftover.exists():
        leftover.unlink()

os.environ["NEXUS_ENV"] = "development"
os.environ["NEXUS_DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["NEXUS_SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["NEXUS_INPROCESS_WORKER"] = "false"
os.environ["NEXUS_ACTIVE_SCANNING_ENABLED"] = "true"
os.environ["NEXUS_ALLOW_PRIVATE_TARGETS"] = "false"
os.environ["NEXUS_RATE_LIMIT_PER_MINUTE"] = "10000"
os.environ["NEXUS_BOOTSTRAP_ADMIN_EMAIL"] = "owner@example.com"
os.environ["NEXUS_BOOTSTRAP_ADMIN_PASSWORD"] = "TestOwner!Nexus2026"

from fastapi.testclient import TestClient  # noqa: E402

from app import models  # noqa: E402,F401  (register all tables)
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client
    engine.dispose()


@pytest.fixture(scope="session")
def owner(client):
    """Bootstrap the owner once and return an authenticated session bundle."""
    r = client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "owner@example.com", "full_name": "Test Owner", "password": "TestOwner!Nexus2026"},
    )
    assert r.status_code == 201, r.text
    token = r.json()["access_token"]
    return {"token": token, "headers": {"Authorization": f"Bearer {token}"}, "user": r.json()["user"]}


@pytest.fixture()
def project(client, owner):
    r = client.post(
        "/api/v1/projects",
        headers=owner["headers"],
        json={"name": "Test Assessment", "kind": "assessment", "description": "pytest project"},
    )
    assert r.status_code == 201, r.text
    return r.json()["project"]


@pytest.fixture(autouse=True)
def clean_job_queue(client):
    """Each test starts with an empty queue so run_jobs() always sees its own job."""
    from sqlalchemy import delete

    from app.models import Job

    with SessionLocal() as db:
        db.execute(delete(Job))
        db.commit()
    yield


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Registration tests share one client IP; clear the sliding window per test."""
    from app.core.ratelimit import limiter

    limiter.reset()
    yield


def run_next_job() -> str:
    """Claim exactly one queued job and execute it in this process."""
    import asyncio

    from app.core.queue import JobQueue
    from app.worker import execute_job

    with SessionLocal() as db:
        job = JobQueue.claim(db, "test-worker")
    if job is None:
        return "none"
    return asyncio.run(execute_job(job.id, "test-worker"))


@pytest.fixture(scope="session")
def run_jobs():
    return run_next_job
