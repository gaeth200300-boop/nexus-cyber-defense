"""Engine primitives shared by every scanner: context, cancellation, result model."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.events import emit, set_phase
from ..core.netguard import allow_private_for_project
from ..models import Project, Scan
from ..services.findings import save_finding

ENGINE_NAME = "nexus-core"
ENGINE_VERSION = "0.1.0"

log = logging.getLogger("nexus.engines")


class ScanCanceled(Exception):
    """Raised cooperatively when the operator cancels a running scan."""


@dataclass
class EngineResult:
    findings: int = 0
    assets: int = 0
    services: int = 0
    notes: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


# Concurrency and politeness limits enforced for every engine.
MAX_TARGET_CONCURRENCY = 4
REQUEST_DELAY_SECONDS = 0.15  # minimum spacing between requests to the same host


class EngineContext:
    """Everything an engine needs: DB session, scan, project, policy and helpers."""

    def __init__(self, db: Session, scan: Scan, project: Project, *, worker_id: str = "worker") -> None:
        self.db = db
        self.scan = scan
        self.project = project
        self.worker_id = worker_id
        self.logger = logging.getLogger(f"nexus.engine.{scan.kind}")
        self.allow_private = allow_private_for_project(db, project.id)
        self.sem = asyncio.Semaphore(MAX_TARGET_CONCURRENCY)
        self.stats: dict[str, Any] = {}

    # ------------------------------------------------------------------ policy
    @property
    def require_active(self) -> bool:
        return self.scan.profile in ("safe_active", "zap_active")

    def check_cancel(self) -> None:
        flag = self.db.execute(select(Scan.cancel_requested).where(Scan.id == self.scan.id)).scalar_one_or_none()
        if flag:
            raise ScanCanceled(f"scan {self.scan.id} canceled by operator")

    # ------------------------------------------------------------------ events
    def emit(
        self,
        message: str,
        *,
        level: str = "info",
        kind: str = "log",
        phase: str = "",
        data: dict[str, Any] | None = None,
    ) -> None:
        emit(
            self.db,
            project_id=self.project.id,
            scan_id=self.scan.id,
            level=level,
            kind=kind,
            message=message,
            phase=phase,
            data=data,
        )
        if level in ("warn", "error"):
            self.logger.warning("%s", message)
        self.db.commit()

    def phase(self, key: str, status: str, *, progress: int | None = None) -> None:
        set_phase(self.db, self.scan, key, status, progress=progress, commit=True)

    # ----------------------------------------------------------------- findings
    def save(self, **kwargs: Any):
        findings, created = save_finding(
            self.db,
            project_id=self.project.id,
            scan=self.scan,
            **kwargs,
        )
        self.db.commit()
        return findings, created

    # -------------------------------------------------------------------- util
    async def gather(self, tasks: list[Awaitable[Any]]) -> list[Any]:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[Any] = []
        for item in results:
            if isinstance(item, Exception):
                if isinstance(item, ScanCanceled):
                    raise item
                self.logger.debug("engine task error: %s", item)
                continue
            out.append(item)
        return out

    async def run_limited(self, fn: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        async with self.sem:
            self.check_cancel()
            return await fn(*args, **kwargs)


def target_host(target: dict[str, Any]) -> str:
    return str(target.get("host") or target.get("value") or "").strip()


def target_url(target: dict[str, Any], *, default_scheme: str = "https") -> str:
    if target.get("url"):
        return str(target["url"])
    scheme = target.get("scheme") or default_scheme
    host = target_host(target)
    port = target.get("port")
    if port and port not in (80, 443):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"
