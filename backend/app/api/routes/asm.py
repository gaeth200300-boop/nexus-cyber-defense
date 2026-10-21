"""Attack Surface Management (ASM): inventory posture, exposure, drift, re-scan.

Every figure here is an aggregate over stored assets/services/changes/findings.
Nothing is estimated or synthesised.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...config import settings
from ...core.constants import SEVERITY_RANK
from ...core.events import build_phases
from ...core.netguard import authorize_target, summarize_policy
from ...core.queue import JOB_DISCOVERY, JOB_HTTP_ANALYSIS, JOB_NETWORK_SCAN, JobQueue
from ...core.utils import to_iso_z, utcnow
from ...db import get_db
from ...models import Asset, AssetChange, Finding, Scan, Service
from ..deps import ProjectAccess, api_error, audit, project_access
from .common import paged

router = APIRouter(prefix="/projects/{project_id}/asm", tags=["asm"])

DEFAULT_PORTS = [80, 443, 8080, 8443, 22, 3306, 5432, 6379, 9200, 27017]


@router.get("/overview")
def asm_overview(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    pid = access.project.id
    now = utcnow()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    def grouped(query) -> dict[str, int]:
        return {str(key): int(count) for key, count in db.execute(query).all()}

    assets_by_type = grouped(select(Asset.type, func.count(Asset.id)).where(Asset.project_id == pid).group_by(Asset.type))
    assets_by_risk = grouped(
        select(Asset.risk_severity, func.count(Asset.id)).where(Asset.project_id == pid).group_by(Asset.risk_severity)
    )
    assets_by_state = grouped(
        select(Asset.state, func.count(Asset.id)).where(Asset.project_id == pid).group_by(Asset.state)
    )
    top_ports = [
        {"port": int(port), "protocol": protocol, "count": int(count)}
        for port, protocol, count in db.execute(
            select(Service.port, Service.protocol, func.count(Service.id))
            .where(Service.project_id == pid, Service.state == "open")
            .group_by(Service.port, Service.protocol)
            .order_by(func.count(Service.id).desc())
            .limit(15)
        ).all()
    ]
    service_names = [
        {"name": name or "unknown", "count": int(count)}
        for name, count in db.execute(
            select(Service.name, func.count(Service.id))
            .where(Service.project_id == pid)
            .group_by(Service.name)
            .order_by(func.count(Service.id).desc())
            .limit(10)
        ).all()
    ]
    changes_by_kind = grouped(
        select(AssetChange.kind, func.count(AssetChange.id))
        .where(AssetChange.project_id == pid, AssetChange.detected_at >= month_ago)
        .group_by(AssetChange.kind)
    )
    new_assets = int(
        db.execute(select(func.count(Asset.id)).where(Asset.project_id == pid, Asset.first_seen_at >= week_ago)).scalar_one()
    )
    unack_changes = int(
        db.execute(
            select(func.count(AssetChange.id)).where(AssetChange.project_id == pid, AssetChange.acknowledged_at.is_(None))
        ).scalar_one()
    )
    monitored = int(
        db.execute(select(func.count(Asset.id)).where(Asset.project_id == pid, Asset.is_monitored.is_(True))).scalar_one()
    )
    open_services = int(
        db.execute(select(func.count(Service.id)).where(Service.project_id == pid, Service.state == "open")).scalar_one()
    )
    last_discovery = db.execute(
        select(func.max(Scan.created_at)).where(
            Scan.project_id == pid,
            Scan.kind.in_(("asset_discovery", "network_scan", "dns_diagnostics")),
            Scan.status.in_(("completed", "partial")),
        )
    ).scalar_one_or_none()
    findings_by_asset = int(
        db.execute(
            select(func.count(func.distinct(Finding.asset_id))).where(
                Finding.project_id == pid, Finding.asset_id.is_not(None), Finding.status.in_(("open", "confirmed"))
            )
        ).scalar_one()
    )
    return {
        "assets": {
            "total": sum(assets_by_type.values()),
            "by_type": assets_by_type,
            "by_risk": assets_by_risk,
            "by_state": assets_by_state,
            "monitored": monitored,
            "new_last_7d": new_assets,
            "with_open_findings": findings_by_asset,
        },
        "services": {"open": open_services, "top_ports": top_ports, "by_name": service_names},
        "changes": {
            "last_30d": sum(changes_by_kind.values()),
            "by_kind": changes_by_kind,
            "unacknowledged": unack_changes,
        },
        "coverage": {
            "last_discovery_at": to_iso_z(last_discovery),
            "stale": bool(last_discovery is None or (now - last_discovery) > timedelta(days=14)),
        },
        "policy": {
            "global_private_targets": settings.allow_private_targets,
            "project_private_targets": access.project.allow_private_targets,
        },
    }


@router.get("/exposure")
def asm_exposure(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    q: str = Query(default="", max_length=200),
    min_severity: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=300),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Open services joined with their asset, ranked by the worst finding on that service/asset."""
    pid = access.project.id
    query = (
        select(Service, Asset)
        .join(Asset, Asset.id == Service.asset_id)
        .where(Service.project_id == pid, Service.state == "open")
    )
    if q:
        pattern = f"%{q.strip().lower()}%"
        query = query.where(
            func.lower(Asset.normalized_value).like(pattern) | func.lower(Service.name).like(pattern)
        )
    total = int(
        db.execute(
            select(func.count(Service.id))
            .join(Asset, Asset.id == Service.asset_id)
            .where(Service.project_id == pid, Service.state == "open")
        ).scalar_one()
    )
    rows = db.execute(query.order_by(Asset.normalized_value.asc(), Service.port.asc()).limit(limit).offset(offset)).all()

    asset_ids = sorted({asset.id for _service, asset in rows})
    severity_by_asset: dict[str, str] = {}
    counts_by_asset: dict[str, int] = {}
    if asset_ids:
        for asset_id, severity, count in db.execute(
            select(Finding.asset_id, Finding.severity, func.count(Finding.id))
            .where(Finding.asset_id.in_(asset_ids), Finding.status.in_(("open", "confirmed")))
            .group_by(Finding.asset_id, Finding.severity)
        ).all():
            counts_by_asset[asset_id] = counts_by_asset.get(asset_id, 0) + int(count)
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(severity_by_asset.get(asset_id, "info"), 0):
                severity_by_asset[asset_id] = severity

    items = []
    for service, asset in rows:
        worst = severity_by_asset.get(asset.id, "info")
        if min_severity and SEVERITY_RANK.get(worst, 0) < SEVERITY_RANK.get(min_severity, 0):
            continue
        items.append(
            {
                "service_id": service.id,
                "asset": {"id": asset.id, "value": asset.value, "type": asset.type},
                "port": service.port,
                "protocol": service.protocol,
                "name": service.name,
                "product": service.product,
                "version": service.version,
                "tls": service.tls or {},
                "worst_severity": worst,
                "open_findings": counts_by_asset.get(asset.id, 0),
                "last_seen_at": to_iso_z(service.last_seen_at),
            }
        )
    return paged(items, total, limit=limit, offset=offset)


@router.get("/monitors")
def asm_monitors(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    query = select(Asset).where(Asset.project_id == access.project.id, Asset.is_monitored.is_(True))
    total = int(
        db.execute(
            select(func.count(Asset.id)).where(Asset.project_id == access.project.id, Asset.is_monitored.is_(True))
        ).scalar_one()
    )
    rows = db.execute(query.order_by(Asset.last_seen_at.desc()).limit(limit).offset(offset)).scalars().all()
    return {
        **paged(
            [
                {
                    "id": a.id,
                    "type": a.type,
                    "value": a.value,
                    "risk_severity": a.risk_severity,
                    "last_seen_at": to_iso_z(a.last_seen_at),
                    "last_scanned_at": to_iso_z(a.last_scanned_at),
                    "discovered_by_scan_id": a.discovered_by_scan_id,
                }
                for a in rows
            ],
            total,
            limit=limit,
            offset=offset,
        ),
        "note": "Monitoring is a scheduling hint: nothing is contacted unless an active scope entry authorizes it.",
    }


class RescanBody(BaseModel):
    asset_ids: list[str] = Field(default_factory=list, max_length=200)
    ports: list[int] = Field(default_factory=list, max_length=200)


def _create_asm_scan(
    db: Session,
    access: ProjectAccess,
    *,
    kind: str,
    profile: str,
    job_type: str,
    name: str,
    targets: list[dict[str, Any]],
    options: dict[str, Any],
    decisions: list[dict[str, Any]],
    require_active: bool,
) -> Scan:
    scan = Scan(
        project_id=access.project.id,
        name=name[:200],
        kind=kind,
        profile=profile,
        status="queued",
        progress=0,
        phases=build_phases(kind),
        targets=targets,
        options=options,
        authorization_snapshot={
            "created_at": to_iso_z(utcnow()),
            "created_by": access.user_id,
            "profile": profile,
            "require_active": require_active,
            "decisions": decisions,
            "scopes": [
                {
                    "id": d.get("scope_id"),
                    "value": d.get("scope_value"),
                    "allow_active": d.get("allow_active"),
                }
                for d in decisions
                if d.get("scope_id")
            ],
            "policy": summarize_policy(),
        },
        requested_by=access.user_id,
    )
    db.add(scan)
    db.flush()
    JobQueue.enqueue(
        db,
        type=job_type,
        project_id=access.project.id,
        scan_id=scan.id,
        priority=120,
        timeout_seconds=1200,
        max_attempts=2,
        dedup_key=f"scan:{scan.id}",
    )
    return scan


@router.post("/rescan", status_code=status.HTTP_201_CREATED)
def asm_rescan(
    body: RescanBody,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(Asset).where(Asset.project_id == access.project.id, Asset.is_monitored.is_(True))
    if body.asset_ids:
        query = query.where(Asset.id.in_(body.asset_ids))
    assets = db.execute(query.limit(200)).scalars().all()
    if not assets:
        raise api_error("no_monitored_assets", "There are no monitored assets to rescan.", status.HTTP_404_NOT_FOUND)
    ports = [p for p in (body.ports or DEFAULT_PORTS) if isinstance(p, int) and 1 <= p <= 65535][:200]

    domains: list[dict[str, Any]] = []
    ips: list[dict[str, Any]] = []
    urls: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    decisions_by_asset: dict[str, dict[str, Any]] = {}

    for asset in assets:
        host = asset.normalized_value
        require_active = asset.type in ("ip", "host")
        decision = authorize_target(db, access.project.id, host, require_active=require_active)
        if not decision.allowed:
            skipped.append({"asset_id": asset.id, "value": asset.value, "reason": decision.reason, "detail": decision.detail})
            continue
        decisions_by_asset[asset.id] = {
            "host": decision.host,
            "scope_id": decision.scope_id,
            "scope_value": decision.scope_value,
            "allow_active": decision.allow_active,
            "asset_id": asset.id,
        }
        asset.last_scanned_at = utcnow()
        if asset.type in ("ip", "host"):
            ips.append({"type": "host", "value": asset.value, "host": host, "scheme": "https", "port": None, "asset_id": asset.id})
        elif asset.type == "url":
            urls.append({"type": "url", "value": asset.value, "url": asset.value, "host": host, "scheme": "https", "port": None, "asset_id": asset.id})
        else:
            domains.append({"type": "host", "value": asset.value, "host": host, "scheme": "https", "port": None, "asset_id": asset.id})
    db.commit()

    created: list[dict[str, Any]] = []
    if domains:
        scan = _create_asm_scan(
            db, access, kind="asset_discovery", profile="passive", job_type=JOB_DISCOVERY,
            name=f"ASM discovery — {utcnow().strftime('%Y-%m-%d %H:%M')}",
            targets=domains, options={},
            decisions=[decisions_by_asset[t["asset_id"]] for t in domains if t.get("asset_id") in decisions_by_asset],
            require_active=False,
        )
        created.append({"scan_id": scan.id, "kind": scan.kind, "targets": len(domains)})
    if urls:
        scan = _create_asm_scan(
            db, access, kind="http_analysis", profile="passive", job_type=JOB_HTTP_ANALYSIS,
            name=f"ASM HTTP analysis — {utcnow().strftime('%Y-%m-%d %H:%M')}",
            targets=urls, options={},
            decisions=[decisions_by_asset[t["asset_id"]] for t in urls if t.get("asset_id") in decisions_by_asset],
            require_active=False,
        )
        created.append({"scan_id": scan.id, "kind": scan.kind, "targets": len(urls)})
    if ips:
        scan = _create_asm_scan(
            db, access, kind="network_scan", profile="safe_active", job_type=JOB_NETWORK_SCAN,
            name=f"ASM port sweep — {utcnow().strftime('%Y-%m-%d %H:%M')}",
            targets=ips, options={"ports": ports},
            decisions=[decisions_by_asset[t["asset_id"]] for t in ips if t.get("asset_id") in decisions_by_asset],
            require_active=True,
        )
        created.append({"scan_id": scan.id, "kind": scan.kind, "targets": len(ips)})
    db.commit()

    audit(db, access.auth, "asm.rescan", project_id=access.project.id, meta={"scans": created, "skipped": len(skipped)})
    return {
        "scans": created,
        "skipped": skipped,
        "note": "Only monitored assets with active authorization were queued. Skipped assets are listed with the exact reason.",
    }
