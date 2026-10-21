"""Asset inventory & attack-surface endpoints (all values from the database)."""

from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...core.constants import ASSET_TYPES
from ...core.utils import normalize_host, parse_target_url, to_iso_z, utcnow
from ...db import get_db
from ...models import Asset, AssetChange, Finding, Service
from ...services.assets import upsert_asset
from ..deps import ProjectAccess, api_error, audit, project_access
from .common import paged

router = APIRouter(prefix="/projects/{project_id}", tags=["assets"])


def asset_public(asset: Asset, *, services: int | None = None, findings: int | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": asset.id,
        "type": asset.type,
        "value": asset.value,
        "normalized_value": asset.normalized_value,
        "state": asset.state,
        "source": asset.source,
        "scope_id": asset.scope_id,
        "parent_id": asset.parent_id,
        "tags": asset.tags or [],
        "risk_severity": asset.risk_severity,
        "risk_score": asset.risk_score,
        "is_monitored": asset.is_monitored,
        "first_seen_at": to_iso_z(asset.first_seen_at),
        "last_seen_at": to_iso_z(asset.last_seen_at),
        "last_scanned_at": to_iso_z(asset.last_scanned_at),
        "created_at": to_iso_z(asset.created_at),
        "meta": asset.meta or {},
    }
    if services is not None:
        data["services_count"] = services
    if findings is not None:
        data["open_findings"] = findings
    return data


def service_public(service: Service, *, findings: int | None = None) -> dict[str, Any]:
    data = {
        "id": service.id,
        "asset_id": service.asset_id,
        "port": service.port,
        "protocol": service.protocol,
        "state": service.state,
        "name": service.name,
        "product": service.product,
        "version": service.version,
        "banner": service.banner,
        "tls": service.tls or {},
        "source": service.source,
        "first_seen_at": to_iso_z(service.first_seen_at),
        "last_seen_at": to_iso_z(service.last_seen_at),
        "meta": service.meta or {},
    }
    if findings is not None:
        data["open_findings"] = findings
    return data


def change_public(change: AssetChange) -> dict[str, Any]:
    return {
        "id": change.id,
        "asset_id": change.asset_id,
        "service_id": change.service_id,
        "scan_id": change.scan_id,
        "kind": change.kind,
        "severity": change.severity,
        "summary": change.summary,
        "before": change.before or {},
        "after": change.after or {},
        "detected_at": to_iso_z(change.detected_at),
        "acknowledged_at": to_iso_z(change.acknowledged_at),
    }


class AssetCreate(BaseModel):
    type: str = Field(default="domain")
    value: str = Field(min_length=1, max_length=512)
    tags: list[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=2000)


class AssetUpdate(BaseModel):
    tags: list[str] | None = None
    is_monitored: bool | None = None
    state: str | None = None
    notes: str | None = Field(default=None, max_length=2000)


def _clean_asset_type(asset_type: str) -> str:
    if asset_type not in ASSET_TYPES:
        raise api_error("invalid_asset_type", f"Asset type must be one of {list(ASSET_TYPES)}.")
    return asset_type


def _clean_asset_value(asset_type: str, value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise api_error("invalid_asset_value", "The asset value is empty.")
    if asset_type in ("url",):
        try:
            host, scheme, port = parse_target_url(raw)
        except ValueError as exc:
            raise api_error("invalid_asset_value", f"'{raw}' is not a valid URL ({exc}).")
        return f"{scheme}://{host}" + (f":{port}" if port else "")
    if asset_type == "ip":
        try:
            return str(ipaddress.ip_address(raw.strip("[]")))
        except ValueError:
            raise api_error("invalid_asset_value", f"'{raw}' is not a valid IP address.")
    if asset_type == "network":
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            raise api_error("invalid_asset_value", f"'{raw}' is not a valid network (CIDR).")
    if asset_type in ("domain", "subdomain", "host"):
        host = normalize_host(raw)
        if not host or " " in host or "/" in host:
            raise api_error("invalid_asset_value", f"'{raw}' is not a valid hostname.")
        return host
    return raw


@router.get("/assets")
def list_assets(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    q: str = Query(default="", max_length=200),
    type: str | None = Query(default=None),
    state: str | None = Query(default=None),
    risk: str | None = Query(default=None),
    monitored: bool | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    pid = access.project.id
    query = select(Asset).where(Asset.project_id == pid)
    count_query = select(func.count(Asset.id)).where(Asset.project_id == pid)
    if q:
        pattern = f"%{q.strip().lower()}%"
        query = query.where(Asset.normalized_value.like(pattern))
        count_query = count_query.where(Asset.normalized_value.like(pattern))
    if type:
        query = query.where(Asset.type == type)
        count_query = count_query.where(Asset.type == type)
    if state:
        query = query.where(Asset.state == state)
        count_query = count_query.where(Asset.state == state)
    if risk:
        query = query.where(Asset.risk_severity == risk)
        count_query = count_query.where(Asset.risk_severity == risk)
    if monitored is not None:
        query = query.where(Asset.is_monitored.is_(monitored))
        count_query = count_query.where(Asset.is_monitored.is_(monitored))
    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(query.order_by(Asset.last_seen_at.desc()).limit(limit).offset(offset)).scalars().all()

    ids = [a.id for a in rows]
    service_counts: dict[str, int] = {}
    finding_counts: dict[str, int] = {}
    if ids:
        service_counts = {
            aid: int(cnt)
            for aid, cnt in db.execute(
                select(Service.asset_id, func.count(Service.id)).where(Service.asset_id.in_(ids)).group_by(Service.asset_id)
            ).all()
        }
        finding_counts = {
            aid: int(cnt)
            for aid, cnt in db.execute(
                select(Finding.asset_id, func.count(Finding.id))
                .where(Finding.asset_id.in_(ids), Finding.status.in_(("open", "confirmed")))
                .group_by(Finding.asset_id)
            ).all()
        }
    items = [asset_public(a, services=service_counts.get(a.id, 0), findings=finding_counts.get(a.id, 0)) for a in rows]
    return paged(items, total, limit=limit, offset=offset)


@router.post("/assets", status_code=status.HTTP_201_CREATED)
def create_asset(
    body: AssetCreate,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    asset_type = _clean_asset_type(body.type)
    value = _clean_asset_value(asset_type, body.value)
    asset, created = upsert_asset(
        db,
        project_id=access.project.id,
        asset_type=asset_type,
        value=value,
        source="manual",
        meta={"notes": body.notes.strip()} if body.notes else {},
        tags=[t.strip()[:60] for t in body.tags if t.strip()][:20],
    )
    db.commit()
    audit(db, access.auth, "asset.create" if created else "asset.merge", project_id=access.project.id, entity_type="asset", entity_id=asset.id, meta={"type": asset.type, "value": asset.value})
    return {"asset": asset_public(asset, services=0, findings=0), "created": created}


@router.get("/assets/{asset_id}")
def get_asset(
    asset_id: str,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.project_id != access.project.id:
        raise api_error("asset_not_found", "Asset not found.", status.HTTP_404_NOT_FOUND)
    services = db.execute(select(Service).where(Service.asset_id == asset.id).order_by(Service.port.asc())).scalars().all()
    findings = db.execute(
        select(Finding)
        .where(Finding.asset_id == asset.id)
        .order_by(Finding.last_seen_at.desc())
        .limit(25)
    ).scalars().all()
    children = db.execute(select(Asset).where(Asset.parent_id == asset.id).limit(100)).scalars().all()
    changes = db.execute(
        select(AssetChange).where(AssetChange.asset_id == asset.id).order_by(AssetChange.detected_at.desc()).limit(20)
    ).scalars().all()
    parent = db.get(Asset, asset.parent_id) if asset.parent_id else None
    return {
        "asset": asset_public(asset, services=len(services), findings=sum(1 for f in findings if f.status in ("open", "confirmed"))),
        "parent": asset_public(parent) if parent else None,
        "children": [asset_public(a) for a in children],
        "services": [service_public(s) for s in services],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "status": f.status,
                "category": f.category,
                "target": f.target,
                "last_seen_at": to_iso_z(f.last_seen_at),
            }
            for f in findings
        ],
        "changes": [change_public(c) for c in changes],
    }


@router.patch("/assets/{asset_id}")
def update_asset(
    asset_id: str,
    body: AssetUpdate,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.project_id != access.project.id:
        raise api_error("asset_not_found", "Asset not found.", status.HTTP_404_NOT_FOUND)
    if body.tags is not None:
        asset.tags = sorted({t.strip()[:60] for t in body.tags if t.strip()})[:30]
    if body.is_monitored is not None:
        asset.is_monitored = bool(body.is_monitored)
    if body.state is not None:
        if body.state not in ("active", "inactive", "unknown"):
            raise api_error("invalid_state", "State must be active, inactive or unknown.")
        asset.state = body.state
    if body.notes is not None:
        meta = dict(asset.meta or {})
        meta["notes"] = body.notes.strip()
        asset.meta = meta
    db.commit()
    audit(db, access.auth, "asset.update", project_id=access.project.id, entity_type="asset", entity_id=asset.id)
    return {"asset": asset_public(asset)}


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: str,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> None:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.project_id != access.project.id:
        raise api_error("asset_not_found", "Asset not found.", status.HTTP_404_NOT_FOUND)
    value = asset.value
    db.delete(asset)
    db.commit()
    audit(db, access.auth, "asset.delete", project_id=access.project.id, entity_type="asset", entity_id=asset_id, meta={"value": value})
    return None


@router.get("/assets/{asset_id}/services")
def list_asset_services(
    asset_id: str,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.project_id != access.project.id:
        raise api_error("asset_not_found", "Asset not found.", status.HTTP_404_NOT_FOUND)
    rows = db.execute(select(Service).where(Service.asset_id == asset.id).order_by(Service.port.asc())).scalars().all()
    finding_counts = {
        sid: int(cnt)
        for sid, cnt in db.execute(
            select(Finding.service_id, func.count(Finding.id))
            .where(Finding.asset_id == asset.id, Finding.status.in_(("open", "confirmed")))
            .group_by(Finding.service_id)
        ).all()
    }
    return {"items": [service_public(s, findings=finding_counts.get(s.id, 0)) for s in rows]}


@router.get("/changes")
def list_changes(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    kind: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    acknowledged: bool | None = Query(default=None),
    asset_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    query = select(AssetChange).where(AssetChange.project_id == access.project.id)
    count_query = select(func.count(AssetChange.id)).where(AssetChange.project_id == access.project.id)
    if kind:
        query = query.where(AssetChange.kind == kind)
        count_query = count_query.where(AssetChange.kind == kind)
    if severity:
        query = query.where(AssetChange.severity == severity)
        count_query = count_query.where(AssetChange.severity == severity)
    if acknowledged is True:
        query = query.where(AssetChange.acknowledged_at.is_not(None))
        count_query = count_query.where(AssetChange.acknowledged_at.is_not(None))
    elif acknowledged is False:
        query = query.where(AssetChange.acknowledged_at.is_(None))
        count_query = count_query.where(AssetChange.acknowledged_at.is_(None))
    if asset_id:
        query = query.where(AssetChange.asset_id == asset_id)
        count_query = count_query.where(AssetChange.asset_id == asset_id)
    total = int(db.execute(count_query).scalar_one())
    rows = db.execute(query.order_by(AssetChange.detected_at.desc()).limit(limit).offset(offset)).scalars().all()
    return paged([change_public(c) for c in rows], total, limit=limit, offset=offset)


@router.post("/changes/{change_id}/ack")
def acknowledge_change(
    change_id: str,
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    change = db.get(AssetChange, change_id)
    if change is None or change.project_id != access.project.id:
        raise api_error("change_not_found", "Change not found.", status.HTTP_404_NOT_FOUND)
    if change.acknowledged_at is None:
        change.acknowledged_at = utcnow()
        change.acknowledged_by = access.user_id
        db.commit()
        audit(db, access.auth, "change.acknowledge", project_id=access.project.id, entity_type="asset_change", entity_id=change.id)
    return {"change": change_public(change)}


@router.post("/changes/ack-all")
def acknowledge_all_changes(
    access: ProjectAccess = Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = db.execute(
        select(AssetChange).where(AssetChange.project_id == access.project.id, AssetChange.acknowledged_at.is_(None))
    ).scalars().all()
    for change in rows:
        change.acknowledged_at = utcnow()
        change.acknowledged_by = access.user_id
    db.commit()
    audit(db, access.auth, "change.acknowledge_all", project_id=access.project.id, meta={"count": len(rows)})
    return {"acknowledged": len(rows)}
