"""Asset inventory service: upserts, service fingerprinting, drift detection."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.constants import SEVERITY_RANK
from ..core.redaction import redact_text
from ..core.utils import normalize_host, stable_hash, utcnow
from ..models import Asset, AssetChange, Finding, Service

log = logging.getLogger("nexus.assets")


def normalized_for(asset_type: str, value: str) -> str:
    if asset_type in ("domain", "subdomain", "host"):
        return normalize_host(value)
    return (value or "").strip().lower()


def upsert_asset(
    db: Session,
    *,
    project_id: str,
    asset_type: str,
    value: str,
    scope_id: str | None = None,
    parent_id: str | None = None,
    source: str = "scan",
    scan_id: str | None = None,
    meta: dict[str, Any] | None = None,
    tags: list[str] | None = None,
) -> tuple[Asset, bool]:
    normalized = normalized_for(asset_type, value)
    asset = db.execute(
        select(Asset).where(
            Asset.project_id == project_id,
            Asset.type == asset_type,
            Asset.normalized_value == normalized,
        )
    ).scalar_one_or_none()

    if asset is None:
        asset = Asset(
            project_id=project_id,
            scope_id=scope_id,
            parent_id=parent_id,
            type=asset_type,
            value=value[:512],
            normalized_value=normalized[:512],
            state="active",
            source=source,
            discovered_by_scan_id=scan_id,
            tags=tags or [],
            meta=meta or {},
        )
        db.add(asset)
        db.flush()
        return asset, True

    asset.last_seen_at = utcnow()
    asset.state = "active"
    if meta:
        merged = dict(asset.meta or {})
        merged.update(meta)
        asset.meta = merged
    if tags:
        asset.tags = sorted(set((asset.tags or []) + tags))
    if scope_id and not asset.scope_id:
        asset.scope_id = scope_id
    if parent_id and not asset.parent_id:
        asset.parent_id = parent_id
    return asset, False


def upsert_service(
    db: Session,
    *,
    project_id: str,
    asset: Asset,
    port: int,
    protocol: str = "tcp",
    state: str = "open",
    name: str = "",
    product: str = "",
    version: str = "",
    banner: str = "",
    tls: dict[str, Any] | None = None,
    source: str = "scan",
) -> tuple[Service, bool, list[str]]:
    """Insert/update a service. Returns (service, created, changed_fields)."""
    service = db.execute(
        select(Service).where(Service.asset_id == asset.id, Service.port == port, Service.protocol == protocol)
    ).scalar_one_or_none()

    if service is None:
        safe_banner, _ = redact_text(banner or "", limit=600)
        service = Service(
            asset_id=asset.id,
            project_id=project_id,
            port=port,
            protocol=protocol,
            state=state,
            name=name[:80],
            product=product[:120],
            version=version[:120],
            banner=safe_banner or "",
            tls=tls or {},
            source=source,
        )
        db.add(service)
        db.flush()
        return service, True, []

    changed: list[str] = []
    for field, new_value in (("name", name), ("product", product), ("version", version), ("state", state)):
        old_value = getattr(service, field)
        if new_value and new_value != old_value:
            changed.append(field)
            setattr(service, field, new_value[:120] if field != "state" else new_value[:12])
    if banner:
        safe_banner, _ = redact_text(banner, limit=600)
        if safe_banner and safe_banner != service.banner:
            changed.append("banner")
            service.banner = safe_banner
    if tls:
        old_fp = (service.tls or {}).get("fingerprint_sha256", "")
        new_fp = tls.get("fingerprint_sha256", "")
        if new_fp and old_fp and new_fp != old_fp:
            changed.append("tls_certificate")
        merged = dict(service.tls or {})
        merged.update(tls)
        service.tls = merged
    service.last_seen_at = utcnow()
    return service, False, changed


def record_change(
    db: Session,
    *,
    project_id: str,
    kind: str,
    summary: str,
    severity: str = "info",
    asset_id: str | None = None,
    service_id: str | None = None,
    scan_id: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> AssetChange:
    change = AssetChange(
        project_id=project_id,
        asset_id=asset_id,
        service_id=service_id,
        scan_id=scan_id,
        kind=kind,
        severity=severity,
        summary=summary[:400],
        before=before or {},
        after=after or {},
    )
    db.add(change)
    return change


def diff_snapshots(before: dict[str, Any], after: dict[str, Any], keys: list[str]) -> dict[str, dict[str, Any]]:
    """Return {key: {before, after}} for keys whose value changed."""
    diff: dict[str, dict[str, Any]] = {}
    for key in keys:
        old = (before or {}).get(key)
        new = (after or {}).get(key)
        if old != new:
            diff[key] = {"before": old, "after": new}
    return diff


def detect_http_changes(
    db: Session,
    *,
    project_id: str,
    asset: Asset,
    scan_id: str | None,
    new_snapshot: dict[str, Any],
) -> list[str]:
    """Compare stored HTTP snapshot with the new one; emit AssetChange rows."""
    old_snapshot = (asset.meta or {}).get("http_snapshot") or {}
    changed_keys: list[str] = []
    if old_snapshot:
        headers_diff = diff_snapshots(
            old_snapshot.get("security_headers", {}), new_snapshot.get("security_headers", {}), sorted(
                set(old_snapshot.get("security_headers", {})) | set(new_snapshot.get("security_headers", {}))
            )
        )
        if headers_diff:
            changed_keys.append("security_headers")
            record_change(
                db,
                project_id=project_id,
                asset_id=asset.id,
                scan_id=scan_id,
                kind="header_change",
                severity="medium",
                summary="Security headers changed: " + ", ".join(sorted(headers_diff)[:6]),
                before=old_snapshot.get("security_headers", {}),
                after=new_snapshot.get("security_headers", {}),
            )
        if old_snapshot.get("status_code") != new_snapshot.get("status_code"):
            changed_keys.append("status_code")
            record_change(
                db,
                project_id=project_id,
                asset_id=asset.id,
                scan_id=scan_id,
                kind="state_change",
                severity="low",
                summary=f"HTTP status changed from {old_snapshot.get('status_code')} to {new_snapshot.get('status_code')}",
                before={"status_code": old_snapshot.get("status_code")},
                after={"status_code": new_snapshot.get("status_code")},
            )
        if old_snapshot.get("title") != new_snapshot.get("title") and new_snapshot.get("title"):
            changed_keys.append("title")
            record_change(
                db,
                project_id=project_id,
                asset_id=asset.id,
                scan_id=scan_id,
                kind="state_change",
                severity="info",
                summary="Page title changed",
                before={"title": old_snapshot.get("title")},
                after={"title": new_snapshot.get("title")},
            )

    merged = dict(asset.meta or {})
    merged["http_snapshot"] = new_snapshot
    asset.meta = merged
    return changed_keys


def recompute_asset_risk(db: Session, asset: Asset) -> None:
    """Asset risk = highest open finding on the asset itself or on its services."""
    rows = db.execute(
        select(Finding.severity)
        .where(
            Finding.asset_id == asset.id,
            Finding.status.in_(("open", "confirmed")),
        )
    ).scalars().all()
    severity = "info"
    score = 0.0
    for value in rows:
        if SEVERITY_RANK.get(value, 0) > SEVERITY_RANK.get(severity, 0):
            severity = value
    if severity != "info":
        score = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}.get(severity, 0.0)
    if asset.risk_severity != severity:
        asset.risk_severity = severity
    asset.risk_score = score


def asset_children(db: Session, asset_id: str) -> list[Asset]:
    return list(db.execute(select(Asset).where(Asset.parent_id == asset_id)).scalars().all())


def search_assets(
    db: Session,
    project_id: str,
    *,
    query: str = "",
    asset_type: str | None = None,
    state: str | None = None,
    risk: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Asset], int]:
    statement = select(Asset).where(Asset.project_id == project_id)
    count_statement = select(func.count(Asset.id)).where(Asset.project_id == project_id)
    if query:
        pattern = f"%{query.strip().lower()}%"
        statement = statement.where(Asset.normalized_value.like(pattern))
        count_statement = count_statement.where(Asset.normalized_value.like(pattern))
    if asset_type:
        statement = statement.where(Asset.type == asset_type)
        count_statement = count_statement.where(Asset.type == asset_type)
    if state:
        statement = statement.where(Asset.state == state)
        count_statement = count_statement.where(Asset.state == state)
    if risk:
        statement = statement.where(Asset.risk_severity == risk)
        count_statement = count_statement.where(Asset.risk_severity == risk)
    total = int(db.execute(count_statement).scalar_one())
    rows = db.execute(statement.order_by(Asset.last_seen_at.desc()).limit(limit).offset(offset)).scalars().all()
    return list(rows), total


def service_identity(service: Service) -> str:
    return f"{service.port}/{service.protocol} {service.name or 'unknown'}" + (f" {service.product} {service.version}".strip() and f" ({service.product} {service.version})".strip())


def asset_fingerprint(asset: Asset) -> str:
    return stable_hash(asset.project_id, asset.type, asset.normalized_value)[:16]
