"""Projects, membership, and authorization scopes (Rules of Engagement).

The scope table is the legal heart of the platform: no scan target may be
contacted unless an *active, unexpired* scope entry matches it (enforced again
independently at run time by `core.netguard`). Scope entries can additionally be
ownership-verified via a DNS TXT record or an HTTP well-known file.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import secrets
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...config import settings
from ...core.constants import (
    DEFAULT_PROJECT_RETENTION_DAYS,
    PROJECT_KINDS,
    PROJECT_ROLES,
    ROLE_POWER,
    SCOPE_KINDS,
    SCOPE_VERIFICATION_METHODS,
)
from ...core.egress import fetch_public
from ...core.netguard import (
    CLOUD_METADATA_HOSTS,
    CLOUD_METADATA_IPS,
    LOCAL_HOSTNAMES,
    check_ip_allowed,
)
from ...core.queue import JobQueue
from ...core.utils import normalize_host, parse_target_url, slugify, to_iso_z, utcnow
from ...db import get_db
from ...models import (
    Alert,
    Asset,
    Finding,
    Incident,
    LogEvent,
    LogSource,
    Project,
    ProjectMember,
    Report,
    Scan,
    Scope,
    Service,
    User,
)
from ...services.findings import severity_counts
from ..deps import AuthContext, ProjectAccess, api_error, audit, project_access, require_scope, write_scope_guard
from .common import parse_dt

log = logging.getLogger("nexus.api.projects")

router = APIRouter(prefix="/projects", tags=["projects"])

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")

ACTIVE_SCOPE_LABELS = {
    "loopback_and_local_hostnames": "Loopback and local hostnames can never be authorized.",
    "cloud_metadata_hostname": "Cloud metadata hostnames are blocked unconditionally.",
}


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------
def project_public(project: Project, *, membership_role: str | None = None, counts: dict[str, Any] | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": project.id,
        "name": project.name,
        "slug": project.slug,
        "description": project.description,
        "kind": project.kind,
        "allow_private_targets": project.allow_private_targets,
        "retention_days": project.retention_days,
        "settings": project.settings or {},
        "archived": project.archived_at is not None,
        "created_at": to_iso_z(project.created_at),
        "updated_at": to_iso_z(project.updated_at),
        "created_by": project.created_by,
    }
    if membership_role is not None:
        data["role"] = membership_role
    if counts is not None:
        data["counts"] = counts
    return data


def member_public(member: ProjectMember, user: User | None = None) -> dict[str, Any]:
    return {
        "id": member.id,
        "user_id": member.user_id,
        "role": member.role,
        "created_at": to_iso_z(member.created_at),
        "email": user.email if user else "",
        "name": (user.full_name or user.email) if user else "",
        "global_role": user.role if user else "",
    }


def scope_public(scope: Scope) -> dict[str, Any]:
    return {
        "id": scope.id,
        "kind": scope.kind,
        "value": scope.value,
        "include_subdomains": scope.include_subdomains,
        "allow_active": scope.allow_active,
        "authorization_ref": scope.authorization_ref,
        "authorized_by": scope.authorized_by,
        "verified_method": scope.verified_method,
        "verified_at": to_iso_z(scope.verified_at),
        "verification_evidence": scope.verification_evidence or "",
        "expires_at": to_iso_z(scope.expires_at),
        "is_active": scope.is_active,
        "expired": bool(scope.expires_at and scope.expires_at <= utcnow()),
        "notes": scope.notes,
        "created_at": to_iso_z(scope.created_at),
        "updated_at": to_iso_z(scope.updated_at),
    }


# ---------------------------------------------------------------------------
# Scope value validation
# ---------------------------------------------------------------------------
def _host_blocked(host: str) -> tuple[bool, str]:
    if host in LOCAL_HOSTNAMES or host.endswith(".localhost") or host.endswith(".local"):
        return True, "loopback_and_local_hostnames"
    if host in CLOUD_METADATA_HOSTS:
        return True, "cloud_metadata_hostname"
    return False, ""


def _validate_scope_value(kind: str, raw: str, project: Project) -> str:
    value = (raw or "").strip()
    if not value:
        raise api_error("invalid_scope_value", "A scope value is required.")
    allow_private = bool(settings.allow_private_targets and project.allow_private_targets)

    if kind == "domain":
        host = normalize_host(value)
        if not _DOMAIN_RE.match(host):
            raise api_error("invalid_scope_value", f"'{value}' is not a valid domain name.")
        blocked, reason = _host_blocked(host)
        if blocked:
            raise api_error("blocked_target", ACTIVE_SCOPE_LABELS.get(reason, "This hostname can never be authorized."), reason=reason)
        return host

    if kind == "ip":
        try:
            addr = ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            raise api_error("invalid_scope_value", f"'{value}' is not a valid IP address.")
        if str(addr) in CLOUD_METADATA_IPS:
            raise api_error("blocked_target", "Cloud metadata addresses are blocked unconditionally.", reason="cloud_metadata_address")
        ok, reason = check_ip_allowed(str(addr), allow_private=allow_private)
        if not ok:
            hint = ""
            if reason == "private_address_not_authorized":
                hint = " Private ranges require NEXUS_ALLOW_PRIVATE_TARGETS=true in backend\\.env AND 'allow_private_targets' on the project."
            raise api_error("blocked_target", f"IP '{addr}' cannot be authorized ({reason}).{hint}", reason=reason)
        return str(addr)

    if kind == "cidr":
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise api_error("invalid_scope_value", f"'{value}' is not a valid CIDR network.")
        if network.prefixlen == 0:
            raise api_error("invalid_scope_value", "A /0 network would authorize the whole internet — refused.")
        if network.network_address.is_loopback or network.is_loopback:
            raise api_error("blocked_target", "Loopback networks can never be authorized.", reason="loopback_address")
        if network.is_multicast or network.network_address.is_unspecified:
            raise api_error("blocked_target", "Multicast/unspecified networks are not valid scan scopes.", reason="reserved_address")
        for meta_ip in CLOUD_METADATA_IPS:
            try:
                if ipaddress.ip_address(meta_ip) in network:
                    raise api_error(
                        "blocked_target",
                        f"This network contains cloud metadata address {meta_ip}, which is blocked unconditionally.",
                        reason="cloud_metadata_address",
                    )
            except ValueError:
                continue
        if network.is_private and not allow_private:
            hint = " Private ranges require NEXUS_ALLOW_PRIVATE_TARGETS=true in backend\\.env AND 'allow_private_targets' on the project."
            raise api_error("blocked_target", f"Network {network} is private and not currently authorized.{hint}", reason="private_address_not_authorized")
        return str(network)

    if kind == "url":
        try:
            host, scheme, port = parse_target_url(value)
        except ValueError as exc:
            raise api_error("invalid_scope_value", f"'{value}' is not a valid http(s) URL ({exc}).")
        blocked, reason = _host_blocked(host)
        if blocked:
            raise api_error("blocked_target", ACTIVE_SCOPE_LABELS.get(reason, "This URL can never be authorized."), reason=reason)
        return f"{scheme}://{host}" + (f":{port}" if port else "")

    raise api_error("invalid_scope_kind", f"Unknown scope kind '{kind}'.", allowed=list(SCOPE_KINDS))


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=2000)
    kind: str = Field(default="assessment")
    slug: str = Field(default="", max_length=80)
    allow_private_targets: bool = False


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    kind: str | None = None
    allow_private_targets: bool | None = None
    retention_days: int | None = Field(default=None, ge=7, le=3650)
    settings: dict[str, Any] | None = None


class MemberCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    role: str = Field(default="analyst")


class MemberUpdate(BaseModel):
    role: str


class ScopeCreate(BaseModel):
    kind: str
    value: str = Field(min_length=1, max_length=255)
    include_subdomains: bool = True
    allow_active: bool = False
    authorization_ref: str = Field(default="", max_length=2000)
    authorized_by: str = Field(default="", max_length=200)
    expires_at: str | None = None
    notes: str = Field(default="", max_length=2000)


class ScopeUpdate(BaseModel):
    include_subdomains: bool | None = None
    allow_active: bool | None = None
    authorization_ref: str | None = Field(default=None, max_length=2000)
    authorized_by: str | None = Field(default=None, max_length=200)
    expires_at: str | None = None
    clear_expiry: bool = False
    notes: str | None = Field(default=None, max_length=2000)


class VerifyChallenge(BaseModel):
    method: str = Field(default="dns_txt")


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------
@router.get("")
def list_projects(
    auth: AuthContext = Depends(require_scope("read:projects")),
    db: Session = Depends(get_db),
    include_archived: bool = Query(default=False),
) -> dict[str, Any]:
    statement = select(Project)
    if not include_archived:
        statement = statement.where(Project.archived_at.is_(None))
    if auth.user.role in ("owner", "admin"):
        rows = db.execute(statement.order_by(Project.created_at.desc())).scalars().all()
        memberships: dict[str, str] = {}
    else:
        memberships = {
            m.project_id: m.role
            for m in db.execute(select(ProjectMember).where(ProjectMember.user_id == auth.user_id)).scalars().all()
        }
        rows = db.execute(statement.where(Project.id.in_(list(memberships) or [""]))).scalars().all()

    items = []
    for project in rows:
        counts = {
            "assets": int(db.execute(select(func.count(Asset.id)).where(Asset.project_id == project.id)).scalar_one()),
            "open_findings": int(
                db.execute(
                    select(func.count(Finding.id)).where(
                        Finding.project_id == project.id,
                        Finding.status.in_(("open", "confirmed")),
                    )
                ).scalar_one()
            ),
            "active_scans": int(
                db.execute(
                    select(func.count(Scan.id)).where(Scan.project_id == project.id, Scan.status.in_(("queued", "running")))
                ).scalar_one()
            ),
        }
        items.append(project_public(project, membership_role=memberships.get(project.id, "owner" if auth.user.role in ("owner", "admin") else None), counts=counts))
    return {"items": items, "total": len(items)}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_project(
    body: ProjectCreate,
    auth: AuthContext = Depends(require_scope("write:projects")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(auth)
    if ROLE_POWER.get(auth.user.role, 0) < ROLE_POWER["analyst"]:
        raise api_error("insufficient_role", "Creating projects requires the analyst role or higher.", status.HTTP_403_FORBIDDEN)
    if body.kind not in PROJECT_KINDS:
        raise api_error("invalid_kind", f"Kind must be one of {sorted(PROJECT_KINDS)}.")
    base_slug = slugify(body.slug or body.name)
    slug = base_slug
    suffix = 1
    while db.execute(select(Project.id).where(Project.slug == slug)).scalar_one_or_none():
        suffix += 1
        slug = f"{base_slug}-{suffix}"

    project = Project(
        name=body.name.strip(),
        slug=slug,
        description=body.description.strip(),
        kind=body.kind,
        allow_private_targets=bool(body.allow_private_targets and auth.is_admin),
        retention_days=DEFAULT_PROJECT_RETENTION_DAYS,
        created_by=auth.user_id,
    )
    db.add(project)
    db.flush()
    db.add(ProjectMember(project_id=project.id, user_id=auth.user_id, role="owner"))
    db.commit()
    audit(db, auth, "project.create", project_id=project.id, entity_type="project", entity_id=project.id, meta={"name": project.name, "kind": project.kind})
    return {"project": project_public(project, membership_role="owner")}


@router.get("/{project_id}")
def get_project(access: ProjectAccess = Depends(project_access("viewer")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"project": project_public(access.project, membership_role=access.role)}


@router.patch("/{project_id}")
def update_project(
    body: ProjectUpdate,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    project = access.project
    if body.name is not None:
        project.name = body.name.strip()
    if body.description is not None:
        project.description = body.description.strip()
    if body.kind is not None:
        if body.kind not in PROJECT_KINDS:
            raise api_error("invalid_kind", f"Kind must be one of {sorted(PROJECT_KINDS)}.")
        project.kind = body.kind
    if body.allow_private_targets is not None:
        if not access.auth.is_admin:
            raise api_error("insufficient_role", "Only admins can change the private-target policy.", status.HTTP_403_FORBIDDEN)
        project.allow_private_targets = bool(body.allow_private_targets)
    if body.retention_days is not None:
        project.retention_days = int(body.retention_days)
    if body.settings is not None:
        project.settings = body.settings
    db.commit()
    audit(db, access.auth, "project.update", project_id=project.id, entity_type="project", entity_id=project.id, meta=body.model_dump(exclude_none=True))
    return {"project": project_public(project, membership_role=access.role)}


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def archive_project(
    access: ProjectAccess = Depends(project_access("owner")),
    db: Session = Depends(get_db),
) -> None:
    if access.auth.user.role != "owner" and access.role != "owner":
        raise api_error("insufficient_role", "Only the project owner can archive it.", status.HTTP_403_FORBIDDEN)
    access.project.archived_at = utcnow()
    db.commit()
    audit(db, access.auth, "project.archive", project_id=access.project.id, entity_type="project", entity_id=access.project.id)
    return None


# ---------------------------------------------------------------------------
# Dashboard summary + timeline (all values come from the database)
# ---------------------------------------------------------------------------
@router.get("/{project_id}/summary")
def project_summary(access: ProjectAccess = Depends(project_access("viewer")), db: Session = Depends(get_db)) -> dict[str, Any]:
    pid = access.project.id

    def count(query) -> int:
        return int(db.execute(query).scalar_one() or 0)

    assets_total = count(select(func.count(Asset.id)).where(Asset.project_id == pid))
    assets_active = count(select(func.count(Asset.id)).where(Asset.project_id == pid, Asset.state == "active"))
    by_type = {
        kind: int(cnt)
        for kind, cnt in db.execute(
            select(Asset.type, func.count(Asset.id)).where(Asset.project_id == pid).group_by(Asset.type)
        ).all()
    }
    by_risk = {
        risk: int(cnt)
        for risk, cnt in db.execute(
            select(Asset.risk_severity, func.count(Asset.id)).where(Asset.project_id == pid).group_by(Asset.risk_severity)
        ).all()
    }
    services_open = count(select(func.count(Service.id)).where(Service.project_id == pid, Service.state == "open"))
    finding_counts = severity_counts(db, pid)
    findings_open = sum(finding_counts.values())
    findings_by_status = {
        state: int(cnt)
        for state, cnt in db.execute(
            select(Finding.status, func.count(Finding.id)).where(Finding.project_id == pid).group_by(Finding.status)
        ).all()
    }
    scans_total = count(select(func.count(Scan.id)).where(Scan.project_id == pid))
    scans_by_status = {
        state: int(cnt)
        for state, cnt in db.execute(
            select(Scan.status, func.count(Scan.id)).where(Scan.project_id == pid).group_by(Scan.status)
        ).all()
    }
    recent_scans = db.execute(
        select(Scan).where(Scan.project_id == pid).order_by(Scan.created_at.desc()).limit(5)
    ).scalars().all()
    alerts_open = count(
        select(func.count(Alert.id)).where(Alert.project_id == pid, Alert.status.in_(("new", "acknowledged", "investigating")))
    )
    incidents_open = count(select(func.count(Incident.id)).where(Incident.project_id == pid, Incident.status != "closed"))
    reports_total = count(select(func.count(Report.id)).where(Report.project_id == pid))
    sources_total = count(select(func.count(LogSource.id)).where(LogSource.project_id == pid))
    events_total = count(select(func.count(LogEvent.id)).where(LogEvent.project_id == pid))
    assets_with_findings = count(
        select(func.count(func.distinct(Finding.asset_id))).where(
            Finding.project_id == pid, Finding.asset_id.is_not(None), Finding.status.in_(("open", "confirmed"))
        )
    )
    last_scan_at = db.execute(select(func.max(Scan.created_at)).where(Scan.project_id == pid)).scalar_one_or_none()
    jobs = JobQueue.stats(db, pid)
    active_scopes = count(
        select(func.count(Scope.id)).where(Scope.project_id == pid, Scope.is_active.is_(True))
    )

    return {
        "project": project_public(access.project, membership_role=access.role),
        "assets": {"total": assets_total, "active": assets_active, "by_type": by_type, "by_risk": by_risk},
        "services": {"open": services_open},
        "findings": {
            "open_total": findings_open,
            "by_severity": finding_counts,
            "by_status": findings_by_status,
            "assets_with_open_findings": assets_with_findings,
        },
        "scans": {
            "total": scans_total,
            "by_status": scans_by_status,
            "recent": [
                {
                    "id": s.id,
                    "name": s.name,
                    "kind": s.kind,
                    "profile": s.profile,
                    "status": s.status,
                    "progress": s.progress,
                    "created_at": to_iso_z(s.created_at),
                    "finished_at": to_iso_z(s.finished_at),
                }
                for s in recent_scans
            ],
        },
        "jobs": jobs,
        "alerts": {"open": alerts_open},
        "incidents": {"open": incidents_open},
        "reports": {"total": reports_total},
        "soc": {"sources": sources_total, "events": events_total},
        "policy": {
            "authorization_scopes": active_scopes,
            "allow_private_targets": bool(settings.allow_private_targets and access.project.allow_private_targets),
        },
        "last_scan_at": to_iso_z(last_scan_at),
    }


@router.get("/{project_id}/timeline")
def project_timeline(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    days: int = Query(default=14, ge=1, le=90),
) -> dict[str, Any]:
    """Daily activity counts for charts — computed from stored rows only."""
    from datetime import timedelta

    since = (utcnow() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    pid = access.project.id

    def series(query) -> dict[str, int]:
        return {str(k): int(v) for k, v in db.execute(query).all()}

    scans = series(
        select(func.date(Scan.created_at), func.count(Scan.id)).where(Scan.project_id == pid, Scan.created_at >= since).group_by(func.date(Scan.created_at)),
    )
    findings = series(
        select(func.date(Finding.created_at), func.count(Finding.id)).where(Finding.project_id == pid, Finding.created_at >= since).group_by(func.date(Finding.created_at)),
    )
    alerts = series(
        select(func.date(Alert.created_at), func.count(Alert.id)).where(Alert.project_id == pid, Alert.created_at >= since).group_by(func.date(Alert.created_at)),
    )
    events = series(
        select(func.date(LogEvent.ingested_at), func.count(LogEvent.id)).where(LogEvent.project_id == pid, LogEvent.ingested_at >= since).group_by(func.date(LogEvent.ingested_at)),
    )

    days_list: list[str] = []
    cursor = since
    for _ in range(days):
        days_list.append(cursor.date().isoformat())
        cursor = cursor + timedelta(days=1)

    def aligned(mapping: dict[str, int]) -> list[int]:
        return [mapping.get(d, 0) for d in days_list]

    return {
        "days": days_list,
        "scans": aligned(scans),
        "findings": aligned(findings),
        "alerts": aligned(alerts),
        "log_events": aligned(events),
    }


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------
@router.get("/{project_id}/members")
def list_members(access: ProjectAccess = Depends(project_access("viewer")), db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(ProjectMember).where(ProjectMember.project_id == access.project.id)).scalars().all()
    users = {u.id: u for u in db.execute(select(User).where(User.id.in_([m.user_id for m in rows] or [""]))).scalars().all()}
    return {"items": [member_public(m, users.get(m.user_id)) for m in rows]}


@router.post("/{project_id}/members", status_code=status.HTTP_201_CREATED)
def add_member(
    body: MemberCreate,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if body.role not in PROJECT_ROLES:
        raise api_error("invalid_role", f"Role must be one of {list(PROJECT_ROLES)}.")
    if body.role == "owner" and access.role != "owner" and access.auth.user.role != "owner":
        raise api_error("insufficient_role", "Only a project owner can grant the owner role.", status.HTTP_403_FORBIDDEN)
    user = db.execute(select(User).where(User.email == body.email.lower().strip())).scalar_one_or_none()
    if user is None:
        raise api_error("user_not_found", f"No account exists for '{body.email}'.", status.HTTP_404_NOT_FOUND)
    existing = db.execute(
        select(ProjectMember).where(ProjectMember.project_id == access.project.id, ProjectMember.user_id == user.id)
    ).scalar_one_or_none()
    if existing:
        existing.role = body.role
        member = existing
    else:
        member = ProjectMember(project_id=access.project.id, user_id=user.id, role=body.role)
        db.add(member)
    db.commit()
    audit(db, access.auth, "project.member_add", project_id=access.project.id, entity_type="user", entity_id=user.id, meta={"role": body.role})
    return {"member": member_public(member, user)}


@router.patch("/{project_id}/members/{member_id}")
def update_member(
    member_id: str,
    body: MemberUpdate,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if body.role not in PROJECT_ROLES:
        raise api_error("invalid_role", f"Role must be one of {list(PROJECT_ROLES)}.")
    member = db.get(ProjectMember, member_id)
    if member is None or member.project_id != access.project.id:
        raise api_error("member_not_found", "Membership not found.", status.HTTP_404_NOT_FOUND)
    if member.role == "owner" and body.role != "owner":
        owners = int(
            db.execute(
                select(func.count(ProjectMember.id)).where(ProjectMember.project_id == access.project.id, ProjectMember.role == "owner")
            ).scalar_one()
        )
        if owners <= 1:
            raise api_error("last_owner", "You cannot demote the last owner of the project.")
    if body.role == "owner" and access.role != "owner" and access.auth.user.role != "owner":
        raise api_error("insufficient_role", "Only a project owner can grant the owner role.", status.HTTP_403_FORBIDDEN)
    member.role = body.role
    db.commit()
    user = db.get(User, member.user_id)
    audit(db, access.auth, "project.member_update", project_id=access.project.id, entity_type="user", entity_id=member.user_id, meta={"role": body.role})
    return {"member": member_public(member, user)}


@router.delete("/{project_id}/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    member_id: str,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> None:
    member = db.get(ProjectMember, member_id)
    if member is None or member.project_id != access.project.id:
        raise api_error("member_not_found", "Membership not found.", status.HTTP_404_NOT_FOUND)
    if member.user_id == access.user_id:
        # leaving voluntarily is always allowed for non-owners
        if member.role == "owner":
            raise api_error("last_owner", "Transfer ownership before leaving the project.")
    elif member.role == "owner" and access.role != "owner" and access.auth.user.role != "owner":
        raise api_error("insufficient_role", "Only a project owner can remove another owner.", status.HTTP_403_FORBIDDEN)
    db.delete(member)
    db.commit()
    audit(db, access.auth, "project.member_remove", project_id=access.project.id, entity_type="user", entity_id=member.user_id)
    return None


# ---------------------------------------------------------------------------
# Scopes (Rules of Engagement)
# ---------------------------------------------------------------------------
@router.get("/{project_id}/scopes")
def list_scopes(access: ProjectAccess = Depends(project_access("viewer")), db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(Scope).where(Scope.project_id == access.project.id).order_by(Scope.created_at.desc())).scalars().all()
    return {
        "items": [scope_public(s) for s in rows],
        "policy": {
            "global_private_targets": settings.allow_private_targets,
            "project_private_targets": access.project.allow_private_targets,
            "active_scanning_enabled": settings.active_scanning_enabled,
            "verification_methods": list(SCOPE_VERIFICATION_METHODS),
        },
    }


@router.post("/{project_id}/scopes", status_code=status.HTTP_201_CREATED)
def create_scope(
    body: ScopeCreate,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if body.kind not in SCOPE_KINDS:
        raise api_error("invalid_scope_kind", f"Kind must be one of {list(SCOPE_KINDS)}.")
    if body.allow_active and not settings.active_scanning_enabled:
        raise api_error(
            "active_scanning_disabled",
            "Active scanning is disabled platform-wide (NEXUS_ACTIVE_SCANNING_ENABLED=false).",
            status.HTTP_409_CONFLICT,
        )
    value = _validate_scope_value(body.kind, body.value, access.project)
    existing = db.execute(
        select(Scope).where(Scope.project_id == access.project.id, Scope.kind == body.kind, Scope.value == value)
    ).scalar_one_or_none()
    if existing:
        raise api_error("scope_exists", f"An authorization entry for '{value}' already exists.", status.HTTP_409_CONFLICT)
    expires_at = parse_dt(body.expires_at, field="expiry") if body.expires_at else None
    if expires_at and expires_at <= utcnow():
        raise api_error("invalid_expiry", "The expiry date is in the past.")
    scope = Scope(
        project_id=access.project.id,
        kind=body.kind,
        value=value,
        include_subdomains=bool(body.include_subdomains),
        allow_active=bool(body.allow_active),
        authorization_ref=body.authorization_ref.strip(),
        authorized_by=body.authorized_by.strip(),
        expires_at=expires_at,
        notes=body.notes.strip(),
        created_by=access.user_id,
    )
    db.add(scope)
    db.commit()
    audit(db, access.auth, "scope.create", project_id=access.project.id, entity_type="scope", entity_id=scope.id, meta={"kind": scope.kind, "value": scope.value, "allow_active": scope.allow_active})
    return {"scope": scope_public(scope)}


@router.patch("/{project_id}/scopes/{scope_id}")
def update_scope(
    scope_id: str,
    body: ScopeUpdate,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scope = db.get(Scope, scope_id)
    if scope is None or scope.project_id != access.project.id:
        raise api_error("scope_not_found", "Authorization entry not found.", status.HTTP_404_NOT_FOUND)
    if body.allow_active is not None:
        if body.allow_active and not settings.active_scanning_enabled:
            raise api_error("active_scanning_disabled", "Active scanning is disabled platform-wide.", status.HTTP_409_CONFLICT)
        scope.allow_active = bool(body.allow_active)
    if body.include_subdomains is not None:
        scope.include_subdomains = bool(body.include_subdomains)
    if body.authorization_ref is not None:
        scope.authorization_ref = body.authorization_ref.strip()
    if body.authorized_by is not None:
        scope.authorized_by = body.authorized_by.strip()
    if body.clear_expiry:
        scope.expires_at = None
    elif body.expires_at is not None:
        scope.expires_at = parse_dt(body.expires_at, field="expiry")
    if body.notes is not None:
        scope.notes = body.notes.strip()
    db.commit()
    audit(db, access.auth, "scope.update", project_id=access.project.id, entity_type="scope", entity_id=scope.id)
    return {"scope": scope_public(scope)}


@router.delete("/{project_id}/scopes/{scope_id}")
def deactivate_scope(
    scope_id: str,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scope = db.get(Scope, scope_id)
    if scope is None or scope.project_id != access.project.id:
        raise api_error("scope_not_found", "Authorization entry not found.", status.HTTP_404_NOT_FOUND)
    scope.is_active = not scope.is_active
    db.commit()
    audit(db, access.auth, "scope.toggle", project_id=access.project.id, entity_type="scope", entity_id=scope.id, meta={"is_active": scope.is_active})
    return {"scope": scope_public(scope)}


# ---------------------------------------------------------------------------
# Scope ownership verification (DNS TXT / well-known file)
# ---------------------------------------------------------------------------
def _scope_host(scope: Scope) -> str:
    if scope.kind == "url":
        try:
            host, _scheme, _port = parse_target_url(scope.value)
            return host
        except ValueError:
            return normalize_host(scope.value)
    return normalize_host(scope.value)


def _verification_payload(scope: Scope) -> dict[str, Any]:
    try:
        return json.loads(scope.verification_evidence or "{}")
    except (ValueError, TypeError):
        return {}


@router.post("/{project_id}/scopes/{scope_id}/verify/challenge")
def scope_verify_challenge(
    scope_id: str,
    body: VerifyChallenge,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scope = db.get(Scope, scope_id)
    if scope is None or scope.project_id != access.project.id:
        raise api_error("scope_not_found", "Authorization entry not found.", status.HTTP_404_NOT_FOUND)
    if body.method not in ("dns_txt", "http_file"):
        raise api_error("invalid_method", "Verification method must be 'dns_txt' or 'http_file'.")
    host = _scope_host(scope)
    token = f"nexus-verify={secrets.token_urlsafe(24)}"
    payload = {
        "challenge_method": body.method,
        "token": token,
        "created_at": to_iso_z(utcnow()),
        "created_by": access.user_id,
    }
    scope.verification_evidence = json.dumps(payload, ensure_ascii=False)
    if scope.verified_method in ("dns_txt", "http_file"):
        scope.verified_method = "none"
        scope.verified_at = None
    db.commit()

    if body.method == "dns_txt":
        instructions = {
            "method": "dns_txt",
            "record_type": "TXT",
            "record_name": f"_nexus-verify.{host}" if scope.kind == "domain" else host,
            "record_value": token,
            "note": "Publish the record, wait for DNS propagation, then confirm verification.",
        }
    else:
        scheme = "https"
        if scope.kind == "url" and "://" in scope.value:
            scheme = scope.value.split("://", 1)[0]
        instructions = {
            "method": "http_file",
            "url": f"{scheme}://{host}/.well-known/nexus-verify.txt",
            "file_content": token,
            "note": "Serve the file publicly with the exact content, then confirm verification.",
        }
    audit(db, access.auth, "scope.verify_challenge", project_id=access.project.id, entity_type="scope", entity_id=scope.id, meta={"method": body.method})
    return {"instructions": instructions, "scope": scope_public(scope)}


async def _dns_txt_values(name: str) -> list[str]:
    try:
        import dns.asyncresolver
        import dns.exception
    except ImportError:  # pragma: no cover
        return []
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8.0
    resolver.timeout = 5.0
    try:
        answer = await resolver.resolve(name, "TXT")
    except (dns.exception.DNSException, Exception):
        return []
    values: list[str] = []
    for record in answer:
        try:
            values.append(b"".join(record.strings).decode("utf-8", errors="replace"))
        except Exception:
            continue
    return values


@router.post("/{project_id}/scopes/{scope_id}/verify")
async def scope_verify(
    scope_id: str,
    access: ProjectAccess = Depends(project_access("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scope = db.get(Scope, scope_id)
    if scope is None or scope.project_id != access.project.id:
        raise api_error("scope_not_found", "Authorization entry not found.", status.HTTP_404_NOT_FOUND)
    payload = _verification_payload(scope)
    method = payload.get("challenge_method")
    token = payload.get("token")
    if not method or not token:
        raise api_error("no_challenge", "Request a verification challenge first.")
    host = _scope_host(scope)

    evidence: dict[str, Any] = {"method": method, "checked_at": to_iso_z(utcnow())}
    verified = False
    if method == "dns_txt":
        record_name = f"_nexus-verify.{host}" if scope.kind == "domain" else host
        values = await _dns_txt_values(record_name)
        verified = any(token in (value or "") for value in values)
        evidence.update({"record_name": record_name, "found_records": len(values), "values_preview": [v[:60] for v in values[:3]]})
        message = (
            "DNS TXT record verified — this project demonstrably controls the domain."
            if verified
            else f"No TXT record containing the token was found at '{record_name}'. Values seen: {len(values)}."
        )
    elif method == "http_file":
        scheme = "https"
        if scope.kind == "url" and "://" in scope.value:
            scheme = scope.value.split("://", 1)[0]
        url = f"{scheme}://{host}/.well-known/nexus-verify.txt"
        response = await fetch_public(url, allowed_hosts=[host], max_redirects=1, timeout=15.0, max_bytes=8192)
        body = response.text() if response.ok else ""
        verified = response.ok and token in body
        evidence.update({"url": url, "status": response.status, "error": response.error, "body_sha256_len": len(body)})
        message = (
            "Well-known file verified — ownership confirmed."
            if verified
            else f"Could not confirm the file at {url} ({response.error or 'token not present'})."
        )
    else:
        raise api_error("invalid_method", "Unknown verification method in the stored challenge.")

    if verified:
        scope.verified_method = method
        scope.verified_at = utcnow()
        scope.verification_evidence = json.dumps({**payload, **evidence, "verified": True}, ensure_ascii=False)
        db.commit()
        audit(db, access.auth, "scope.verified", project_id=access.project.id, entity_type="scope", entity_id=scope.id, meta={"method": method})
    else:
        scope.verification_evidence = json.dumps({**payload, **evidence, "verified": False}, ensure_ascii=False)
        db.commit()
        audit(db, access.auth, "scope.verify_failed", project_id=access.project.id, entity_type="scope", entity_id=scope.id, outcome="denied", meta={"method": method})

    return {"verified": verified, "message": message, "scope": scope_public(scope)}
