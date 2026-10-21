"""Shared API dependencies: authentication, roles, project access, limits, audit.

Authentication accepts either a JWT access token (interactive sessions) or an
X-API-Key header (automation). Both resolve to the same `AuthContext`, so every
route checks the same permissions regardless of how the caller authenticated.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..core.audit import record as audit_record
from ..core.constants import ROLE_POWER
from ..core.ratelimit import limiter
from ..core.utils import utcnow
from ..db import get_db
from ..models import ApiKey, Project, ProjectMember, User
from ..security import decode_token, hash_api_key

log = logging.getLogger("nexus.api.auth")


def api_error(code: str, message: str, status_code: int = 400, **extra: Any) -> HTTPException:
    """Consistent error body: {"code", "message", ...}."""
    payload = {"code": code, "message": message, **extra}
    return HTTPException(status_code=status_code, detail=payload)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "")[:64]


@dataclass
class AuthContext:
    user: User
    method: str  # "jwt" | "api_key"
    api_key: ApiKey | None = None
    ip: str = ""
    user_agent: str = ""
    scopes: list[str] = field(default_factory=list)

    @property
    def user_id(self) -> str:
        return self.user.id

    @property
    def label(self) -> str:
        return self.user.full_name or self.user.email

    @property
    def is_admin(self) -> bool:
        return ROLE_POWER.get(self.user.role, 0) >= ROLE_POWER["admin"]

    def has_scope(self, needed: str) -> bool:
        if self.method != "api_key":
            return True
        if not self.scopes:
            return False
        if needed in self.scopes or "*" in self.scopes:
            return True
        family = needed.split(":")[-1]
        return f"*:{family}" in self.scopes


def get_auth(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    auth_header = request.headers.get("authorization", "")
    api_key_header = request.headers.get("x-api-key", "")
    ip = client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:300]

    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        payload = decode_token(token, expected_type="access")
        if not payload:
            raise api_error("invalid_token", "The access token is invalid or has expired.", status.HTTP_401_UNAUTHORIZED)
        user = db.get(User, str(payload.get("sub", "")))
        if user is None or not user.is_active:
            raise api_error("account_disabled", "This account is disabled or no longer exists.", status.HTTP_401_UNAUTHORIZED)
        if int(payload.get("tv", 0)) != int(user.token_version or 0):
            raise api_error("session_revoked", "This session was revoked. Sign in again.", status.HTTP_401_UNAUTHORIZED)
        _enforce_rate_limit(f"user:{user.id}", settings.rate_limit_per_minute)
        return AuthContext(user=user, method="jwt", ip=ip, user_agent=user_agent)

    if api_key_header:
        key_hash = hash_api_key(api_key_header.strip())
        api_key = db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash)).scalar_one_or_none()
        if api_key is None or api_key.revoked_at is not None:
            raise api_error("invalid_api_key", "The API key is invalid or revoked.", status.HTTP_401_UNAUTHORIZED)
        if api_key.expires_at is not None and api_key.expires_at < utcnow():
            raise api_error("expired_api_key", "The API key has expired.", status.HTTP_401_UNAUTHORIZED)
        user = db.get(User, api_key.user_id)
        if user is None or not user.is_active:
            raise api_error("account_disabled", "This account is disabled.", status.HTTP_401_UNAUTHORIZED)
        _enforce_rate_limit(f"key:{api_key.id}", int(api_key.rate_limit_per_min or 120))
        api_key.last_used_at = utcnow()
        db.commit()
        return AuthContext(
            user=user,
            method="api_key",
            api_key=api_key,
            ip=ip,
            user_agent=user_agent,
            scopes=list(api_key.scopes or []),
        )

    raise api_error("unauthenticated", "Sign in first (Authorization: Bearer) or provide X-API-Key.", status.HTTP_401_UNAUTHORIZED)


def _enforce_rate_limit(key: str, limit: int) -> None:
    allowed, remaining, retry_after = limiter.check(key, limit)
    if not allowed:
        raise api_error(
            "rate_limited",
            f"Rate limit exceeded — retry in {retry_after}s.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            retry_after=retry_after,
        )


def require_global_role(minimum: str) -> Callable[..., AuthContext]:
    """Dependency factory: caller's global role must be >= `minimum`."""

    def dependency(auth: AuthContext = Depends(get_auth)) -> AuthContext:
        needed = ROLE_POWER.get(minimum, 0)
        if ROLE_POWER.get(auth.user.role, 0) < needed:
            raise api_error(
                "insufficient_role",
                f"This action requires the '{minimum}' role or higher.",
                status.HTTP_403_FORBIDDEN,
                required=minimum,
                current=auth.user.role,
            )
        return auth

    return dependency


def require_scope(scope: str) -> Callable[..., AuthContext]:
    def dependency(auth: AuthContext = Depends(get_auth)) -> AuthContext:
        if not auth.has_scope(scope):
            raise api_error(
                "insufficient_scope",
                f"This API key is missing the '{scope}' scope.",
                status.HTTP_403_FORBIDDEN,
                required=scope,
            )
        return auth

    return dependency


# ---------------------------------------------------------------------------
# Project access
# ---------------------------------------------------------------------------
@dataclass
class ProjectAccess:
    project: Project
    role: str  # effective project role
    auth: AuthContext

    @property
    def user_id(self) -> str:
        return self.auth.user_id

    def require(self, minimum: str) -> None:
        if ROLE_POWER.get(self.role, 0) < ROLE_POWER.get(minimum, 0):
            raise api_error(
                "insufficient_project_role",
                f"This action requires the project role '{minimum}' or higher.",
                status.HTTP_403_FORBIDDEN,
                required=minimum,
                current=self.role,
            )


def project_access(minimum_role: str = "viewer") -> Callable[..., ProjectAccess]:
    """Dependency factory: membership + minimum role on the project in the path."""

    def dependency(
        project_id: str,
        auth: AuthContext = Depends(get_auth),
        db: Session = Depends(get_db),
    ) -> ProjectAccess:
        project = db.get(Project, project_id)
        if project is None or project.archived_at is not None:
            raise api_error("project_not_found", "Project not found.", status.HTTP_404_NOT_FOUND)
        if auth.user.role == "owner":
            access = ProjectAccess(project=project, role="owner", auth=auth)
        else:
            membership = db.execute(
                select(ProjectMember).where(ProjectMember.project_id == project.id, ProjectMember.user_id == auth.user_id)
            ).scalar_one_or_none()
            if membership is None and auth.user.role == "admin":
                access = ProjectAccess(project=project, role="admin", auth=auth)
            elif membership is None:
                raise api_error("not_a_member", "You are not a member of this project.", status.HTTP_403_FORBIDDEN)
            else:
                access = ProjectAccess(project=project, role=membership.role, auth=auth)
        access.require(minimum_role)
        return access

    return dependency


# ---------------------------------------------------------------------------
# Auditing
# ---------------------------------------------------------------------------
def audit(
    db: Session,
    auth: AuthContext,
    action: str,
    *,
    project_id: str | None = None,
    entity_type: str = "",
    entity_id: str = "",
    outcome: str = "success",
    meta: dict[str, Any] | None = None,
) -> None:
    """Append an audit entry; never fails the request."""
    try:
        audit_record(
            db,
            action,
            actor_user_id=auth.user_id if auth.method == "jwt" else None,
            actor_label=auth.label,
            actor_api_key_id=auth.api_key.id if auth.api_key else None,
            project_id=project_id,
            entity_type=entity_type,
            entity_id=entity_id,
            outcome=outcome,
            ip=auth.ip,
            user_agent=auth.user_agent,
            meta=meta or {},
            commit=True,
        )
    except Exception as exc:  # pragma: no cover - auditing must not break the API
        log.error("audit write failed for action %s: %s", action, exc)


def write_scope_guard(auth: AuthContext) -> None:
    """API keys need an explicit write scope for mutating routes."""
    if auth.method == "api_key" and not (auth.has_scope("write:*") or any(s.startswith("write:") for s in auth.scopes)):
        raise api_error("read_only_key", "This API key has read-only scopes.", status.HTTP_403_FORBIDDEN)
