"""User administration (global owner/admin only)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...config import settings
from ...core.constants import GLOBAL_ROLES
from ...core.utils import is_valid_email, to_iso_z
from ...db import get_db
from ...models import ProjectMember, User
from ...security import hash_password, password_strength
from ..deps import AuthContext, api_error, audit, require_global_role

router = APIRouter(prefix="/users", tags=["users"])


class UserCreate(BaseModel):
    # Plain str so admin-created accounts may use self-hosted domains such as
    # analyst@nexus.local; syntax is validated with is_valid_email() below.
    email: str = Field(min_length=3, max_length=255)
    full_name: str = Field(default="", max_length=160)
    role: str = Field(default="analyst")
    password: str = Field(min_length=12, max_length=200)


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, max_length=160)
    role: str | None = None
    is_active: bool | None = None


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=12, max_length=200)


def user_admin_view(user: User, memberships: list[ProjectMember] | None = None) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "last_login_at": to_iso_z(user.last_login_at),
        "created_at": to_iso_z(user.created_at),
        "projects": [{"project_id": m.project_id, "role": m.role} for m in (memberships or [])],
    }


@router.get("")
def list_users(
    q: str = Query(default="", max_length=120),
    role: str = Query(default=""),
    active_only: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(User)
    if q:
        like = f"%{q.lower()}%"
        query = query.where(or_(func.lower(User.email).like(like), func.lower(User.full_name).like(like)))
    if role:
        query = query.where(User.role == role)
    if active_only:
        query = query.where(User.is_active.is_(True))
    total = int(db.execute(select(func.count()).select_from(query.subquery())).scalar_one() or 0)
    rows = db.execute(query.order_by(User.created_at.desc()).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    memberships: dict[str, list[ProjectMember]] = {user.id: [] for user in rows}
    if rows:
        for member in db.execute(
            select(ProjectMember).where(ProjectMember.user_id.in_(list(memberships)))
        ).scalars():
            memberships[member.user_id].append(member)
    return {
        "items": [user_admin_view(u, memberships.get(u.id, [])) for u in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "roles": list(GLOBAL_ROLES),
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if body.role not in GLOBAL_ROLES:
        raise api_error("invalid_role", f"Role must be one of {list(GLOBAL_ROLES)}.")
    if body.role == "owner" and auth.user.role != "owner":
        raise api_error("insufficient_role", "Only an owner can create another owner.", status.HTTP_403_FORBIDDEN)
    email = body.email.strip().lower()
    if not is_valid_email(email):
        raise api_error("invalid_email", "Enter a valid email address.", status.HTTP_422_UNPROCESSABLE_ENTITY)
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise api_error("email_taken", "An account with this email already exists.", status.HTTP_409_CONFLICT)
    score, suggestions = password_strength(body.password)
    if score < 2:
        raise api_error("weak_password", "Choose a stronger initial password.", suggestions=suggestions)
    user = User(email=email, full_name=body.full_name.strip(), role=body.role, password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    audit(db, auth, "user.create", entity_type="user", entity_id=user.id, meta={"email": email, "role": body.role})
    return {"item": user_admin_view(user), "note": "Share the initial password securely; the user should change it after first login."}


@router.get("/{user_id}")
def get_user(
    user_id: str,
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        raise api_error("user_not_found", "User not found.", status.HTTP_404_NOT_FOUND)
    memberships = db.execute(select(ProjectMember).where(ProjectMember.user_id == user.id)).scalars().all()
    return {"item": user_admin_view(user, memberships)}


@router.patch("/{user_id}")
def update_user(
    user_id: str,
    body: UserUpdate,
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        raise api_error("user_not_found", "User not found.", status.HTTP_404_NOT_FOUND)
    if body.role is not None:
        if body.role not in GLOBAL_ROLES:
            raise api_error("invalid_role", f"Role must be one of {list(GLOBAL_ROLES)}.")
        if auth.user.role != "owner":
            raise api_error("insufficient_role", "Only an owner can change global roles.", status.HTTP_403_FORBIDDEN)
        if user.id == auth.user_id:
            raise api_error("self_role_change", "You cannot change your own role.")
        if user.role == "owner" and body.role != "owner":
            owners = int(db.execute(select(func.count(User.id)).where(User.role == "owner", User.is_active.is_(True))).scalar_one() or 0)
            if owners <= 1:
                raise api_error("last_owner", "The last active owner cannot be demoted.")
        user.role = body.role
    if body.full_name is not None:
        user.full_name = body.full_name.strip()
    if body.is_active is not None:
        if user.id == auth.user_id and not body.is_active:
            raise api_error("self_deactivate", "You cannot deactivate your own account.")
        if not body.is_active and user.role == "owner":
            owners = int(db.execute(select(func.count(User.id)).where(User.role == "owner", User.is_active.is_(True))).scalar_one() or 0)
            if owners <= 1:
                raise api_error("last_owner", "The last active owner cannot be deactivated.")
        user.is_active = body.is_active
        if not body.is_active:
            user.token_version = int(user.token_version or 0) + 1  # revoke sessions immediately
    db.commit()
    audit(db, auth, "user.update", entity_type="user", entity_id=user.id, meta=body.model_dump(exclude_none=True))
    return {"item": user_admin_view(user)}


@router.post("/{user_id}/reset-password")
def reset_password(
    user_id: str,
    body: PasswordReset,
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        raise api_error("user_not_found", "User not found.", status.HTTP_404_NOT_FOUND)
    if user.role == "owner" and auth.user.role != "owner":
        raise api_error("insufficient_role", "Only an owner can reset another owner's password.", status.HTTP_403_FORBIDDEN)
    score, suggestions = password_strength(body.new_password)
    if score < 2:
        raise api_error("weak_password", "Choose a stronger password.", suggestions=suggestions)
    user.password_hash = hash_password(body.new_password)
    user.token_version = int(user.token_version or 0) + 1
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    audit(db, auth, "user.password_reset", entity_type="user", entity_id=user.id)
    return {"ok": True, "note": "All active sessions for this user were revoked."}


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_user(
    user_id: str,
    hard: bool = Query(default=False, description="Owner only: permanently delete the account"),
    auth: AuthContext = Depends(require_global_role("admin")),
    db: Session = Depends(get_db),
) -> None:
    user = db.get(User, user_id)
    if user is None:
        raise api_error("user_not_found", "User not found.", status.HTTP_404_NOT_FOUND)
    if user.id == auth.user_id:
        raise api_error("self_deactivate", "You cannot delete your own account.")
    if hard:
        if auth.user.role != "owner":
            raise api_error("insufficient_role", "Only an owner can permanently delete accounts.", status.HTTP_403_FORBIDDEN)
        db.delete(user)
        db.commit()
        audit(db, auth, "user.delete", entity_type="user", entity_id=user_id, meta={"email": user.email, "hard": True})
        return None
    user.is_active = False
    user.token_version = int(user.token_version or 0) + 1
    db.commit()
    audit(db, auth, "user.deactivate", entity_type="user", entity_id=user.id)
    return None


@router.get("/bootstrap/summary")
def developer_hint(auth: AuthContext = Depends(require_global_role("owner"))) -> dict[str, Any]:
    return {
        "bootstrap_admin_email": settings.bootstrap_admin_email,
        "note": "Seeded during `nexus.cmd seed`; change the password after first login.",
    }
