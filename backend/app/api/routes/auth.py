"""Authentication: login, refresh, MFA (TOTP), password change, first-run bootstrap."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...config import settings
from ...core.audit import record as audit_record
from ...core.ratelimit import limiter
from ...core.utils import humanize_age, is_valid_email, to_iso_z, utcnow
from ...db import get_db
from ...models import ProjectMember, User
from ...security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    decrypt_field,
    encrypt_field,
    generate_recovery_codes,
    generate_totp_secret,
    hash_password,
    needs_rehash,
    password_strength,
    totp_provisioning_uri,
    verify_password,
    verify_totp,
)
from ..deps import AuthContext, api_error, audit, client_ip, get_auth

log = logging.getLogger("nexus.api.auth")

router = APIRouter(prefix="/auth", tags=["auth"])

LOCKOUT_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


class LoginBody(BaseModel):
    # A plain str (not EmailStr) so self-hosted deployments can use addresses in
    # special-use domains such as admin@nexus.local. The value is only ever used
    # in a parameterized lookup, never echoed.
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=200)
    totp_code: str = Field(default="", max_length=10)


class RefreshBody(BaseModel):
    refresh_token: str


class BootstrapBody(BaseModel):
    # Plain str: self-hosted installs bootstrap with special-use domains such
    # as admin@nexus.local, which stricter email validators reject.
    email: str = Field(min_length=3, max_length=255)
    full_name: str = Field(default="", max_length=160)
    password: str = Field(min_length=12, max_length=200)


class RegisterBody(BaseModel):
    """Self-service registration. The role is fixed server-side to viewer."""

    email: str = Field(min_length=3, max_length=255)
    full_name: str = Field(default="", max_length=160)
    password: str = Field(min_length=12, max_length=200)


class PasswordChangeBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=12, max_length=200)


class MfaCodeBody(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class MfaDisableBody(BaseModel):
    password: str = Field(min_length=1, max_length=200)


def user_public(user: User, memberships: list[ProjectMember] | None = None) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "last_login_at": to_iso_z(user.last_login_at),
        "created_at": to_iso_z(user.created_at),
        "projects": [
            {"project_id": m.project_id, "role": m.role} for m in (memberships or [])
        ],
    }


def _token_response(db: Session, user: User) -> dict[str, Any]:
    access = create_access_token(user.id, tv=user.token_version, role=user.role)
    refresh = create_refresh_token(user.id, token_version=user.token_version)
    memberships = db.execute(select(ProjectMember).where(ProjectMember.user_id == user.id)).scalars().all()
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in_minutes": settings.access_token_minutes,
        "user": user_public(user, memberships),
    }


@router.post("/login")
def login(body: LoginBody, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.execute(select(User).where(User.email == body.email.lower().strip())).scalar_one_or_none()
    generic = "Invalid email or password."
    if user is None:
        raise api_error("invalid_credentials", generic, status.HTTP_401_UNAUTHORIZED)
    if not user.is_active:
        raise api_error("account_disabled", "This account is disabled.", status.HTTP_403_FORBIDDEN)
    if user.locked_until is not None and user.locked_until > utcnow():
        raise api_error(
            "account_locked",
            f"Too many failed attempts. Try again in {humanize_age(user.locked_until).replace(' ago','')}.",
            status.HTTP_423_LOCKED,
        )
    if not verify_password(body.password, user.password_hash):
        user.failed_login_attempts = int(user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= LOCKOUT_ATTEMPTS:
            from datetime import timedelta

            user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_attempts = 0
        db.commit()
        raise api_error("invalid_credentials", generic, status.HTTP_401_UNAUTHORIZED)

    if user.mfa_enabled:
        if not body.totp_code:
            raise api_error("mfa_required", "This account requires a TOTP code.", status.HTTP_401_UNAUTHORIZED, mfa_required=True)
        secret = decrypt_field(user.mfa_secret_enc or "") or ""
        if not verify_totp(secret, body.totp_code.strip()):
            raise api_error("invalid_mfa_code", "The TOTP code is invalid or expired.", status.HTTP_401_UNAUTHORIZED, mfa_required=True)

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    db.commit()
    log.info("login ok: %s", user.email)
    return _token_response(db, user)


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterBody, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Create a self-service account with least-privilege viewer access.

    Existing installations only: the first account is still created through
    the bootstrap flow, so a public endpoint can never mint an owner. New
    accounts receive no project memberships until an administrator grants them.
    """
    if not settings.self_registration_enabled:
        raise api_error(
            "registration_disabled",
            "Self-service registration is disabled on this platform.",
            status.HTTP_403_FORBIDDEN,
        )

    ip = client_ip(request)
    allowed, _, retry_after = limiter.check(f"register:{ip}", 5)
    if not allowed:
        raise api_error(
            "rate_limited",
            f"Too many registration attempts. Try again in {retry_after}s.",
            status.HTTP_429_TOO_MANY_REQUESTS,
            retry_after=retry_after,
        )

    count = int(db.execute(select(func.count(User.id))).scalar_one() or 0)
    if count == 0:
        raise api_error(
            "bootstrap_required",
            "Create the initial owner account before registering other users.",
            status.HTTP_409_CONFLICT,
        )

    email = body.email.strip().lower()
    if not is_valid_email(email):
        raise api_error("invalid_email", "Enter a valid email address.", status.HTTP_422_UNPROCESSABLE_ENTITY)
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise api_error("email_taken", "An account with this email already exists.", status.HTTP_409_CONFLICT)

    score, suggestions = password_strength(body.password)
    if score < 2:
        raise api_error(
            "weak_password",
            "Choose a stronger password.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            suggestions=suggestions,
        )

    full_name = (body.full_name.strip() or email.split("@", 1)[0])[:160]
    user = User(
        email=email,
        full_name=full_name,
        role="viewer",
        password_hash=hash_password(body.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise api_error("email_taken", "An account with this email already exists.", status.HTTP_409_CONFLICT)

    public_user = user_public(user)
    try:
        audit_record(
            db,
            "auth.register",
            actor_user_id=user.id,
            actor_label=user.email,
            entity_type="user",
            entity_id=user.id,
            outcome="success",
            ip=ip,
            user_agent=request.headers.get("user-agent", "")[:300],
            meta={"email": email, "role": "viewer", "source": "self_registration"},
            commit=True,
        )
    except Exception as exc:  # auditing must not lose a successfully created account
        db.rollback()
        log.error("registration audit write failed for %s: %s", email, exc)

    log.info("self-registration created viewer account: %s", email)
    return {
        "ok": True,
        "user": public_user,
        "message": "Account created. Sign in to continue.",
    }


@router.post("/refresh")
def refresh(body: RefreshBody, db: Session = Depends(get_db)) -> dict[str, Any]:
    payload = decode_token(body.refresh_token, expected_type="refresh")
    if not payload:
        raise api_error("invalid_refresh", "The refresh token is invalid or expired.", status.HTTP_401_UNAUTHORIZED)
    user = db.get(User, str(payload.get("sub", "")))
    if user is None or not user.is_active:
        raise api_error("account_disabled", "This account is disabled.", status.HTTP_401_UNAUTHORIZED)
    if int(payload.get("tv", -1)) != int(user.token_version or 0):
        raise api_error("session_revoked", "This session was revoked. Sign in again.", status.HTTP_401_UNAUTHORIZED)
    return _token_response(db, user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> None:
    """Sign out everywhere by rotating the user's token version."""
    auth.user.token_version = int(auth.user.token_version or 0) + 1
    db.commit()
    audit(db, auth, "auth.logout_all")
    return None


@router.get("/me")
def me(auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    memberships = db.execute(select(ProjectMember).where(ProjectMember.user_id == auth.user_id)).scalars().all()
    return {"user": user_public(auth.user, memberships), "auth_method": auth.method}


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(body: PasswordChangeBody, auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> None:
    if not verify_password(body.current_password, auth.user.password_hash):
        raise api_error("invalid_password", "The current password is incorrect.", status.HTTP_403_FORBIDDEN)
    score, suggestions = password_strength(body.new_password)
    if score < 2:
        raise api_error("weak_password", "Choose a stronger password.", status.HTTP_422_UNPROCESSABLE_ENTITY, suggestions=suggestions)
    auth.user.password_hash = hash_password(body.new_password)
    auth.user.token_version = int(auth.user.token_version or 0) + 1  # all sessions must re-authenticate
    db.commit()
    audit(db, auth, "auth.password_changed")
    return None


# ---------------------------------------------------------------------------
# MFA
# ---------------------------------------------------------------------------
@router.post("/mfa/setup")
def mfa_setup(auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    if auth.user.mfa_enabled:
        raise api_error("mfa_already_enabled", "MFA is already enabled for this account.")
    secret = generate_totp_secret()
    recovery = generate_recovery_codes()
    auth.user.mfa_secret_enc = encrypt_field(secret)
    auth.user.recovery_codes_enc = encrypt_field("\n".join(recovery))
    db.commit()
    audit(db, auth, "auth.mfa_setup_started")
    return {
        "secret": secret,
        "provisioning_uri": totp_provisioning_uri(secret, auth.user.email),
        "recovery_codes": recovery,
        "note": "Scan the URI in an authenticator app, then confirm with a code. Recovery codes are shown once.",
    }


@router.post("/mfa/enable")
def mfa_enable(body: MfaCodeBody, auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    secret = decrypt_field(auth.user.mfa_secret_enc or "") or ""
    if not secret:
        raise api_error("mfa_not_setup", "Run /auth/mfa/setup first.")
    if not verify_totp(secret, body.code.strip()):
        raise api_error("invalid_mfa_code", "The code did not match. Check the device clock and try again.", status.HTTP_400_BAD_REQUEST)
    auth.user.mfa_enabled = True
    db.commit()
    audit(db, auth, "auth.mfa_enabled")
    return {"mfa_enabled": True}


@router.post("/mfa/disable")
def mfa_disable(body: MfaDisableBody, auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    if not verify_password(body.password, auth.user.password_hash):
        raise api_error("invalid_password", "Password confirmation failed.", status.HTTP_403_FORBIDDEN)
    auth.user.mfa_enabled = False
    auth.user.mfa_secret_enc = None
    auth.user.recovery_codes_enc = None
    db.commit()
    audit(db, auth, "auth.mfa_disabled", outcome="success")
    return {"mfa_enabled": False}


# ---------------------------------------------------------------------------
# First-run bootstrap (only possible while no accounts exist)
# ---------------------------------------------------------------------------
@router.get("/bootstrap")
def bootstrap_status(db: Session = Depends(get_db)) -> dict[str, Any]:
    count = int(db.execute(select(func.count(User.id))).scalar_one() or 0)
    return {
        "bootstrap_required": count == 0,
        "accounts": count,
        "admin_email": settings.bootstrap_admin_email if count == 0 else "",
        "self_registration": bool(settings.self_registration_enabled),
    }


@router.post("/bootstrap", status_code=status.HTTP_201_CREATED)
def bootstrap(body: BootstrapBody, db: Session = Depends(get_db)) -> dict[str, Any]:
    count = int(db.execute(select(func.count(User.id))).scalar_one() or 0)
    if count > 0:
        raise api_error("already_bootstrapped", "Accounts already exist — sign in instead.", status.HTTP_409_CONFLICT)
    score, suggestions = password_strength(body.password)
    if score < 2:
        raise api_error("weak_password", "Choose a stronger password for the owner account.", status.HTTP_422_UNPROCESSABLE_ENTITY, suggestions=suggestions)
    email = body.email.strip().lower()
    if not is_valid_email(email):
        raise api_error("invalid_email", "Enter a valid email address.", status.HTTP_422_UNPROCESSABLE_ENTITY)
    user = User(
        email=email,
        full_name=body.full_name.strip() or "Owner",
        role="owner",
        password_hash=hash_password(body.password),
    )
    db.add(user)
    db.commit()
    log.warning("first-run owner account created: %s", user.email)
    return _token_response(db, user)
