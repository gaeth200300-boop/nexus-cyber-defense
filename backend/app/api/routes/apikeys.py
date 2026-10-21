"""Personal API keys — hashed at rest, scoped, rate-limited, audited."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.utils import mask_secret, to_iso_z, utcnow
from ...db import get_db
from ...models import ApiKey
from ...security import generate_api_key, hash_api_key
from ..deps import AuthContext, api_error, audit, get_auth

router = APIRouter(prefix="/apikeys", tags=["api-keys"])

SCOPE_RE = re.compile(r"^(\*|read|write):(\*|[a-z_]{2,30})$")
KNOWN_FAMILIES = {
    "findings", "scans", "assets", "projects", "reports", "intel", "soc", "labs", "copilot", "system", "users",
}


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    scopes: list[str] = Field(default_factory=lambda: ["read:*"])
    expires_in_days: int = Field(default=90, ge=1, le=730)
    rate_limit_per_min: int = Field(default=120, ge=10, le=5000)


def api_key_public(key: ApiKey) -> dict[str, Any]:
    return {
        "id": key.id,
        "name": key.name,
        "prefix": key.key_prefix,
        "scopes": key.scopes,
        "rate_limit_per_min": key.rate_limit_per_min,
        "created_at": to_iso_z(key.created_at),
        "expires_at": to_iso_z(key.expires_at),
        "last_used_at": to_iso_z(key.last_used_at),
        "revoked": key.revoked_at is not None,
    }


@router.get("")
def list_keys(auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(ApiKey).where(ApiKey.user_id == auth.user_id).order_by(ApiKey.created_at.desc())).scalars().all()
    return {"items": [api_key_public(k) for k in rows]}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_key(
    body: ApiKeyCreate,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    for scope in body.scopes:
        if not SCOPE_RE.match(scope):
            raise api_error("invalid_scope", f"Scope '{scope}' is not valid. Use read:<family>, write:<family>, or *:*.")
        family = scope.split(":")[1]
        if family != "*" and family not in KNOWN_FAMILIES:
            raise api_error("unknown_scope_family", f"Unknown scope family '{family}'.", known=sorted(KNOWN_FAMILIES))
    if any(s.startswith("write") or s == "*:*" for s in body.scopes):
        from ...core.constants import ROLE_POWER

        if ROLE_POWER.get(auth.user.role, 0) < ROLE_POWER["analyst"]:
            raise api_error("insufficient_role", "Write scopes require the analyst role or higher.", status.HTTP_403_FORBIDDEN)

    raw_key, prefix, key_hash = generate_api_key()
    key = ApiKey(
        user_id=auth.user_id,
        name=body.name.strip(),
        key_prefix=prefix,
        key_hash=hash_api_key(raw_key),
        scopes=body.scopes,
        rate_limit_per_min=body.rate_limit_per_min,
        expires_at=utcnow() + timedelta(days=body.expires_in_days),
    )
    db.add(key)
    db.commit()
    audit(db, auth, "apikey.create", entity_type="api_key", entity_id=key.id, meta={"name": key.name, "scopes": body.scopes})
    return {
        "key": raw_key,
        "item": api_key_public(key),
        "note": "Copy this key now — it is hashed at rest and will never be shown again.",
        "usage": "Send it as the X-API-Key header. Example: curl -H \"X-API-Key: <key>\" http://127.0.0.1:8787/api/v1/system/health",
    }


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_key(key_id: str, auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> None:
    key = db.get(ApiKey, key_id)
    if key is None:
        raise api_error("key_not_found", "API key not found.", status.HTTP_404_NOT_FOUND)
    if key.user_id != auth.user_id and not auth.is_admin:
        raise api_error("not_owner", "You can only revoke your own API keys.", status.HTTP_403_FORBIDDEN)
    key.revoked_at = utcnow()
    db.commit()
    audit(db, auth, "apikey.revoke", entity_type="api_key", entity_id=key.id, meta={"prefix": mask_secret(key.key_prefix, 2)})
    return None
