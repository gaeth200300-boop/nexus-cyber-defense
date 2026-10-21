"""Authentication, JWT lifetime, API keys and MFA contracts."""

from __future__ import annotations

import time
from datetime import datetime, timezone

import jwt
import pyotp

from app.config import settings


def test_bootstrap_is_closed_after_first_account(client, owner):
    r = client.get("/api/v1/auth/bootstrap")
    assert r.status_code == 200
    assert r.json()["bootstrap_required"] is False


def test_login_sets_valid_future_expiry(client, owner):
    r = client.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": "TestOwner!Nexus2026"})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]

    payload = jwt.decode(token, settings.resolve_secret_key(), algorithms=["HS256"])
    now = int(time.time())
    assert payload["typ"] == "access"
    assert abs(payload["iat"] - now) < 120, "iat must be in real UTC, not shifted by the host timezone"
    assert payload["exp"] - payload["iat"] == settings.access_token_minutes * 60
    assert payload["exp"] > now

    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["user"]["email"] == "owner@example.com"


def test_bad_password_is_rejected(client):
    r = client.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": "definitely-wrong"})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "invalid_credentials"


def test_self_registration_creates_viewer_account(client, owner):
    email = "new.viewer@example.com"
    r = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "full_name": "New Viewer",
            "password": "Viewer!Nexus2026",
            # A client cannot choose a privileged role; unknown fields are ignored.
            "role": "owner",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["user"]["email"] == email
    assert body["user"]["role"] == "viewer"
    assert body["user"]["is_active"] is True
    assert "access_token" not in body
    assert "password" not in body["user"]

    login = client.post("/api/v1/auth/login", json={"email": email, "password": "Viewer!Nexus2026"})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["user"]["role"] == "viewer"

    audit = client.get(
        "/api/v1/audit",
        headers=owner["headers"],
        params={"action": "auth.register", "entity_type": "user"},
    )
    assert audit.status_code == 200, audit.text
    assert any(item["entity_id"] == body["user"]["id"] for item in audit.json()["items"])


def test_self_registration_rejects_duplicate_email(client, owner):
    payload = {
        "email": "duplicate.viewer@example.com",
        "full_name": "Duplicate Viewer",
        "password": "Viewer!Nexus2026",
    }
    first = client.post("/api/v1/auth/register", json=payload)
    assert first.status_code == 201, first.text
    second = client.post("/api/v1/auth/register", json=payload)
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "email_taken"


def test_self_registration_rejects_weak_password(client, owner):
    r = client.post(
        "/api/v1/auth/register",
        json={
            "email": "weak.viewer@example.com",
            "full_name": "Weak Viewer",
            "password": "passwordpassword",
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "weak_password"


def test_refresh_rotates_to_working_access_token(client):
    login = client.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": "TestOwner!Nexus2026"})
    refresh = login.json()["refresh_token"]
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200, r.text
    access = r.json()["access_token"]
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code == 200


def test_api_key_lifecycle(client, owner):
    created = client.post(
        "/api/v1/apikeys",
        headers=owner["headers"],
        json={"name": "pytest read key", "scopes": ["read:system"], "expires_in_days": 1},
    )
    assert created.status_code == 201, created.text
    raw = created.json()["key"]
    key_id = created.json()["item"]["id"]
    assert raw.startswith("nxs_")

    listing = client.get("/api/v1/apikeys", headers=owner["headers"])
    assert listing.status_code == 200
    assert all("key_hash" not in item for item in listing.json()["items"])

    health = client.get("/api/v1/auth/me", headers={"X-API-Key": raw})
    assert health.status_code == 200

    revoked = client.delete(f"/api/v1/apikeys/{key_id}", headers=owner["headers"])
    assert revoked.status_code == 204
    assert client.get("/api/v1/auth/me", headers={"X-API-Key": raw}).status_code == 401


def test_api_key_scope_is_enforced(client, owner):
    created = client.post(
        "/api/v1/apikeys",
        headers=owner["headers"],
        json={"name": "pytest read-only", "scopes": ["read:system"], "expires_in_days": 1},
    )
    raw = created.json()["key"]
    key_id = created.json()["item"]["id"]
    try:
        denied = client.post("/api/v1/projects", headers={"X-API-Key": raw}, json={"name": "Nope"})
        assert denied.status_code == 403
    finally:
        client.delete(f"/api/v1/apikeys/{key_id}", headers=owner["headers"])


def test_mfa_enable_login_and_disable(client, owner):
    setup = client.post("/api/v1/auth/mfa/setup", headers=owner["headers"])
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    assert setup.json()["recovery_codes"]

    enable = client.post("/api/v1/auth/mfa/enable", headers=owner["headers"], json={"code": pyotp.TOTP(secret).now()})
    assert enable.status_code == 200, enable.text

    no_code = client.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": "TestOwner!Nexus2026"})
    assert no_code.status_code == 401
    assert no_code.json()["detail"]["code"] == "mfa_required"

    with_code = client.post(
        "/api/v1/auth/login",
        json={"email": "owner@example.com", "password": "TestOwner!Nexus2026", "totp_code": pyotp.TOTP(secret).now()},
    )
    assert with_code.status_code == 200, with_code.text

    disabled = client.post(
        "/api/v1/auth/mfa/disable",
        headers=owner["headers"],
        json={"password": "TestOwner!Nexus2026"},
    )
    assert disabled.status_code == 200, disabled.text
    assert client.get("/api/v1/auth/me", headers=owner["headers"]).json()["user"]["mfa_enabled"] is False


def test_audit_chain_verifies(client, owner):
    r = client.get("/api/v1/audit/verify", headers=owner["headers"])
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    assert r.json()["checked"] >= 1


def test_notification_dismissal_roundtrip(client, owner):
    # A dismiss for an unknown id is a no-op and must not 500.
    r = client.post("/api/v1/system/notifications/dismiss", headers=owner["headers"], json={"ids": ["alert:none"]})
    assert r.status_code == 200
    assert "dismissed" in r.json()
