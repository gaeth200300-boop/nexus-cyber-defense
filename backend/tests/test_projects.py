"""Projects, authorization scopes and the private-target guard rails."""

from __future__ import annotations


def test_project_crud_and_membership(client, owner, project):
    listed = client.get("/api/v1/projects", headers=owner["headers"])
    assert listed.status_code == 200
    assert any(p["id"] == project["id"] for p in listed.json()["items"])

    detail = client.get(f"/api/v1/projects/{project['id']}", headers=owner["headers"])
    assert detail.status_code == 200
    assert detail.json()["project"]["role"] == "owner"

    updated = client.patch(
        f"/api/v1/projects/{project['id']}",
        headers=owner["headers"],
        json={"description": "updated by pytest"},
    )
    assert updated.status_code == 200
    assert updated.json()["project"]["description"] == "updated by pytest"


def test_private_scope_requires_explicit_authorization(client, owner, project):
    r = client.post(
        f"/api/v1/projects/{project['id']}/scopes",
        headers=owner["headers"],
        json={"kind": "cidr", "value": "10.0.0.0/24", "allow_active": True},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "blocked_target"


def test_loopback_and_metadata_are_never_authorized(client, owner, project):
    for kind, value in (("ip", "127.0.0.1"), ("ip", "169.254.169.254"), ("url", "http://localhost:8000")):
        r = client.post(
            f"/api/v1/projects/{project['id']}/scopes",
            headers=owner["headers"],
            json={"kind": kind, "value": value},
        )
        assert r.status_code == 400, (kind, value, r.text)
        assert r.json()["detail"]["code"] == "blocked_target"


def test_public_scope_can_be_created_and_toggled(client, owner, project):
    r = client.post(
        f"/api/v1/projects/{project['id']}/scopes",
        headers=owner["headers"],
        json={
            "kind": "domain",
            "value": "example.com",
            "include_subdomains": True,
            "allow_active": False,
            "authorization_ref": "PYTEST-2026-01",
            "authorized_by": "Test Owner",
        },
    )
    assert r.status_code == 201, r.text
    scope = r.json()["scope"]
    assert scope["value"] == "example.com"
    assert scope["allow_active"] is False

    toggled = client.delete(f"/api/v1/projects/{project['id']}/scopes/{scope['id']}", headers=owner["headers"])
    assert toggled.status_code == 200
    assert toggled.json()["scope"]["is_active"] is False

    policy = client.get(f"/api/v1/projects/{project['id']}/scopes", headers=owner["headers"]).json()["policy"]
    assert policy["global_private_targets"] is False
    assert policy["active_scanning_enabled"] is True


def test_scan_target_must_be_inside_an_authorized_scope(client, owner, project):
    r = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        headers=owner["headers"],
        json={"kind": "web_vuln", "profile": "passive", "targets": ["https://not-authorized.example"]},
    )
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] in ("target_not_authorized", "blocked_target")


def test_scan_requires_explicit_active_scope(client, owner, project):
    client.post(
        f"/api/v1/projects/{project['id']}/scopes",
        headers=owner["headers"],
        json={"kind": "domain", "value": "example.com", "allow_active": False},
    )
    r = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        headers=owner["headers"],
        json={"kind": "network_scan", "profile": "safe_active", "targets": ["example.com"]},
    )
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "target_not_authorized"
    assert r.json()["detail"]["reason"] == "active_testing_not_authorized"
