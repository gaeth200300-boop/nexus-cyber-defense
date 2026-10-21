"""Global dashboard, search, notifications, settings and capabilities."""

from __future__ import annotations


def test_dashboard_is_computed_from_real_rows(client, owner, project):
    # Give the dashboard something real to count.
    client.post(
        f"/api/v1/projects/{project['id']}/scopes",
        headers=owner["headers"],
        json={"kind": "domain", "value": "example.com"},
    )
    r = client.get("/api/v1/system/dashboard", headers=owner["headers"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scope"]["projects"] >= 1
    assert project["id"] in body["scope"]["project_ids"]
    assert set(body["findings"]["by_severity"]) == {"critical", "high", "medium", "low", "info"}
    assert body["jobs"]["total"] >= 0
    assert len(body["trend"]["days"]) == 14
    assert body["trend"]["days"] == sorted(body["trend"]["days"])


def test_meta_and_capabilities_are_honest(client, owner):
    meta = client.get("/api/v1/system/meta", headers=owner["headers"])
    assert meta.status_code == 200
    body = meta.json()
    assert body["app"]["api_version"] == "v1"
    assert "ai_configured" in body["features"]
    assert body["locale"]["directions"]["ar"] == "rtl"

    caps = client.get("/api/v1/system/capabilities", headers=owner["headers"])
    assert caps.status_code == 200
    capabilities = caps.json()["capabilities"]
    assert capabilities["pcap"]["available"] is True
    assert "never simulated" in caps.json()["note"]


def test_search_groups_are_real(client, owner, project):
    r = client.get("/api/v1/system/search", headers=owner["headers"], params={"q": project["slug"]})
    assert r.status_code == 200
    groups = r.json()["groups"]
    assert set(groups) == {"projects", "assets", "findings", "scans", "alerts", "reports", "labs", "intel"}
    assert any(item["id"] == project["id"] for item in groups["projects"])


def test_notifications_shape(client, owner):
    r = client.get("/api/v1/system/notifications", headers=owner["headers"])
    assert r.status_code == 200
    body = r.json()
    for key in ("items", "unread", "counts", "window_days"):
        assert key in body
    assert body["unread"] == len(body["items"])


def test_settings_reject_unknown_values(client, owner):
    r = client.patch("/api/v1/system/settings", headers=owner["headers"], json={"event_retention_days": 0})
    assert r.status_code == 422
    ok = client.patch("/api/v1/system/settings", headers=owner["headers"], json={"event_retention_days": 45})
    assert ok.status_code == 200, ok.text
    assert ok.json()["runtime"]["event_retention_days"] == 45
    # restore
    client.patch("/api/v1/system/settings", headers=owner["headers"], json={"event_retention_days": 30})


def test_jobs_list_and_detail(client, owner):
    r = client.get("/api/v1/system/jobs", headers=owner["headers"])
    assert r.status_code == 200
    assert "counts" in r.json()


def test_health_is_public_and_flat_for_scripts(client):
    r = client.get("/api/v1/system/health")
    assert r.status_code == 200
    body = r.json()
    for key in ("status", "version", "database", "worker", "uptime_seconds"):
        assert key in body
