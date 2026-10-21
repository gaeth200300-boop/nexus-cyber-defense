"""Command platform: graph, timeline, posture, rule studio, workbench, vault.

Every assertion below checks that the platform reports *real* state: edges
carry a provenance, posture never invents a factor it could not measure, and a
rule only reports matches that exist in the stored telemetry.
"""

from __future__ import annotations

import io

import pytest
from sqlalchemy import select

from app.db import SessionLocal
from app.models import Asset, Evidence, Finding, LogEvent, Service, User
from app.security import create_access_token, hash_password


def _make_viewer(email: str = "command.viewer@example.com") -> dict[str, str]:
    """Create a non-member directly in the database and mint a token for it.

    The HTTP registration endpoint is rate limited, so tests that only need an
    authenticated non-member build the account directly instead.
    """
    from app.core.utils import new_id

    with SessionLocal() as db:
        existing = db.query(User).filter(User.email == email).first()
        if existing is None:
            user = User(
                id=new_id(),
                email=email,
                full_name="Command Viewer",
                role="viewer",
                is_active=True,
                password_hash=hash_password("ViewerPass!2026"),
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            user = existing
    token = create_access_token(user.id, role=user.role)
    return {"Authorization": f"Bearer {token}"}


def _seed_telemetry(project_id: str) -> None:
    """Insert a small, deterministic telemetry set the tests can rely on."""
    suffix = project_id[:8]
    with SessionLocal() as db:
        db.add(
            Asset(
                id=f"asset-graph-{suffix}",
                project_id=project_id,
                type="domain",
                value="app.example.test",
                normalized_value="app.example.test",
                source="discovery",
                risk_severity="high",
                risk_score=70.0,
                state="active",
                last_seen_at=__import__("datetime").datetime.utcnow(),
            )
        )
        db.add(
            Service(
                id=f"service-graph-{suffix}",
                project_id=project_id,
                asset_id=f"asset-graph-{suffix}",
                port=443,
                protocol="tcp",
                state="open",
                name="https",
                product="nginx",
                source="scan",
            )
        )
        db.add(
            Finding(
                id=f"finding-graph-{suffix}",
                project_id=project_id,
                asset_id=f"asset-graph-{suffix}",
                service_id=f"service-graph-{suffix}",
                title="Missing security header",
                fingerprint=f"test-fingerprint-graph-{suffix}",
                category="headers",
                severity="medium",
                confidence="firm",
                status="open",
                target="app.example.test",
                detected_by="http-engine",
            )
        )
        db.add(
            LogEvent(
                project_id=project_id,
                ts=__import__("datetime").datetime.utcnow(),
                severity="high",
                event_type="auth_failure",
                message="Failed login for admin from 203.0.113.9",
                src_ip="203.0.113.9",
                dst_ip="10.0.0.5",
                dst_port=443,
                url="/login",
                method="POST",
                status_code=401,
            )
        )
        db.add(
            LogEvent(
                project_id=project_id,
                ts=__import__("datetime").datetime.utcnow(),
                severity="info",
                event_type="http_request",
                message="GET /health 200",
                src_ip="203.0.113.9",
                url="/health",
                method="GET",
                status_code=200,
            )
        )
        db.commit()


# ---------------------------------------------------------------------------
# Unified security graph
# ---------------------------------------------------------------------------
def test_graph_edges_are_derived_from_stored_records(client, owner, project):
    _seed_telemetry(project["id"])

    r = client.get(f"/api/v1/projects/{project['id']}/graph", headers=owner["headers"])
    assert r.status_code == 200, r.text
    graph = r.json()

    kinds = {node["kind"] for node in graph["nodes"]}
    assert {"asset", "service", "finding", "log_event"} <= kinds

    edge_keys = {(edge["source"], edge["target"], edge["kind"]) for edge in graph["edges"]}
    suffix = project["id"][:8]
    assert (f"asset:asset-graph-{suffix}", f"finding:finding-graph-{suffix}", "has_finding") in edge_keys
    assert (f"asset:asset-graph-{suffix}", f"service:service-graph-{suffix}", "exposes") in edge_keys

    for edge in graph["edges"]:
        assert edge["origin"], "every edge must name the record that produced it"
        assert edge["confidence"] in {"certain", "firm", "tentative"}
        assert edge["source"] in {node["id"] for node in graph["nodes"]}


def test_graph_is_empty_when_the_project_has_no_records(client, owner, project):
    r = client.get(f"/api/v1/projects/{project['id']}/graph", headers=owner["headers"])
    assert r.status_code == 200
    graph = r.json()
    assert graph["stats"]["assets"] == 0
    assert graph["stats"]["findings"] == 0
    assert graph["edges"] == []


def test_graph_rejects_a_non_member(client, owner, project):
    headers = _make_viewer("graph.viewer@example.com")
    r = client.get(f"/api/v1/projects/{project['id']}/graph", headers=headers)
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Timeline engine
# ---------------------------------------------------------------------------
def test_timeline_merges_every_recorded_source(client, owner, project):
    _seed_telemetry(project["id"])
    r = client.get(f"/api/v1/projects/{project['id']}/timeline/events", headers=owner["headers"])
    assert r.status_code == 200, r.text
    payload = r.json()
    sources = payload["stats"]["by_source"]
    assert sources.get("log_event", 0) >= 2
    assert sources.get("finding", 0) >= 1
    assert payload["stats"]["anomalies"] >= 1
    timestamps = [item["ts"] for item in payload["events"] if item["ts"]]
    assert timestamps == sorted(timestamps), "timeline must be ordered"


def test_timeline_severity_filter_narrows_the_result(client, owner, project):
    _seed_telemetry(project["id"])
    r = client.get(
        f"/api/v1/projects/{project['id']}/timeline/events",
        headers=owner["headers"],
        params={"severities": "high"},
    )
    assert r.status_code == 200
    for item in r.json()["events"]:
        assert item["severity"] == "high"


# ---------------------------------------------------------------------------
# Security posture
# ---------------------------------------------------------------------------
def test_posture_is_transparent_and_reports_missing_information(client, owner, project):
    r = client.get(f"/api/v1/projects/{project['id']}/posture", headers=owner["headers"])
    assert r.status_code == 200, r.text
    payload = r.json()

    assert 0 <= payload["score"] <= 100
    assert payload["coverage"] <= 100
    assert payload["methodology"]["model"], "the scoring model must be documented"
    for factor in payload["factors"]:
        assert factor["earned"] <= factor["max"]
        assert factor["detail"], "every factor must explain itself"
    measured = {item["key"] for item in payload["factors"]}
    missing = {item["key"] for item in payload["missing_information"]}
    assert not (measured & missing), "a factor cannot be both measured and missing"


def test_posture_snapshot_is_persisted(client, owner, project):
    r = client.post(
        f"/api/v1/projects/{project['id']}/posture/snapshot",
        headers=owner["headers"],
        json={"save": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["history"], "a snapshot must be readable back"


# ---------------------------------------------------------------------------
# Detection rule studio
# ---------------------------------------------------------------------------
VALID_RULE = {
    "name": "Authentication Failure Burst",
    "title": "Authentication failure burst",
    "description": "Repeated authentication failures from one source.",
    "status": "experimental",
    "level": "high",
    "logsource": {"product": "windows", "service": "security"},
    "detection": {
        "selection": {"event_type": "auth_failure"},
        "condition": "selection",
    },
    "falsepositives": ["Users mistyping a password repeatedly."],
    "references": ["https://attack.mitre.org/techniques/T1110/"],
}


def test_sigma_rule_validation_reports_errors_and_blind_spots(client, owner, project):
    r = client.post(
        f"/api/v1/projects/{project['id']}/rules/validate",
        headers=owner["headers"],
        json={
            "name": "Broken rule",
            "detection": {"condition": "missing_selection"},
        },
    )
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["valid"] is False
    assert report["errors"]
    assert report["blind_spots"], "the studio must explain what a rule cannot see"


def test_sigma_rule_is_saved_validated_and_tested_against_stored_events(client, owner, project):
    _seed_telemetry(project["id"])
    created = client.post(
        f"/api/v1/projects/{project['id']}/rules", headers=owner["headers"], json=VALID_RULE
    )
    assert created.status_code == 201, created.text
    rule = created.json()
    assert rule["validation"]["valid"] is True
    assert rule["name"] == "authentication-failure-burst"

    tested = client.post(
        f"/api/v1/projects/{project['id']}/rules/{rule['id']}/test",
        headers=owner["headers"],
        json={"limit": 500},
    )
    assert tested.status_code == 200, tested.text
    result = tested.json()
    assert result["tested_events"] >= 2
    assert result["matched_events"] == 1, "only the auth_failure event may match"
    assert result["matches"][0]["event_type"] == "auth_failure"


def test_sigma_rule_test_reports_an_empty_telemetry_set_honestly(client, owner, project):
    created = client.post(
        f"/api/v1/projects/{project['id']}/rules", headers=owner["headers"], json=VALID_RULE
    )
    rule = created.json()
    tested = client.post(
        f"/api/v1/projects/{project['id']}/rules/{rule['id']}/test",
        headers=owner["headers"],
        json={"limit": 100},
    )
    assert tested.status_code == 200
    result = tested.json()
    assert result["tested_events"] == 0
    assert result["matched_events"] == 0
    assert "No log events" in result["sample_size_note"]


def test_sigma_rule_name_must_be_unique_per_project(client, owner, project):
    first = client.post(f"/api/v1/projects/{project['id']}/rules", headers=owner["headers"], json=VALID_RULE)
    assert first.status_code == 201
    second = client.post(f"/api/v1/projects/{project['id']}/rules", headers=owner["headers"], json=VALID_RULE)
    assert second.status_code == 409


# ---------------------------------------------------------------------------
# Investigation workbench
# ---------------------------------------------------------------------------
def test_case_holds_hypotheses_annotations_and_tasks(client, owner, project):
    created = client.post(
        f"/api/v1/projects/{project['id']}/cases",
        headers=owner["headers"],
        json={"title": "Suspected credential stuffing", "severity": "high", "summary": "Burst of failures."},
    )
    assert created.status_code == 201, created.text
    case = created.json()
    assert case["reference"].startswith("NX-")

    hypothesis = client.post(
        f"/api/v1/projects/{project['id']}/cases/{case['id']}/hypotheses",
        headers=owner["headers"],
        json={
            "statement": "A single actor is replaying breached credentials.",
            "confidence": "tentative",
            "evidence_refs": [{"kind": "log_event", "id": "1", "label": "failed login"}],
        },
    )
    assert hypothesis.status_code == 201, hypothesis.text

    annotation = client.post(
        f"/api/v1/projects/{project['id']}/cases/{case['id']}/annotations",
        headers=owner["headers"],
        json={"body": "Correlated with the WAF log.", "entity_type": "finding"},
    )
    assert annotation.status_code == 201

    task = client.post(
        f"/api/v1/projects/{project['id']}/cases/{case['id']}/tasks",
        headers=owner["headers"],
        json={"title": "Pull the WAF logs for the window"},
    )
    assert task.status_code == 201

    detail = client.get(f"/api/v1/projects/{project['id']}/cases/{case['id']}", headers=owner["headers"]).json()
    assert detail["counts"]["hypotheses"] == 1
    assert detail["counts"]["annotations"] == 1
    assert detail["counts"]["tasks"] == 1
    assert detail["counts"]["open_tasks"] == 1

    patched = client.patch(
        f"/api/v1/projects/{project['id']}/cases/{case['id']}/hypotheses/{detail['hypotheses'][0]['id']}",
        headers=owner["headers"],
        json={"status": "supported", "confidence": "firm"},
    )
    assert patched.status_code == 200
    assert patched.json()["hypotheses"][0]["status"] == "supported"


def test_case_is_not_visible_to_a_non_member(client, owner, project):
    case = client.post(
        f"/api/v1/projects/{project['id']}/cases",
        headers=owner["headers"],
        json={"title": "Private case"},
    ).json()
    headers = _make_viewer("case.viewer@example.com")
    r = client.get(f"/api/v1/projects/{project['id']}/cases/{case['id']}", headers=headers)
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Digital evidence vault
# ---------------------------------------------------------------------------
def test_evidence_upload_hashes_and_opens_a_custody_chain(client, owner, project):
    payload = b"PK\x03\x04 synthetic forensic container for NEXUS tests"
    r = client.post(
        f"/api/v1/projects/{project['id']}/evidence",
        headers=owner["headers"],
        files={"file": ("case.zip", io.BytesIO(payload), "application/zip")},
        data={"label": "Case archive", "kind": "archive"},
    )
    assert r.status_code == 201, r.text
    item = r.json()
    assert len(item["sha256"]) == 64
    assert item["custody"], "an upload must open a chain of custody"
    assert item["custody"][0]["action"] == "collected"
    assert item["custody"][0]["sha256_at_action"] == item["sha256"]


def test_evidence_upload_rejects_unsupported_formats_with_a_clear_message(client, owner, project):
    r = client.post(
        f"/api/v1/projects/{project['id']}/evidence",
        headers=owner["headers"],
        files={"file": ("payload.exe", io.BytesIO(b"MZ"), "application/octet-stream")},
    )
    assert r.status_code == 415, r.text
    assert "not an accepted evidence format" in r.json()["detail"]["message"]


def test_evidence_integrity_verification_detects_a_tampered_digest(client, owner, project):
    payload = b"synthetic evidence body"
    item = client.post(
        f"/api/v1/projects/{project['id']}/evidence",
        headers=owner["headers"],
        files={"file": ("case.log", io.BytesIO(payload), "text/plain")},
    ).json()

    custody = client.post(
        f"/api/v1/projects/{project['id']}/evidence/{item['id']}/custody",
        headers=owner["headers"],
        json={"action": "analyzed", "location": "lab-1", "notes": "Mounted read-only."},
    )
    assert custody.status_code == 201, custody.text

    verified = client.get(f"/api/v1/projects/{project['id']}/evidence/verify", headers=owner["headers"]).json()
    assert verified["integrity_ok"] is True
    assert verified["verified"] >= 1

    # Tamper with the stored digest and the vault must notice.
    with SessionLocal() as db:
        row = db.get(Evidence, item["id"])
        row.raw_sha256 = "0" * 64
        db.commit()

    verified = client.get(f"/api/v1/projects/{project['id']}/evidence/verify", headers=owner["headers"]).json()
    assert verified["integrity_ok"] is False
    assert verified["mismatched"]


# ---------------------------------------------------------------------------
# Purple team
# ---------------------------------------------------------------------------
def test_purple_simulation_reports_missed_signals(client, owner, project):
    scenarios = client.get(
        f"/api/v1/projects/{project['id']}/purple/scenarios", headers=owner["headers"]
    )
    assert scenarios.status_code == 200, scenarios.text
    assert scenarios.json()["count"] >= 5

    run = client.post(
        f"/api/v1/projects/{project['id']}/purple/run",
        headers=owner["headers"],
        json={"scenario_key": "ransomware_staging", "notes": "Lab run."},
    )
    assert run.status_code == 200, run.text
    payload = run.json()
    assert payload["expected"], "the scenario must declare its expected telemetry"
    assert payload["missed"], "an unconfigured project must miss signals"
    assert 0 <= payload["score"] <= 100

    stored = client.get(f"/api/v1/projects/{project['id']}/purple/simulations", headers=owner["headers"])
    assert stored.status_code == 200
    assert stored.json()["items"], "the simulation must be recorded"


def test_purple_run_rejects_an_unknown_scenario(client, owner, project):
    r = client.post(
        f"/api/v1/projects/{project['id']}/purple/run",
        headers=owner["headers"],
        json={"scenario_key": "does-not-exist"},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Knowledge graph
# ---------------------------------------------------------------------------
def test_knowledge_graph_links_cves_detections_and_lessons(client, owner):
    r = client.get("/api/v1/knowledge", headers=owner["headers"])
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["stats"]["lessons"] == 300
    kinds = {node["kind"] for node in payload["nodes"]}
    assert "lesson" in kinds
    assert payload["sources"], "the graph must name its data sources"
