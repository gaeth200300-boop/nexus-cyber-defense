"""End-to-end scan pipeline: upload -> queued job -> engine -> findings/phases."""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "storage" / "labs"


def _upload(client, owner, project, path: Path, kind: str) -> dict:
    mime = "application/vnd.tcpdump.pcap" if path.suffix == ".pcap" else "text/plain"
    with path.open("rb") as fh:
        r = client.post(
            f"/api/v1/projects/{project['id']}/scans/uploads",
            headers=owner["headers"],
            files={"file": (path.name, fh, mime)},
            data={"kind": kind},
        )
    assert r.status_code == 201, r.text
    return r.json()


def test_pcap_scan_runs_engine_and_closes_phases(client, owner, project, run_jobs):
    upload = _upload(client, owner, project, FIXTURES / "lab_traffic.pcap", "pcap_analysis")
    created = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        headers=owner["headers"],
        json={
            "kind": "pcap_analysis",
            "name": "pytest pcap",
            "profile": "passive",
            "options": {"upload_path": upload["upload_path"]},
        },
    )
    assert created.status_code == 201, created.text
    scan_id = created.json()["scan"]["id"]

    assert run_jobs() == "succeeded"

    scan = client.get(f"/api/v1/projects/{project['id']}/scans/{scan_id}", headers=owner["headers"]).json()["scan"]
    assert scan["status"] == "completed"
    assert scan["progress"] == 100
    assert scan["phases"], "phase plan must be stored"
    assert all(p["status"] == "done" for p in scan["phases"]), scan["phases"]
    assert scan["stats"]["pcap"]["packets"] > 0

    findings = client.get(f"/api/v1/projects/{project['id']}/findings", headers=owner["headers"]).json()
    assert findings["total"] >= 1
    titles = {item["title"] for item in findings["items"]}
    assert any("clear text" in title or "MAC" in title or "DNS" in title for title in titles)


def test_log_upload_runs_detection_rules(client, owner, project, run_jobs):
    r = client.post(
        f"/api/v1/projects/{project['id']}/soc/sources",
        headers=owner["headers"],
        files={"file": ("lab_nginx_access.log", (FIXTURES / "lab_nginx_access.log").read_bytes(), "text/plain")},
        data={"name": "pytest nginx", "format": "auto"},
    )
    assert r.status_code == 201, r.text
    scan_id = r.json()["scan_id"]
    assert run_jobs() == "succeeded"

    sources = client.get(f"/api/v1/projects/{project['id']}/soc/sources", headers=owner["headers"]).json()
    assert sources["total"] >= 1
    assert sources["items"][0]["event_count"] > 0

    alerts = client.get(f"/api/v1/projects/{project['id']}/soc/alerts", headers=owner["headers"]).json()
    assert alerts["total"] >= 1
    assert alerts["items"][0]["event_count"] >= 1

    events = client.get(f"/api/v1/projects/{project['id']}/soc/events", headers=owner["headers"], params={"limit": 5}).json()
    assert events["total"] > 0
    assert events["items"][0]["event_type"]


def test_findings_sort_options_and_invalid_sort_fallback(client, owner, project):
    for sort in ("last_seen", "first_seen", "cvss", "created", "not-a-sort"):
        r = client.get(
            f"/api/v1/projects/{project['id']}/findings",
            headers=owner["headers"],
            params={"sort": sort, "limit": 5},
        )
        assert r.status_code == 200, (sort, r.text)


def test_scan_events_and_sse_replay(client, owner, project, run_jobs):
    upload = _upload(client, owner, project, FIXTURES / "lab_traffic.pcap", "pcap_analysis")
    scan_id = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        headers=owner["headers"],
        json={"kind": "pcap_analysis", "profile": "passive", "options": {"upload_path": upload["upload_path"]}},
    ).json()["scan"]["id"]
    assert run_jobs() == "succeeded"

    events = client.get(
        f"/api/v1/projects/{project['id']}/scans/{scan_id}/events",
        headers=owner["headers"],
    )
    assert events.status_code == 200
    assert len(events.json()["items"]) >= 1
    assert events.json()["scan"]["status"] == "completed"

    with client.stream(
        "GET",
        f"/api/v1/projects/{project['id']}/scans/{scan_id}/stream?after_id=0",
        headers=owner["headers"],
    ) as response:
        assert response.status_code == 200
        first = next(response.iter_lines())
        assert first.startswith("retry:") or first.startswith("id:")


def test_cancel_queued_scan(client, owner, project, run_jobs):
    upload = _upload(client, owner, project, FIXTURES / "lab_traffic.pcap", "pcap_analysis")
    scan_id = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        headers=owner["headers"],
        json={"kind": "pcap_analysis", "profile": "passive", "options": {"upload_path": upload["upload_path"]}},
    ).json()["scan"]["id"]
    r = client.post(f"/api/v1/projects/{project['id']}/scans/{scan_id}/cancel", headers=owner["headers"])
    assert r.status_code == 200, r.text
    # Drain the canceled job if the queue still holds it.
    run_jobs()
