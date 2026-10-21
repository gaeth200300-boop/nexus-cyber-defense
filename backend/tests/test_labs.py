"""Lab catalogue, grading and fixture integrity (no external network needed)."""

from __future__ import annotations


def _quiz_answers() -> dict[str, str]:
    # The incident-triage lab is pure judgement: answers are part of the fixture.
    return {
        "q_containment_order": "isolate",
        "q_evidence": "capture_live",
        "q_comms": "policy",
    }


def test_catalogue_exposes_labels_but_not_answer_keys(client, owner):
    import json

    r = client.get("/api/v1/labs", headers=owner["headers"])
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert len(items) >= 9
    for item in items:
        assert item["title_en"] and item["title_ar"]
        payload = json.dumps(item, ensure_ascii=False)
        assert '"answer"' not in payload
        assert "explanation_en" not in payload


def test_lab_detail_hides_answers(client, owner):
    items = client.get("/api/v1/labs", headers=owner["headers"]).json()["items"]
    lab = next(i for i in items if i["slug"] == "incident-triage-order")
    detail = client.get(f"/api/v1/labs/{lab['id']}", headers=owner["headers"]).json()["lab"]
    for check in detail["checks"]:
        assert "answer" not in check.get("spec", {})
        assert "spec" not in check
    assert detail["hints_total"] == 1
    assert detail["hints"] == []


def test_quiz_grading_pending_then_pass(client, owner, project):
    items = client.get("/api/v1/labs", headers=owner["headers"]).json()["items"]
    lab = next(i for i in items if i["slug"] == "incident-triage-order")
    started = client.post(f"/api/v1/labs/{lab['id']}/start", headers=owner["headers"], json={"project_id": project["id"]})
    assert started.status_code == 201, started.text
    run_id = started.json()["run"]["id"]

    # Unknown keys mean "still needs answers", never a fake pass.
    pending = client.post(f"/api/v1/labs/runs/{run_id}/submit", headers=owner["headers"], json={"answers": {"q_evidence": "capture_live"}})
    assert pending.status_code == 200
    assert pending.json()["passed"] is False
    assert pending.json()["pending"] is True

    passed = client.post(f"/api/v1/labs/runs/{run_id}/submit", headers=owner["headers"], json={"answers": _quiz_answers()})
    assert passed.status_code == 200, passed.text
    body = passed.json()
    assert body["passed"] is True
    assert body["pending"] is False
    assert body["score"] == body["max_points"] == 250
    assert len(body["explanations"]) == 3

    stats = client.get("/api/v1/labs/me/stats", headers=owner["headers"]).json()
    assert stats["labs_passed"] >= 1
    assert stats["total_score"] >= 250

    leaderboard = client.get("/api/v1/labs/leaderboard", headers=owner["headers"]).json()
    assert leaderboard["total"] >= 1


def test_wrong_answers_fail_without_pending(client, owner, project):
    items = client.get("/api/v1/labs", headers=owner["headers"]).json()["items"]
    lab = next(i for i in items if i["slug"] == "incident-triage-order")
    run_id = client.post(f"/api/v1/labs/{lab['id']}/start", headers=owner["headers"], json={"project_id": project["id"]}).json()["run"]["id"]
    wrong = {key: "nonsense" for key in _quiz_answers()}
    r = client.post(f"/api/v1/labs/runs/{run_id}/submit", headers=owner["headers"], json={"answers": wrong})
    assert r.status_code == 200
    assert r.json()["passed"] is False
    assert r.json()["pending"] is False
    assert r.json()["run"]["status"] == "failed"


def test_fixture_download_is_safe_and_real(client, owner):
    items = client.get("/api/v1/labs", headers=owner["headers"]).json()["items"]
    lab = next(i for i in items if i["slug"] == "pcap-dns-tunnel")
    r = client.get(f"/api/v1/labs/{lab['id']}/fixture", headers=owner["headers"])
    assert r.status_code == 200
    assert r.headers["content-type"] in ("application/vnd.tcpdump.pcap", "application/octet-stream")
    assert len(r.content) > 0
