"""Academy curriculum, progress persistence and privacy boundaries."""

from __future__ import annotations

import json
import secrets

from app.academy.content import lesson_definitions


def _answer_key(slug: str) -> dict[str, str]:
    definition = next(item for item in lesson_definitions() if item["slug"] == slug)
    return {question["id"]: question["answer"] for question in definition["quiz"]}


def test_catalogue_has_three_divisions_and_300_lessons(client, owner):
    r = client.get("/api/v1/academy/divisions", headers=owner["headers"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert [d["key"] for d in body["divisions"]] == ["defense", "offense", "forensics"]
    assert body["totals"]["lesson_count"] == 300
    assert body["totals"]["video_verified"] == 0
    assert body["totals"]["video_pending"] == 300
    for division in body["divisions"]:
        assert division["lesson_count"] == 100
        assert len(division["categories"]) == 20
        assert division["video_verified"] == 0
        assert division["video_pending"] == 100


def test_lesson_payload_marks_video_pending_and_hides_answers(client, owner):
    r = client.get("/api/v1/academy/lessons", headers=owner["headers"], params={"division": "defense", "limit": 1})
    assert r.status_code == 200, r.text
    item = r.json()["items"][0]
    assert item["video"]["available"] is False
    assert item["video"]["status"] == "pending_verification"
    assert item["resource"]["kind"] == "official_documentation"

    detail = client.get(f"/api/v1/academy/lessons/{item['slug']}", headers=owner["headers"])
    assert detail.status_code == 200, detail.text
    payload = detail.json()
    assert payload["lesson"]["quiz"]
    raw = json.dumps(payload, ensure_ascii=False)
    assert '"answer"' not in raw
    assert "explanation_en" not in raw
    assert "explanation_ar" not in raw


def test_progress_bookmark_notes_quiz_and_stats_persist(client, owner):
    slug = "offense-cloud_container-capstone"
    detail = client.get(f"/api/v1/academy/lessons/{slug}", headers=owner["headers"]).json()
    lesson_id = detail["lesson"]["id"]

    started = client.put(
        f"/api/v1/academy/lessons/{lesson_id}/progress",
        headers=owner["headers"],
        json={"status": "in_progress", "progress_percent": 35},
    )
    assert started.status_code == 200, started.text
    assert started.json()["user_state"]["status"] == "in_progress"
    assert started.json()["user_state"]["progress_percent"] == 35

    bookmarked = client.post(
        f"/api/v1/academy/lessons/{lesson_id}/bookmark",
        headers=owner["headers"],
        json={"bookmarked": True},
    )
    assert bookmarked.status_code == 200
    assert bookmarked.json()["user_state"]["bookmarked"] is True

    notes = client.put(
        f"/api/v1/academy/lessons/{lesson_id}/notes",
        headers=owner["headers"],
        json={"notes": "Synthetic lab note: verify scope before testing."},
    )
    assert notes.status_code == 200
    assert notes.json()["notes"].startswith("Synthetic lab note")

    wrong = client.post(
        f"/api/v1/academy/lessons/{lesson_id}/quiz",
        headers=owner["headers"],
        json={"answers": {question: "wrong" for question in _answer_key(slug)}},
    )
    assert wrong.status_code == 200, wrong.text
    assert wrong.json()["passed"] is False
    assert wrong.json()["score"] == 0

    correct = client.post(
        f"/api/v1/academy/lessons/{lesson_id}/quiz",
        headers=owner["headers"],
        json={"answers": _answer_key(slug)},
    )
    assert correct.status_code == 200, correct.text
    assert correct.json()["passed"] is True
    assert correct.json()["score"] == 100

    refreshed = client.get(f"/api/v1/academy/lessons/{lesson_id}", headers=owner["headers"]).json()
    assert refreshed["lesson"]["user_state"]["status"] == "completed"
    assert refreshed["lesson"]["user_state"]["bookmarked"] is True
    assert refreshed["lesson"]["notes"].startswith("Synthetic lab note")

    stats = client.get("/api/v1/academy/me/stats", headers=owner["headers"])
    assert stats.status_code == 200
    assert stats.json()["totals"]["completed"] >= 1


def test_private_lesson_state_is_scoped_to_the_authenticated_user(client, owner):
    slug = "forensics-case_reporting-capstone"
    lesson = client.get(f"/api/v1/academy/lessons/{slug}", headers=owner["headers"]).json()["lesson"]
    client.put(
        f"/api/v1/academy/lessons/{lesson['id']}/notes",
        headers=owner["headers"],
        json={"notes": "Owner-only case note"},
    )

    email = f"academy.viewer.{secrets.token_hex(4)}@example.com"
    password = "AcademyViewer!2026"
    registered = client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": "Academy Viewer", "password": password},
    )
    assert registered.status_code == 201, registered.text
    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200, login.text
    viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    viewer_detail = client.get(f"/api/v1/academy/lessons/{slug}", headers=viewer_headers).json()
    assert viewer_detail["lesson"]["notes"] == ""
    assert viewer_detail["lesson"]["user_state"]["status"] == "not_started"

    client.put(
        f"/api/v1/academy/lessons/{lesson['id']}/notes",
        headers=viewer_headers,
        json={"notes": "Viewer-only note"},
    )
    owner_detail = client.get(f"/api/v1/academy/lessons/{slug}", headers=owner["headers"]).json()
    assert owner_detail["lesson"]["notes"] == "Owner-only case note"