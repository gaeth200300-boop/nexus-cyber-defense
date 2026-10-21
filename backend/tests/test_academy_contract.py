"""The academy contract the web client depends on.

The UI reads division counters, a personalised path and training records from
dedicated endpoints and renders flattened learner state on every lesson row.
These tests pin that shape so a backend refactor cannot silently break the
interface.
"""

from __future__ import annotations

from app.academy.content import lesson_definitions
from app.core.utils import new_id, utcnow
from app.db import SessionLocal
from app.models import Lesson, LessonProgress, User
from app.security import create_access_token, hash_password


def _fresh_learner(email: str = "contract.learner@example.com") -> dict[str, str]:
    """A brand new account, so a learner's progress cannot leak into other tests."""
    with SessionLocal() as db:
        existing = db.query(User).filter(User.email == email).first()
        if existing is None:
            user = User(
                id=new_id(),
                email=email,
                full_name="Contract Learner",
                role="viewer",
                is_active=True,
                password_hash=hash_password("LearnerPass!2026"),
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            user = existing
    return {"Authorization": f"Bearer {create_access_token(user.id, role=user.role)}"}


def test_overview_reports_divisions_and_per_division_counters(client, owner):
    r = client.get("/api/v1/academy/overview", headers=owner["headers"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert [d["key"] for d in body["divisions"]] == ["defense", "offense", "forensics"]
    for division in body["divisions"]:
        assert division["total"] == 100
        assert 0 <= division["completed"] <= 100
        assert division["percent"] == division["completed"]
        assert division["average_quiz"] is None or isinstance(division["average_quiz"], int)
    assert body["summary"]["total_lessons"] == 300
    assert set(body["summary"]["divisions"]) == {"defense", "offense", "forensics"}


def test_learning_path_returns_unmet_prerequisites_and_a_reason(client, owner):
    r = client.get(
        "/api/v1/academy/learning-path", headers=owner["headers"], params={"division": "defense"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["division"] == "defense"
    assert body["recommendations"], "a fresh learner must get a starting point"
    first = body["recommendations"][0]
    assert "reason" in first
    assert "unmet_prerequisites" in first
    assert first["status"] == "not_started"


def test_learning_path_rejects_an_unknown_division(client, owner):
    r = client.get(
        "/api/v1/academy/learning-path", headers=owner["headers"], params={"division": "nope"}
    )
    assert r.status_code == 422


def test_lesson_list_flattens_learner_state(client, owner):
    r = client.get(
        "/api/v1/academy/lessons", headers=owner["headers"], params={"division": "offense", "limit": 5}
    )
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert len(items) == 5
    for item in items:
        for field in ("status", "progress_percent", "quiz_score", "bookmarked", "completed_at"):
            assert field in item, f"{field} must be available on a list row"
        assert item["video_status"] == "pending_verification"
        assert item["video"]["available"] is False


def test_lesson_detail_exposes_objectives_exercise_and_resource(client, owner):
    slug = "defense-soc_operations-foundations"
    r = client.get(f"/api/v1/academy/lessons/{slug}", headers=owner["headers"])
    assert r.status_code == 200, r.text
    lesson = r.json()["lesson"]
    assert lesson["slug"] == slug
    assert lesson["objectives"]
    assert lesson["exercise_en"] and lesson["exercise_ar"]
    assert lesson["resource_url"].startswith("https://")
    assert lesson["quiz"], "the lesson must carry a knowledge check"
    assert all("answer" not in question for question in lesson["quiz"])


def test_certificates_are_empty_until_the_track_is_complete(client, owner):
    headers = _fresh_learner("contract.certificates@example.com")
    r = client.get("/api/v1/academy/certificates", headers=headers)
    assert r.status_code == 200
    assert r.json()["items"] == []

    issued = client.post(
        "/api/v1/academy/certificates/defense",
        headers=headers,
        json={"display_name": "Contract Learner"},
    )
    assert issued.status_code == 409, "a partial track must not issue a record"
    assert issued.json()["detail"]["code"] == "not_complete"


def test_certificate_is_issued_when_every_lesson_is_complete(client, owner):
    import sqlalchemy

    headers = _fresh_learner("contract.complete@example.com")
    with SessionLocal() as db:
        user_id = db.query(User).filter(User.email == "contract.complete@example.com").one().id
        lesson_ids = db.execute(sqlalchemy.select(Lesson.id)).scalars().all()
        for lesson_id in lesson_ids:
            db.add(
                LessonProgress(
                    id=new_id(),
                    user_id=user_id,
                    lesson_id=lesson_id,
                    status="completed",
                    progress_percent=100,
                    quiz_score=90,
                    quiz_answers={},
                    quiz_attempts=1,
                    completed_at=utcnow(),
                )
            )
        db.commit()

    issued = client.post(
        "/api/v1/academy/certificates/forensics",
        headers=headers,
        json={"display_name": "Contract Learner"},
    )
    assert issued.status_code == 200, issued.text
    payload = issued.json()
    assert payload["division"] == "forensics"
    assert payload["lessons_completed"] == 100
    assert payload["serial"].startswith("NX-FORENSICS-")
    assert "not an external professional certification" in payload["disclaimer"]

    listed = client.get("/api/v1/academy/certificates", headers=headers)
    assert any(item["division"] == "forensics" for item in listed.json()["items"])


def test_lesson_count_is_exactly_one_hundred_per_division():
    definitions = lesson_definitions()
    assert len(definitions) == 300
    for division in ("defense", "offense", "forensics"):
        items = [item for item in definitions if item["division"] == division]
        assert len(items) == 100
        assert len({item["slug"] for item in items}) == 100
        assert len({item["title_en"] for item in items}) == 100
