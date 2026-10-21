"""Command-platform routes: unified graph, timeline engine, posture, purple team.

Every response is computed from stored records.  Where a feature needs data
that does not exist yet, the response says so explicitly instead of returning
a plausible-looking placeholder.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.utils import new_id, to_iso_z, utcnow
from ...db import get_db
from ...engines.logs_engine import OPS, rule_matches
from ...models import (
    CveRecord,
    DetectionRule,
    Finding,
    FindingIntelLink,
    KevEntry,
    Lesson,
    PurpleSimulation,
    SigmaRule,
)
from ...purple.scenarios import SCENARIO_INDEX, list_scenarios
from ...services.graph import attack_paths, build_graph
from ...services.posture import compute_posture
from ...services.timeline import build_timeline, group_timeline
from ..deps import AuthContext, api_error, audit, get_auth, project_access, write_scope_guard
from .common import parse_dt

log = logging.getLogger("nexus.api.command")

router = APIRouter(tags=["command"])


class PostureSnapshotBody(BaseModel):
    save: bool = True


class PurpleRunBody(BaseModel):
    scenario_key: str = Field(min_length=3, max_length=80)
    notes: str = Field(default="", max_length=4000)


# ---------------------------------------------------------------------------
# Unified security graph
# ---------------------------------------------------------------------------
@router.get("/projects/{project_id}/graph")
def graph(
    project_id: str,
    kinds: str | None = Query(default=None, description="Comma separated node kinds"),
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Nodes and edges derived from the project's stored records."""
    wanted = [item.strip() for item in (kinds or "").split(",") if item.strip()] or None
    payload = build_graph(db, project_id, kinds=wanted)
    payload["attack_paths"] = attack_paths(payload)
    return payload


@router.get("/projects/{project_id}/graph/attack-paths")
def graph_paths(
    project_id: str,
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    payload = build_graph(db, project_id)
    paths = attack_paths(payload)
    return {
        "project_id": project_id,
        "paths": paths,
        "count": len(paths),
        "note": (
            "Paths are computed from connected stored records. An empty result means no "
            "recorded chain currently reaches an incident."
        ),
    }


# ---------------------------------------------------------------------------
# Timeline engine
# ---------------------------------------------------------------------------
@router.get("/projects/{project_id}/timeline/events")
def timeline(
    project_id: str,
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    sources: str | None = Query(default=None),
    severities: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    granularity: str = Query(default="hour", pattern="^(hour|day|week)$"),
    limit: int = Query(default=800, ge=1, le=3000),
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Merged event timeline across every stored telemetry source."""
    payload = build_timeline(
        db,
        project_id,
        start=parse_dt(start, field="start"),
        end=parse_dt(end, field="end"),
        sources=[item.strip() for item in (sources or "").split(",") if item.strip()] or None,
        severities=[item.strip() for item in (severities or "").split(",") if item.strip()] or None,
        search=q,
        limit=limit,
    )
    payload["groups"] = group_timeline(payload["events"], granularity)
    payload["granularity"] = granularity
    return payload


# ---------------------------------------------------------------------------
# Security posture
# ---------------------------------------------------------------------------
@router.get("/projects/{project_id}/posture")
def posture(
    project_id: str,
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Transparent posture score computed from recorded findings."""
    return compute_posture(db, project_id)


@router.post("/projects/{project_id}/posture/snapshot")
def posture_snapshot(
    project_id: str,
    body: PostureSnapshotBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Persist a dated snapshot so the trend can be compared over time."""
    from ...models import PostureSnapshot

    write_scope_guard(access.auth)
    result = compute_posture(db, project_id)
    if body.save:
        snapshot = PostureSnapshot(
            id=new_id(),
            project_id=project_id,
            score=result["score"],
            grade=result["grade"],
            factors=result["factors"],
            missing_information=result["missing_information"],
            coverage=result["coverage"],
            computed_by=access.auth.user_id,
        )
        db.add(snapshot)
        db.commit()
        audit(db, access.auth, "posture.snapshot", project_id=project_id, entity_type="project", entity_id=project_id)
    history = [
        {
            "score": row.score,
            "grade": row.grade,
            "coverage": row.coverage,
            "computed_at": to_iso_z(row.computed_at),
        }
        for row in db.execute(
            select(PostureSnapshot)
            .where(PostureSnapshot.project_id == project_id)
            .order_by(PostureSnapshot.computed_at.desc())
            .limit(30)
        ).scalars().all()
    ]
    result["history"] = history
    return result


# ---------------------------------------------------------------------------
# Purple-team simulation
# ---------------------------------------------------------------------------
def _rule_covers_signal(rule: DetectionRule, signal: dict[str, Any]) -> bool:
    """Would this NEXUS detection rule fire on the described signal?"""
    definition = rule.definition or {}
    conditions = definition.get("conditions") or []
    if not conditions:
        return False
    field = signal.get("field")
    pattern = signal.get("pattern") or ""
    for condition in conditions:
        if not isinstance(condition, dict):
            continue
        if condition.get("field") != field:
            continue
        op = condition.get("op")
        expected = condition.get("value")
        comparator = OPS.get(op)
        if comparator is None:
            continue
        try:
            # A regex condition overlaps the signal pattern when both mention the
            # same literal token; otherwise compare the signal as a sample value.
            if op == "regex" and isinstance(expected, str):
                import re as _re

                try:
                    literal = _re.sub(r"[\\^$.|?*+()\[\]{}]", "", expected).strip("()")
                except Exception:
                    literal = expected
                if literal and literal.lower() in pattern.lower():
                    return True
            if comparator(pattern, expected):
                return True
        except Exception:
            continue
    return False


@router.get("/projects/{project_id}/purple/scenarios")
def purple_scenarios(
    project_id: str,
    division: str | None = Query(default=None, pattern="^(defense|offense|forensics)$"),
    access=Depends(project_access("viewer")),
) -> dict[str, Any]:
    """Catalogue of emulated adversary behaviours available for simulation."""
    return {
        "items": list_scenarios(division),
        "count": len(list_scenarios(division)),
        "note": (
            "Simulations never contact a target. They evaluate the project's own "
            "detection rules against the telemetry each scenario would produce."
        ),
    }


@router.get("/projects/{project_id}/purple/simulations")
def purple_simulations(
    project_id: str,
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = db.execute(
        select(PurpleSimulation)
        .where(PurpleSimulation.project_id == project_id)
        .order_by(PurpleSimulation.started_at.desc())
        .limit(50)
    ).scalars().all()
    return {
        "items": [
            {
                "id": row.id,
                "scenario_key": row.scenario_key,
                "scenario_title": row.scenario_title,
                "division": row.division,
                "status": row.status,
                "score": row.score,
                "notes": row.notes,
                "started_at": to_iso_z(row.started_at),
                "finished_at": to_iso_z(row.finished_at),
                "missed": row.missed,
                "detections": row.detections,
            }
            for row in rows
        ]
    }


@router.post("/projects/{project_id}/purple/run")
def purple_run(
    project_id: str,
    body: PurpleRunBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Evaluate the project's detections against a scenario's expected telemetry."""
    write_scope_guard(access.auth)
    scenario = SCENARIO_INDEX.get(body.scenario_key)
    if scenario is None:
        raise api_error("unknown_scenario", "Unknown purple-team scenario.", status.HTTP_404_NOT_FOUND)

    rules = db.execute(
        select(DetectionRule).where(DetectionRule.project_id == project_id)
    ).scalars().all()
    enabled = [rule for rule in rules if rule.enabled]

    expected: list[dict[str, Any]] = []
    observed: list[dict[str, Any]] = []
    missed: list[dict[str, Any]] = []
    detections: list[dict[str, Any]] = []

    for signal in scenario["expected_telemetry"]:
        expected.append(signal)
        matched = []
        for rule in enabled:
            if _rule_covers_signal(rule, signal):
                matched.append(
                    {
                        "rule_id": rule.id,
                        "rule": rule.name,
                        "severity": rule.severity,
                        "origin": "detection_rules",
                    }
                )
        # A Sigma rule stored for this project is also consulted by name.
        sigma_rows = db.execute(
            select(SigmaRule).where(SigmaRule.project_id == project_id)
        ).scalars().all()
        for rule in sigma_rows:
            haystack = f"{rule.name} {rule.title} {rule.description}".lower()
            for keyword in scenario["expected_detections"]:
                if keyword.lower() in haystack:
                    matched.append(
                        {
                            "rule_id": rule.id,
                            "rule": rule.name,
                            "severity": rule.level,
                            "origin": "sigma_rules",
                        }
                    )
                    break

        record = {
            "signal": signal["signal"],
            "field": signal["field"],
            "detected": bool(matched),
            "rules": matched,
        }
        observed.append(record)
        if matched:
            detections.append(record)
        else:
            missed.append(record)

    total = len(expected)
    score = round((len(detections) / total) * 100, 1) if total else 0.0

    simulation = PurpleSimulation(
        id=new_id(),
        project_id=project_id,
        scenario_key=scenario["key"],
        scenario_title=scenario["title_en"],
        division=scenario["division"],
        status="completed",
        expected_telemetry=expected,
        observed_telemetry=observed,
        detections=detections,
        missed=missed,
        score=score,
        notes=body.notes,
        actor_id=access.auth.user_id,
        started_at=utcnow(),
        finished_at=utcnow(),
    )
    db.add(simulation)
    db.commit()
    db.refresh(simulation)
    audit(
        db,
        access.auth,
        "purple.run",
        project_id=project_id,
        entity_type="purple_simulation",
        entity_id=simulation.id,
        meta={"scenario": scenario["key"], "score": score},
    )

    return {
        "id": simulation.id,
        "scenario": scenario,
        "expected": expected,
        "observed": observed,
        "detections": detections,
        "missed": missed,
        "score": score,
        "rules_evaluated": len(enabled),
        "recommendation": (
            "Every expected signal is covered by an enabled detection."
            if not missed
            else "Add or refine detections for the uncovered signals listed under 'missed'."
        ),
    }


# ---------------------------------------------------------------------------
# Security knowledge graph
# ---------------------------------------------------------------------------
@router.get("/knowledge")
def knowledge_graph(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
) -> dict[str, Any]:
    """Connect CVEs, MITRE techniques, detections and lessons.

    Built from the local intelligence cache and the platform curriculum.  Each
    node reports when its data was last refreshed so a stale link is visible.
    """
    cves = db.execute(select(CveRecord)).scalars().all()
    kevs = db.execute(select(KevEntry)).scalars().all()
    rules = db.execute(select(DetectionRule)).scalars().all()
    lessons = db.execute(select(Lesson)).scalars().all()

    kev_by_cve = {row.cve_id for row in kevs}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for record in cves:
        nodes.append(
            {
                "id": f"cve:{record.id}",
                "kind": "cve",
                "label": record.id,
                "severity": record.cvss_severity or "unknown",
                "updated_at": to_iso_z(record.modified_at or record.fetched_at),
                "meta": {
                    "cvss": record.cvss_v3_score,
                    "cwes": record.cwes,
                    "kev": record.id in kev_by_cve,
                    "source": record.source,
                    "source_url": record.source_url,
                },
            }
        )
        for cwe in record.cwes or []:
            nodes.append(
                {
                    "id": f"cwe:{cwe}",
                    "kind": "cwe",
                    "label": cwe,
                    "severity": "info",
                    "updated_at": to_iso_z(record.modified_at or record.fetched_at),
                    "meta": {},
                }
            )
            edges.append(
                {
                    "id": f"cve:{record.id}->cwe:{cwe}",
                    "source": f"cve:{record.id}",
                    "target": f"cwe:{cwe}",
                    "kind": "weakness",
                    "label": "is classified as",
                    "confidence": "certain",
                    "origin": "cve_records.cwes",
                }
            )

    for row in kevs:
        nodes.append(
            {
                "id": f"kev:{row.cve_id}",
                "kind": "kev",
                "label": row.cve_id,
                "severity": "critical",
                "updated_at": to_iso_z(row.fetched_at),
                "meta": {
                    "vendor": row.vendor_project,
                    "product": row.product,
                    "ransomware": row.known_ransomware,
                    "due_date": to_iso_z(row.due_date),
                    "source_url": row.source_url,
                },
            }
        )
        if f"cve:{row.cve_id}" in {node["id"] for node in nodes}:
            edges.append(
                {
                    "id": f"cve:{row.cve_id}->kev:{row.cve_id}",
                    "source": f"cve:{row.cve_id}",
                    "target": f"kev:{row.cve_id}",
                    "kind": "known_exploited",
                    "label": "known exploited",
                    "confidence": "certain",
                    "origin": "kev_entries",
                }
            )

    for rule in rules:
        node_id = f"rule:{rule.id}"
        nodes.append(
            {
                "id": node_id,
                "kind": "detection",
                "label": rule.name,
                "severity": rule.severity,
                "updated_at": to_iso_z(rule.updated_at),
                "meta": {"enabled": rule.enabled, "builtin": rule.is_builtin, "description": rule.description},
            }
        )
        for tag in rule.definition.get("tags", []) if isinstance(rule.definition, dict) else []:
            technique = str(tag).upper()
            if not technique.startswith("T"):
                continue
            nodes.append(
                {
                    "id": f"technique:{technique}",
                    "kind": "technique",
                    "label": technique,
                    "severity": "info",
                    "updated_at": to_iso_z(rule.updated_at),
                    "meta": {"framework": "MITRE ATT&CK"},
                }
            )
            edges.append(
                {
                    "id": f"{node_id}->technique:{technique}",
                    "source": node_id,
                    "target": f"technique:{technique}",
                    "kind": "detects",
                    "label": "detects",
                    "confidence": "certain",
                    "origin": "detection_rules.definition.tags",
                }
            )

    # Link lessons to techniques by their tags (the curriculum records ATT&CK ids).
    lesson_nodes: list[dict[str, Any]] = []
    for lesson in lessons:
        lesson_nodes.append(
            {
                "id": f"lesson:{lesson.id}",
                "kind": "lesson",
                "label": lesson.title_en or lesson.title_ar,
                "severity": "info",
                "updated_at": to_iso_z(lesson.updated_at),
                "meta": {
                    "slug": lesson.slug,
                    "division": lesson.division,
                    "category": lesson.category,
                    "difficulty": lesson.difficulty,
                    "duration_minutes": lesson.duration_minutes,
                    "video_status": lesson.video_status,
                },
            }
        )
        for tag in lesson.tags or []:
            technique = str(tag).upper()
            if not technique.startswith("T"):
                continue
            nodes.append(
                {
                    "id": f"technique:{technique}",
                    "kind": "technique",
                    "label": technique,
                    "severity": "info",
                    "updated_at": to_iso_z(lesson.updated_at),
                    "meta": {"framework": "MITRE ATT&CK"},
                }
            )
            edges.append(
                {
                    "id": f"lesson:{lesson.id}->technique:{technique}",
                    "source": f"lesson:{lesson.id}",
                    "target": f"technique:{technique}",
                    "kind": "teaches",
                    "label": "teaches",
                    "confidence": "firm",
                    "origin": "academy_lessons.tags",
                }
            )
    nodes.extend(lesson_nodes)

    # Deduplicate nodes by id.
    unique: dict[str, dict[str, Any]] = {}
    for node in nodes:
        unique.setdefault(node["id"], node)

    latest = max(
        [to_iso_z(row.fetched_at) or "" for row in cves] + [to_iso_z(row.fetched_at) or "" for row in kevs] or [""]
    )
    return {
        "nodes": list(unique.values()),
        "edges": edges,
        "stats": {
            "cves": len(cves),
            "kev": len(kevs),
            "detections": len(rules),
            "lessons": len(lessons),
            "techniques": sum(1 for node in unique.values() if node["kind"] == "technique"),
        },
        "last_updated": latest or None,
        "sources": [
            {"name": "NVD 2.0", "kind": "cve", "updated_at": latest or None},
            {"name": "CISA KEV", "kind": "kev", "updated_at": latest or None},
            {"name": "NEXUS curriculum", "kind": "lesson", "updated_at": None},
        ],
        "note": (
            "The knowledge graph joins the local CVE/KEV cache, the configured detections "
            "and the published curriculum. Nodes report the timestamp of the record they "
            "were built from."
        ),
    }
