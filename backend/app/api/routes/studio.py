"""Studio routes: detection rules, investigation workbench, evidence vault.

* Detection Rule Studio - author, validate and test Sigma rules against the
  log events NEXUS actually stores.
* Investigation Workbench - cases, competing hypotheses, annotations, tasks.
* Digital Evidence Integrity Vault - uploads with SHA-256, integrity
  verification and an append-only chain of custody.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...config import settings
from ...core.utils import new_id, slugify, to_iso_z, utcnow
from ...db import get_db
from ...models import (
    CaseAnnotation,
    CaseFile,
    CaseHypothesis,
    CaseTask,
    CustodyEvent,
    Evidence,
    SigmaRule,
)
from ...services.sigma import RuleError, test_rule, validate_rule
from ..deps import AuthContext, api_error, audit, project_access, write_scope_guard
from .common import paged

log = logging.getLogger("nexus.api.studio")

router = APIRouter(tags=["studio"])

# Evidence formats the vault accepts.  Anything else is refused with a clear
# message rather than silently stored.
ALLOWED_EVIDENCE_SUFFIXES = {
    ".pcap": "application/vnd.tcpdump.pcap",
    ".pcapng": "application/vnd.tcpdump.pcapng",
    ".cap": "application/vnd.tcpdump.pcap",
    ".evtx": "application/octet-stream",
    ".log": "text/plain; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".json": "application/json",
    ".csv": "text/csv; charset=utf-8",
    ".zip": "application/zip",
    ".mem": "application/octet-stream",
    ".raw": "application/octet-stream",
    ".img": "application/octet-stream",
    ".dd": "application/octet-stream",
    ".E01": "application/octet-stream",
    ".e01": "application/octet-stream",
}

MAX_EVIDENCE_BYTES = 512 * 1024 * 1024  # 512 MiB hard ceiling per file


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------
class SigmaRuleBody(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    title: str = Field(default="", max_length=240)
    description: str = Field(default="", max_length=8000)
    status: str = Field(default="experimental", max_length=30)
    author: str = Field(default="", max_length=120)
    license: str = Field(default="", max_length=60)
    level: str = Field(default="medium", max_length=20)
    logsource: dict = Field(default_factory=dict)
    detection: dict = Field(default_factory=dict)
    fields: list = Field(default_factory=list)
    falsepositives: list = Field(default_factory=list)
    references: list = Field(default_factory=list)
    tags: list = Field(default_factory=list)
    techniques: list = Field(default_factory=list)
    lessons: list = Field(default_factory=list)


class RuleTestBody(BaseModel):
    limit: int = Field(default=500, ge=1, le=5000)


class CaseBody(BaseModel):
    title: str = Field(min_length=3, max_length=240)
    summary: str = Field(default="", max_length=8000)
    severity: str = Field(default="medium", max_length=20)
    status: str = Field(default="open", max_length=30)
    classification: str = Field(default="internal", max_length=60)
    tags: list = Field(default_factory=list)
    assignee_id: str = Field(default="", max_length=36)


class HypothesisBody(BaseModel):
    statement: str = Field(min_length=5, max_length=4000)
    confidence: str = Field(default="tentative", max_length=20)
    rationale: str = Field(default="", max_length=4000)
    evidence_refs: list = Field(default_factory=list)


class HypothesisPatch(BaseModel):
    status: str | None = Field(default=None, max_length=30)
    confidence: str | None = Field(default=None, max_length=20)
    rationale: str | None = Field(default=None, max_length=4000)


class AnnotationBody(BaseModel):
    body: str = Field(min_length=1, max_length=8000)
    entity_type: str = Field(default="", max_length=40)
    entity_id: str = Field(default="", max_length=36)


class TaskBody(BaseModel):
    title: str = Field(min_length=3, max_length=240)
    detail: str = Field(default="", max_length=4000)
    assignee_id: str = Field(default="", max_length=36)


class TaskPatch(BaseModel):
    title: str | None = Field(default=None, max_length=240)
    detail: str | None = Field(default=None, max_length=4000)
    status: str | None = Field(default=None, max_length=30)
    assignee_id: str | None = Field(default=None, max_length=36)


class CustodyBody(BaseModel):
    action: str = Field(default="analyzed", max_length=30)
    location: str = Field(default="", max_length=160)
    notes: str = Field(default="", max_length=4000)
    sha256_at_action: str = Field(default="", max_length=64)


# ---------------------------------------------------------------------------
# Detection Rule Studio
# ---------------------------------------------------------------------------
def _rule_payload(rule: SigmaRule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "title": rule.title,
        "description": rule.description,
        "status": rule.status,
        "author": rule.author,
        "license": rule.license,
        "level": rule.level,
        "logsource": rule.logsource or {},
        "detection": rule.detection or {},
        "fields": rule.fields or [],
        "falsepositives": rule.falsepositives or [],
        "references": rule.references or [],
        "tags": rule.tags or [],
        "techniques": rule.techniques or [],
        "lessons": rule.lessons or [],
        "validation": rule.validation or {},
        "last_validated_at": to_iso_z(rule.last_validated_at),
        "created_at": to_iso_z(rule.created_at),
        "updated_at": to_iso_z(rule.updated_at),
    }


@router.get("/projects/{project_id}/rules")
def list_rules(
    project_id: str,
    q: str | None = Query(default=None, max_length=120),
    rule_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    stmt = select(SigmaRule).where(SigmaRule.project_id == project_id)
    count_stmt = select(func.count(SigmaRule.id)).where(SigmaRule.project_id == project_id)
    if q:
        needle = f"%{q.strip()}%"
        clause = SigmaRule.name.ilike(needle) | SigmaRule.title.ilike(needle) | SigmaRule.description.ilike(needle)
        stmt = stmt.where(clause)
        count_stmt = count_stmt.where(clause)
    if rule_status:
        stmt = stmt.where(SigmaRule.status == rule_status)
        count_stmt = count_stmt.where(SigmaRule.status == rule_status)
    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.order_by(SigmaRule.updated_at.desc()).limit(limit).offset(offset)).scalars().all()
    return paged([_rule_payload(row) for row in rows], int(total), limit=limit, offset=offset)


@router.post("/projects/{project_id}/rules/validate")
def validate_only(
    body: SigmaRuleBody,
    access=Depends(project_access("analyst")),
) -> dict[str, Any]:
    """Validate a rule without saving it."""
    return validate_rule(body.model_dump())


@router.post("/projects/{project_id}/rules", status_code=status.HTTP_201_CREATED)
def create_rule(
    project_id: str,
    body: SigmaRuleBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    name = slugify(body.name, 150)
    if not name:
        raise api_error("invalid_name", "The rule name could not be normalised.", status.HTTP_422_UNPROCESSABLE_ENTITY)
    existing = db.execute(
        select(SigmaRule).where(SigmaRule.project_id == project_id, SigmaRule.name == name)
    ).scalar_one_or_none()
    if existing is not None:
        raise api_error("rule_exists", "A rule with this name already exists in the project.", status.HTTP_409_CONFLICT)

    payload = body.model_dump()
    payload["name"] = name
    report = validate_rule(payload)
    rule = SigmaRule(
        id=new_id(),
        project_id=project_id,
        created_by=access.auth.user_id,
        validation=report,
        last_validated_at=utcnow(),
        **payload,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    audit(db, access.auth, "rule.create", project_id=project_id, entity_type="sigma_rule", entity_id=rule.id)
    return _rule_payload(rule)


@router.get("/projects/{project_id}/rules/{rule_id}")
def get_rule(
    project_id: str,
    rule_id: str,
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rule = db.get(SigmaRule, rule_id)
    if rule is None or rule.project_id != project_id:
        raise api_error("rule_not_found", "Detection rule not found.", status.HTTP_404_NOT_FOUND)
    return _rule_payload(rule)


@router.put("/projects/{project_id}/rules/{rule_id}")
def update_rule(
    project_id: str,
    rule_id: str,
    body: SigmaRuleBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    rule = db.get(SigmaRule, rule_id)
    if rule is None or rule.project_id != project_id:
        raise api_error("rule_not_found", "Detection rule not found.", status.HTTP_404_NOT_FOUND)
    payload = body.model_dump()
    payload["name"] = slugify(payload["name"], 150) or rule.name
    for key, value in payload.items():
        setattr(rule, key, value)
    rule.validation = validate_rule(payload)
    rule.last_validated_at = utcnow()
    db.commit()
    db.refresh(rule)
    audit(db, access.auth, "rule.update", project_id=project_id, entity_type="sigma_rule", entity_id=rule.id)
    return _rule_payload(rule)


@router.delete("/projects/{project_id}/rules/{rule_id}")
def delete_rule(
    project_id: str,
    rule_id: str,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    rule = db.get(SigmaRule, rule_id)
    if rule is None or rule.project_id != project_id:
        raise api_error("rule_not_found", "Detection rule not found.", status.HTTP_404_NOT_FOUND)
    db.delete(rule)
    db.commit()
    audit(db, access.auth, "rule.delete", project_id=project_id, entity_type="sigma_rule", entity_id=rule_id)
    return {"deleted": rule_id}


@router.post("/projects/{project_id}/rules/{rule_id}/validate")
def revalidate_rule(
    project_id: str,
    rule_id: str,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    rule = db.get(SigmaRule, rule_id)
    if rule is None or rule.project_id != project_id:
        raise api_error("rule_not_found", "Detection rule not found.", status.HTTP_404_NOT_FOUND)
    report = validate_rule(
        {
            "name": rule.name,
            "title": rule.title,
            "description": rule.description,
            "status": rule.status,
            "level": rule.level,
            "logsource": rule.logsource,
            "detection": rule.detection,
            "falsepositives": rule.falsepositives,
            "references": rule.references,
        }
    )
    rule.validation = report
    rule.last_validated_at = utcnow()
    db.commit()
    db.refresh(rule)
    return _rule_payload(rule)


@router.post("/projects/{project_id}/rules/{rule_id}/test")
def test_saved_rule(
    project_id: str,
    rule_id: str,
    body: RuleTestBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Run a saved rule against the log events stored for this project."""
    rule = db.get(SigmaRule, rule_id)
    if rule is None or rule.project_id != project_id:
        raise api_error("rule_not_found", "Detection rule not found.", status.HTTP_404_NOT_FOUND)
    try:
        return test_rule(db, project_id, {"detection": rule.detection or {}}, limit=body.limit)
    except RuleError as exc:
        raise api_error("invalid_rule", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY) from exc


@router.post("/projects/{project_id}/rules/test")
def test_inline_rule(
    project_id: str,
    body: SigmaRuleBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Run an unsaved rule against the project's stored log events."""
    try:
        return test_rule(db, project_id, {"detection": body.detection or {}})
    except RuleError as exc:
        raise api_error("invalid_rule", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY) from exc


# ---------------------------------------------------------------------------
# Investigation Workbench
# ---------------------------------------------------------------------------
def _case_payload(case: CaseFile, db: Session) -> dict[str, Any]:
    hypotheses = db.execute(
        select(CaseHypothesis).where(CaseHypothesis.case_id == case.id).order_by(CaseHypothesis.created_at)
    ).scalars().all()
    annotations = db.execute(
        select(CaseAnnotation).where(CaseAnnotation.case_id == case.id).order_by(CaseAnnotation.created_at.desc())
    ).scalars().all()
    tasks = db.execute(select(CaseTask).where(CaseTask.case_id == case.id).order_by(CaseTask.created_at)).scalars().all()
    return {
        "id": case.id,
        "reference": case.reference,
        "title": case.title,
        "summary": case.summary,
        "status": case.status,
        "severity": case.severity,
        "classification": case.classification,
        "tags": case.tags or [],
        "assignee_id": case.assignee_id,
        "created_by": case.created_by,
        "opened_at": to_iso_z(case.opened_at),
        "closed_at": to_iso_z(case.closed_at),
        "created_at": to_iso_z(case.created_at),
        "updated_at": to_iso_z(case.updated_at),
        "hypotheses": [
            {
                "id": item.id,
                "statement": item.statement,
                "status": item.status,
                "confidence": item.confidence,
                "rationale": item.rationale,
                "evidence_refs": item.evidence_refs or [],
                "created_at": to_iso_z(item.created_at),
            }
            for item in hypotheses
        ],
        "annotations": [
            {
                "id": item.id,
                "body": item.body,
                "entity_type": item.entity_type,
                "entity_id": item.entity_id,
                "author_id": item.author_id,
                "created_at": to_iso_z(item.created_at),
            }
            for item in annotations
        ],
        "tasks": [
            {
                "id": item.id,
                "title": item.title,
                "detail": item.detail,
                "status": item.status,
                "assignee_id": item.assignee_id,
                "due_at": to_iso_z(item.due_at),
                "created_at": to_iso_z(item.created_at),
            }
            for item in tasks
        ],
        "counts": {
            "hypotheses": len(hypotheses),
            "annotations": len(annotations),
            "tasks": len(tasks),
            "open_tasks": sum(1 for item in tasks if item.status != "done"),
        },
    }


@router.get("/projects/{project_id}/cases")
def list_cases(
    project_id: str,
    case_status: str | None = Query(default=None, alias="status"),
    q: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    stmt = select(CaseFile).where(CaseFile.project_id == project_id)
    count_stmt = select(func.count(CaseFile.id)).where(CaseFile.project_id == project_id)
    if case_status:
        stmt = stmt.where(CaseFile.status == case_status)
        count_stmt = count_stmt.where(CaseFile.status == case_status)
    if q:
        needle = f"%{q.strip()}%"
        clause = CaseFile.title.ilike(needle) | CaseFile.reference.ilike(needle) | CaseFile.summary.ilike(needle)
        stmt = stmt.where(clause)
        count_stmt = count_stmt.where(clause)
    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.order_by(CaseFile.created_at.desc()).limit(limit).offset(offset)).scalars().all()
    return paged([_case_payload(row, db) for row in rows], int(total), limit=limit, offset=offset)


@router.post("/projects/{project_id}/cases", status_code=status.HTTP_201_CREATED)
def create_case(
    project_id: str,
    body: CaseBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    count = db.execute(
        select(func.count(CaseFile.id)).where(CaseFile.project_id == project_id)
    ).scalar_one()
    reference = f"NX-{utcnow().year}-{int(count) + 1:04d}"
    case = CaseFile(
        id=new_id(),
        project_id=project_id,
        reference=reference,
        title=body.title,
        summary=body.summary,
        severity=body.severity,
        status=body.status,
        classification=body.classification,
        tags=body.tags,
        assignee_id=body.assignee_id or access.auth.user_id,
        created_by=access.auth.user_id,
        opened_at=utcnow(),
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    audit(db, access.auth, "case.create", project_id=project_id, entity_type="case_file", entity_id=case.id)
    return _case_payload(case, db)


def _load_case(db: Session, project_id: str, case_id: str) -> CaseFile:
    case = db.get(CaseFile, case_id)
    if case is None or case.project_id != project_id:
        raise api_error("case_not_found", "Investigation case not found.", status.HTTP_404_NOT_FOUND)
    return case


@router.get("/projects/{project_id}/cases/{case_id}")
def get_case(
    project_id: str,
    case_id: str,
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _case_payload(_load_case(db, project_id, case_id), db)


@router.patch("/projects/{project_id}/cases/{case_id}")
def patch_case(
    project_id: str,
    case_id: str,
    body: CaseBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    case = _load_case(db, project_id, case_id)
    case.title = body.title
    case.summary = body.summary
    case.severity = body.severity
    case.status = body.status
    case.classification = body.classification
    case.tags = body.tags
    if body.assignee_id:
        case.assignee_id = body.assignee_id
    if body.status == "closed" and case.closed_at is None:
        case.closed_at = utcnow()
    db.commit()
    db.refresh(case)
    audit(db, access.auth, "case.update", project_id=project_id, entity_type="case_file", entity_id=case.id)
    return _case_payload(case, db)


@router.delete("/projects/{project_id}/cases/{case_id}")
def delete_case(
    project_id: str,
    case_id: str,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Remove a case and the records that hang off it."""
    write_scope_guard(access.auth)
    case = _load_case(db, project_id, case_id)
    db.delete(case)
    db.commit()
    audit(db, access.auth, "case.delete", project_id=project_id, entity_type="case_file", entity_id=case_id)
    return {"deleted": case_id}


@router.post("/projects/{project_id}/cases/{case_id}/hypotheses", status_code=status.HTTP_201_CREATED)
def create_hypothesis(
    project_id: str,
    case_id: str,
    body: HypothesisBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    case = _load_case(db, project_id, case_id)
    hypothesis = CaseHypothesis(
        id=new_id(),
        case_id=case.id,
        statement=body.statement,
        confidence=body.confidence,
        rationale=body.rationale,
        evidence_refs=body.evidence_refs,
        created_by=access.auth.user_id,
    )
    db.add(hypothesis)
    db.commit()
    db.refresh(hypothesis)
    audit(db, access.auth, "case.hypothesis", project_id=project_id, entity_type="case_file", entity_id=case.id)
    return _case_payload(case, db)


@router.patch("/projects/{project_id}/cases/{case_id}/hypotheses/{hypothesis_id}")
def patch_hypothesis(
    project_id: str,
    case_id: str,
    hypothesis_id: str,
    body: HypothesisPatch,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    case = _load_case(db, project_id, case_id)
    hypothesis = db.get(CaseHypothesis, hypothesis_id)
    if hypothesis is None or hypothesis.case_id != case.id:
        raise api_error("hypothesis_not_found", "Hypothesis not found.", status.HTTP_404_NOT_FOUND)
    if body.status is not None:
        hypothesis.status = body.status
    if body.confidence is not None:
        hypothesis.confidence = body.confidence
    if body.rationale is not None:
        hypothesis.rationale = body.rationale
    db.commit()
    db.refresh(hypothesis)
    return _case_payload(case, db)


@router.post("/projects/{project_id}/cases/{case_id}/annotations", status_code=status.HTTP_201_CREATED)
def create_annotation(
    project_id: str,
    case_id: str,
    body: AnnotationBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    case = _load_case(db, project_id, case_id)
    annotation = CaseAnnotation(
        id=new_id(),
        case_id=case.id,
        body=body.body,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        author_id=access.auth.user_id,
    )
    db.add(annotation)
    db.commit()
    db.refresh(case)
    audit(db, access.auth, "case.annotation", project_id=project_id, entity_type="case_file", entity_id=case.id)
    return _case_payload(case, db)


@router.post("/projects/{project_id}/cases/{case_id}/tasks", status_code=status.HTTP_201_CREATED)
def create_task(
    project_id: str,
    case_id: str,
    body: TaskBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    case = _load_case(db, project_id, case_id)
    task = CaseTask(
        id=new_id(),
        case_id=case.id,
        title=body.title,
        detail=body.detail,
        assignee_id=body.assignee_id,
    )
    db.add(task)
    db.commit()
    db.refresh(case)
    audit(db, access.auth, "case.task", project_id=project_id, entity_type="case_file", entity_id=case.id)
    return _case_payload(case, db)


@router.patch("/projects/{project_id}/cases/{case_id}/tasks/{task_id}")
def patch_task(
    project_id: str,
    case_id: str,
    task_id: str,
    body: TaskPatch,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    write_scope_guard(access.auth)
    case = _load_case(db, project_id, case_id)
    task = db.get(CaseTask, task_id)
    if task is None or task.case_id != case.id:
        raise api_error("task_not_found", "Task not found.", status.HTTP_404_NOT_FOUND)
    if body.title is not None:
        task.title = body.title
    if body.detail is not None:
        task.detail = body.detail
    if body.status is not None:
        task.status = body.status
    if body.assignee_id is not None:
        task.assignee_id = body.assignee_id
    db.commit()
    db.refresh(case)
    return _case_payload(case, db)


# ---------------------------------------------------------------------------
# Digital Evidence Integrity Vault
# ---------------------------------------------------------------------------
def _evidence_payload(item: Evidence, custody: list[CustodyEvent]) -> dict[str, Any]:
    return {
        "id": item.id,
        "finding_id": item.finding_id,
        "scan_id": item.scan_id,
        "kind": item.kind,
        "label": item.label,
        "sha256": item.raw_sha256,
        "redacted": item.redacted,
        "redactions": item.redactions or [],
        "source": item.source,
        "created_at": to_iso_z(item.created_at),
        "custody": [
            {
                "id": row.id,
                "action": row.action,
                "actor_label": row.actor_label,
                "location": row.location,
                "notes": row.notes,
                "sha256_at_action": row.sha256_at_action,
                "created_at": to_iso_z(row.created_at),
            }
            for row in custody
        ],
    }


@router.get("/projects/{project_id}/evidence")
def list_evidence(
    project_id: str,
    q: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    stmt = select(Evidence).where(Evidence.project_id == project_id)
    count_stmt = select(func.count(Evidence.id)).where(Evidence.project_id == project_id)
    if q:
        needle = f"%{q.strip()}%"
        clause = Evidence.label.ilike(needle) | Evidence.kind.ilike(needle) | Evidence.raw_sha256.ilike(needle)
        stmt = stmt.where(clause)
        count_stmt = count_stmt.where(clause)
    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.order_by(Evidence.created_at.desc()).limit(limit).offset(offset)).scalars().all()
    ids = [row.id for row in rows]
    custody_rows = (
        db.execute(select(CustodyEvent).where(CustodyEvent.evidence_id.in_(ids))).scalars().all() if ids else []
    )
    by_evidence: dict[str, list[CustodyEvent]] = {}
    for row in custody_rows:
        by_evidence.setdefault(row.evidence_id or "", []).append(row)
    return paged(
        [_evidence_payload(row, by_evidence.get(row.id, [])) for row in rows],
        int(total),
        limit=limit,
        offset=offset,
    )


@router.get("/projects/{project_id}/evidence/verify")
def verify_evidence(
    project_id: str,
    access=Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Re-check every recorded digest against the stored custody history."""
    rows = db.execute(select(Evidence).where(Evidence.project_id == project_id)).scalars().all()
    checked = 0
    verified = 0
    mismatched: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for row in rows:
        if not row.raw_sha256:
            missing.append({"id": row.id, "label": row.label, "kind": row.kind})
            continue
        checked += 1
        custody = db.execute(
            select(CustodyEvent).where(CustodyEvent.evidence_id == row.id).order_by(CustodyEvent.created_at)
        ).scalars().all()
        digests = {event.sha256_at_action for event in custody if event.sha256_at_action}
        if not digests:
            verified += 1
            continue
        if digests == {row.raw_sha256}:
            verified += 1
        else:
            mismatched.append(
                {
                    "id": row.id,
                    "label": row.label,
                    "recorded": row.raw_sha256,
                    "in_custody": sorted(digests),
                }
            )
    return {
        "total": len(rows),
        "checked": checked,
        "verified": verified,
        "mismatched": mismatched,
        "missing_digest": missing,
        "integrity_ok": not mismatched,
        "note": (
            "Evidence integrity is confirmed when the digest recorded at acquisition matches "
            "every digest recorded in the chain of custody."
        ),
    }


@router.post("/projects/{project_id}/evidence", status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    project_id: str,
    file: UploadFile = File(...),
    label: str = Form(default=""),
    kind: str = Form(default="raw"),
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Store an authorised evidence file, hash it and open its custody record."""
    write_scope_guard(access.auth)
    original = (file.filename or "evidence.bin").strip()
    suffix = Path(original).suffix
    if suffix not in ALLOWED_EVIDENCE_SUFFIXES:
        supported = ", ".join(sorted(ALLOWED_EVIDENCE_SUFFIXES))
        raise api_error(
            "unsupported_format",
            f"'{suffix or original}' is not an accepted evidence format. Supported formats: {supported}.",
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        )

    settings.ensure_dirs()
    safe_name = f"{new_id()}-{slugify(Path(original).stem, 40)}{suffix}"
    destination = settings.uploads_dir / safe_name
    digest = hashlib.sha256()
    size = 0
    max_bytes = min(MAX_EVIDENCE_BYTES, settings.max_upload_mb * 1024 * 1024 * 8)
    try:
        with destination.open("wb") as handle:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    handle.close()
                    destination.unlink(missing_ok=True)
                    raise api_error(
                        "file_too_large",
                        f"Evidence uploads are limited to {max_bytes // (1024 * 1024)} MB.",
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    )
                digest.update(chunk)
                handle.write(chunk)
    finally:
        await file.close()

    if size == 0:
        destination.unlink(missing_ok=True)
        raise api_error("empty_file", "The uploaded evidence file is empty.", status.HTTP_400_BAD_REQUEST)

    sha256 = digest.hexdigest()
    item = Evidence(
        id=new_id(),
        project_id=project_id,
        kind=kind[:24],
        label=(label or original)[:200],
        raw_sha256=sha256,
        redacted=False,
        source="evidence-vault",
    )
    db.add(item)
    db.flush()
    custody = CustodyEvent(
        id=new_id(),
        project_id=project_id,
        evidence_id=item.id,
        action="collected",
        actor_user_id=access.auth.user_id,
        actor_label=access.auth.label,
        location="evidence-vault",
        notes=f"Uploaded file '{original}'.",
        sha256_at_action=sha256,
        source_path=safe_name,
    )
    db.add(custody)
    db.commit()
    db.refresh(item)
    audit(
        db,
        access.auth,
        "evidence.upload",
        project_id=project_id,
        entity_type="evidence",
        entity_id=item.id,
        meta={"sha256": sha256, "size": size},
    )
    return {
        **_evidence_payload(item, [custody]),
        "size_bytes": size,
        "original_name": original,
        "storage_name": safe_name,
    }


@router.post("/projects/{project_id}/evidence/{evidence_id}/custody", status_code=status.HTTP_201_CREATED)
def add_custody_event(
    project_id: str,
    evidence_id: str,
    body: CustodyBody,
    access=Depends(project_access("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Append a custody event. The chain is append-only; entries are never edited."""
    write_scope_guard(access.auth)
    item = db.get(Evidence, evidence_id)
    if item is None or item.project_id != project_id:
        raise api_error("evidence_not_found", "Evidence not found.", status.HTTP_404_NOT_FOUND)
    event = CustodyEvent(
        id=new_id(),
        project_id=project_id,
        evidence_id=item.id,
        action=body.action,
        actor_user_id=access.auth.user_id,
        actor_label=access.auth.label,
        location=body.location,
        notes=body.notes,
        sha256_at_action=body.sha256_at_action or item.raw_sha256,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    audit(db, access.auth, "evidence.custody", project_id=project_id, entity_type="evidence", entity_id=item.id)
    custody = db.execute(
        select(CustodyEvent).where(CustodyEvent.evidence_id == item.id).order_by(CustodyEvent.created_at)
    ).scalars().all()
    return _evidence_payload(item, custody)
