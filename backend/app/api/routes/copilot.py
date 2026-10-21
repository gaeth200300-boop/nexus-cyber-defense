"""AI Security Copilot API.

Deterministic analysis (explain / prioritise / summary) is always available and
is the source of truth. A configured AI provider only adds language on top of
facts that already exist in the database — it can never invent findings.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...copilot.service import (
    chat,
    copilot_status,
    explain_finding,
    prioritize,
    prioritized_findings,
    project_facts,
    summarize,
)
from ...core.ratelimit import limiter
from ...db import get_db
from ...models import Finding
from ..deps import ProjectAccess, api_error, audit, project_access
from .common import paged

log = logging.getLogger("nexus.api.copilot")

router = APIRouter(prefix="/projects/{project_id}/copilot", tags=["copilot"])

LANGS = ("ar", "en")


def _check_lang(lang: str) -> str:
    value = (lang or "ar").lower()
    if value not in LANGS:
        raise api_error("invalid_lang", "Language must be 'ar' or 'en'.")
    return value


class ExplainBody(BaseModel):
    finding_id: str
    lang: str = Field(default="ar")


class PrioritizeBody(BaseModel):
    lang: str = Field(default="ar")
    limit: int = Field(default=15, ge=1, le=50)


class SummarizeBody(BaseModel):
    lang: str = Field(default="ar")


class ChatBody(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    lang: str = Field(default="ar")
    history: list[dict[str, str]] = Field(default_factory=list, max_length=12)


@router.get("/status")
def status_endpoint(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return {
        "copilot": copilot_status(db),
        "project_facts": project_facts(db, access.project.id),
        "modes": {
            "deterministic": {
                "available": True,
                "description": "Explanations, prioritisation and summaries computed from stored findings, evidence and intel.",
            },
            "ai": {
                "available": bool(copilot_status(db)["configured"]),
                "description": "Adds natural-language rewriting on top of the deterministic facts. Never introduces new facts.",
            },
        },
    }


@router.get("/priorities")
def priorities(
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
    limit: int = 50,
) -> dict[str, Any]:
    items = prioritized_findings(db, access.project.id, limit=max(1, min(limit, 200)))
    return paged(items, len(items), limit=limit, offset=0)


@router.post("/explain")
async def explain(
    body: ExplainBody,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    finding = db.get(Finding, body.finding_id)
    if finding is None or finding.project_id != access.project.id:
        raise api_error("finding_not_found", "Finding not found.", status.HTTP_404_NOT_FOUND)
    result = await explain_finding(db, finding, lang=_check_lang(body.lang))
    audit(db, access.auth, "copilot.explain", project_id=access.project.id, entity_type="finding", entity_id=finding.id, meta={"engine": result.get("engine"), "status": result.get("status")})
    return {"finding_id": finding.id, "analysis": result}


@router.post("/prioritize")
async def prioritize_endpoint(
    body: PrioritizeBody,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    result = await prioritize(db, access.project.id, lang=_check_lang(body.lang), limit=body.limit)
    audit(db, access.auth, "copilot.prioritize", project_id=access.project.id, meta={"limit": body.limit, "status": result.get("status")})
    return result


@router.post("/summarize")
async def summarize_endpoint(
    body: SummarizeBody,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    result = await summarize(db, access.project.id, lang=_check_lang(body.lang))
    audit(db, access.auth, "copilot.summarize", project_id=access.project.id, meta={"status": result.get("status")})
    return result


@router.post("/chat")
async def chat_endpoint(
    body: ChatBody,
    access: ProjectAccess = Depends(project_access("viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    allowed, _remaining, retry_after = limiter.check(f"copilot:{access.user_id}", 30)
    if not allowed:
        raise api_error(
            "rate_limited",
            f"Copilot requests are limited to 30/minute — retry in {retry_after}s.",
            status.HTTP_429_TOO_MANY_REQUESTS,
            retry_after=retry_after,
        )
    result = await chat(db, access.project.id, body.message, lang=_check_lang(body.lang), history=body.history)
    audit(db, access.auth, "copilot.chat", project_id=access.project.id, meta={"status": result.get("status")})
    return result
