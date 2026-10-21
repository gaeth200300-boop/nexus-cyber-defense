"""Finding lifecycle: deduplication, evidence capture, status transitions.

Every engine funnels its results through `save_finding`, which guarantees:
* deterministic fingerprints (so the same issue found twice is one row, not two),
* redacted evidence stored once and linked to the finding,
* an immutable lifecycle trail in `finding_events`,
* honest severity/confidence values (never invented by the UI).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.constants import SEVERITY_RANK
from ..core.redaction import redact_headers, redact_text, redact_url, summarize_redactions
from ..core.utils import stable_hash, utcnow
from ..models import Evidence, Finding, FindingEvent, Scan

log = logging.getLogger("nexus.findings")


def make_fingerprint(project_id: str, check_id: str, category: str, target: str, location: str = "") -> str:
    """Stable identity of an issue: same check + same place => same finding."""
    return stable_hash(project_id, check_id or category, category, target.strip().lower(), (location or "").strip().lower())


def _build_evidence(
    db: Session,
    *,
    project_id: str,
    scan_id: str | None,
    finding_id: str | None,
    kind: str,
    label: str,
    request_snippet: str = "",
    response_snippet: str = "",
    headers: dict[str, Any] | None = None,
    body_excerpt: str = "",
    source: str = "",
) -> Evidence:
    redactions: list[dict[str, str]] = []

    safe_headers, header_redactions = redact_headers(headers or {})
    redactions.extend(header_redactions)

    req_clean, req_redactions = redact_text(request_snippet or "")
    redactions.extend(req_redactions)
    req_clean, url_redactions = redact_url(req_clean) if req_clean else (req_clean, [])
    redactions.extend(url_redactions)

    res_clean, res_redactions = redact_text(response_snippet or "")
    redactions.extend(res_redactions)

    body_clean, body_redactions = redact_text(body_excerpt or "")
    redactions.extend(body_redactions)

    from ..core.utils import sha256_hex

    evidence = Evidence(
        project_id=project_id,
        finding_id=finding_id,
        scan_id=scan_id,
        kind=kind[:24],
        label=label[:200],
        request_snippet=req_clean,
        response_snippet=res_clean,
        headers=safe_headers,
        body_excerpt=body_clean,
        raw_sha256=sha256_hex(f"{req_clean}|{res_clean}|{body_clean}"),
        redacted=True,
        redactions=redactions,
        source=source[:60],
    )
    db.add(evidence)
    db.flush()
    return evidence


def save_finding(
    db: Session,
    *,
    project_id: str,
    scan: Scan | None,
    check_id: str,
    category: str,
    title: str,
    severity: str,
    confidence: str = "firm",
    target: str = "",
    location: str = "",
    description: str = "",
    impact: str = "",
    remediation: str = "",
    references: list[str] | None = None,
    cwe: str = "",
    cve: str = "",
    owasp: str = "",
    cvss_score: float | None = None,
    cvss_vector: str = "",
    detected_by: str = "",
    engine_version: str = "",
    asset_id: str | None = None,
    service_id: str | None = None,
    tags: list[str] | None = None,
    verified: bool = False,
    active_check: bool = False,
    evidence: dict[str, Any] | None = None,
    status: str = "open",
) -> tuple[Finding, bool]:
    """Insert or update a finding. Returns (finding, created)."""
    fingerprint = make_fingerprint(project_id, check_id, category, target, location)
    finding = db.execute(
        select(Finding).where(Finding.project_id == project_id, Finding.fingerprint == fingerprint)
    ).scalar_one_or_none()

    created = False
    if finding is None:
        created = True
        finding = Finding(
            project_id=project_id,
            scan_id=scan.id if scan else None,
            asset_id=asset_id,
            service_id=service_id,
            fingerprint=fingerprint,
            title=title[:300],
            category=category,
            severity=severity,
            confidence=confidence,
            status=status,
            verified=verified,
            active_check=active_check,
            cwe=cwe[:40],
            cve=cve[:30],
            owasp=owasp[:80],
            cvss_score=cvss_score,
            cvss_vector=cvss_vector[:120],
            target=target[:512],
            location=location[:512],
            description=description,
            impact=impact,
            remediation=remediation,
            references=references or [],
            tags=tags or [],
            detected_by=detected_by[:60],
            engine_version=engine_version[:40],
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
        )
        db.add(finding)
        db.flush()
        db.add(
            FindingEvent(
                finding_id=finding.id,
                kind="status_change",
                actor_label="scanner",
                from_status="",
                to_status=status,
                note=f"Detected by {detected_by} during scan '{scan.name if scan else 'n/a'}'",
            )
        )
    else:
        # Refresh volatile fields but never downgrade human triage decisions.
        finding.last_seen_at = utcnow()
        finding.occurrence_count += 1
        finding.scan_id = scan.id if scan else finding.scan_id
        finding.asset_id = asset_id or finding.asset_id
        finding.service_id = service_id or finding.service_id
        if severity and SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(finding.severity, 0):
            finding.severity = severity
        if confidence == "certain":
            finding.confidence = "certain"
        if verified:
            finding.verified = True
        if finding.status in ("fixed",):
            finding.status = "open"
            finding.resolved_at = None
            db.add(
                FindingEvent(
                    finding_id=finding.id,
                    kind="status_change",
                    actor_label="scanner",
                    from_status="fixed",
                    to_status="open",
                    note="Issue re-observed by a later scan.",
                )
            )

    if evidence:
        item = _build_evidence(
            db,
            project_id=project_id,
            scan_id=scan.id if scan else None,
            finding_id=finding.id,
            kind=evidence.get("kind", "raw"),
            label=evidence.get("label", title)[:200],
            request_snippet=evidence.get("request", ""),
            response_snippet=evidence.get("response", ""),
            headers=evidence.get("headers", {}),
            body_excerpt=evidence.get("body", ""),
            source=evidence.get("source", detected_by),
        )
        if not finding.primary_evidence_id:
            finding.primary_evidence_id = item.id

    return finding, created


def change_status(
    db: Session,
    finding: Finding,
    new_status: str,
    *,
    actor_user_id: str | None,
    actor_label: str,
    note: str = "",
) -> Finding:
    previous = finding.status
    finding.status = new_status
    if new_status in ("fixed", "false_positive"):
        finding.resolved_at = utcnow()
    else:
        finding.resolved_at = None
    db.add(
        FindingEvent(
            finding_id=finding.id,
            actor_user_id=actor_user_id,
            actor_label=actor_label[:200],
            kind="status_change",
            from_status=previous,
            to_status=new_status,
            note=note[:2000],
        )
    )
    db.commit()
    return finding


def add_note(db: Session, finding: Finding, *, actor_user_id: str | None, actor_label: str, note: str) -> FindingEvent:
    event = FindingEvent(
        finding_id=finding.id,
        actor_user_id=actor_user_id,
        actor_label=actor_label[:200],
        kind="note",
        note=note[:4000],
    )
    db.add(event)
    db.commit()
    return event


def evidence_summary(db: Session, finding_id: str) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Evidence).where(Evidence.finding_id == finding_id).order_by(Evidence.created_at.desc())
    ).scalars().all()
    return [
        {
            "id": e.id,
            "kind": e.kind,
            "label": e.label,
            "request": e.request_snippet,
            "response": e.response_snippet,
            "headers": e.headers,
            "body": e.body_excerpt,
            "redacted": e.redacted,
            "redactions": e.redactions,
            "redaction_summary": summarize_redactions(e.redactions or []),
            "sha256": e.raw_sha256,
            "source": e.source,
            "created_at": e.created_at,
        }
        for e in rows
    ]


def severity_counts(db: Session, project_id: str) -> dict[str, int]:
    from sqlalchemy import func

    rows = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.project_id == project_id, Finding.status.notin_(("false_positive", "duplicate")))
        .group_by(Finding.severity)
    ).all()
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for severity, count in rows:
        counts[severity] = count
    return counts


def highest_unresolved(db: Session, project_id: str, limit: int = 5) -> list[Finding]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = db.execute(
        select(Finding)
        .where(Finding.project_id == project_id, Finding.status.in_(("open", "confirmed")))
        .order_by(Finding.detected_by, Finding.last_seen_at.desc())
        .limit(limit * 4)
    ).scalars().all()
    rows.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.occurrence_count))
    return rows[:limit]
