"""Attack and incident timeline engine.

Correlates the real event records NEXUS stores - scan events, findings and
their transitions, ingested log events, alerts, incidents, asset changes, job
outcomes and evidence custody - into one ordered timeline.  Each entry keeps
the table it came from and a confidence label, so the timeline is auditable
rather than decorative.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.utils import to_iso_z, utcnow
from ..models import (
    Alert,
    AssetChange,
    CaseAnnotation,
    CaseFile,
    CustodyEvent,
    Evidence,
    Finding,
    FindingEvent,
    Incident,
    IncidentEvent,
    Job,
    LogEvent,
    Scan,
    ScanEvent,
)

log = logging.getLogger("nexus.services.timeline")

SOURCE_LABELS = {
    "scan_event": "Assessment event",
    "finding": "Finding",
    "finding_event": "Finding transition",
    "log_event": "Log event",
    "alert": "Detection",
    "incident": "Incident",
    "incident_event": "Incident activity",
    "asset_change": "Attack-surface change",
    "job": "Background job",
    "evidence": "Evidence captured",
    "custody": "Evidence custody",
    "annotation": "Analyst note",
}

# Events that materially change the picture of an incident.
ANOMALY_KINDS = {"finding", "alert", "incident", "asset_change", "custody"}


def _iso(value: datetime | None) -> str | None:
    return to_iso_z(value)


def build_timeline(
    db: Session,
    project_id: str,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    sources: Iterable[str] | None = None,
    severities: Iterable[str] | None = None,
    search: str | None = None,
    limit: int = 800,
) -> dict[str, Any]:
    """Return a merged, ordered timeline for a project."""
    wanted_sources = set(sources) if sources else set(SOURCE_LABELS)
    wanted_severities = {s.lower() for s in severities} if severities else set()
    needle = (search or "").strip().lower()

    events: list[dict[str, Any]] = []

    def add_event(
        *,
        ts: datetime | None,
        source: str,
        kind: str,
        title: str,
        description: str = "",
        severity: str = "info",
        entity_type: str = "",
        entity_id: str = "",
        reference: str = "",
        confidence: str = "certain",
        data: dict[str, Any] | None = None,
    ) -> None:
        if source not in wanted_sources:
            return
        if wanted_severities and severity.lower() not in wanted_severities:
            return
        if needle:
            haystack = f"{title} {description} {reference}".lower()
            if needle not in haystack:
                return
        events.append(
            {
                "ts": _iso(ts),
                "source": source,
                "source_label": SOURCE_LABELS.get(source, source),
                "kind": kind,
                "title": title,
                "description": description,
                "severity": severity,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "reference": reference,
                "confidence": confidence,
                "anomaly": kind in ANOMALY_KINDS,
                "data": data or {},
            }
        )

    # --- assessment events --------------------------------------------------
    if "scan_event" in wanted_sources:
        rows = db.execute(
            select(ScanEvent).where(ScanEvent.project_id == project_id).order_by(ScanEvent.ts)
        ).scalars().all()
        for row in rows:
            add_event(
                ts=row.ts,
                source="scan_event",
                kind=row.kind,
                title=row.message or row.kind,
                description=row.phase or "",
                severity="info",
                entity_type="scan",
                entity_id=str(row.scan_id or ""),
                data=row.data or {},
            )

    # --- scans themselves ---------------------------------------------------
    if "scan_event" in wanted_sources:
        scans = db.execute(select(Scan).where(Scan.project_id == project_id)).scalars().all()
        for scan in scans:
            add_event(
                ts=scan.created_at,
                source="scan_event",
                kind="scan",
                title=f"Assessment queued: {scan.name or scan.kind}",
                description=f"{scan.kind} · {scan.profile} profile",
                severity="info",
                entity_type="scan",
                entity_id=scan.id,
                data={"status": scan.status, "engine": scan.engine},
            )
            if scan.finished_at:
                add_event(
                    ts=scan.finished_at,
                    source="scan_event",
                    kind="scan",
                    title=f"Assessment finished: {scan.name or scan.kind}",
                    description=f"Final status: {scan.status}",
                    severity="info",
                    entity_type="scan",
                    entity_id=scan.id,
                    data={"status": scan.status},
                )

    # --- findings -----------------------------------------------------------
    if "finding" in wanted_sources:
        rows = db.execute(
            select(Finding).where(Finding.project_id == project_id).order_by(Finding.first_seen_at)
        ).scalars().all()
        for row in rows:
            add_event(
                ts=row.first_seen_at,
                source="finding",
                kind="finding",
                title=f"Finding raised: {row.title}",
                description=row.description or "",
                severity=row.severity,
                entity_type="finding",
                entity_id=row.id,
                reference=row.target,
                confidence=row.confidence,
                data={"status": row.status, "category": row.category, "cvss": row.cvss_score},
            )

    if "finding_event" in wanted_sources:
        rows = db.execute(
            select(FindingEvent)
            .join(Finding, Finding.id == FindingEvent.finding_id)
            .where(Finding.project_id == project_id)
            .order_by(FindingEvent.ts)
        ).scalars().all()
        for row in rows:
            label = row.note or f"{row.from_status or '-'} → {row.to_status or '-'}"
            add_event(
                ts=row.ts,
                source="finding_event",
                kind="status_change",
                title=label,
                description=f"Triage by {row.actor_label}",
                severity="info",
                entity_type="finding",
                entity_id=row.finding_id,
                data={"from": row.from_status, "to": row.to_status},
            )

    # --- log events ---------------------------------------------------------
    if "log_event" in wanted_sources:
        rows = db.execute(
            select(LogEvent).where(LogEvent.project_id == project_id).order_by(LogEvent.ts).limit(2000)
        ).scalars().all()
        for row in rows:
            add_event(
                ts=row.ts or row.ingested_at,
                source="log_event",
                kind=row.event_type or "log",
                title=row.message[:400],
                description=f"{row.src_ip or '-'} → {row.dst_ip or '-'}:{row.dst_port or '-'}",
                severity=row.severity,
                entity_type="log_event",
                entity_id=str(row.id),
                reference=row.url or "",
                data={"method": row.method, "status_code": row.status_code, "rule_hits": row.rule_hits},
            )

    # --- alerts -------------------------------------------------------------
    if "alert" in wanted_sources:
        rows = db.execute(select(Alert).where(Alert.project_id == project_id)).scalars().all()
        for row in rows:
            add_event(
                ts=row.first_seen_at,
                source="alert",
                kind="alert",
                title=f"Detection raised: {row.title}",
                description=row.description or "",
                severity=row.severity,
                entity_type="alert",
                entity_id=row.id,
                data={"status": row.status, "events": row.event_count},
            )

    # --- incidents ----------------------------------------------------------
    if "incident" in wanted_sources:
        rows = db.execute(select(Incident).where(Incident.project_id == project_id)).scalars().all()
        for row in rows:
            add_event(
                ts=row.opened_at,
                source="incident",
                kind="incident",
                title=f"Incident opened: {row.title}",
                description=row.summary or "",
                severity=row.severity,
                entity_type="incident",
                entity_id=row.id,
                data={"status": row.status},
            )

    if "incident_event" in wanted_sources:
        rows = db.execute(
            select(IncidentEvent)
            .join(Incident, Incident.id == IncidentEvent.incident_id)
            .where(Incident.project_id == project_id)
            .order_by(IncidentEvent.ts)
        ).scalars().all()
        for row in rows:
            add_event(
                ts=row.ts,
                source="incident_event",
                kind=row.kind,
                title=row.body[:400] or row.kind,
                description=f"By {row.actor_label}",
                severity="info",
                entity_type="incident",
                entity_id=row.incident_id,
                data=row.meta or {},
            )

    # --- attack surface changes --------------------------------------------
    if "asset_change" in wanted_sources:
        rows = db.execute(
            select(AssetChange).where(AssetChange.project_id == project_id).order_by(AssetChange.detected_at)
        ).scalars().all()
        for row in rows:
            add_event(
                ts=row.detected_at,
                source="asset_change",
                kind="asset_change",
                title=row.summary or row.kind,
                description=row.kind,
                severity=row.severity,
                entity_type="asset",
                entity_id=row.asset_id or "",
                data={"before": row.before, "after": row.after},
            )

    # --- jobs ---------------------------------------------------------------
    if "job" in wanted_sources:
        rows = db.execute(select(Job).where(Job.project_id == project_id)).scalars().all()
        for row in rows:
            add_event(
                ts=row.created_at,
                source="job",
                kind="job",
                title=f"Job {row.type} → {row.status}",
                description=row.last_error or row.phase or "",
                severity="info",
                entity_type="job",
                entity_id=row.id,
                data={"attempts": row.attempts},
            )

    # --- evidence -----------------------------------------------------------
    if "evidence" in wanted_sources:
        rows = db.execute(
            select(Evidence).where(Evidence.project_id == project_id).order_by(Evidence.created_at)
        ).scalars().all()
        for row in rows:
            add_event(
                ts=row.created_at,
                source="evidence",
                kind="evidence",
                title=f"Evidence captured: {row.label or row.kind}",
                description=row.source or "",
                severity="info",
                entity_type="evidence",
                entity_id=row.id,
                reference=row.raw_sha256[:16],
                data={"sha256": row.raw_sha256, "redacted": row.redacted},
            )

    if "custody" in wanted_sources:
        rows = db.execute(
            select(CustodyEvent).where(CustodyEvent.project_id == project_id).order_by(CustodyEvent.created_at)
        ).scalars().all()
        for row in rows:
            add_event(
                ts=row.created_at,
                source="custody",
                kind="custody",
                title=f"Chain of custody: {row.action}",
                description=row.notes or "",
                severity="info",
                entity_type="evidence",
                entity_id=row.evidence_id or "",
                reference=row.actor_label,
                data={"location": row.location, "sha256": row.sha256_at_action},
            )

    if "annotation" in wanted_sources:
        rows = db.execute(
            select(CaseAnnotation).join(CaseFile, CaseFile.id == CaseAnnotation.case_id)
            .where(CaseFile.project_id == project_id)
            .order_by(CaseAnnotation.created_at)
        ).scalars().all()
        for row in rows:
            add_event(
                ts=row.created_at,
                source="annotation",
                kind="annotation",
                title=row.body[:400],
                description=row.entity_type,
                severity="info",
                entity_type=row.entity_type or "case",
                entity_id=row.entity_id or row.case_id,
            )

    # --- order, filter and summarise ---------------------------------------
    events.sort(key=lambda item: (item["ts"] or "", item["source"], item["title"]))

    # Trim to the requested window (inclusive).
    if start:
        start_iso = _iso(start)
        events = [item for item in events if (item["ts"] or "") >= (start_iso or "")]
    if end:
        end_iso = _iso(end)
        events = [item for item in events if (item["ts"] or "") <= (end_iso or "")]

    truncated = len(events) > limit
    events = events[:limit]

    by_source: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for item in events:
        by_source[item["source"]] = by_source.get(item["source"], 0) + 1
        by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1

    return {
        "project_id": project_id,
        "events": events,
        "stats": {
            "total": len(events),
            "truncated": truncated,
            "by_source": by_source,
            "by_severity": by_severity,
            "anomalies": sum(1 for item in events if item["anomaly"]),
            "window_start": events[0]["ts"] if events else None,
            "window_end": events[-1]["ts"] if events else None,
        },
        "sources": [{"key": key, "label": label} for key, label in SOURCE_LABELS.items()],
        "note": (
            "Entries are read from stored records only. A gap in the timeline means no "
            "record was collected for that period, not that nothing happened."
        ),
    }


def group_timeline(events: list[dict[str, Any]], granularity: str = "hour") -> list[dict[str, Any]]:
    """Group timeline entries into buckets for condensed views."""
    buckets: dict[str, dict[str, Any]] = {}
    for item in events:
        ts = item.get("ts")
        if not ts:
            continue
        if granularity == "day":
            key = ts[:10]
        elif granularity == "week":
            key = ts[:10]
        else:
            key = ts[:13]
        bucket = buckets.setdefault(
            key,
            {"bucket": key, "count": 0, "severities": {}, "sources": {}, "events": []},
        )
        bucket["count"] += 1
        bucket["severities"][item["severity"]] = bucket["severities"].get(item["severity"], 0) + 1
        bucket["sources"][item["source"]] = bucket["sources"].get(item["source"], 0) + 1
        if len(bucket["events"]) < 25:
            bucket["events"].append(item)
    return [buckets[key] for key in sorted(buckets)]
