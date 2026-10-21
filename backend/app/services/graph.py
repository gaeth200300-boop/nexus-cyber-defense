"""Unified security graph.

Every node and edge in the graph is derived from a record that NEXUS actually
collected or imported.  Each edge therefore carries the table (or engine) that
produced it and a confidence label, so an analyst can always tell a confirmed
relationship from an inferred one.  Nothing here is invented: if the database
holds no assets, the graph is empty.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Alert,
    Asset,
    AssetChange,
    Evidence,
    Finding,
    FindingEvent,
    FindingIntelLink,
    Incident,
    Job,
    LogEvent,
    LogSource,
    Scan,
    Service,
    User,
)

log = logging.getLogger("nexus.services.graph")

# Confidence vocabulary mirrors the platform's finding confidence scale.
CERTAIN = "certain"      # a direct foreign key or stored identifier
FIRM = "firm"            # observed together in the same record
TENTATIVE = "tentative"  # correlated by name/host heuristics

NODE_KINDS = (
    "project",
    "asset",
    "service",
    "finding",
    "alert",
    "incident",
    "evidence",
    "scan",
    "job",
    "log_source",
    "log_event",
    "user",
    "cve",
    "change",
)

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _node(
    node_id: str,
    kind: str,
    label: str,
    *,
    sublabel: str = "",
    severity: str = "info",
    state: str = "",
    meta: dict[str, Any] | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    return {
        "id": node_id,
        "kind": kind,
        "label": label,
        "sublabel": sublabel,
        "severity": severity,
        "state": state,
        "meta": meta or {},
        "observed_at": observed_at,
    }


def _edge(
    source: str,
    target: str,
    kind: str,
    label: str,
    *,
    confidence: str = CERTAIN,
    origin: str = "",
    observed_at: str | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": f"{source}->{target}:{kind}",
        "source": source,
        "target": target,
        "kind": kind,
        "label": label,
        "confidence": confidence,
        "origin": origin,
        "observed_at": observed_at,
        "meta": meta or {},
    }


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def build_graph(
    db: Session,
    project_id: str,
    *,
    kinds: Iterable[str] | None = None,
    max_nodes: int = 600,
) -> dict[str, Any]:
    """Build the project graph from stored records.

    ``kinds`` restricts the node types that are pulled from the database; the
    default is every type.  ``max_nodes`` bounds the response so a large
    project cannot exhaust the API's memory budget.
    """
    wanted = set(kinds) if kinds else set(NODE_KINDS)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def add(node: dict[str, Any]) -> str:
        existing = nodes.get(node["id"])
        if existing is None:
            nodes[node["id"]] = node
        return node["id"]

    # --- project ------------------------------------------------------------
    if "project" in wanted:
        add(
            _node(
                f"project:{project_id}",
                "project",
                f"Project {project_id[:8]}",
                sublabel="workspace",
                meta={"project_id": project_id},
            )
        )

    # --- assets -------------------------------------------------------------
    assets = db.execute(select(Asset).where(Asset.project_id == project_id)).scalars().all()
    asset_by_id = {asset.id: asset for asset in assets}
    if "asset" in wanted:
        for asset in assets:
            add(
                _node(
                    f"asset:{asset.id}",
                    "asset",
                    asset.value,
                    sublabel=asset.type,
                    severity=asset.risk_severity or "info",
                    state=asset.state,
                    meta={
                        "source": asset.source,
                        "risk_score": asset.risk_score,
                        "monitored": asset.is_monitored,
                        "first_seen_at": _iso(asset.first_seen_at),
                        "last_seen_at": _iso(asset.last_seen_at),
                    },
                    observed_at=_iso(asset.last_seen_at),
                )
            )
    if "project" in wanted:
        for asset in assets:
            edges.append(
                _edge(
                    f"project:{project_id}",
                    f"asset:{asset.id}",
                    "contains",
                    "contains asset",
                    confidence=CERTAIN,
                    origin="assets.project_id",
                    observed_at=_iso(asset.last_seen_at),
                )
            )
    if "asset" in wanted:
        for asset in assets:
            if asset.parent_id and asset.parent_id in asset_by_id:
                edges.append(
                    _edge(
                        f"asset:{asset.parent_id}",
                        f"asset:{asset.id}",
                        "resolves_to",
                        "resolves to child",
                        confidence=FIRM,
                        origin="assets.parent_id",
                        observed_at=_iso(asset.last_seen_at),
                    )
                )

    # --- services -----------------------------------------------------------
    services = db.execute(select(Service).where(Service.project_id == project_id)).scalars().all()
    if "service" in wanted:
        for service in services:
            port = f"{service.port}/{service.protocol}"
            add(
                _node(
                    f"service:{service.id}",
                    "service",
                    service.name or port,
                    sublabel=port,
                    severity="info",
                    state=service.state,
                    meta={
                        "product": service.product,
                        "version": service.version,
                        "source": service.source,
                    },
                    observed_at=_iso(service.last_seen_at),
                )
            )
    for service in services:
        if service.asset_id:
            edges.append(
                _edge(
                    f"asset:{service.asset_id}",
                    f"service:{service.id}",
                    "exposes",
                    "exposes service",
                    confidence=CERTAIN,
                    origin="services.asset_id",
                    observed_at=_iso(service.last_seen_at),
                )
            )

    # --- scans and jobs -----------------------------------------------------
    scans = db.execute(select(Scan).where(Scan.project_id == project_id)).scalars().all()
    scan_by_id = {scan.id: scan for scan in scans}
    if "scan" in wanted:
        for scan in scans:
            add(
                _node(
                    f"scan:{scan.id}",
                    "scan",
                    scan.name or scan.kind,
                    sublabel=f"{scan.kind} · {scan.status}",
                    severity="info",
                    state=scan.status,
                    meta={"engine": scan.engine, "profile": scan.profile, "progress": scan.progress},
                    observed_at=_iso(scan.created_at),
                )
            )
    for scan in scans:
        edges.append(
            _edge(
                f"project:{project_id}",
                f"scan:{scan.id}",
                "assessed_by",
                "assessed by scan",
                confidence=CERTAIN,
                origin="scans.project_id",
                observed_at=_iso(scan.created_at),
            )
        )
        if scan.requested_by:
            edges.append(
                _edge(
                    f"scan:{scan.id}",
                    f"user:{scan.requested_by}",
                    "requested_by",
                    "requested by",
                    confidence=CERTAIN,
                    origin="scans.requested_by",
                    observed_at=_iso(scan.created_at),
                )
            )

    if "job" in wanted:
        jobs = db.execute(select(Job).where(Job.project_id == project_id)).scalars().all()
        for job in jobs:
            add(
                _node(
                    f"job:{job.id}",
                    "job",
                    job.type,
                    sublabel=job.status,
                    severity="info",
                    state=job.status,
                    meta={"phase": job.phase, "attempts": job.attempts},
                    observed_at=_iso(job.created_at),
                )
            )
            if job.scan_id:
                edges.append(
                    _edge(
                        f"scan:{job.scan_id}",
                        f"job:{job.id}",
                        "executed_as",
                        "executed as job",
                        confidence=CERTAIN,
                        origin="jobs.scan_id",
                        observed_at=_iso(job.created_at),
                    )
                )

    # --- findings -----------------------------------------------------------
    findings = db.execute(select(Finding).where(Finding.project_id == project_id)).scalars().all()
    if "finding" in wanted:
        for finding in findings:
            add(
                _node(
                    f"finding:{finding.id}",
                    "finding",
                    finding.title,
                    sublabel=finding.category,
                    severity=finding.severity,
                    state=finding.status,
                    meta={
                        "target": finding.target,
                        "confidence": finding.confidence,
                        "verified": finding.verified,
                        "cvss": finding.cvss_score,
                        "cve": finding.cve,
                        "cwe": finding.cwe,
                        "detected_by": finding.detected_by,
                    },
                    observed_at=_iso(finding.last_seen_at),
                )
            )
    for finding in findings:
        if finding.asset_id:
            edges.append(
                _edge(
                    f"asset:{finding.asset_id}",
                    f"finding:{finding.id}",
                    "has_finding",
                    "has finding",
                    confidence=CERTAIN,
                    origin="findings.asset_id",
                    observed_at=_iso(finding.last_seen_at),
                    meta={"severity": finding.severity, "status": finding.status},
                )
            )
        if finding.scan_id:
            edges.append(
                _edge(
                    f"scan:{finding.scan_id}",
                    f"finding:{finding.id}",
                    "produced",
                    "produced finding",
                    confidence=CERTAIN,
                    origin="findings.scan_id",
                    observed_at=_iso(finding.last_seen_at),
                )
            )

    # --- evidence -----------------------------------------------------------
    evidence_rows = db.execute(select(Evidence).where(Evidence.project_id == project_id)).scalars().all()
    if "evidence" in wanted:
        for item in evidence_rows:
            add(
                _node(
                    f"evidence:{item.id}",
                    "evidence",
                    item.label or item.kind,
                    sublabel=item.kind,
                    severity="info",
                    meta={
                        "sha256": item.raw_sha256,
                        "redacted": item.redacted,
                        "source": item.source,
                    },
                    observed_at=_iso(item.created_at),
                )
            )
    for item in evidence_rows:
        if item.finding_id:
            edges.append(
                _edge(
                    f"finding:{item.finding_id}",
                    f"evidence:{item.id}",
                    "evidenced_by",
                    "evidenced by",
                    confidence=CERTAIN,
                    origin="evidence.finding_id",
                    observed_at=_iso(item.created_at),
                )
            )
        elif item.scan_id:
            edges.append(
                _edge(
                    f"scan:{item.scan_id}",
                    f"evidence:{item.id}",
                    "captured",
                    "captured evidence",
                    confidence=CERTAIN,
                    origin="evidence.scan_id",
                    observed_at=_iso(item.created_at),
                )
            )

    # --- alerts and incidents ----------------------------------------------
    alerts = db.execute(select(Alert).where(Alert.project_id == project_id)).scalars().all()
    if "alert" in wanted:
        for alert in alerts:
            add(
                _node(
                    f"alert:{alert.id}",
                    "alert",
                    alert.title,
                    sublabel=alert.status,
                    severity=alert.severity,
                    state=alert.status,
                    meta={"events": alert.event_count, "group": alert.group_key},
                    observed_at=_iso(alert.last_seen_at),
                )
            )
    incidents = db.execute(select(Incident).where(Incident.project_id == project_id)).scalars().all()
    if "incident" in wanted:
        for incident in incidents:
            add(
                _node(
                    f"incident:{incident.id}",
                    "incident",
                    incident.title,
                    sublabel=incident.status,
                    severity=incident.severity,
                    state=incident.status,
                    meta={"summary": incident.summary},
                    observed_at=_iso(incident.opened_at),
                )
            )
    for alert in alerts:
        if alert.incident_id:
            edges.append(
                _edge(
                    f"alert:{alert.id}",
                    f"incident:{alert.incident_id}",
                    "escalated_to",
                    "escalated to incident",
                    confidence=CERTAIN,
                    origin="alerts.incident_id",
                    observed_at=_iso(alert.last_seen_at),
                )
            )
        if alert.rule_id:
            edges.append(
                _edge(
                    f"alert:{alert.id}",
                    f"rule:{alert.rule_id}",
                    "detected_by",
                    "detected by rule",
                    confidence=CERTAIN,
                    origin="alerts.rule_id",
                    observed_at=_iso(alert.last_seen_at),
                )
            )
    for incident in incidents:
        edges.append(
            _edge(
                f"project:{project_id}",
                f"incident:{incident.id}",
                "has_incident",
                "has incident",
                confidence=CERTAIN,
                origin="incidents.project_id",
                observed_at=_iso(incident.opened_at),
            )
        )

    # --- CVE correlation ----------------------------------------------------
    if "cve" in wanted and findings:
        links = db.execute(
            select(FindingIntelLink).where(FindingIntelLink.finding_id.in_([f.id for f in findings]))
        ).scalars().all()
        for link in links:
            cve_id = link.cve_id or ""
            if not cve_id:
                continue
            node_id = f"cve:{cve_id}"
            add(
                _node(
                    node_id,
                    "cve",
                    cve_id,
                    sublabel="CVE",
                    severity="info",
                    meta={"match_type": link.match_type, "confidence": link.confidence},
                )
            )
            edges.append(
                _edge(
                    f"finding:{link.finding_id}",
                    node_id,
                    "correlates_to",
                    "correlates to CVE",
                    confidence=CERTAIN if link.match_type == "exact" else FIRM,
                    origin="finding_intel_links",
                    meta={"match_type": link.match_type, "rationale": link.rationale},
                )
            )

    # --- log sources and log events ----------------------------------------
    sources = db.execute(select(LogSource).where(LogSource.project_id == project_id)).scalars().all()
    if "log_source" in wanted:
        for source in sources:
            add(
                _node(
                    f"log_source:{source.id}",
                    "log_source",
                    source.name,
                    sublabel=source.format,
                    severity="info",
                    meta={"events": source.event_count, "sha256": source.sha256},
                    observed_at=_iso(source.last_event_at),
                )
            )
            edges.append(
                _edge(
                    f"project:{project_id}",
                    f"log_source:{source.id}",
                    "ingests",
                    "ingests logs",
                    confidence=CERTAIN,
                    origin="log_sources.project_id",
                    observed_at=_iso(source.last_event_at),
                )
            )

    if "log_event" in wanted:
        log_events = db.execute(
            select(LogEvent)
            .where(LogEvent.project_id == project_id)
            .order_by(LogEvent.ts.desc())
            .limit(400)
        ).scalars().all()
        # Index assets by address so a log event can be attached to the host it
        # touched.  The link is an inference, so it is reported as such.
        asset_by_address: dict[str, Asset] = {}
        for asset in assets:
            address = (asset.normalized_value or "").strip().lower()
            if address:
                asset_by_address.setdefault(address, asset)

        for event in log_events:
            node_id = f"log_event:{event.id}"
            add(
                _node(
                    node_id,
                    "log_event",
                    (event.message or event.event_type or "log event")[:120],
                    sublabel=event.event_type,
                    severity=event.severity,
                    meta={
                        "src_ip": event.src_ip,
                        "dst_ip": event.dst_ip,
                        "url": event.url,
                        "status_code": event.status_code,
                        "rule_hits": event.rule_hits,
                    },
                    observed_at=_iso(event.ts or event.ingested_at),
                )
            )
            if event.source_id:
                edges.append(
                    _edge(
                        f"log_source:{event.source_id}",
                        node_id,
                        "produced",
                        "produced event",
                        confidence=CERTAIN,
                        origin="log_events.source_id",
                        observed_at=_iso(event.ts or event.ingested_at),
                    )
                )
            for address in (event.src_ip, event.dst_ip):
                asset = asset_by_address.get((address or "").strip().lower())
                if asset is None:
                    continue
                edges.append(
                    _edge(
                        f"asset:{asset.id}",
                        node_id,
                        "observed",
                        "observed in telemetry",
                        confidence=FIRM,
                        origin="log_events.src_ip/dst_ip matched assets.normalized_value",
                        observed_at=_iso(event.ts or event.ingested_at),
                    )
                )
                break

    # --- users --------------------------------------------------------------
    referenced_users = {scan.requested_by for scan in scans if scan.requested_by}
    if referenced_users:
        users = db.execute(select(User).where(User.id.in_(list(referenced_users)))).scalars().all()
        for user in users:
            add(
                _node(
                    f"user:{user.id}",
                    "user",
                    user.full_name or user.email,
                    sublabel=user.role,
                    severity="info",
                    meta={"email": user.email},
                )
            )

    # --- asset changes ------------------------------------------------------
    if "change" in wanted:
        changes = db.execute(
            select(AssetChange).where(AssetChange.project_id == project_id).limit(200)
        ).scalars().all()
        for change in changes:
            add(
                _node(
                    f"change:{change.id}",
                    "change",
                    change.summary or change.kind,
                    sublabel=change.kind,
                    severity=change.severity,
                    observed_at=_iso(change.detected_at),
                )
            )
            if change.asset_id:
                edges.append(
                    _edge(
                        f"asset:{change.asset_id}",
                        f"change:{change.id}",
                        "changed",
                        "surface changed",
                        confidence=CERTAIN,
                        origin="asset_changes.asset_id",
                        observed_at=_iso(change.detected_at),
                    )
                )

    # --- prune --------------------------------------------------------------
    if len(nodes) > max_nodes:
        keep = set(list(nodes)[:max_nodes])
        nodes = {key: value for key, value in nodes.items() if key in keep}
        edges = [edge for edge in edges if edge["source"] in keep and edge["target"] in keep]

    # Degree drives the layout: the most connected records sit in the centre.
    degree: dict[str, int] = {}
    for edge in edges:
        degree[edge["source"]] = degree.get(edge["source"], 0) + 1
        degree[edge["target"]] = degree.get(edge["target"], 0) + 1
    for node_id, node in nodes.items():
        node["degree"] = degree.get(node_id, 0)

    kinds_present: dict[str, int] = {}
    for node in nodes.values():
        kinds_present[node["kind"]] = kinds_present.get(node["kind"], 0) + 1

    return {
        "project_id": project_id,
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "by_kind": kinds_present,
            "scans": len(scans),
            "assets": len(assets),
            "findings": len(findings),
        },
        "note": (
            "Every edge is derived from a stored record. The origin column names the "
            "table that produced the relationship and confidence states how direct it is."
        ),
    }


def kind_project(project_id: str) -> dict[str, Any]:
    """Small helper kept separate so the project node stays consistent."""
    return {"project_id": project_id}


def attack_paths(graph: dict[str, Any], entry_kinds: tuple[str, ...] = ("asset", "finding")) -> list[dict[str, Any]]:
    """Simple breadth-first paths from entry nodes to incidents.

    Returns paths that are actually connected in the stored data; an empty
    result means no recorded chain reaches an incident.
    """
    adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for edge in graph["edges"]:
        adjacency.setdefault(edge["source"], []).append((edge["target"], edge))

    node_by_id = {node["id"]: node for node in graph["nodes"]}
    targets = {node["id"] for node in graph["nodes"] if node["kind"] == "incident"}
    starts = [
        node["id"]
        for node in graph["nodes"]
        if node["kind"] in entry_kinds and node["id"] not in targets
    ]

    paths: list[dict[str, Any]] = []
    for start in starts[:40]:
        queue: list[tuple[str, list[dict[str, Any]]]] = [(start, [])]
        visited = {start}
        while queue and len(paths) < 25:
            current, trail = queue.pop(0)
            for neighbour, edge in adjacency.get(current, []):
                if neighbour in visited:
                    continue
                visited.add(neighbour)
                step = {
                    "from": node_by_id.get(current, {}).get("label", current),
                    "to": node_by_id.get(neighbour, {}).get("label", neighbour),
                    "kind": edge["kind"],
                    "confidence": edge["confidence"],
                    "origin": edge["origin"],
                }
                chain = trail + [step]
                if neighbour in targets:
                    paths.append(
                        {
                            "entry": node_by_id.get(start, {}).get("label", start),
                            "length": len(chain),
                            "steps": chain,
                            "weakest_link": min((step["confidence"] for step in chain), default=CERTAIN),
                        }
                    )
                    break
                if len(chain) < 6:
                    queue.append((neighbour, chain))
    paths.sort(key=lambda item: item["length"])
    return paths
