"""Log analysis & detection engine — the analytical core of the SOC module.

Parses nginx/apache/syslog/JSON/CSV uploads into normalized events, then evaluates a
*declarative* rule set (safe interpreter, never `eval`) to produce grouped alerts.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.constants import SEVERITY_RANK
from ..core.redaction import redact_text
from ..core.utils import stable_hash, utcnow
from ..models import Alert, DetectionRule, LogEvent, LogSource
from .base import EngineContext, EngineResult

log = logging.getLogger("nexus.engine.logs")

MAX_LINES = 200_000
BATCH_SIZE = 500

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
COMBINED_LOG_RE = re.compile(
    r'(?P<src_ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>[^"]*?) (?P<proto>HTTP/[\d.]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)
SYSLOG_RE = re.compile(
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<process>[\w\-./]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)"
)
ISO_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")

SEVERITY_KEYWORDS = (
    ("critical", ("panic", "critical", "emerg", "emergency", "fatal")),
    ("high", ("error", "err", "fail", "denied", "refused", "unauthorized", "attack")),
    ("medium", ("warn", "warning")),
    ("low", ("notice",)),
)


def _severity_from_message(message: str) -> str:
    lowered = message.lower()
    for severity, keywords in SEVERITY_KEYWORDS:
        if any(keyword in lowered for keyword in keywords):
            return severity
    return "info"


def detect_format(sample_lines: list[str]) -> str:
    for line in sample_lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            return "json"
        if COMBINED_LOG_RE.search(stripped):
            return "combined"
        if SYSLOG_RE.search(stripped):
            return "syslog"
        if stripped.count(",") >= 3 and ISO_TS_RE.search(stripped):
            return "csv"
        if ISO_TS_RE.search(stripped):
            return "generic"
    return "generic"


def parse_line(line: str, fmt: str) -> dict[str, Any] | None:
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    if fmt == "json":
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return None
        message = str(payload.get("message") or payload.get("msg") or payload.get("event") or line)
        return {
            "message": message,
            "ts_text": str(payload.get("timestamp") or payload.get("time") or payload.get("ts") or ""),
            "src_ip": str(payload.get("src_ip") or payload.get("source_ip") or payload.get("client_ip") or payload.get("remote_addr") or ""),
            "dst_ip": str(payload.get("dst_ip") or payload.get("dest_ip") or ""),
            "src_port": _int_or_none(payload.get("src_port")),
            "dst_port": _int_or_none(payload.get("dst_port") or payload.get("port")),
            "method": str(payload.get("method") or ""),
            "url": str(payload.get("url") or payload.get("path") or payload.get("uri") or ""),
            "status_code": _int_or_none(payload.get("status") or payload.get("status_code")),
            "user_agent": str(payload.get("user_agent") or payload.get("http_user_agent") or ""),
            "severity": str(payload.get("severity") or payload.get("level") or "").lower(),
            "event_type": str(payload.get("event_type") or payload.get("type") or ""),
        }

    if fmt in ("combined", "csv"):
        match = COMBINED_LOG_RE.search(line)
        if match:
            data = match.groupdict()
            return {
                "message": line,
                "ts_text": data.get("ts") or "",
                "src_ip": data.get("src_ip") or "",
                "method": data.get("method") or "",
                "url": data.get("url") or "",
                "status_code": _int_or_none(data.get("status")),
                "user_agent": data.get("user_agent") or "",
                "severity": "high" if _int_or_none(data.get("status") or 0) and int(data["status"]) >= 500 else "info",
                "event_type": "http_request",
            }
        if fmt == "csv":
            try:
                row = next(csv.reader(io.StringIO(line)))
                return {
                    "message": " | ".join(row)[:1000],
                    "src_ip": next((cell for cell in row if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", cell.strip())), ""),
                    "ts_text": next((cell for cell in row if ISO_TS_RE.search(cell)), ""),
                    "severity": _severity_from_message(line),
                    "event_type": "csv_row",
                }
            except Exception:
                return None
        return None

    if fmt == "syslog":
        match = SYSLOG_RE.search(line)
        if match:
            data = match.groupdict()
            message = data.get("message") or ""
            return {
                "message": message,
                "ts_text": data.get("ts") or "",
                "host": data.get("host") or "",
                "process": data.get("process") or "",
                "severity": _severity_from_message(f"{data.get('process','')} {message}"),
                "event_type": (data.get("process") or "syslog").split("/")[-1][:40],
            }
        return None

    # generic
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
    ts_match = ISO_TS_RE.search(line)
    return {
        "message": line[:1000],
        "ts_text": ts_match.group(1) if ts_match else "",
        "src_ip": ips[0] if ips else "",
        "dst_ip": ips[1] if len(ips) > 1 else "",
        "severity": _severity_from_message(line),
        "event_type": "generic",
    }


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_timestamp(text: str) -> Any:
    if not text:
        return None
    from datetime import datetime

    cleaned = text.strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            parsed = datetime.strptime(cleaned[:26], fmt)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone().replace(tzinfo=None)
            if fmt == "%b %d %H:%M:%S":
                parsed = parsed.replace(year=utcnow().year)
            return parsed
        except ValueError:
            continue
    return None


def event_fingerprint(event: dict[str, Any]) -> str:
    url = re.sub(r"\d+", "N", str(event.get("url") or "")[:120])
    return stable_hash(
        event.get("event_type", ""), event.get("method", ""), url, event.get("status_code"), event.get("severity", "")
    )[:20]


# ---------------------------------------------------------------------------
# Rule DSL (safe interpreter)
# ---------------------------------------------------------------------------
OPS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "gt": lambda a, b: _num(a) > _num(b),
    "gte": lambda a, b: _num(a) >= _num(b),
    "lt": lambda a, b: _num(a) < _num(b),
    "lte": lambda a, b: _num(a) <= _num(b),
    "contains": lambda a, b: str(b).lower() in str(a or "").lower(),
    "not_contains": lambda a, b: str(b).lower() not in str(a or "").lower(),
    "startswith": lambda a, b: str(a or "").lower().startswith(str(b).lower()),
    "endswith": lambda a, b: str(a or "").lower().endswith(str(b).lower()),
    "in": lambda a, b: a in b if isinstance(b, (list, tuple, set)) else False,
    "not_in": lambda a, b: a not in b if isinstance(b, (list, tuple, set)) else True,
    "exists": lambda a, b: bool(a) is bool(b),
    "regex": lambda a, b: bool(re.search(str(b), str(a or ""), re.IGNORECASE)),
    "len_gt": lambda a, b: len(str(a or "")) > _num(b),
}


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def validate_rule_definition(definition: dict[str, Any]) -> list[str]:
    """Return a list of validation errors (empty = valid). Used by the API too."""
    errors: list[str] = []
    if not isinstance(definition, dict):
        return ["definition must be an object"]
    if definition.get("match", "all") not in ("all", "any"):
        errors.append("match must be 'all' or 'any'")
    conditions = definition.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        errors.append("conditions must be a non-empty list")
    else:
        for index, condition in enumerate(conditions):
            if not isinstance(condition, dict):
                errors.append(f"condition {index} must be an object")
                continue
            op = condition.get("op")
            if op not in OPS:
                errors.append(f"condition {index}: unsupported op '{op}'")
            if op == "regex":
                pattern = str(condition.get("value", ""))
                if len(pattern) > 300:
                    errors.append(f"condition {index}: regex too long (max 300 chars)")
                else:
                    try:
                        re.compile(pattern)
                    except re.error as exc:
                        errors.append(f"condition {index}: invalid regex ({exc})")
    group_by = definition.get("group_by", [])
    if group_by and not isinstance(group_by, list):
        errors.append("group_by must be a list of field names")
    allowed_fields = set(EVENT_FIELDS)
    for field in [condition.get("field") for condition in (conditions or []) if isinstance(condition, dict)]:
        if field not in allowed_fields:
            errors.append(f"unknown field '{field}' (allowed: {', '.join(sorted(allowed_fields))})")
    for field in group_by if isinstance(group_by, list) else []:
        if field not in allowed_fields:
            errors.append(f"unknown group_by field '{field}'")
    return errors


def rule_matches(definition: dict[str, Any], event: dict[str, Any]) -> bool:
    conditions = definition.get("conditions") or []
    match_mode = definition.get("match", "all")
    results = []
    for condition in conditions:
        if not isinstance(condition, dict):
            continue
        field = condition.get("field")
        op = condition.get("op")
        expected = condition.get("value")
        actual = event.get(field)
        comparator = OPS.get(op)
        if comparator is None:
            continue
        try:
            results.append(bool(comparator(actual, expected)))
        except Exception:
            results.append(False)
    if not results:
        return False
    return all(results) if match_mode == "all" else any(results)


EVENT_FIELDS = (
    "message",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "method",
    "url",
    "status_code",
    "user_agent",
    "severity",
    "event_type",
)


# ---------------------------------------------------------------------------
# Built-in detection rules
# ---------------------------------------------------------------------------
BUILTIN_RULES: tuple[dict[str, Any], ...] = (
    {
        "name": "SQL injection attempts",
        "severity": "high",
        "description": "SQL meta-characters and keywords in request URLs",
        "definition": {
            "match": "any",
            "conditions": [
                {"field": "url", "op": "regex", "value": "(?i)(union\\s+select|or\\s+1=1|'\\s*or\\s*'|sleep\\(|benchmark\\(|information_schema|xp_cmdshell)"},
                {"field": "message", "op": "regex", "value": "(?i)(union\\s+select|information_schema|sleep\\(\\d)"},
            ],
            "group_by": ["src_ip"],
            "threshold": 1,
            "window_minutes": 30,
        },
    },
    {
        "name": "Path traversal attempts",
        "severity": "high",
        "description": "Traversal sequences or sensitive file targets in requests",
        "definition": {
            "match": "any",
            "conditions": [
                {"field": "url", "op": "regex", "value": "(?i)(\\.\\./|\\.\\.%2f|%2e%2e/|/etc/passwd|/proc/self|win\\.ini|boot\\.ini)"},
                {"field": "message", "op": "regex", "value": "(?i)(\\.\\./|/etc/shadow)"},
            ],
            "group_by": ["src_ip"],
            "threshold": 3,
            "window_minutes": 60,
        },
    },
    {
        "name": "Cross-site scripting attempts",
        "severity": "medium",
        "description": "Script tags or event handlers submitted to the application",
        "definition": {
            "match": "any",
            "conditions": [
                {"field": "url", "op": "regex", "value": "(?i)(<script|%3cscript|onerror=|javascript:|srcdoc=|alert\\()"},
                {"field": "message", "op": "regex", "value": "(?i)<script"},
            ],
            "group_by": ["src_ip"],
            "threshold": 2,
            "window_minutes": 60,
        },
    },
    {
        "name": "Sensitive path probing",
        "severity": "medium",
        "description": "Requests for administrative, configuration or backup paths",
        "definition": {
            "match": "any",
            "conditions": [
                {"field": "url", "op": "regex", "value": "(?i)(/\\.env|/\\.git|/wp-admin|/wp-login|/phpmyadmin|/admin|/backup|/config|/\\.ssh|/manager/html|/actuator)"},
            ],
            "group_by": ["src_ip"],
            "threshold": 5,
            "window_minutes": 30,
        },
    },
    {
        "name": "Automated scanner user-agent",
        "severity": "low",
        "description": "Known security tooling or scripted clients in the user-agent",
        "definition": {
            "match": "any",
            "conditions": [
                {"field": "user_agent", "op": "regex", "value": "(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|gobuster|dirbuster|wfuzz|hydra|zgrab|nuclei|python-requests|go-http-client|curl/)"},
            ],
            "group_by": ["src_ip"],
            "threshold": 1,
            "window_minutes": 60,
        },
    },
    {
        "name": "Authentication brute force",
        "severity": "high",
        "description": "Repeated failed logins from one source",
        "definition": {
            "match": "any",
            "conditions": [
                {"field": "status_code", "op": "in", "value": [401, 403]},
                {"field": "url", "op": "regex", "value": "(?i)(login|signin|auth|session|token)"},
            ],
            "group_by": ["src_ip"],
            "threshold": 10,
            "window_minutes": 15,
            "match": "any",
        },
    },
    {
        "name": "Server error burst",
        "severity": "medium",
        "description": "Many 5xx responses — an outage or a failing attack",
        "definition": {
            "match": "all",
            "conditions": [{"field": "status_code", "op": "gte", "value": 500}],
            "group_by": ["url"],
            "threshold": 20,
            "window_minutes": 10,
        },
    },
    {
        "name": "Directory brute force (404 burst)",
        "severity": "medium",
        "description": "High volume of 404 responses from a single source",
        "definition": {
            "match": "all",
            "conditions": [
                {"field": "status_code", "op": "eq", "value": 404},
                {"field": "method", "op": "in", "value": ["GET", "HEAD", "POST"]},
            ],
            "group_by": ["src_ip"],
            "threshold": 50,
            "window_minutes": 15,
        },
    },
    {
        "name": "Cleartext credentials in logs",
        "severity": "high",
        "description": "Passwords or tokens written to log files by the application",
        "definition": {
            "match": "any",
            "conditions": [{"field": "message", "op": "regex", "value": "(?i)(password=|passwd=|pwd=|api[_-]?key=|authorization:\\s*basic)"}],
            "group_by": ["event_type"],
            "threshold": 1,
            "window_minutes": 120,
        },
    },
)

def ensure_builtin_rules(db: Session, project_id: str) -> None:
    existing = {
        row.name
        for row in db.execute(select(DetectionRule).where(DetectionRule.project_id == project_id)).scalars().all()
    }
    created = 0
    for rule in BUILTIN_RULES:
        if rule["name"] in existing:
            continue
        db.add(
            DetectionRule(
                project_id=project_id,
                name=rule["name"],
                description=rule["description"],
                severity=rule["severity"],
                enabled=True,
                is_builtin=True,
                definition={"severity": rule["severity"], "alert_title": rule["name"], **rule["definition"]},
            )
        )
        created += 1
    if created:
        db.commit()
        log.info("created %s built-in detection rule(s) for project %s", created, project_id)


# ---------------------------------------------------------------------------
# Engine entry point
# ---------------------------------------------------------------------------
async def run(ctx: EngineContext, targets: list[dict[str, Any]]) -> EngineResult:
    result = EngineResult(data={})
    options = ctx.scan.options or {}
    upload_path = str(options.get("upload_path") or "")
    source_name = str(options.get("source_name") or Path(upload_path).name or "upload")
    fmt = str(options.get("format") or "auto")

    if not upload_path or not Path(upload_path).exists():
        ctx.emit("No log file found for this scan.", level="error", phase="parse")
        ctx.phase("parse", "failed", progress=100)
        return result

    path = Path(upload_path)
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        ctx.emit(f"File has {len(lines)} lines; analysing the first {MAX_LINES}.", level="warn", phase="parse")
        lines = lines[:MAX_LINES]

    ctx.phase("parse", "running", progress=20)
    detected = detect_format([line for line in lines[:50] if line.strip()])
    if fmt == "auto":
        fmt = detected
    source = LogSource(
        project_id=ctx.project.id,
        name=source_name[:200],
        kind="upload",
        format=fmt,
        filename=path.name,
        size_bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        created_by=ctx.scan.requested_by,
    )
    ctx.db.add(source)
    ctx.db.flush()
    ctx.emit(f"Parsing {len(lines)} line(s) as '{fmt}' format.", phase="parse", data={"format": fmt, "lines": len(lines)})
    ctx.phase("parse", "done", progress=100)

    # ------------------------------------------------------------- normalize
    ctx.phase("normalize", "running", progress=25)
    parsed_events: list[dict[str, Any]] = []
    parse_errors = 0
    severity_counter: Counter[str] = Counter()
    event_types: Counter[str] = Counter()
    src_ips: Counter[str] = Counter()

    for index, line in enumerate(lines):
        event = parse_line(line, fmt)
        if not event:
            parse_errors += 1
            continue
        event["ts"] = parse_timestamp(event.get("ts_text", ""))
        if not event.get("severity"):
            event["severity"] = "info"
        safe_message, _ = redact_text(event.get("message", ""), limit=1500)
        safe_url, _ = redact_text(event.get("url", ""), limit=900)
        event["message"] = safe_message
        event["url"] = safe_url
        event["fingerprint"] = event_fingerprint(event)
        parsed_events.append(event)
        severity_counter[event["severity"]] += 1
        event_types[event.get("event_type") or "unknown"] += 1
        if event.get("src_ip"):
            src_ips[event["src_ip"]] += 1

        if len(parsed_events) % BATCH_SIZE == 0:
            _flush_batch(ctx, source, parsed_events)
            ctx.emit(f"Normalized {len(parsed_events)} event(s) …", level="debug", phase="normalize", kind="progress")
            parsed_events = []

    if parsed_events:
        _flush_batch(ctx, source, parsed_events)

    source.event_count = sum(severity_counter.values())
    source.parse_errors = parse_errors
    source.last_event_at = utcnow()
    ctx.db.commit()
    ctx.emit(
        f"Normalized {source.event_count} event(s); {parse_errors} line(s) could not be parsed.",
        phase="normalize",
        kind="metric",
        data={"severity": dict(severity_counter), "event_types": dict(event_types.most_common(10))},
    )
    ctx.phase("normalize", "done", progress=100)

    # ----------------------------------------------------------------- rules
    ctx.phase("rules", "running", progress=30)
    ensure_builtin_rules(ctx.db, ctx.project.id)
    rules = db_enabled_rules(ctx.db, ctx.project.id)
    ctx.emit(f"Evaluating {len(rules)} detection rule(s) across the uploaded events.", phase="rules")

    matches_by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rows = ctx.db.execute(
        select(LogEvent).where(LogEvent.source_id == source.id).order_by(LogEvent.id.asc()).limit(MAX_LINES)
    ).scalars().all()
    for row in rows:
        event_dict = {
            "message": row.message,
            "src_ip": row.src_ip,
            "dst_ip": row.dst_ip,
            "src_port": row.src_port,
            "dst_port": row.dst_port,
            "method": row.method,
            "url": row.url,
            "status_code": row.status_code,
            "user_agent": row.user_agent,
            "severity": row.severity,
            "event_type": row.event_type,
            "id": row.id,
            "ts": row.ts,
        }
        for rule in rules:
            if rule_matches(rule.definition or {}, event_dict):
                matches_by_rule[rule.id].append({**event_dict, "rule_id": rule.id})
    total_matches = sum(len(v) for v in matches_by_rule.values())
    ctx.emit(f"{total_matches} event(s) matched detection rules.", phase="rules", kind="metric")
    ctx.phase("rules", "done", progress=100)

    # ---------------------------------------------------------------- alerts
    ctx.phase("alerts", "running", progress=40)
    created_alerts = 0
    updated_alerts = 0
    for rule in rules:
        matches = matches_by_rule.get(rule.id, [])
        if not matches:
            continue
        definition = rule.definition or {}
        threshold = int(definition.get("threshold", 1) or 1)
        group_by = definition.get("group_by") or []
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        if group_by:
            for match in matches:
                key = "|".join(str(match.get(field, "")) for field in group_by) or "any"
                groups[key].append(match)
        else:
            groups["any"] = matches

        for group_value, group_matches in groups.items():
            if len(group_matches) < threshold:
                continue
            group_key = stable_hash(ctx.project.id, rule.id, group_value)[:40]
            alert = ctx.db.execute(
                select(Alert).where(Alert.project_id == ctx.project.id, Alert.group_key == group_key)
            ).scalar_one_or_none()
            evidence_ids = [str(m["id"]) for m in group_matches[:20]]
            sample_lines = [str(m.get("message", ""))[:400] for m in group_matches[:5]]
            title = definition.get("alert_title") or rule.name
            if group_value and group_value != "any":
                title = f"{title} — {group_value}"

            if alert is None:
                alert = Alert(
                    project_id=ctx.project.id,
                    rule_id=rule.id,
                    title=title[:300],
                    description=f"{len(group_matches)} matching event(s). Rule: {rule.name}.",
                    severity=rule.severity,
                    status="new",
                    group_key=group_key,
                    event_count=len(group_matches),
                    first_seen_at=min((m.get("ts") or utcnow() for m in group_matches), default=utcnow()),
                    last_seen_at=utcnow(),
                    evidence_event_ids=evidence_ids,
                    meta={
                        "rule_name": rule.name,
                        "group_by": group_by,
                        "group_value": group_value,
                        "samples": sample_lines,
                        "source_id": source.id,
                        "source_name": source.name,
                    },
                )
                ctx.db.add(alert)
                created_alerts += 1
            else:
                alert.event_count += len(group_matches)
                alert.last_seen_at = utcnow()
                alert.evidence_event_ids = list({*(alert.evidence_event_ids or []), *evidence_ids})[:50]
                merged_samples = list({*(alert.meta or {}).get("samples", []), *sample_lines})[:8]
                meta = dict(alert.meta or {})
                meta["samples"] = merged_samples
                alert.meta = meta
                if SEVERITY_RANK.get(rule.severity, 0) > SEVERITY_RANK.get(alert.severity, 0):
                    alert.severity = rule.severity
                updated_alerts += 1

            rule.trigger_count += len(group_matches)
            rule.last_triggered_at = utcnow()

    ctx.db.commit()
    ctx.emit(
        f"{created_alerts} new alert(s) and {updated_alerts} updated alert(s) generated.",
        phase="alerts",
        kind="metric",
        data={"created": created_alerts, "updated": updated_alerts},
    )
    ctx.phase("alerts", "done", progress=100)

    # ---------------------------------------------------------------- IOCs
    iocs = {
        "top_sources": [{"ip": ip, "events": count} for ip, count in src_ips.most_common(25)],
        "event_types": dict(event_types.most_common(20)),
        "severity": dict(severity_counter),
        "parse_errors": parse_errors,
    }
    result.data = {
        "source_id": source.id,
        "source_name": source.name,
        "format": fmt,
        "events": source.event_count,
        "rules_evaluated": len(rules),
        "rule_matches": total_matches,
        "alerts_created": created_alerts,
        "alerts_updated": updated_alerts,
        "iocs": iocs,
    }
    ctx.scan.stats = {**(ctx.scan.stats or {}), "logs": result.data}
    ctx.db.commit()
    return result


def db_enabled_rules(db: Session, project_id: str) -> list[DetectionRule]:
    return list(
        db.execute(
            select(DetectionRule).where(DetectionRule.project_id == project_id, DetectionRule.enabled.is_(True))
        ).scalars().all()
    )


def _flush_batch(ctx: EngineContext, source: LogSource, events: list[dict[str, Any]]) -> None:
    for event in events:
        ctx.db.add(
            LogEvent(
                project_id=ctx.project.id,
                source_id=source.id,
                ts=event.get("ts"),
                severity=str(event.get("severity") or "info")[:12],
                event_type=str(event.get("event_type") or "")[:60],
                message=event.get("message", "")[:4000],
                src_ip=str(event.get("src_ip") or "")[:64],
                dst_ip=str(event.get("dst_ip") or "")[:64],
                src_port=event.get("src_port"),
                dst_port=event.get("dst_port"),
                method=str(event.get("method") or "")[:10],
                url=str(event.get("url") or "")[:1000],
                status_code=event.get("status_code"),
                user_agent=str(event.get("user_agent") or "")[:400],
                fingerprint=event.get("fingerprint", ""),
                meta={"host": event.get("host", ""), "process": event.get("process", "")},
            )
        )
    ctx.db.commit()
