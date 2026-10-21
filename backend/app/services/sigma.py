"""Detection Rule Studio: Sigma validation and testing.

The validator checks a rule against the Sigma specification and reports what
it detects, what it can miss and how false positives arise.  The tester runs a
rule against the normalised log events NEXUS actually stores, so a rule can be
proved against real ingested telemetry instead of a mock.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import LogEvent

log = logging.getLogger("nexus.services.sigma")

VALID_STATUS = {"experimental", "test", "stable", "deprecated", "unsupported"}
VALID_LEVEL = {"informational", "low", "medium", "high", "critical"}

# Sigma modifier -> how the value is compared.
MODIFIER_HINTS = {
    "contains": "substring match (case-insensitive)",
    "startswith": "prefix match (case-insensitive)",
    "endswith": "suffix match (case-insensitive)",
    "re": "regular expression match",
    "all": "the field must contain every listed value",
    "base64": "value is compared after base64 decoding",
    "utf16": "value is compared after UTF-16LE decoding",
    "windash": "Windows command-line argument matching",
    "lt": "the field is numerically less than the value",
    "gte": "the field is numerically greater than or equal to the value",
}


class RuleError(ValueError):
    """Raised when a rule cannot be parsed at all."""


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _match_value(spec: Any, actual: Any) -> bool:
    """Compare one field specification against the event value."""
    if isinstance(spec, list):
        if not spec:
            return False
        # A list of lists means AND across the inner alternatives.
        if all(isinstance(item, list) for item in spec):
            return all(_match_value(inner, actual) for inner in spec)
        return any(_match_value(item, actual) for item in spec)
    if spec is None:
        return actual in (None, "", [], {})
    return _as_text(spec).lower() == _as_text(actual).lower()


def _match_field(field: str, spec: Any, event: dict[str, Any]) -> bool:
    parts = field.split("|")
    name = parts[0]
    modifiers = [part.lower() for part in parts[1:]]

    actual = event.get(name)
    if name == "keywords":
        haystack = " ".join(
            _as_text(event.get(key))
            for key in ("message", "command_line", "service_name", "event_type", "raw")
        ).lower()
        if isinstance(spec, list) and not any(isinstance(item, list) for item in spec):
            return any(_as_text(item).lower() in haystack for item in spec)
        return _as_text(spec).lower() in haystack

    if actual is None:
        # A null spec explicitly matches "field absent or empty".
        if spec is None:
            return True
        if "null" in modifiers:
            return True
        return False

    text = _as_text(actual)
    lowered = text.lower()

    if "contains" in modifiers:
        needle = _as_text(spec).lower()
        return needle in lowered
    if "startswith" in modifiers:
        return lowered.startswith(_as_text(spec).lower())
    if "endswith" in modifiers:
        return lowered.endswith(_as_text(spec).lower())
    if "re" in modifiers:
        try:
            return re.search(_as_text(spec), text, re.IGNORECASE) is not None
        except re.error:
            return False
    if "all" in modifiers and isinstance(spec, list):
        return all(_as_text(item).lower() in lowered for item in spec)
    if "lt" in modifiers:
        try:
            return float(actual) < float(spec)
        except (TypeError, ValueError):
            return False
    if "gte" in modifiers:
        try:
            return float(actual) >= float(spec)
        except (TypeError, ValueError):
            return False

    return _match_value(spec, actual)


def _match_selection(selection: Any, event: dict[str, Any]) -> bool:
    """A selection is a map of field -> value; every field must match."""
    if not isinstance(selection, dict):
        return False
    if not selection:
        return False
    for field, spec in selection.items():
        if not _match_field(field, spec, event):
            return False
    return True


def _selection_names(detection: dict[str, Any]) -> list[str]:
    return [key for key in detection if key != "condition"]


def _evaluate_condition(condition: str, detection: dict[str, Any], event: dict[str, Any]) -> bool:
    """Evaluate a Sigma condition expression against a single event."""
    text = (condition or "").strip()
    if not text:
        return False

    # "all of X" / "1 of X" / "any of X" with optional wildcard.
    match = re.fullmatch(r"(all|any|1)\s+of\s+([A-Za-z0-9_*]+)", text, re.IGNORECASE)
    if match:
        mode = match.group(1).lower()
        target = match.group(2)
        names = _selection_names(detection)
        if target.endswith("*"):
            prefix = target[:-1]
            candidates = [name for name in names if name.startswith(prefix)]
        else:
            candidates = [name for name in names if name == target]
        results = [_match_selection(detection[name], event) for name in candidates]
        if not results:
            return False
        return all(results) if mode == "all" else any(results)

    # Boolean expression over named selections: split on " and not " first.
    lowered = text.lower()
    if " and not " in lowered:
        left, right = re.split(r"\s+and\s+not\s+", text, maxsplit=1, flags=re.IGNORECASE)
        return _evaluate_condition(left, detection, event) and not _evaluate_condition(
            right, detection, event
        )

    parts = re.split(r"\s+or\s+", text, flags=re.IGNORECASE)
    if len(parts) > 1:
        return any(_evaluate_condition(part.strip(), detection, event) for part in parts)

    parts = re.split(r"\s+and\s+", text, flags=re.IGNORECASE)
    if len(parts) > 1:
        return all(_evaluate_condition(part.strip(), detection, event) for part in parts)

    if text.lower().startswith("not "):
        return not _evaluate_condition(text[4:].strip(), detection, event)

    name = text.strip()
    if name not in detection:
        raise RuleError(f"condition references unknown selection: {name}")
    return _match_selection(detection[name], event)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Structural validation plus a plain-language explanation of the rule."""
    errors: list[str] = []
    warnings: list[str] = []
    info: list[str] = []

    title = str(rule.get("title") or "").strip()
    if not title:
        errors.append("title is required")
    elif len(title) > 120:
        warnings.append("title is longer than the recommended 120 characters")

    status = str(rule.get("status") or "experimental").lower()
    if status not in VALID_STATUS:
        errors.append(f"status must be one of {sorted(VALID_STATUS)}")

    level = str(rule.get("level") or "").lower()
    if not level:
        warnings.append("level is not set; triage will default to medium")
    elif level not in VALID_LEVEL:
        errors.append(f"level must be one of {sorted(VALID_LEVEL)}")

    logsource = rule.get("logsource")
    if not isinstance(logsource, dict) or not logsource:
        errors.append("logsource is required (product, service or category)")
    else:
        if not any(logsource.get(key) for key in ("product", "service", "category")):
            errors.append("logsource must define at least one of product, service or category")
        else:
            info.append(
                f"Targets {logsource.get('product') or logsource.get('service') or logsource.get('category')} "
                f"logs"
            )

    detection = rule.get("detection")
    if not isinstance(detection, dict) or not detection:
        errors.append("detection is required")
        detection = {}
    else:
        condition = detection.get("condition")
        names = _selection_names(detection)
        if not condition:
            errors.append("detection.condition is required")
        elif not isinstance(condition, str):
            errors.append("detection.condition must be a string")
        else:
            referenced = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", condition))
            unknown = sorted(
                name
                for name in referenced
                if name not in names and name.lower() not in {"all", "any", "of", "and", "or", "not"}
            )
            if unknown:
                errors.append(f"condition references unknown selections: {', '.join(unknown)}")
            if not names:
                errors.append("detection has no selection to evaluate")
            else:
                try:
                    _evaluate_condition(condition, detection, {})
                except RuleError as exc:
                    errors.append(str(exc))
                except Exception as exc:  # pragma: no cover - defensive
                    errors.append(f"condition could not be parsed: {exc}")
        for name in names:
            selection = detection[name]
            if not isinstance(selection, dict):
                errors.append(f"selection '{name}' must be a map of field to value")
                continue
            for field in selection:
                if "|" in field:
                    modifier = field.split("|", 1)[1].lower()
                    if modifier not in MODIFIER_HINTS:
                        warnings.append(f"selection '{name}' uses an unknown modifier: {modifier}")

    if not rule.get("falsepositives"):
        warnings.append("no falsepositives entry: expected in a publishable rule")
    if not rule.get("references"):
        warnings.append("no references: reviewers cannot verify the behaviour")
    if not rule.get("description"):
        warnings.append("no description: triage responders will lack context")

    detects = _describe_detects(detection)
    blind_spots = _describe_blind_spots(detection)
    false_positive_notes = _describe_false_positives(rule, detection)

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "info": info,
        "detects": detects,
        "blind_spots": blind_spots,
        "false_positives": false_positive_notes,
        "selections": _selection_names(detection),
    }


def _describe_detects(detection: dict[str, Any]) -> list[str]:
    if not isinstance(detection, dict):
        return []
    out: list[str] = []
    for name in _selection_names(detection):
        selection = detection[name]
        if not isinstance(selection, dict):
            continue
        fields = []
        for field, spec in selection.items():
            base = field.split("|")[0]
            if base == "keywords":
                values = spec if isinstance(spec, list) else [spec]
                rendered = ", ".join(_as_text(item) for item in values[:6])
                fields.append(f"message contains any of: {rendered}")
            else:
                fields.append(f"{base} matches {_as_text(spec)}")
        out.append(f"Selection '{name}': " + "; ".join(fields))
    return out


def _describe_blind_spots(detection: dict[str, Any]) -> list[str]:
    spots: list[str] = []
    if not isinstance(detection, dict):
        return spots
    names = _selection_names(detection)
    fields = {
        field.split("|")[0]
        for selection in detection.values()
        if isinstance(selection, dict)
        for field in selection
    }
    if "keywords" not in fields:
        spots.append("Events that carry the same signal in a different field name are not matched.")
    if len(names) == 1 and not any(
        key.startswith("filter") for key in detection
    ):
        spots.append("There is no exclusion filter, so benign activity matching the selection is reported too.")
    if not any("|" in field for selection in detection.values() if isinstance(selection, dict) for field in selection):
        spots.append("All matching is exact; partial or obfuscated values are not detected.")
    return spots


def _describe_false_positives(rule: dict[str, Any], detection: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    declared = rule.get("falsepositives")
    if isinstance(declared, list):
        notes.extend(str(item) for item in declared if item)
    elif isinstance(declared, str) and declared.strip():
        notes.append(declared.strip())
    fields = {
        field.split("|")[0]
        for selection in detection.values()
        if isinstance(selection, dict)
        for field in selection
    }
    if "process" in fields or "Image" in fields or "ParentImage" in fields:
        notes.append("Signed or approved administrative tooling can satisfy the same field values.")
    if "user" in fields or "User" in fields:
        notes.append("Service and administrative accounts frequently trigger user-scoped rules.")
    if not notes:
        notes.append("No false-positive guidance has been declared for this rule yet.")
    return notes


# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------
def test_rule(
    db: Session,
    project_id: str,
    rule: dict[str, Any],
    *,
    limit: int = 500,
) -> dict[str, Any]:
    """Run a rule against the normalised log events stored for a project."""
    detection = rule.get("detection") or {}
    condition = detection.get("condition") if isinstance(detection, dict) else None
    if not isinstance(detection, dict) or not condition:
        raise RuleError("detection.condition is required to test a rule")

    events = db.execute(
        select(LogEvent)
        .where(LogEvent.project_id == project_id)
        .order_by(LogEvent.ts.desc())
        .limit(limit)
    ).scalars().all()

    matches: list[dict[str, Any]] = []
    for event in events:
        payload = {
            "message": event.message,
            "event_type": event.event_type,
            "severity": event.severity,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "method": event.method,
            "url": event.url,
            "status_code": event.status_code,
            "user_agent": event.user_agent,
            "raw": event.raw,
            "fingerprint": event.fingerprint,
        }
        try:
            hit = _evaluate_condition(condition, detection, payload)
        except RuleError:
            raise
        except Exception:  # pragma: no cover - defensive
            hit = False
        if hit:
            matches.append(
                {
                    "event_id": str(event.id),
                    "ts": event.ts.isoformat() if event.ts else None,
                    "severity": event.severity,
                    "event_type": event.event_type,
                    "message": event.message[:500],
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "url": event.url,
                }
            )

    return {
        "tested_events": len(events),
        "matched_events": len(matches),
        "match_rate": round((len(matches) / len(events) * 100), 2) if events else 0.0,
        "matches": matches[:50],
        "sample_size_note": (
            f"Tested against {len(events)} stored log events."
            if events
            else "No log events are stored for this project, so the rule could not be exercised. "
            "Upload a log file first."
        ),
    }
