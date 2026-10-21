"""Evidence redaction — secrets never reach the database in clear text.

Rules (see core.constants.SENSITIVE_HEADERS / SENSITIVE_PATTERNS) are applied to
every header dump, request/response snippet and uploaded log line before storage.
Each redaction is recorded so reports can state *what* was withheld and why.
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .constants import MAX_EVIDENCE_SNIPPET, SENSITIVE_HEADERS, SENSITIVE_PATTERNS

REDACTED = "[REDACTED]"

_COMPILED = [re.compile(p) for p in SENSITIVE_PATTERNS]
_SENSITIVE_HEADER_SET = {h.lower() for h in SENSITIVE_HEADERS}


def _is_sensitive_name(name: str) -> bool:
    lowered = (name or "").strip().lower()
    if lowered in _SENSITIVE_HEADER_SET:
        return True
    return any(token in lowered for token in ("token", "secret", "passw", "api-key", "apikey", "authorization", "cookie", "session"))


def redact_headers(headers: Any) -> tuple[dict[str, str], list[dict[str, str]]]:
    """Return (safe_headers, redactions). Accepts dict or list-of-pairs."""
    redactions: list[dict[str, str]] = []
    out: dict[str, str] = {}

    if headers is None:
        return out, redactions
    if isinstance(headers, dict):
        items: Iterable[tuple[str, Any]] = list(headers.items())
    elif isinstance(headers, (list, tuple)):
        items = [(str(k), v) for k, v in headers]
    else:
        return {"value": str(headers)[:MAX_EVIDENCE_SNIPPET]}, redactions

    for key, value in items:
        text = "" if value is None else str(value)
        if _is_sensitive_name(str(key)):
            out[str(key)] = REDACTED
            redactions.append({"field": f"header:{key}", "reason": "sensitive_header"})
        else:
            cleaned, extra = redact_text(text)
            out[str(key)] = cleaned
            redactions.extend(extra)
    return out, redactions


def redact_text(text: str | None, *, limit: int = MAX_EVIDENCE_SNIPPET) -> tuple[str, list[dict[str, str]]]:
    """Mask secrets inside free text (bodies, log lines, banners)."""
    if not text:
        return "", []
    redactions: list[dict[str, str]] = []
    result = str(text)
    for pattern in _COMPILED:
        matches = pattern.findall(result)
        if matches:
            result = pattern.sub(REDACTED, result)
            sample = matches[0]
            sample = sample if isinstance(sample, str) else str(sample)
            redactions.append({"field": "text", "reason": "pattern_match", "preview": sample[:14] + "…"})
    if len(result) > limit:
        result = result[:limit] + "\n…[truncated]"
    return result, redactions


def redact_url(url: str) -> tuple[str, list[dict[str, str]]]:
    """Mask values of sensitive query parameters but keep the parameter names visible."""
    try:
        parts = urlsplit(url)
    except Exception:
        return url, []
    if not parts.query:
        return url, []
    redactions: list[dict[str, str]] = []
    new_pairs: list[tuple[str, str]] = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if _is_sensitive_name(key):
            new_pairs.append((key, REDACTED))
            redactions.append({"field": f"query:{key}", "reason": "sensitive_parameter"})
        elif value.startswith("http"):
            # nested URLs may hide their own secrets — recurse once
            nested, nested_redactions = redact_url(value)
            new_pairs.append((key, nested))
            redactions.extend(nested_redactions)
        else:
            new_pairs.append((key, value))
    rebuilt = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new_pairs), parts.fragment))
    return rebuilt, redactions


def redact_cookie_header(value: str) -> tuple[str, list[dict[str, str]]]:
    """Keep cookie *names and flags* (security-relevant) but hide their values."""
    redactions: list[dict[str, str]] = []
    parts: list[str] = []
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            name, _, raw = chunk.partition("=")
            if name.strip().lower() in ("expires", "max-age", "path", "domain", "samesite", "secure", "httponly"):
                parts.append(chunk)
            else:
                parts.append(f"{name.strip()}={REDACTED}")
                redactions.append({"field": f"cookie:{name.strip()}", "reason": "cookie_value"})
        else:
            parts.append(chunk)
    return "; ".join(parts), redactions


def summarize_redactions(redactions: list[dict[str, str]]) -> str:
    if not redactions:
        return ""
    fields = sorted({r.get("field", "?") for r in redactions})
    return f"{len(redactions)} value(s) redacted ({', '.join(fields[:6])}{'…' if len(fields) > 6 else ''})"
