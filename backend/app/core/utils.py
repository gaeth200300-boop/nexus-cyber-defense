"""Core cross-cutting helpers: time, ids, hashing, text utilities."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import secrets
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Time — all timestamps are stored as *naive UTC* for SQLite/PostgreSQL parity.
# ---------------------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utcnow_iso() -> str:
    return utcnow().isoformat(timespec="seconds") + "Z"


def to_iso_z(dt: datetime | None) -> str | None:
    """Serialize a naive-UTC datetime as an ISO-8601 string with a Z suffix."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="milliseconds") + "Z"


def humanize_age(dt: datetime | None) -> str:
    if dt is None:
        return "never"
    delta = utcnow() - dt
    seconds = int(max(delta.total_seconds(), 0))
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


# ---------------------------------------------------------------------------
# IDs
# ---------------------------------------------------------------------------
def new_id() -> str:
    return str(uuid.uuid4())


def short_id(size: int = 8) -> str:
    return secrets.token_hex(size // 2)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def stable_hash(*parts: Any) -> str:
    """Deterministic fingerprint used for dedup keys."""
    payload = "\u0000".join("" if p is None else str(p) for p in parts)
    return sha256_hex(payload)[:32]


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------
_AR_DIACRITICS = re.compile(r"[\u0617-\u061A\u064B-\u0652]")


def slugify(value: str, max_len: int = 60) -> str:
    value = unicodedata.normalize("NFKC", value or "").strip().lower()
    value = _AR_DIACRITICS.sub("", value)
    value = re.sub(r"[^\w\s\-\u0600-\u06FF]", "", value, flags=re.UNICODE)
    value = re.sub(r"[\s_]+", "-", value).strip("-")
    return (value or "item")[:max_len]


def truncate(text: str | None, limit: int = 2000, suffix: str = "\n…[truncated]") -> str | None:
    if text is None:
        return None
    if len(text) <= limit:
        return text
    return text[:limit] + suffix


def mask_secret(value: str | None, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


# A pragmatic, syntax-only email shape. Self-hosted deployments legitimately
# use internal domains such as "admin@nexus.local" that DNS-aware validators
# reject, and this platform never relies on deliverability - only on a sane
# local@domain form for account keys.
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def is_valid_email(value: str) -> bool:
    """True when *value* looks like a usable ``local@domain`` address."""
    if not isinstance(value, str):
        return False
    if len(value) > 255 or value.count("@") != 1 or any(ch.isspace() for ch in value):
        return False
    local, _, domain = value.partition("@")
    if not local or len(local) > 64 or not domain or len(domain) > 253:
        return False
    if domain.startswith(".") or domain.endswith(".") or ".." in domain:
        return False
    return bool(_EMAIL_RE.match(value))


# ---------------------------------------------------------------------------
# Networking helpers
# ---------------------------------------------------------------------------
def is_private_or_reserved(ip: str) -> bool:
    """True for loopback / private / link-local / reserved / multicast ranges."""
    try:
        addr = ipaddress.ip_address(ip.strip().strip("[]"))
    except ValueError:
        return True  # unparseable => treat as unsafe
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "metadata.azure.com",
}


def normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    # IDN → punycode so scope matching is consistent
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            pass
    return host


def parse_target_url(raw: str, default_scheme: str = "https") -> tuple[str, str, int | None]:
    """Return (normalized_host, scheme, port) for a user supplied target string."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty target")
    if "://" not in raw:
        raw = f"{default_scheme}://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme}")
    host = normalize_host(parsed.hostname or "")
    if not host:
        raise ValueError("target has no host")
    port = parsed.port
    return host, parsed.scheme, port


def domain_in_scope(candidate: str, scope_value: str, include_subdomains: bool) -> bool:
    candidate = normalize_host(candidate)
    scope_value = normalize_host(scope_value)
    if not candidate or not scope_value:
        return False
    if candidate == scope_value:
        return True
    if include_subdomains and candidate.endswith("." + scope_value):
        return True
    return False


def ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
        return True
    except ValueError:
        return False


def chunked(items: Iterable[Any], size: int) -> Iterable[list[Any]]:
    bucket: list[Any] = []
    for item in items:
        bucket.append(item)
        if len(bucket) >= size:
            yield bucket
            bucket = []
    if bucket:
        yield bucket


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def safe_div(a: float, b: float, default: float = 0.0) -> float:
    try:
        if b == 0:
            return default
        return a / b
    except Exception:
        return default


def entropy_bits(sample_size: float, charset_size: float) -> float:
    try:
        if sample_size <= 0 or charset_size <= 1:
            return 0.0
        return math.log2(charset_size) * sample_size
    except Exception:
        return 0.0
