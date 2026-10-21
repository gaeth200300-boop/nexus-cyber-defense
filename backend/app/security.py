"""Authentication primitives: password hashing, JWTs, API keys, TOTP, secret encryption."""

from __future__ import annotations

import base64
import hmac
import secrets
from datetime import timedelta, timezone
from typing import Any

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import settings
from .core.utils import sha256_hex, utcnow

# ---------------------------------------------------------------------------
# Passwords (Argon2id)
# ---------------------------------------------------------------------------
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

PASSWORD_MIN_LENGTH = 10


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except (InvalidHashError, ValueError):
        return True


def password_strength(password: str) -> tuple[int, list[str]]:
    """Return (score 0..4, issues[]) — used by the UI password meter and the API."""
    issues: list[str] = []
    score = 0
    if len(password) >= PASSWORD_MIN_LENGTH:
        score += 1
    else:
        issues.append(f"min_length_{PASSWORD_MIN_LENGTH}")
    classes = sum(
        1
        for check in (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
        if check
    )
    score += max(0, classes - 1)
    if len(password) >= 16:
        score += 1
    for weak in ("password", "admin", "123456", "qwerty", "nexus", "welcome"):
        if weak in password.lower():
            issues.append(f"contains_common_word_{weak}")
            score = max(0, score - 1)
    return min(score, 4), issues


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
ALGORITHM = "HS256"


def _epoch(dt) -> int:
    """Convert a naive-UTC datetime into a POSIX timestamp without local-time drift.

    ``utcnow()`` returns a naive datetime; calling ``.timestamp()`` on it makes
    Python interpret it in the host timezone, which silently shifts JWT
    ``iat``/``exp`` by the local UTC offset.  Attaching UTC first keeps tokens
    valid on every machine.
    """
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def create_access_token(subject: str, **claims: Any) -> str:
    now = utcnow()
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": _epoch(now),
        "exp": _epoch(now + timedelta(minutes=settings.access_token_minutes)),
        "typ": "access",
        **claims,
    }
    return jwt.encode(payload, settings.resolve_secret_key(), algorithm=ALGORITHM)


def create_refresh_token(subject: str, token_version: int = 0) -> str:
    now = utcnow()
    payload = {
        "sub": subject,
        "iat": _epoch(now),
        "exp": _epoch(now + timedelta(days=settings.refresh_token_days)),
        "typ": "refresh",
        "tv": token_version,
        "jti": secrets.token_urlsafe(12),
    }
    return jwt.encode(payload, settings.resolve_secret_key(), algorithm=ALGORITHM)


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any] | None:
    try:
        payload = jwt.decode(token, settings.resolve_secret_key(), algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
    if payload.get("typ") != expected_type:
        return None
    return payload


# ---------------------------------------------------------------------------
# API keys — stored as SHA-256 hashes, shown to the user exactly once.
# ---------------------------------------------------------------------------
API_KEY_PREFIX = "nxs"


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix_for_display, sha256_hash)."""
    body = secrets.token_urlsafe(32)
    full = f"{API_KEY_PREFIX}_{body}"
    display_prefix = full[:12]
    return full, display_prefix, sha256_hex(full)


def hash_api_key(raw_key: str) -> str:
    return sha256_hex(raw_key)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------------------------------------------------------------------------
# TOTP (MFA)
# ---------------------------------------------------------------------------
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=settings.app_name)


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=valid_window)
    except Exception:
        return False


def generate_recovery_codes(count: int = 8) -> list[str]:
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(count)]


# ---------------------------------------------------------------------------
# Application-level encryption for sensitive fields (e.g. TOTP secrets at rest)
# ---------------------------------------------------------------------------
def _fernet() -> Fernet:
    material = settings.resolve_secret_key().encode("utf-8")
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"nexus-field-encryption", info=b"v1").derive(material)
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_field(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_field(ciphertext: str) -> str | None:
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, AttributeError):
        return None
