"""Upload storage: hard size caps, safe filenames, hashes for integrity.

All uploads land in `settings.uploads_dir` under a generated name. The original
name is preserved only as metadata. Files are never executed or served back.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fastapi import UploadFile

from ..config import settings
from ..core.utils import new_id, slugify

PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
REJECTED_LOG_SUFFIXES = {".exe", ".dll", ".bin", ".zip", ".rar", ".7z", ".msi", ".bat", ".cmd", ".ps1"}


class UploadRejected(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


async def store_upload(file: UploadFile, *, kind: str = "generic") -> dict[str, Any]:
    """Stream an uploaded file to managed storage. Returns storage metadata."""
    original = (file.filename or "upload.bin").strip()
    suffix = Path(original).suffix.lower()[:12]
    if kind == "pcap" and suffix not in PCAP_SUFFIXES:
        raise UploadRejected("invalid_file_type", "PCAP uploads must end with .pcap, .pcapng or .cap.")
    if kind == "log" and suffix in REJECTED_LOG_SUFFIXES:
        raise UploadRejected("invalid_file_type", f"'{suffix}' is not a log file.")

    settings.ensure_dirs()
    safe_name = f"{new_id()}-{slugify(Path(original).stem, 40)}{suffix}"
    destination = settings.uploads_dir / safe_name
    max_bytes = settings.max_upload_mb * 1024 * 1024
    digest = hashlib.sha256()
    size = 0
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
                    raise UploadRejected(
                        "file_too_large",
                        f"Uploads are limited to {settings.max_upload_mb} MB.",
                        413,
                    )
                digest.update(chunk)
                handle.write(chunk)
    finally:
        await file.close()

    if size == 0:
        destination.unlink(missing_ok=True)
        raise UploadRejected("empty_file", "The uploaded file is empty.")

    return {
        "upload_path": str(destination),
        "source_name": original[:200],
        "size_bytes": size,
        "sha256": digest.hexdigest(),
        "kind": kind,
        "max_mb": settings.max_upload_mb,
    }
