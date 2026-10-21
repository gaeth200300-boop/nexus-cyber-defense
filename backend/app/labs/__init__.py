"""Built-in training labs (CTF-style, fully verifiable, safe by construction)."""

from .content import LAB_DEFINITIONS, sync_labs
from .files import ensure_lab_files
from .verify import verify_lab_run

__all__ = ["LAB_DEFINITIONS", "ensure_lab_files", "sync_labs", "verify_lab_run"]
