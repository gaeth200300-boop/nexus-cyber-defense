"""NEXUS command line utilities.

Examples (run from `nexus/backend` with the virtualenv active):
    python -m app.cli seed
    python -m app.cli sync-labs
    python -m app.cli create-admin --email you@example.com --role owner
    python -m app.cli kev-sync
    python -m app.cli status

`scripts\\nexus.cmd setup` calls `seed` after migrations, so a fresh install
needs no manual CLI step.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys
from typing import Any

from sqlalchemy import func, select

from .config import settings
from .core.queue import JobQueue
from .core.utils import to_iso_z, utcnow
from .db import ping, session_scope
from .engines.logs_engine import ensure_builtin_rules
from .labs.content import sync_labs
from .labs.files import ensure_lab_files
from .models import Project, User
from .security import hash_password, password_strength

log = logging.getLogger("nexus.cli")


def _print(message: str = "") -> None:
    # The Windows control script expects ASCII-only output; paths may contain
    # Arabic folder names, so replace anything unrepresentable instead of crashing.
    text = str(message).encode("ascii", "replace").decode("ascii")
    print(text, flush=True)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_seed(_: argparse.Namespace) -> int:
    settings.ensure_dirs()
    files = ensure_lab_files()
    _print(f"[OK] Lab fixtures ready ({len(files)} files) in storage/labs")

    with session_scope() as db:
        result = sync_labs(db)
        _print(f"[OK] Labs synced: {result['created']} created, {result['updated']} updated")

        users = int(db.execute(select(func.count(User.id))).scalar_one() or 0)
        if users == 0:
            owner = User(
                email=settings.bootstrap_admin_email.lower().strip(),
                full_name=settings.bootstrap_admin_name,
                role="owner",
                password_hash=hash_password(settings.bootstrap_admin_password),
            )
            db.add(owner)
            db.commit()
            _print(f"[OK] Bootstrap owner created: {owner.email}")
            if settings.bootstrap_admin_password == "ChangeMe!Nexus2026":
                _print("[!] The bootstrap password is the public default. Change it after first sign-in.")
        else:
            _print(f"[OK] Accounts already exist ({users}) — bootstrap owner not created.")

        projects = db.execute(select(Project.id).where(Project.archived_at.is_(None))).scalars().all()
        for project_id in projects:
            ensure_builtin_rules(db, project_id)
        _print(f"[OK] Built-in detection rules ensured for {len(projects)} active project(s)")

    try:
        _print("[i] CISA KEV is not downloaded during seed (it needs network access).")
        _print("    Run: python -m app.cli kev-sync   — or use Intelligence → KEV → Sync in the UI")
    except Exception:  # pragma: no cover
        pass
    return 0


def cmd_create_admin(args: argparse.Namespace) -> int:
    email = (args.email or "").strip().lower()
    if not email or "@" not in email:
        _print("[x] A valid --email is required.")
        return 2
    if not args.password:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            _print("[x] Passwords do not match.")
            return 2
    else:
        password = args.password
    score, suggestions = password_strength(password)
    if len(password) < 12 or score < 2:
        _print(f"[x] Password too weak (score {score}). Suggestions: {', '.join(suggestions) or 'use 12+ characters'}")
        return 2

    with session_scope() as db:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            user = User(
                email=email,
                full_name=args.name or email.split("@")[0],
                role=args.role,
                password_hash=hash_password(password),
            )
            db.add(user)
            db.commit()
            _print(f"[OK] Created {args.role} account: {email}")
        else:
            if not args.reset:
                _print(f"[!] Account already exists: {email}. Use --reset to set a new password.")
                return 1
            user.password_hash = hash_password(password)
            user.token_version = int(user.token_version or 0) + 1
            user.role = args.role
            db.commit()
            _print(f"[OK] Password reset and role set to {args.role}: {email}")
    return 0


def cmd_sync_labs(_: argparse.Namespace) -> int:
    with session_scope() as db:
        result = sync_labs(db)
    _print(f"[OK] Labs synced: {result['created']} created, {result['updated']} updated, {result['total']} total")
    return 0


def cmd_ensure_lab_files(_: argparse.Namespace) -> int:
    files = ensure_lab_files(force=False)
    for name, path in sorted(files.items()):
        _print(f"[OK] {name} ({path.stat().st_size} bytes)")
    return 0


def cmd_rules(_: argparse.Namespace) -> int:
    with session_scope() as db:
        project_ids = db.execute(select(Project.id).where(Project.archived_at.is_(None))).scalars().all()
        for project_id in project_ids:
            ensure_builtin_rules(db, project_id)
    _print(f"[OK] Built-in rules ensured for {len(project_ids)} project(s)")
    return 0


def cmd_kev_sync(_: argparse.Namespace) -> int:
    from .engines.intel_engine import sync_kev

    async def run() -> dict[str, Any]:
        with session_scope() as db:
            return await sync_kev(db, force=True)

    try:
        result = asyncio.run(run())
    except Exception as exc:  # noqa: BLE001 - CLI reports a readable error
        _print(f"[x] KEV sync failed: {type(exc).__name__}: {exc}")
        _print("    Check internet access / proxy, or set NEXUS_KEV_FEED_URL to a mirror.")
        return 1
    _print(f"[OK] KEV sync: {result}")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    ok, dialect = ping()
    _print(f"App:       {settings.app_name} {settings.version} ({settings.env})")
    _print(f"Database:  {dialect}{'' if ok else ' (unreachable)'}")
    _print(f"Data dir:  {settings.data_dir}")
    if not ok:
        return 1
    with session_scope() as db:
        users = int(db.execute(select(func.count(User.id))).scalar_one() or 0)
        projects = int(db.execute(select(func.count(Project.id)).where(Project.archived_at.is_(None))).scalar_one() or 0)
        stats = JobQueue.stats(db)
        _print(f"Accounts:  {users}")
        _print(f"Projects:  {projects}")
        _print(
            "Queue:     "
            + ", ".join(f"{key}={value}" for key, value in stats.items() if key != "total")
            + f" (total {stats['total']})"
        )
    _print(f"Time:      {to_iso_z(utcnow())}")
    return 0


def cmd_worker(_: argparse.Namespace) -> int:
    from .worker import run_forever

    run_forever()
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="NEXUS maintenance commands")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("seed", help="create dirs/fixtures, sync labs, create the first owner, ensure rules")

    admin = sub.add_parser("create-admin", help="create an account (or reset one with --reset)")
    admin.add_argument("--email", required=True)
    admin.add_argument("--password", default="", help="omit to be prompted securely")
    admin.add_argument("--name", default="")
    admin.add_argument("--role", default="admin", choices=["owner", "admin", "analyst", "viewer"])
    admin.add_argument("--reset", action="store_true", help="reset the password if the account exists")

    sub.add_parser("sync-labs", help="insert/refresh the built-in training labs")
    sub.add_parser("ensure-lab-files", help="regenerate missing lab fixture files")
    sub.add_parser("rules", help="ensure built-in detection rules in every project")
    sub.add_parser("kev-sync", help="download the CISA KEV catalogue now")
    sub.add_parser("status", help="show database, account and queue status")
    sub.add_parser("worker", help="run a standalone worker loop (NEXUS_INPROCESS_WORKER=false)")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "seed": cmd_seed,
        "create-admin": cmd_create_admin,
        "sync-labs": cmd_sync_labs,
        "ensure-lab-files": cmd_ensure_lab_files,
        "rules": cmd_rules,
        "kev-sync": cmd_kev_sync,
        "status": cmd_status,
        "worker": cmd_worker,
    }
    return int(handlers[args.command](args) or 0)


if __name__ == "__main__":
    sys.exit(main())
