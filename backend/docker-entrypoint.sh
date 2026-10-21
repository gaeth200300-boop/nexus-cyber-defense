#!/usr/bin/env sh
# NEXUS backend entrypoint.
#
#   api      run migrations + seed, then start the API (default)
#   worker   run the standalone job worker (no migrations)
#   migrate  run migrations only and exit
#   kev-sync run the CISA KEV feed sync once and exit
set -eu

MODE="${1:-api}"

wait_for_db() {
  python - <<'PY'
import os, socket, time
host = os.environ.get("POSTGRES_HOST", "db")
port = int(os.environ.get("POSTGRES_PORT", "5432"))
url = os.environ.get("NEXUS_DATABASE_URL", "")
if "@" in url:
    host = url.rsplit("@", 1)[1].split(":", 1)[0] or host
    tail = url.rsplit("@", 1)[1].split(":", 1)[1] if ":" in url.rsplit("@", 1)[1] else ""
    if tail.isdigit():
        port = int(tail)
deadline = time.time() + 60
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=2):
            print(f"database reachable at {host}:{port}")
            raise SystemExit(0)
    except OSError:
        time.sleep(1)
print(f"database not reachable at {host}:{port}", file=__import__("sys").stderr)
raise SystemExit(1)
PY
}

case "$MODE" in
  api)
    wait_for_db
    python -m alembic upgrade head
    python -m app.cli seed
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000
    ;;
  worker)
    wait_for_db
    exec python -m app.worker
    ;;
  migrate)
    wait_for_db
    exec python -m alembic upgrade head
    ;;
  kev-sync)
    wait_for_db
    exec python -m app.cli kev-sync
    ;;
  *)
    echo "Unknown NEXUS mode: $MODE (expected api|worker|migrate|kev-sync)" >&2
    exit 2
    ;;
esac
