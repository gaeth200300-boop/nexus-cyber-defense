"""NEXUS API application entry point.

Run (development):
    uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

The in-process worker starts automatically when NEXUS_INPROCESS_WORKER=true.
Set it to false and run `python -m app.worker` when you want a separate process.
"""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import OperationalError

from .academy.content import sync_academy
from .api.routes import api_router
from .config import BASE_DIR, settings
from .core.utils import utcnow
from .db import session_scope
from .labs.content import sync_labs
from .labs.files import ensure_lab_files
from .worker import start_background_worker, stop_background_worker, worker_status

log = logging.getLogger("nexus.main")

FRONTEND_DIST = (BASE_DIR.parent / "frontend" / "dist").resolve()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_dirs()
    try:
        written = ensure_lab_files()
        log.info("lab fixtures ready (%s files)", len(written))
    except Exception as exc:  # a fixture problem must not stop the API
        log.error("lab fixture generation failed: %s", exc)

    try:
        with session_scope() as db:
            sync_labs(db)
            sync_academy(db)
    except OperationalError as exc:
        raise RuntimeError(
            "The database schema is missing or unreachable. "
            "Run 'scripts\\nexus.cmd migrate' (or 'python -m alembic upgrade head' from backend) first."
        ) from exc

    if settings.inprocess_worker:
        start_background_worker()
        log.info("in-process worker started")
    else:
        log.info("in-process worker disabled (NEXUS_INPROCESS_WORKER=false)")

    log.info("NEXUS %s ready (env=%s)", settings.version, settings.env)
    try:
        yield
    finally:
        stop_background_worker()
        log.info("NEXUS stopped")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description=(
        "Enterprise security assessment platform: authorized scanning, real engines, "
        "SOC, vulnerability intelligence, labs, reports and an optional AI copilot.\n\n"
        "All findings and metrics are computed from stored results — unavailable "
        "integrations are reported as unavailable, never simulated."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
    contact={"name": "NEXUS Cyber Defense"},
    license_info={"name": "Proprietary"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origin_list or ["http://127.0.0.1:5173"],
    allow_credentials="*" not in settings.origin_list,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Request-ID"],
)


@app.middleware("http")
async def _request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
    started = utcnow()
    try:
        response = await call_next(request)
    except Exception:
        log.exception("unhandled error on %s %s (request=%s)", request.method, request.url.path, request_id)
        raise
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    duration_ms = int((utcnow() - started).total_seconds() * 1000)
    if duration_ms > 2000:
        log.warning("slow request %s %s took %sms (request=%s)", request.method, request.url.path, duration_ms, request_id)
    return response


@app.exception_handler(RequestValidationError)
async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = []
    for error in exc.errors():
        errors.append(
            {
                "field": ".".join(str(part) for part in error.get("loc", []) if part not in ("body", "query", "path")),
                "message": error.get("msg", "Invalid value"),
                "type": error.get("type", "value_error"),
            }
        )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": {
                "code": "validation_error",
                "message": "The request contains invalid or missing values.",
                "errors": errors,
            }
        },
    )


@app.exception_handler(HTTPException)
async def _http_error(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail
    if not isinstance(detail, dict):
        detail = {"code": f"http_{exc.status_code}", "message": str(detail)}
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": detail},
        headers=exc.headers or None,
    )


@app.exception_handler(Exception)
async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": {
                "code": "internal_error",
                "message": "An unexpected server error occurred. Check the API log for the request id.",
            }
        },
    )


app.include_router(api_router, prefix="/api/v1")


@app.get("/api/v1", include_in_schema=False)
def api_root() -> dict[str, object]:
    return {
        "app": settings.app_name,
        "version": settings.version,
        "docs": "/docs",
        "health": "/api/v1/system/health",
        "worker": worker_status(),
    }


@app.get("/", include_in_schema=False)
def root(request: Request):
    index = FRONTEND_DIST / "index.html"
    if index.exists():
        return FileResponse(index)
    return {
        "app": settings.app_name,
        "version": settings.version,
        "message": "NEXUS API is running. The web UI is not built yet.",
        "docs": "/docs",
        "health": "/api/v1/system/health",
        "frontend_setup": "cd frontend && npm.cmd install && npm.cmd run dev",
    }


# ---------------------------------------------------------------------------
# Optional production static frontend
# ---------------------------------------------------------------------------
if (FRONTEND_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="frontend-assets")


@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str):
    if full_path.startswith("api/") or full_path in ("docs", "redoc", "openapi.json"):
        raise HTTPException(status_code=404, detail="Not found")
    candidate = (FRONTEND_DIST / full_path).resolve()
    try:
        candidate.relative_to(FRONTEND_DIST)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not found")
    if candidate.is_file():
        return FileResponse(candidate)
    index = FRONTEND_DIST / "index.html"
    if index.exists():
        return FileResponse(index)
    raise HTTPException(
        status_code=404,
        detail="The web UI is not built. Run: cd frontend && npm.cmd install && npm.cmd run dev",
    )
