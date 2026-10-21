"""API v1 router aggregation."""

from __future__ import annotations

from fastapi import APIRouter

from . import academy, apikeys, asm, assets, audit, auth, command, copilot, findings, intel, labs, projects, reports, scans, soc, studio, system, users

api_router = APIRouter()

# Order is intentional: static and more specific routers first, project routers
# later. Path matching itself is unambiguous because every prefix is explicit.
api_router.include_router(auth.router)
api_router.include_router(academy.router)
api_router.include_router(users.router)
api_router.include_router(apikeys.router)
api_router.include_router(projects.router)
api_router.include_router(assets.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(reports.router)
api_router.include_router(copilot.router)
api_router.include_router(intel.router)
api_router.include_router(intel.project_router)
api_router.include_router(asm.router)
api_router.include_router(soc.router)
api_router.include_router(labs.router)
api_router.include_router(audit.router)
api_router.include_router(audit.project_router)
api_router.include_router(system.router)
api_router.include_router(command.router)
api_router.include_router(studio.router)

__all__ = ["api_router"]
