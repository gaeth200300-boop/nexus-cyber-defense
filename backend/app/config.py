"""Application settings — loaded from environment / backend/.env (NEXUS_* prefix)."""

from __future__ import annotations

import logging
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[1]  # <repo>/backend
PLACEHOLDER_SECRET = "CHANGE_ME_GENERATE_A_REAL_SECRET"

log = logging.getLogger("nexus.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NEXUS_",
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- basics ---
    env: str = Field(default="development")
    app_name: str = Field(default="NEXUS Cyber Defense")
    version: str = Field(default="0.1.0")
    secret_key: str = Field(default=PLACEHOLDER_SECRET)
    database_url: str = Field(default="sqlite:///./storage/nexus.db")
    data_dir: str = Field(default="./storage")
    access_token_minutes: int = Field(default=30, ge=5, le=1440)
    refresh_token_days: int = Field(default=14, ge=1, le=90)
    allowed_origins: str = Field(default="http://127.0.0.1:5173,http://localhost:5173")

    # --- worker ---
    inprocess_worker: bool = Field(default=True)
    worker_concurrency: int = Field(default=2, ge=1, le=16)
    job_poll_seconds: float = Field(default=1.5, ge=0.2, le=30)
    job_lease_seconds: int = Field(default=120, ge=30, le=3600)
    max_concurrent_scans: int = Field(default=2, ge=1, le=32)

    # --- security policy ---
    allow_private_targets: bool = Field(default=False)
    active_scanning_enabled: bool = Field(default=True)
    rate_limit_per_minute: int = Field(default=240, ge=10, le=100000)
    max_upload_mb: int = Field(default=25, ge=1, le=512)

    # --- engines / integrations ---
    zap_url: str = Field(default="")
    zap_api_key: str = Field(default="")
    nmap_path: str = Field(default="")

    # --- AI copilot (optional) ---
    ai_provider: str = Field(default="none")
    ai_base_url: str = Field(default="")
    ai_api_key: str = Field(default="")
    ai_model: str = Field(default="")
    ai_max_tokens: int = Field(default=1200, ge=128, le=32000)
    ai_timeout_seconds: int = Field(default=60, ge=5, le=600)
    ai_monthly_token_budget: int = Field(default=500000, ge=0)

    # --- intel ---
    nvd_api_key: str = Field(default="")
    intel_cache_hours: int = Field(default=24, ge=1, le=720)
    kev_feed_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    # --- bootstrap admin ---
    bootstrap_admin_email: str = Field(default="admin@nexus.local")
    bootstrap_admin_password: str = Field(default="ChangeMe!Nexus2026")
    bootstrap_admin_name: str = Field(default="Nexus Admin")

    # --- derived ---
    @property
    def is_production(self) -> bool:
        return self.env.lower() in ("production", "prod")

    @property
    def origin_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def data_path(self) -> Path:
        p = Path(self.data_dir)
        if not p.is_absolute():
            p = (BASE_DIR / p).resolve()
        return p

    @property
    def storage_dir(self) -> Path:
        return self.data_path

    @property
    def evidence_dir(self) -> Path:
        return self.data_path / "evidence"

    @property
    def uploads_dir(self) -> Path:
        return self.data_path / "uploads"

    @property
    def reports_dir(self) -> Path:
        return self.data_path / "reports"

    @property
    def logs_dir(self) -> Path:
        return self.data_path / "logs"

    def ensure_dirs(self) -> None:
        for p in (self.data_path, self.evidence_dir, self.uploads_dir, self.reports_dir, self.logs_dir):
            p.mkdir(parents=True, exist_ok=True)

    @property
    def sqlite_path(self) -> Path | None:
        if not self.database_url.startswith("sqlite"):
            return None
        raw = self.database_url.split("///", 1)[-1]
        p = Path(raw)
        if not p.is_absolute():
            p = (BASE_DIR / p).resolve()
        return p

    @field_validator("ai_provider")
    @classmethod
    def _check_provider(cls, v: str) -> str:
        allowed = {"none", "openai", "openrouter", "azure", "ollama", "custom"}
        v = (v or "none").strip().lower()
        if v not in allowed:
            raise ValueError(f"NEXUS_AI_PROVIDER must be one of {sorted(allowed)}")
        return v

    # ------------------------------------------------------------------
    # Secret handling — never silently insecure in production.
    # ------------------------------------------------------------------
    def resolve_secret_key(self) -> str:
        if self.secret_key and self.secret_key != PLACEHOLDER_SECRET and len(self.secret_key) >= 24:
            return self.secret_key
        if self.is_production:
            raise RuntimeError(
                "NEXUS_SECRET_KEY is not set (or still the placeholder) while NEXUS_ENV=production. "
                "Generate one: python -c \"import secrets;print(secrets.token_urlsafe(48))\""
            )
        # Development: keep sessions stable across reloads using a local dev secret file.
        self.ensure_dirs()
        dev_secret_file = self.data_path / ".dev_secret_key"
        if dev_secret_file.exists():
            return dev_secret_file.read_text(encoding="utf-8").strip()
        generated = secrets.token_urlsafe(48)
        dev_secret_file.write_text(generated, encoding="utf-8")
        log.warning(
            "NEXUS_SECRET_KEY was not configured — generated a local development secret at %s",
            dev_secret_file,
        )
        return generated


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
