"""AI provider adapter — OpenAI-compatible APIs, Ollama, Azure, or none.

The platform must work *without* an AI provider: every copilot task has a
deterministic implementation, and the AI path only ever adds language on top of
real data (never new facts). When no provider is configured the API says so and
returns the deterministic result, labelled as such.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings
from ..core.egress import fetch_public

log = logging.getLogger("nexus.copilot.provider")

DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "ollama": "http://127.0.0.1:11434/v1",
    "azure": "",
    "custom": "",
}


class AIUnavailable(RuntimeError):
    """Raised when the copilot is asked to use AI with no working provider."""


@dataclass
class ChatMessage:
    role: str  # system | user | assistant
    content: str


@dataclass
class ChatResult:
    text: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


def provider_configured() -> bool:
    if settings.ai_provider == "none" or not settings.ai_model:
        return False
    if settings.ai_provider in ("openai", "openrouter", "azure", "custom") and not settings.ai_api_key:
        return False
    return True


def base_url() -> str:
    configured = (settings.ai_base_url or "").strip()
    if configured:
        return configured.rstrip("/")
    return DEFAULT_BASE_URLS.get(settings.ai_provider, "")


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class AIProvider:
    """Minimal chat-completions client covering every supported provider shape."""

    def __init__(self) -> None:
        if not provider_configured():
            raise AIUnavailable(
                "AI Copilot is not configured. Set NEXUS_AI_PROVIDER, NEXUS_AI_MODEL and NEXUS_AI_API_KEY "
                "in backend\\.env (OpenRouter: NEXUS_AI_PROVIDER=openrouter, base https://openrouter.ai/api/v1)."
            )
        self.provider = settings.ai_provider
        self.model = settings.ai_model
        self.base = base_url()
        if not self.base:
            raise AIUnavailable(f"no base URL configured for provider '{self.provider}' (set NEXUS_AI_BASE_URL)")

    # ------------------------------------------------------------------ helpers
    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.provider == "azure":
            headers["api-key"] = settings.ai_api_key
        elif settings.ai_api_key:
            headers["Authorization"] = f"Bearer {settings.ai_api_key}"
        if self.provider == "openrouter":
            headers["HTTP-Referer"] = "https://localhost/nexus-cyber-defense"
            headers["X-Title"] = settings.app_name
        return headers

    def _endpoint(self) -> str:
        if self.provider == "azure":
            # azure base: https://<resource>.openai.azure.com/openai/deployments/<deployment>
            return f"{self.base}/chat/completions?api-version=2024-06-01"
        return f"{self.base}/chat/completions"

    async def chat(self, messages: list[ChatMessage], *, max_tokens: int | None = None, temperature: float = 0.2) -> ChatResult:
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": max_tokens or settings.ai_max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        endpoint = self._endpoint()
        headers = self._headers()

        if self.provider == "ollama":
            # Local inference server explicitly configured by the operator: the URL is
            # server-side config, never user input, so loopback is allowed here only.
            async with httpx.AsyncClient(timeout=httpx.Timeout(settings.ai_timeout_seconds, connect=5.0), trust_env=False) as client:
                response = await client.post(endpoint, json=payload, headers=headers)
            if response.status_code >= 400:
                raise AIUnavailable(f"Ollama returned HTTP {response.status_code}: {response.text[:300]}")
            data = response.json()
        else:
            from urllib.parse import urlsplit

            host = urlsplit(self.base).hostname or ""
            data, raw = await fetch_public_json_safe(endpoint, payload=payload, headers=headers, host=host)
            if data is None:
                raise AIUnavailable(raw.error or "provider request failed")

        try:
            choice = (data.get("choices") or [])[0]
            text = str(choice.get("message", {}).get("content", "")).strip()
        except (IndexError, AttributeError, TypeError) as exc:
            raise AIUnavailable(f"unexpected provider response shape: {exc}") from exc
        usage = data.get("usage") or {}
        return ChatResult(
            text=text,
            model=str(data.get("model") or self.model),
            provider=self.provider,
            prompt_tokens=int(usage.get("prompt_tokens") or _estimate_tokens(str(payload))),
            completion_tokens=int(usage.get("completion_tokens") or _estimate_tokens(text)),
            raw={"finish_reason": choice.get("finish_reason", "")},
        )


async def fetch_public_json_safe(url: str, *, payload: dict[str, Any], headers: dict[str, str], host: str):
    """POST JSON through the guarded egress layer (pinned, no proxy, no private IPs)."""
    import json

    from ..core.egress import PublicResponse

    response: PublicResponse = await fetch_public(
        url,
        method="POST",
        headers=headers,
        content=json.dumps(payload).encode("utf-8"),
        timeout=float(settings.ai_timeout_seconds),
        max_bytes=4_000_000,
        allowed_hosts=[host] if host else None,
    )
    if not response.ok:
        return None, response
    try:
        return response.json(), response
    except Exception as exc:
        return None, PublicResponse(False, error=f"invalid_json: {exc}", final_url=response.final_url)
