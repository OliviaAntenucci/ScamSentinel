"""Runtime settings, loaded from environment variables (prefix SCAMSENTINEL_) and `.env`."""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Host header values the API accepts (SECURITY.md T5: DNS rebinding against localhost).
LOOPBACK_HOSTNAMES = ("127.0.0.1", "localhost")

# openai/gpt-oss-20b supports Groq's strict JSON-schema output (checked 2026-10-14,
# https://console.groq.com/docs/structured-outputs). Other models fall back to JSON mode.
DEFAULT_LLM_MODELS = {
    "groq": "openai/gpt-oss-20b",
    "anthropic": "claude-sonnet-5-5",
}


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SCAMSENTINEL_",
        env_file=".env",
        # utf-8-sig: accept UTF-8 with or without a byte-order mark. Without an explicit
        # encoding, Windows reads .env in the locale code page, and a BOM turns the first
        # variable name into "ï»¿GROQ_API_KEY", silently dropping the key.
        env_file_encoding="utf-8-sig",
        extra="ignore",
        populate_by_name=True,
    )

    env: Literal["development", "test", "production"] = "development"

    # API-only, localhost-only (NFR-9).
    host: str = "127.0.0.1"
    port: int = 8000
    # Post-MVP (P2): lets the URL guard reach private addresses for local test fixtures.
    # Refused in production.
    allow_private_targets: bool = False

    # LLM feature extractor (M2). Without the selected provider's key: rules-only.
    llm_provider: Literal["groq", "anthropic"] = "groq"
    llm_model: str | None = None  # None -> DEFAULT_LLM_MODELS[llm_provider]
    llm_timeout_seconds: float = 20.0
    # Screenshot transcription (M5). Groq's only vision model is a *preview* model (checked
    # 2026-10-14) and may be retired at short notice; change it here when that happens.
    vision_model: str = "qwen/qwen3.8-27b"
    vision_timeout_seconds: float = 30.0
    groq_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("GROQ_API_KEY", "SCAMSENTINEL_GROQ_API_KEY"),
    )
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("ANTHROPIC_API_KEY", "SCAMSENTINEL_ANTHROPIC_API_KEY"),
    )

    data_dir: Path = Path("data")
    config_dir: Path = Path("config")
    db_path: Path = Path("var/scamsentinel.db")

    # Input limits (FR-1, FR-2, FR-4).
    max_text_chars: int = 20_000
    max_email_bytes: int = 2 * 1024 * 1024
    max_image_bytes: int = 5 * 1024 * 1024
    max_image_pixels: int = 25_000_000
    # Whole request body. Covers a 2 MB email after JSON escaping, or a 5 MB image plus
    # multipart overhead.
    max_request_bytes: int = 6 * 1024 * 1024
    rate_limit_per_minute: int = 30

    retention_days: int = 7

    # Certificate Transparency watcher (post-MVP P1). crt.sh is a free community service,
    # so polling more often than hourly is refused.
    ct_poll_interval_hours: float = Field(default=6.0, ge=1.0)
    ct_min_score: int = Field(default=50, ge=0, le=100)
    ct_timeout_seconds: float = 120.0

    @property
    def allowed_hosts(self) -> list[str]:
        return list(LOOPBACK_HOSTNAMES)

    @property
    def llm_api_key(self) -> SecretStr | None:
        key = self.groq_api_key if self.llm_provider == "groq" else self.anthropic_api_key
        # An empty `GROQ_API_KEY=` line in .env counts as no key.
        return key if key is not None and key.get_secret_value().strip() else None

    @property
    def resolved_llm_model(self) -> str:
        return self.llm_model or DEFAULT_LLM_MODELS[self.llm_provider]

    @model_validator(mode="after")
    def _enforce_network_policy(self) -> Settings:
        if not is_loopback_host(self.host):
            raise ValueError(f"refusing to bind to {self.host!r}: the API is localhost-only")
        if self.env == "production" and self.allow_private_targets:
            raise ValueError("allow_private_targets cannot be enabled in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
