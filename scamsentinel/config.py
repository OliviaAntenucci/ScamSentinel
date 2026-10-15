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

# Groq's model lineup changes; check https://console.groq.com/docs/models before M2.
DEFAULT_LLM_MODELS = {
    "groq": "llama-3.3-70b-versatile",
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
        extra="ignore",
        populate_by_name=True,
    )

    env: Literal["development", "test", "production"] = "development"

    # API-only, localhost-only (NFR-9).
    host: str = "127.0.0.1"
    port: int = 8000
    # Only for the API container, where Compose publishes the port on 127.0.0.1.
    allow_non_loopback_bind: bool = False
    # Lets the URL guard reach private addresses for local test fixtures. Refused in production.
    allow_private_targets: bool = False

    # LLM feature extractor (M2). Without the selected provider's key: rules-only.
    llm_provider: Literal["groq", "anthropic"] = "groq"
    llm_model: str | None = None  # None -> DEFAULT_LLM_MODELS[llm_provider]
    groq_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("GROQ_API_KEY", "SCAMSENTINEL_GROQ_API_KEY"),
    )
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("ANTHROPIC_API_KEY", "SCAMSENTINEL_ANTHROPIC_API_KEY"),
    )

    sandbox_url: str = "http://sandbox:8100"
    ocr_url: str = "http://ocr:8200"

    data_dir: Path = Path("data")
    config_dir: Path = Path("config")
    db_path: Path = Path("var/scamsentinel.db")

    # Input limits (FR-1, FR-2, FR-4).
    max_text_chars: int = 20_000
    max_email_bytes: int = 2 * 1024 * 1024
    max_image_bytes: int = 5 * 1024 * 1024
    max_image_pixels: int = 25_000_000

    retention_days: int = 7

    @property
    def allowed_hosts(self) -> list[str]:
        return list(LOOPBACK_HOSTNAMES)

    @property
    def llm_api_key(self) -> SecretStr | None:
        return self.groq_api_key if self.llm_provider == "groq" else self.anthropic_api_key

    @property
    def resolved_llm_model(self) -> str:
        return self.llm_model or DEFAULT_LLM_MODELS[self.llm_provider]

    @model_validator(mode="after")
    def _enforce_network_policy(self) -> Settings:
        if not is_loopback_host(self.host) and not self.allow_non_loopback_bind:
            raise ValueError(
                f"refusing to bind to {self.host!r}: the API is localhost-only "
                "(SCAMSENTINEL_ALLOW_NON_LOOPBACK_BIND is only for the API container)"
            )
        if self.env == "production" and self.allow_private_targets:
            raise ValueError("allow_private_targets cannot be enabled in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
