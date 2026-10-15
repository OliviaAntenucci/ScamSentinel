"""Playwright URL detonator (architecture.md §8, M5). Runs only inside the sandbox
container. Observe-only: no form submission, downloads, or permission grants."""

from __future__ import annotations

from pydantic import BaseModel

NAVIGATION_TIMEOUT_S = 20
MAX_REDIRECTS = 10
MAX_TRANSFER_BYTES = 10 * 1024 * 1024


class FormField(BaseModel):
    name: str | None
    type: str | None
    autocomplete: str | None
    label: str | None


class Form(BaseModel):
    action: str | None
    method: str
    fields: list[FormField]


class SandboxReport(BaseModel):
    requested_url: str
    final_url: str | None
    status: int | None
    redirect_chain: list[str] = []
    title: str | None = None
    visible_text: str = ""
    hidden_text: str = ""
    forms: list[Form] = []
    external_script_domains: list[str] = []
    favicon_mmh3: int | None = None
    tls_issuer: str | None = None
    tls_not_before: str | None = None
    screenshot_path: str | None = None
    blocked_requests: list[str] = []
    error: str | None = None


def detonate(url: str) -> SandboxReport:
    raise NotImplementedError("M5: URL detonator")
