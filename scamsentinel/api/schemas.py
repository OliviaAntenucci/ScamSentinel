"""Request schemas for the public API (prd.txt §7)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AnalyzeRequest(BaseModel):
    """Exactly one of text / url / email_raw. Images use multipart upload (M5)."""

    model_config = ConfigDict(extra="forbid")

    text: str | None = Field(default=None, max_length=20_000)  # FR-1
    url: str | None = Field(default=None, max_length=2_048)  # FR-3
    email_raw: str | None = Field(default=None, max_length=2 * 1024 * 1024)  # FR-2

    @model_validator(mode="after")
    def _exactly_one_input(self) -> AnalyzeRequest:
        provided = [v for v in (self.text, self.url, self.email_raw) if v is not None]
        if len(provided) != 1:
            raise ValueError("provide exactly one of: text, url, email_raw")
        return self
