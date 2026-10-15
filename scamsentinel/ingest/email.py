"""Raw .eml parsing (FR-2, M2). HTML is converted to text, never rendered.
Attachments are listed, never opened."""

from __future__ import annotations

from pydantic import BaseModel


class Attachment(BaseModel):
    filename: str | None
    content_type: str
    size: int


class ParsedEmail(BaseModel):
    from_header: str | None
    reply_to: str | None
    return_path: str | None
    authentication_results: str | None
    subject: str | None
    body_text: str
    attachments: list[Attachment] = []


def parse_eml(raw: bytes) -> ParsedEmail:
    raise NotImplementedError("M2: email parsing")
