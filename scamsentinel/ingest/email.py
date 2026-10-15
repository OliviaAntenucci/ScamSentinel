"""Raw .eml parsing (FR-2). HTML is converted to text, never rendered.
Attachments are listed, never opened."""

from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from typing import cast

from pydantic import BaseModel

from scamsentinel.ingest.html import html_to_text

_DKIM_PASS = re.compile(r"dkim=pass\b[^;]*?\bheader\.d=([\w.-]+)", re.IGNORECASE)


class Attachment(BaseModel):
    filename: str | None
    content_type: str
    size: int


class ParsedEmail(BaseModel):
    from_display: str | None = None
    from_address: str | None = None
    from_domain: str | None = None
    reply_to_address: str | None = None
    reply_to_domain: str | None = None
    return_path_domain: str | None = None
    dkim_pass_domains: list[str] = []
    subject: str | None = None
    body_text: str = ""
    # href targets from the HTML body, which may differ from the visible link text.
    links: list[str] = []
    attachments: list[Attachment] = []

    def analysis_text(self) -> str:
        """What the message analyzer reads: sender name, subject, and body."""
        header = f"From: {self.from_display or self.from_address or ''}\n"
        return f"{header}Subject: {self.subject or ''}\n\n{self.body_text}"


def parse_eml(raw: bytes) -> ParsedEmail:
    # policy.default makes the parser return EmailMessage (with get_body/iter_attachments).
    msg = cast(EmailMessage, BytesParser(policy=policy.default).parsebytes(raw))

    from_display, from_address = _address(msg, "From")
    _, reply_to = _address(msg, "Reply-To")
    _, return_path = _address(msg, "Return-Path")
    auth = _header(msg, "Authentication-Results") or ""

    body_text, links = "", []
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is not None:
        if body.get_content_type() == "text/html":
            body_text, links = html_to_text(_content(body))
        else:
            body_text = _content(body)
    html = msg.get_body(preferencelist=("html",))
    if html is not None and html is not body:
        _, links = html_to_text(_content(html))

    attachments = [
        Attachment(
            filename=part.get_filename(),
            content_type=part.get_content_type(),
            size=len(part.get_payload(decode=True) or b""),
        )
        for part in msg.iter_attachments()
    ]

    return ParsedEmail(
        from_display=from_display or None,
        from_address=from_address or None,
        from_domain=_domain(from_address),
        reply_to_address=reply_to or None,
        reply_to_domain=_domain(reply_to),
        return_path_domain=_domain(return_path),
        dkim_pass_domains=[d.lower() for d in _DKIM_PASS.findall(auth)],
        subject=_header(msg, "Subject"),
        body_text=body_text,
        links=links,
        attachments=attachments,
    )


def _header(msg: EmailMessage, name: str) -> str | None:
    value = msg.get(name)
    return str(value).strip() if value is not None else None


def _address(msg: EmailMessage, name: str) -> tuple[str, str]:
    return parseaddr(_header(msg, name) or "")


def _domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rpartition("@")[2].strip().lower() or None


def _content(part: EmailMessage) -> str:
    try:
        return str(part.get_content())
    except (LookupError, UnicodeError):
        # Unknown or lying charset: decode leniently instead of failing the analysis.
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")
