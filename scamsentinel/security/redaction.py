"""PII redaction for logs (NFR-4, M4): SSN-like, card-like, and phone numbers."""

from __future__ import annotations


def redact(text: str) -> str:
    raise NotImplementedError("M4: log redaction")
