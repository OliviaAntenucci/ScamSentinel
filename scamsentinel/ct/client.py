"""crt.sh client (post-MVP P1). Polite: sequential, spaced, backoff, descriptive UA."""

from __future__ import annotations

from pydantic import BaseModel

CRTSH_URL = "https://crt.sh/"
USER_AGENT = "ScamSentinel-CT-Watcher/0.1 (educational lookalike-domain research)"


class CtEntry(BaseModel):
    cert_id: int
    name: str
    issuer: str
    not_before: str


def search(pattern: str) -> list[CtEntry]:
    """Query crt.sh for certificates whose names match `pattern` (e.g. "%turbotax%")."""
    raise NotImplementedError("P1: crt.sh client")
