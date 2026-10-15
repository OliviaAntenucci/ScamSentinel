"""Persistence for CT candidates (table `ct_candidates`, architecture.md §12, M7)."""

from __future__ import annotations

from pydantic import BaseModel


class CtCandidate(BaseModel):
    """An unverified lead: a newly certified name that resembles a protected brand."""

    domain: str
    score: int
    brand: str | None
    techniques: list[str]
    cert_id: int
    issuer: str
    not_before: str
    first_seen: str
    last_seen: str


def list_candidates(since: str | None, min_score: int) -> list[CtCandidate]:
    raise NotImplementedError("M7: CT candidate store")
