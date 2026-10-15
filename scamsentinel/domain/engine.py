"""Lookalike-domain engine (architecture.md §4, M1).

Pipeline: canonicalize -> PSL split -> allowlist -> homoglyph skeleton -> tokenize ->
detectors (exact_brand_unofficial, homoglyph, typosquat, brand_plus_keywords,
brand_in_subdomain, tld_swap, idn_mixed_script) -> max-over-techniques score.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from scamsentinel.models import Reason


class DomainResult(BaseModel):
    input: str
    registrable: str
    official: bool
    score: int = Field(ge=0, le=100)
    brand: str | None = None
    techniques: list[str] = []
    # Skeleton after IDN decoding + confusable/ASCII normalization, for explainability.
    normalized: str
    reasons: list[Reason] = []


def score_domain(host_or_url: str) -> DomainResult:
    raise NotImplementedError("M1: lookalike-domain engine")
