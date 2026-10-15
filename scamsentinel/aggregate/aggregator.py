"""Risk aggregator (architecture.md §10): renormalized weights, floors, mitigating cap."""

from __future__ import annotations

from scamsentinel.data import Bands, ScoringConfig
from scamsentinel.models import AnalysisResult, ModuleResult, Verdict


def verdict_for_score(score: int, bands: Bands) -> Verdict:
    if score >= bands.likely_scam:
        return Verdict.LIKELY_SCAM
    if score >= bands.suspicious:
        return Verdict.SUSPICIOUS
    return Verdict.LIKELY_LEGITIMATE


def aggregate(
    analysis_id: str, results: list[ModuleResult], config: ScoringConfig
) -> AnalysisResult:
    raise NotImplementedError("M3: risk aggregator")
