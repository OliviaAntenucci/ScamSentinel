"""Analysis orchestrator: ingest -> domain/message/sandbox -> verify -> aggregate (M3)."""

from __future__ import annotations

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.models import AnalysisResult


def analyze(request: AnalyzeRequest) -> AnalysisResult:
    raise NotImplementedError("M3: analysis pipeline")


def get_analysis(analysis_id: str) -> AnalysisResult:
    raise NotImplementedError("M3: analysis storage")
