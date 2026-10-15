"""HTTP routes (prd.txt §7)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request

from scamsentinel import __version__, pipeline
from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.ct.store import CtCandidate, list_candidates
from scamsentinel.domain.engine import DomainResult, score_domain
from scamsentinel.models import AnalysisResult

router = APIRouter()


@router.get("/healthz")
def healthz(request: Request) -> dict[str, str]:
    settings = request.app.state.settings
    return {
        "status": "ok",
        "version": __version__,
        "llm_provider": settings.llm_provider,
        "llm_model": settings.resolved_llm_model,
        "llm": "configured" if settings.llm_api_key else "missing_api_key (rules-only)",
    }


@router.post("/v1/analyze")
def analyze(body: AnalyzeRequest) -> AnalysisResult:
    return pipeline.analyze(body)


@router.get("/v1/analysis/{analysis_id}")
def get_analysis(analysis_id: str) -> AnalysisResult:
    return pipeline.get_analysis(analysis_id)


@router.get("/v1/domain/score")
def domain_score(d: Annotated[str, Query(min_length=1, max_length=253)]) -> DomainResult:
    return score_domain(d)


@router.get("/v1/ct/candidates")
def ct_candidates(
    since: str | None = None,
    min_score: Annotated[int, Query(ge=0, le=100)] = 50,
) -> list[CtCandidate]:
    return list_candidates(since=since, min_score=min_score)
