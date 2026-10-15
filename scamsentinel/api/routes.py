"""HTTP routes (prd.txt §7)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request

from scamsentinel import __version__, pipeline
from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.domain.engine import DomainResult, get_engine
from scamsentinel.domain.normalize import InvalidHost
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
def domain_score(
    request: Request, d: Annotated[str, Query(min_length=1, max_length=2_048)]
) -> DomainResult:
    settings = request.app.state.settings
    try:
        return get_engine(settings.data_dir, settings.config_dir).score(d)
    except InvalidHost as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
