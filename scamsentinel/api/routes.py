"""HTTP routes (prd.txt §8)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, Request

from scamsentinel import __version__
from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.domain.engine import DomainResult, get_engine
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.models import AnalysisResult
from scamsentinel.pipeline import AnalysisService

router = APIRouter()

ANALYSIS_ID_PATTERN = r"^an_[0-9a-f]{32}$"


def _service(request: Request) -> AnalysisService:
    return request.app.state.service


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
def analyze(request: Request, body: AnalyzeRequest) -> AnalysisResult:
    try:
        return _service(request).analyze(body)
    except InvalidHost as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/v1/analysis/{analysis_id}")
def get_analysis(
    request: Request, analysis_id: Annotated[str, Path(pattern=ANALYSIS_ID_PATTERN)]
) -> AnalysisResult:
    result = _service(request).get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="analysis not found or expired")
    return result


@router.get("/v1/domain/score")
def domain_score(
    request: Request, d: Annotated[str, Query(min_length=1, max_length=2_048)]
) -> DomainResult:
    settings = request.app.state.settings
    try:
        return get_engine(settings.data_dir, settings.config_dir).score(d)
    except InvalidHost as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
