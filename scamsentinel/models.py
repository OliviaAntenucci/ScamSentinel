"""Core result types shared by every module (architecture.md §10)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Verdict(StrEnum):
    LIKELY_LEGITIMATE = "likely_legitimate"
    SUSPICIOUS = "suspicious"
    LIKELY_SCAM = "likely_scam"


class Module(StrEnum):
    DOMAIN = "domain"
    MESSAGE = "message"
    VERIFY = "verify"
    OCR = "ocr"


class Reason(BaseModel):
    """One piece of evidence. Every point in a risk score traces to a Reason (NFR-1)."""

    module: Module
    signal: str
    detail: str
    evidence: str | None = None
    # Negative points are mitigating evidence (e.g. "link goes to irs.gov").
    points: int


class ModuleResult(BaseModel):
    module: Module
    score: int = Field(ge=0, le=100)
    reasons: list[Reason] = []


class AnalysisResult(BaseModel):
    analysis_id: str
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    module_scores: dict[Module, int] = {}
    modules_run: list[Module] = []
    degraded: list[str] = []
    reasons: list[Reason] = []
    overrides_applied: list[str] = []
