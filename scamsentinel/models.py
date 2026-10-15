"""Core result types shared by every module (architecture.md §9)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from scamsentinel.domain.explain import DomainExplanation

InputType = Literal["text", "url", "email", "image"]


class Verdict(StrEnum):
    LIKELY_LEGITIMATE = "likely_legitimate"
    SUSPICIOUS = "suspicious"
    LIKELY_SCAM = "likely_scam"


class Module(StrEnum):
    DOMAIN = "domain"
    MESSAGE = "message"
    VERIFY = "verify"
    OCR = "ocr"
    # Reasons the aggregator adds itself: the weighting math, floors and caps.
    AGGREGATE = "aggregate"


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


class NextStep(BaseModel):
    """One piece of advice (E1). Built from fixed templates and data files only, never from
    the analyzed content, so it can't repeat a scammer's link or phone number."""

    id: str
    text: str
    # Where an official contact or reporting channel in the text comes from.
    source: str | None = None


class AnalysisResult(BaseModel):
    analysis_id: str
    created_at: datetime
    input_type: InputType
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    module_scores: dict[Module, int] = {}
    modules_run: list[Module] = []
    llm_used: bool = False
    degraded: list[str] = []
    reasons: list[Reason] = []
    overrides_applied: list[str] = []
    # Indicators the rules found but the LLM missed (possible injection or extraction gaps).
    disagreements: list[str] = []
    # "What should I do next?", most important first.
    next_steps: list[NextStep] = []
    # How each lookalike link imitates a brand (E2), highest-scoring domain first.
    domain_explanations: list[DomainExplanation] = []
