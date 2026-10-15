"""Core result types shared by every module (architecture.md §9)."""

from __future__ import annotations

from datetime import date, datetime
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


# What a claim was compared with: a fact from facts.yaml, the official domains in
# brands.yaml, the email's own headers, an LLM's knowledge (unverified), or nothing
# because no published fact covers the claim.
FactBasis = Literal["published_fact", "brand_list", "email_headers", "model_knowledge", "no_fact"]


class FactCheck(BaseModel):
    """One claim in the message checked against what's known (E3)."""

    check: str  # official_domain, contact_channel, payment_method_policy, ...
    claim: str
    outcome: Literal["matches", "conflicts", "cannot_verify"]
    detail: str
    basis: FactBasis
    fact: str | None = None  # the statement the claim was compared with
    fact_id: str | None = None
    source: str | None = None
    last_reviewed: date | None = None


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
    # Every claim checked against trusted facts (E3): conflicts, then can't verify, then
    # matches.
    fact_checks: list[FactCheck] = []
