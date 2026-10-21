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
    # P2b: evidence from a fetched (or, in evaluation, snapshot) page.
    PAGE = "page"
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


class Scenario(BaseModel):
    """The named story a scam message tells (E4), e.g. "Refund lure". It explains the
    score and adds no points. Chosen by fixed rules (data/scenarios.yaml), never by the LLM."""

    id: str
    name: str
    category: str | None = None
    description: str
    source: str
    # The conditions that matched, e.g. ['threat: refund loss', 'phrase: "tax refund"'].
    matched_on: list[str] = []


class Resource(BaseModel):
    """A curated "learn more" link: an article about the type of scam, or the impersonated
    organization's own help page. Always from data/resources.yaml, never from the message."""

    kind: Literal["scam_type", "official_help"]
    title: str
    publisher: str
    url: str
    last_reviewed: date


class PageFinding(BaseModel):
    """Something the fetched page shows (P2), e.g. a password field or a form that posts
    to another domain. Scored through the page module (P2b, config page_points)."""

    signal: str
    detail: str


class PageReport(BaseModel):
    """What one linked page showed (P2). Only present when page fetching isn't "off"
    (SCAMSENTINEL_PAGE_FETCH). In "dry_run" mode the URL is checked but never fetched."""

    requested_url: str
    final_url: str | None = None
    redirects: list[str] = []
    status: Literal["analyzed", "dry_run", "blocked", "failed"]
    # Stable code when the page wasn't analyzed (dry_run, blocked:non_public_address,
    # blocked:egress, disabled:safety, timeout, http_404, ...). Never evidence that the
    # link is safe.
    error: str | None = None
    title: str | None = None
    # The curated brand the page presents itself as (title or logo), when that isn't its
    # own domain.
    brand: str | None = None
    # What its input fields ask for: password, card details, verification code,
    # Social Security number.
    asks_for: list[str] = []
    findings: list[PageFinding] = []
    truncated: bool = False


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


class SubmittedInput(BaseModel):
    """What was analyzed, kept with the result so a saved analysis shows it. SSN- and
    card-like numbers are masked like everywhere else."""

    # The message, URL or raw email as entered; for a screenshot, the text read from it.
    content: str
    # Set for a screenshot: its cleaned image (metadata stripped) is stored separately and
    # served by /v1/analysis/{id}/image.
    image_mime: str | None = None


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
    # The named scenario the message follows (E4). Only on suspicious or likely-scam
    # results that contain a message.
    scenario: Scenario | None = None
    # Where to read more: about this type of scam, and the impersonated organization's
    # own help pages.
    resources: list[Resource] = []
    # What the linked pages showed (P2). Empty unless page fetching is turned on.
    pages: list[PageReport] = []
    # What was submitted. None on analyses made before inputs were kept.
    submitted: SubmittedInput | None = None
