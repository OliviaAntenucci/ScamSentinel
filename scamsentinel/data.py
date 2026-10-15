"""Loaders for the versioned YAML data/config files, validated at load time."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from scamsentinel.message.features import CtaType, PaymentType, SensitiveType, ThreatType
from scamsentinel.models import Module


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


# --- data/brands.yaml ---------------------------------------------------------


class Brand(BaseModel):
    name: str
    # Scam category this brand belongs to (a key of `categories` in brands.yaml).
    category: str
    tokens: list[str]
    # Tokens that only match as a whole word, e.g. "irs" (not inside "first") or
    # "intuit" (not inside "intuition"). Their neighbors must be other known words.
    boundary_tokens: list[str] = []
    # Tokens that are ordinary words a single edit away from other ordinary words
    # ("chase" vs. "phase", "chose"). They match literally or through lookalike
    # characters, never by edit distance.
    no_typo_tokens: list[str] = []
    # Registrable domains (Public Suffix List), matched exactly, never by substring.
    official_domains: list[str]
    sources: list[str] = []

    @model_validator(mode="after")
    def _token_options_are_tokens(self) -> Brand:
        for field in ("boundary_tokens", "no_typo_tokens"):
            unknown = set(getattr(self, field)) - set(self.tokens)
            if unknown:
                raise ValueError(f"{field} not in tokens: {sorted(unknown)}")
        return self

    @field_validator("official_domains")
    @classmethod
    def _registrable_domains_only(cls, domains: list[str]) -> list[str]:
        for d in domains:
            if d != d.lower() or "/" in d or ":" in d or d.startswith("."):
                raise ValueError(f"official domain must be a bare lowercase domain: {d!r}")
        return domains


class Category(BaseModel):
    """A scam category, such as tax-season impersonation or package delivery."""

    description: str


class BrandsFile(BaseModel):
    categories: dict[str, Category]
    brands: list[Brand]

    @model_validator(mode="after")
    def _consistent(self) -> BrandsFile:
        names = [b.name for b in self.brands]
        if len(set(names)) != len(names):
            raise ValueError("brand names must be unique")
        # "other" and "none" are reserved values of MessageFeatures.impersonated_entity.
        if {"other", "none"} & set(names):
            raise ValueError("'other' and 'none' are reserved and can't be brand names")
        unknown = {b.category for b in self.brands} - set(self.categories)
        if unknown:
            raise ValueError(f"brands use undefined categories: {sorted(unknown)}")
        return self


def load_brands_file(data_dir: Path) -> BrandsFile:
    return BrandsFile.model_validate(load_yaml(data_dir / "brands.yaml"))


def load_brands(data_dir: Path) -> list[Brand]:
    return load_brands_file(data_dir).brands


def load_categories(data_dir: Path) -> dict[str, Category]:
    return load_brands_file(data_dir).categories


# --- data/keywords.yaml -------------------------------------------------------


class Keywords(BaseModel):
    stuffing_keywords: list[str]
    urgency_phrases: list[str]
    payment_methods: dict[str, list[str]]
    payment_received_markers: list[str] = []
    sensitive_requests: dict[str, list[str]]
    threats: dict[str, list[str]]
    injection_phrases: list[str]
    ascii_substitutions: dict[str, str]
    entity_mentions: dict[str, list[str]]
    negations: list[str]


def load_keywords(data_dir: Path) -> Keywords:
    return Keywords.model_validate(load_yaml(data_dir / "keywords.yaml"))


# --- data/facts.yaml ----------------------------------------------------------


class Fact(BaseModel):
    id: str
    entity: str
    statement: str
    source: str
    last_reviewed: date
    data: dict[str, Any] = {}


class FactsFile(BaseModel):
    facts: list[Fact]


def load_facts(data_dir: Path) -> list[Fact]:
    return FactsFile.model_validate(load_yaml(data_dir / "facts.yaml")).facts


# --- data/guidance.yaml -------------------------------------------------------


class Guidance(BaseModel):
    """Next-step templates (E1). Placeholders are filled from data files only."""

    steps: dict[str, str]
    references: dict[str, str] = {}

    @field_validator("steps")
    @classmethod
    def _single_line(cls, steps: dict[str, str]) -> dict[str, str]:
        return {k: " ".join(v.split()) for k, v in steps.items()}

    @field_validator("references")
    @classmethod
    def _https_sources(cls, refs: dict[str, str]) -> dict[str, str]:
        for name, url in refs.items():
            if not url.startswith("https://"):
                raise ValueError(f"reference {name!r} must be an https:// URL")
        return refs


def load_guidance(data_dir: Path) -> Guidance:
    return Guidance.model_validate(load_yaml(data_dir / "guidance.yaml"))


# --- data/scenarios.yaml ------------------------------------------------------


_LIST_CONDITIONS = ("category", "threats", "requests", "payments", "call_to_action", "phrases")


class ScenarioCondition(BaseModel):
    """One way a scenario can match (E4). Every field that's set must hold, and a list
    field holds when any of its values is present. They read signals the rules already
    produce, plus `phrases`, which are matched in the message text."""

    model_config = ConfigDict(extra="forbid")

    category: list[str] = []  # category of the brand the message claims or links to
    threats: list[ThreatType] = []
    requests: list[SensitiveType] = []
    payments: list[PaymentType] = []
    call_to_action: list[CtaType] = []
    phrases: list[str] = []
    phone: bool | None = None  # the message contains a phone number
    link: bool | None = None  # the message links to a domain that isn't official

    @model_validator(mode="after")
    def _not_empty(self) -> ScenarioCondition:
        if not any(getattr(self, f) for f in _LIST_CONDITIONS) and (
            self.phone is None and self.link is None
        ):
            raise ValueError("a scenario condition needs at least one non-empty field")
        return self


# Generic E1 steps a scenario step may stand in for, when it already says the same thing
# more specifically. Contact and reporting steps are never replaced.
REPLACEABLE_STEPS = frozenset({"dont_open_link", "dont_share", "dont_pay", "dont_call"})


class ScenarioStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    source: str
    replaces: list[str] = []

    @field_validator("replaces")
    @classmethod
    def _replaceable(cls, value: list[str]) -> list[str]:
        unknown = set(value) - REPLACEABLE_STEPS
        if unknown:
            raise ValueError(f"steps that can't be replaced: {sorted(unknown)}")
        return value

    @field_validator("text")
    @classmethod
    def _single_line(cls, value: str) -> str:
        return " ".join(value.split())

    @field_validator("source")
    @classmethod
    def _https_source(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError(f"source must be an https:// URL: {value!r}")
        return value


class ScenarioRule(BaseModel):
    """A named scenario: a plain-language description, the conditions that recognize it,
    and its own next step."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    category: str | None = None  # None: shared by several categories
    description: str
    source: str
    when: list[ScenarioCondition]
    step: ScenarioStep

    @field_validator("description")
    @classmethod
    def _single_line(cls, value: str) -> str:
        return " ".join(value.split())

    @field_validator("source")
    @classmethod
    def _https_source(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError(f"source must be an https:// URL: {value!r}")
        return value

    @field_validator("id")
    @classmethod
    def _snake_case(cls, value: str) -> str:
        if not value.replace("_", "").isalnum() or value != value.lower() or value == "none":
            raise ValueError(f"scenario id must be lower_snake_case and not 'none': {value!r}")
        return value

    @field_validator("when")
    @classmethod
    def _has_conditions(cls, value: list[ScenarioCondition]) -> list[ScenarioCondition]:
        if not value:
            raise ValueError("a scenario needs at least one condition")
        return value


class ScenariosFile(BaseModel):
    scenarios: list[ScenarioRule]

    @model_validator(mode="after")
    def _unique_ids(self) -> ScenariosFile:
        ids = [s.id for s in self.scenarios]
        if len(set(ids)) != len(ids):
            raise ValueError("scenario ids must be unique")
        return self


def _https_url(value: str) -> str:
    if not value.startswith("https://"):
        raise ValueError(f"must be an https:// URL: {value!r}")
    return value


class Article(BaseModel):
    """A page about a type of scam, on a trusted consumer-protection site."""

    model_config = ConfigDict(extra="forbid")

    title: str
    publisher: str
    url: str
    reviewed: date

    @field_validator("url")
    @classmethod
    def _https(cls, value: str) -> str:
        return _https_url(value)


class HelpPage(BaseModel):
    """An organization's own help page; `scenarios` limits it to some scenarios."""

    model_config = ConfigDict(extra="forbid")

    title: str
    url: str
    reviewed: date
    scenarios: list[str] = []

    @field_validator("url")
    @classmethod
    def _https(cls, value: str) -> str:
        return _https_url(value)


class ScamTypeReading(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenarios: dict[str, list[str]] = {}
    categories: dict[str, list[str]] = {}
    default: list[str] = []


class ResourcesFile(BaseModel):
    """data/resources.yaml: the curated "learn more" links of an analysis."""

    model_config = ConfigDict(extra="forbid")

    trusted_domains: list[str]
    articles: dict[str, Article]
    scam_types: ScamTypeReading
    official_help: dict[str, list[HelpPage]] = {}

    @model_validator(mode="after")
    def _consistent(self) -> ResourcesFile:
        used = [
            *(a for ids in self.scam_types.scenarios.values() for a in ids),
            *(a for ids in self.scam_types.categories.values() for a in ids),
            *self.scam_types.default,
        ]
        unknown = set(used) - set(self.articles)
        if unknown:
            raise ValueError(f"unknown article ids: {sorted(unknown)}")
        if not self.scam_types.default:
            raise ValueError("scam_types.default needs at least one article")
        for article_id, article in self.articles.items():
            if not url_on_domains(article.url, self.trusted_domains):
                raise ValueError(f"article {article_id!r} is not on a trusted domain")
        return self


def url_on_domains(url: str, domains: list[str]) -> bool:
    """True if the URL's host is one of `domains` or a subdomain of one."""
    host = (urlsplit(url).hostname or "").lower()
    return any(host == d or host.endswith(f".{d}") for d in domains)


def load_resources(data_dir: Path) -> ResourcesFile:
    return ResourcesFile.model_validate(load_yaml(data_dir / "resources.yaml"))


def load_scenarios(data_dir: Path) -> list[ScenarioRule]:
    """Scenarios in priority order: the first one that matches is reported."""
    return ScenariosFile.model_validate(load_yaml(data_dir / "scenarios.yaml")).scenarios


# --- config/scoring.yaml ------------------------------------------------------


class Bands(BaseModel):
    suspicious: int
    likely_scam: int

    @model_validator(mode="after")
    def _ordered(self) -> Bands:
        if not 0 < self.suspicious < self.likely_scam <= 100:
            raise ValueError("bands must satisfy 0 < suspicious < likely_scam <= 100")
        return self


class ScoringConfig(BaseModel):
    weights: dict[Module, float]
    bands: Bands
    floors: dict[str, int]
    mitigating_cap: int
    domain_points: dict[str, int]
    message_points: dict[str, int]
    verify_points: dict[str, int]

    @field_validator("weights")
    @classmethod
    def _positive_weights(cls, weights: dict[Module, float]) -> dict[Module, float]:
        if any(w <= 0 for w in weights.values()):
            raise ValueError("module weights must be positive")
        return weights


def load_scoring(config_dir: Path) -> ScoringConfig:
    return ScoringConfig.model_validate(load_yaml(config_dir / "scoring.yaml"))
