"""Loaders for the versioned YAML data/config files, validated at load time."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, field_validator, model_validator

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
