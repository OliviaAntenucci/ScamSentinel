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
    tokens: list[str]
    # Short tokens (e.g. "irs") only match as a whole token or next to tax keywords.
    short_token: bool = False
    # Registrable domains (Public Suffix List), matched exactly, never by substring.
    official_domains: list[str]
    sources: list[str] = []

    @field_validator("official_domains")
    @classmethod
    def _registrable_domains_only(cls, domains: list[str]) -> list[str]:
        for d in domains:
            if d != d.lower() or "/" in d or ":" in d or d.startswith("."):
                raise ValueError(f"official domain must be a bare lowercase domain: {d!r}")
        return domains


class BrandsFile(BaseModel):
    brands: list[Brand]


def load_brands(data_dir: Path) -> list[Brand]:
    return BrandsFile.model_validate(load_yaml(data_dir / "brands.yaml")).brands


# --- data/keywords.yaml -------------------------------------------------------


class Keywords(BaseModel):
    stuffing_keywords: list[str]
    urgency_phrases: list[str]
    payment_methods: dict[str, list[str]]
    sensitive_requests: dict[str, list[str]]
    threats: dict[str, list[str]]
    injection_phrases: list[str]
    ascii_substitutions: dict[str, str]


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
    sandbox_points: dict[str, int]

    @field_validator("weights")
    @classmethod
    def _positive_weights(cls, weights: dict[Module, float]) -> dict[Module, float]:
        if any(w <= 0 for w in weights.values()):
            raise ValueError("module weights must be positive")
        return weights


def load_scoring(config_dir: Path) -> ScoringConfig:
    return ScoringConfig.model_validate(load_yaml(config_dir / "scoring.yaml"))
