"""Deterministic keyword/regex feature extractor (architecture.md §6.2, M2).
Never sees LLM output, so prompt injection can't influence it."""

from __future__ import annotations

from scamsentinel.message.features import MessageFeatures


def extract_features_rules(text: str) -> MessageFeatures:
    raise NotImplementedError("M2: rule feature extractor")
