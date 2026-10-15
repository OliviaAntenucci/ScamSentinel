"""Message analyzer: run LLM + rule extractors, ground spans, merge, score (M2)."""

from __future__ import annotations

from scamsentinel.message.features import MessageFeatures
from scamsentinel.models import ModuleResult


def merge_features(llm: MessageFeatures | None, rules: MessageFeatures) -> MessageFeatures:
    """Union both extractors, tagging each feature with source llm|rule|both (§6.3)."""
    raise NotImplementedError("M2: feature merge")


def analyze_message(text: str) -> tuple[MessageFeatures, ModuleResult]:
    raise NotImplementedError("M2: message analyzer")
