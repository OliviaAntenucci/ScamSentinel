"""LLM feature extractor (architecture.md §6.1, M2).

Content is wrapped in a randomly named delimiter, the model must answer through a
strict tool schema, and the output is validated as MessageFeatures. Any failure
falls back to rules-only (FR-19).
"""

from __future__ import annotations

from scamsentinel.message.features import MessageFeatures

PROMPT_VERSION = "v0"


def extract_features_llm(text: str) -> MessageFeatures:
    raise NotImplementedError("M2: LLM feature extractor")
