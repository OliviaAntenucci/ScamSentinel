"""Message analyzer: rules + LLM extraction, grounding, merge, verification, scoring.

    rules ───────────────────────────┐
    LLM ──▶ validate ──▶ ground ─────┴─▶ merge ──▶ verify ──▶ score (rules decide)
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel

from scamsentinel.config import Settings
from scamsentinel.data import (
    Brand,
    Fact,
    Keywords,
    load_brands,
    load_facts,
    load_keywords,
    load_scoring,
)
from scamsentinel.domain.engine import DomainEngine, get_engine
from scamsentinel.ingest.email import ParsedEmail
from scamsentinel.message.features import MessageFeatures, Urgency
from scamsentinel.message.grounding import ground
from scamsentinel.message.llm import FeatureExtractor, LlmUnavailable, build_extractor
from scamsentinel.message.rules import RuleExtractor
from scamsentinel.message.scoring import score_message
from scamsentinel.models import InputType, ModuleResult
from scamsentinel.verify.checks import CheckResult, Verifier


class MessageAnalysis(BaseModel):
    features: MessageFeatures
    checks: list[CheckResult]
    result: ModuleResult
    llm_used: bool
    degraded: list[str] = []
    # Indicators the rules found but the LLM missed: possible injection or extraction gaps.
    disagreements: list[str] = []
    dropped_llm_spans: int = 0


def merge_features(
    llm: MessageFeatures | None, rules: MessageFeatures
) -> tuple[MessageFeatures, list[str]]:
    """Union of both extractors. On conflicts the rules win, since they can't be injected."""
    if llm is None:
        return rules, []
    disagreements: list[str] = []

    entity = rules.impersonated_entity
    if entity and llm.impersonated_entity:
        if entity.value == llm.impersonated_entity.value:
            entity = entity.model_copy(update={"source": "both"})
        else:
            disagreements.append(
                f"entity: rules={entity.value} llm={llm.impersonated_entity.value}"
            )
    entity = entity or llm.impersonated_entity

    def merge_keyed(rule_items, llm_items, key: str, label: str):
        merged = {getattr(item, key): item for item in rule_items}
        llm_keys = {getattr(item, key) for item in llm_items}
        for name, item in merged.items():
            if name in llm_keys:
                merged[name] = item.model_copy(update={"source": "both"})
            else:
                disagreements.append(f"llm_missed_{label}:{name}")
        for item in llm_items:
            merged.setdefault(getattr(item, key), item)
        return list(merged.values())

    cta = rules.call_to_action
    if cta and llm.call_to_action and cta.value == llm.call_to_action.value:
        cta = cta.model_copy(update={"source": "both"})
    cta = cta or llm.call_to_action

    injection = rules.injection_attempt
    if injection.detected and not llm.injection_attempt.detected:
        disagreements.append("llm_missed_injection_attempt")
    if not injection.detected:
        injection = llm.injection_attempt

    merged = MessageFeatures(
        impersonated_entity=entity,
        urgency=Urgency(
            level=max(rules.urgency.level, llm.urgency.level),
            spans=_dedupe([*rules.urgency.spans, *llm.urgency.spans]),
        ),
        payment_methods=merge_keyed(
            rules.payment_methods, llm.payment_methods, "method", "payment_method"
        ),
        sensitive_requests=merge_keyed(
            rules.sensitive_requests, llm.sensitive_requests, "type", "sensitive_request"
        ),
        claimed_urls=_dedupe([*rules.claimed_urls, *llm.claimed_urls]),
        claimed_phone_numbers=_dedupe([*rules.claimed_phone_numbers, *llm.claimed_phone_numbers]),
        call_to_action=cta,
        threats=merge_keyed(rules.threats, llm.threats, "type", "threat"),
        injection_attempt=injection,
    )
    return merged, disagreements


class MessageAnalyzer:
    def __init__(
        self,
        *,
        keywords: Keywords,
        brands: list[Brand],
        facts: list[Fact],
        engine: DomainEngine,
        message_points: dict[str, int],
        verify_points: dict[str, int],
        llm: FeatureExtractor | None = None,
        max_chars: int = 20_000,
    ) -> None:
        self._rules = RuleExtractor(keywords)
        self._verifier = Verifier(brands, facts, engine, keywords.entity_mentions)
        self._message_points = message_points
        self._verify_points = verify_points
        self._llm = llm
        self._max_chars = max_chars

    @classmethod
    def from_settings(
        cls, settings: Settings, llm: FeatureExtractor | None = None
    ) -> MessageAnalyzer:
        scoring = load_scoring(settings.config_dir)
        return cls(
            keywords=load_keywords(settings.data_dir),
            brands=load_brands(settings.data_dir),
            facts=load_facts(settings.data_dir),
            engine=get_engine(settings.data_dir, settings.config_dir),
            message_points=scoring.message_points,
            verify_points=scoring.verify_points,
            llm=llm if llm is not None else build_extractor(settings),
            max_chars=settings.max_text_chars,
        )

    def analyze(
        self,
        text: str,
        *,
        input_type: InputType = "text",
        email: ParsedEmail | None = None,
        extra_urls: Iterable[str] = (),
    ) -> MessageAnalysis:
        text = text[: self._max_chars]
        rules = self._rules.extract(text)
        extra = list(extra_urls)
        if extra:
            # e.g. email link targets, which aren't in the visible text.
            urls = _dedupe([*rules.claimed_urls, *extra])
            rules = rules.model_copy(update={"claimed_urls": urls})

        degraded: list[str] = []
        llm_features: MessageFeatures | None = None
        dropped = 0
        if self._llm is None:
            degraded.append("llm_not_configured")
        else:
            try:
                llm_features, dropped = ground(self._llm.extract(text), text)
            except LlmUnavailable as exc:
                degraded.append(f"llm_unavailable:{exc.reason}")

        features, disagreements = merge_features(llm_features, rules)
        checks = self._verifier.run(features, input_type=input_type, email=email)
        result = score_message(features, checks, self._message_points, self._verify_points)
        return MessageAnalysis(
            features=features,
            checks=checks,
            result=result,
            llm_used=llm_features is not None,
            degraded=degraded,
            disagreements=disagreements,
            dropped_llm_spans=dropped,
        )


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item.casefold() not in seen:
            seen.add(item.casefold())
            unique.append(item)
    return unique
