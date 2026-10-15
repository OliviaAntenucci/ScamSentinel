"""Named scenarios (E4, architecture.md §21).

Recognizes the story a scam message tells ("refund lure", "fake virus warning") with
fixed rules from data/scenarios.yaml. The rules read signals the rule extractor already
produced (threats, requests, payment methods, the claimed brand's category) plus phrases
in the message text. Scenarios are tried in file order and the first match wins.

A scenario explains a result; it never changes the score. The LLM can't choose one: an
LLM-only feature can satisfy a condition, but the condition and the scenario's wording
come from the data file. Evidence lists only what the rules matched (our own phrases,
threat and request types), never free text from the message.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from scamsentinel.data import ScenarioCondition, ScenarioRule
from scamsentinel.message.features import MessageFeatures
from scamsentinel.message.rules import NEGATION_WINDOW, phrase_pattern
from scamsentinel.models import Scenario

_Compiled = tuple[ScenarioCondition, re.Pattern[str] | None]


class ScenarioMatcher:
    def __init__(self, rules: Iterable[ScenarioRule], negations: Iterable[str] = ()) -> None:
        self._rules: list[tuple[ScenarioRule, list[_Compiled]]] = [
            (
                rule,
                [(c, phrase_pattern(c.phrases) if c.phrases else None) for c in rule.when],
            )
            for rule in rules
        ]
        negations = list(negations)
        # Same rule as the extractor: a negation earlier in the clause cancels a phrase
        # ("we will never ask you to move your money").
        self._negated_clause = (
            re.compile(rf"{phrase_pattern(negations).pattern}[^.!?;:,\n]*$", re.IGNORECASE)
            if negations
            else None
        )

    @property
    def rules(self) -> list[ScenarioRule]:
        return [rule for rule, _ in self._rules]

    def match(
        self,
        *,
        features: MessageFeatures,
        text: str,
        entity: str | None,
        category: str | None,
        unofficial_link: bool,
    ) -> Scenario | None:
        for rule, conditions in self._rules:
            for condition, pattern in conditions:
                matched_on = self._holds(
                    condition, pattern, features, text, entity, category, unofficial_link
                )
                if matched_on is not None:
                    return Scenario(
                        id=rule.id,
                        name=rule.name,
                        category=rule.category,
                        description=rule.description,
                        source=rule.source,
                        matched_on=matched_on,
                    )
        return None

    def _holds(
        self,
        c: ScenarioCondition,
        pattern: re.Pattern[str] | None,
        features: MessageFeatures,
        text: str,
        entity: str | None,
        category: str | None,
        unofficial_link: bool,
    ) -> list[str] | None:
        """What matched, if every field of the condition holds; otherwise None."""
        matched: list[str] = []
        if c.category:
            if category not in c.category:
                return None
            matched.append(f"claims to be {entity} ({category.replace('_', ' ')})")
        for label, wanted, present in (
            ("threat", c.threats, [t.type for t in features.threats]),
            ("asks for", c.requests, [r.type for r in features.sensitive_requests]),
            ("payment", c.payments, [p.method for p in features.payment_methods]),
            (
                "call to action",
                c.call_to_action,
                [features.call_to_action.value] if features.call_to_action else [],
            ),
        ):
            if not wanted:
                continue
            hit = next((value for value in present if value in wanted), None)
            if hit is None:
                return None
            matched.append(f"{label}: {hit.replace('_', ' ')}")
        if pattern is not None:
            phrase = self._phrase(pattern, text)
            if phrase is None:
                return None
            matched.append(f'phrase: "{phrase}"')
        if c.phone is not None:
            has_phone = bool(features.claimed_phone_numbers)
            if has_phone != c.phone:
                return None
            matched.append("has a phone number" if has_phone else "no phone number")
        if c.link is not None:
            if unofficial_link != c.link:
                return None
            matched.append("links to a site that isn't official" if c.link else "no other links")
        return matched

    def _phrase(self, pattern: re.Pattern[str], text: str) -> str | None:
        """The first non-negated phrase, lowercased: one of our phrases, not message text."""
        for m in pattern.finditer(text):
            before = text[max(0, m.start() - NEGATION_WINDOW) : m.start()]
            if self._negated_clause is not None and self._negated_clause.search(before):
                continue
            return " ".join(m.group().lower().split())
        return None
