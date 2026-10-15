"""Deterministic keyword/regex feature extractor (architecture.md §5.1).

Never sees LLM output, so prompt injection can't influence it. Every span is the exact
text that matched in the input.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping

from scamsentinel.data import Keywords
from scamsentinel.ingest.phones import extract_phone_numbers
from scamsentinel.ingest.urls import extract_urls
from scamsentinel.message.features import (
    CallToAction,
    Impersonation,
    InjectionAttempt,
    MessageFeatures,
    PaymentMethod,
    SensitiveRequest,
    Threat,
    Urgency,
)

# How far back (in characters, within one clause) a negation word cancels a match.
NEGATION_WINDOW = 80

_CLICK = re.compile(
    r"(?<!\w)(?:click|tap|visit|go to|log\s?in|sign\s?in|verify (?:at|here|now|your)"
    r"|follow (?:the|this) link)(?!\w)",
    re.IGNORECASE,
)
_CALL = re.compile(r"(?<!\w)(?:call|dial|contact us at)(?!\w)", re.IGNORECASE)
_REPLY = re.compile(r"(?<!\w)(?:reply|respond|text back)(?!\w)", re.IGNORECASE)
# A code being delivered ("Your verification code for Amazon is 482913", "Access code:
# 4829") is what a real one-time-code text looks like; it isn't a request for one.
# Both are used with pattern.match(text, pos), which anchors at pos (a "^" wouldn't).
_CODE_DELIVERED = re.compile(r"[^.!?\n]{0,30}?(?:\bis|:)\s*\d{4,8}\b", re.IGNORECASE)
# "Your debit card ending in 4421" refers to a card by its last digits, the way banks do;
# it doesn't ask for the card details.
_MASKED_REFERENCE = re.compile(r"\s*(?:ending|that ends|which ends)\s+(?:in|with)\s+\d{4}\b")


def phrase_pattern(phrases: Iterable[str]) -> re.Pattern[str]:
    """Case-insensitive whole-phrase matcher. Inner spaces match any whitespace, and a
    trailing plural "s" is allowed ("gift card" matches "gift cards")."""
    alternatives = sorted({p.strip() for p in phrases if p.strip()}, key=len, reverse=True)
    body = "|".join(r"\s+".join(map(re.escape, p.split())) for p in alternatives)
    return re.compile(rf"(?<!\w)(?:{body})s?(?!\w)", re.IGNORECASE)


class RuleExtractor:
    def __init__(self, keywords: Keywords) -> None:
        self._urgency = phrase_pattern(keywords.urgency_phrases)
        self._injection = phrase_pattern(keywords.injection_phrases)
        self._payments = _patterns(keywords.payment_methods)
        self._sensitive = _patterns(keywords.sensitive_requests)
        self._threats = _patterns(keywords.threats)
        self._entities = _patterns(keywords.entity_mentions)
        negations = phrase_pattern(keywords.negations).pattern
        # A negation word followed by the rest of the same clause, up to the match. Commas
        # end the clause too, so "Do not delay, send bitcoin" still counts as a request.
        self._negated_clause = re.compile(rf"{negations}[^.!?;:,\n]*$", re.IGNORECASE)
        self._received_clause = (
            re.compile(
                # Same clause, but amounts ("$1,200.00") don't end it.
                rf"{phrase_pattern(keywords.payment_received_markers).pattern}"
                r"(?:[^.!?;:,\n]|[.,](?=\d))*$",
                re.IGNORECASE,
            )
            if keywords.payment_received_markers
            else None
        )

    def extract(self, text: str) -> MessageFeatures:
        urls = extract_urls(text)
        phones = extract_phone_numbers(text)

        payments = [
            PaymentMethod(method=key, span=m.group(), source="rule")
            for key, m in self._affirmed(self._payments, text, skip=self._money_received)
        ]
        sensitive = [
            SensitiveRequest(type=key, span=m.group(), source="rule")
            for key, m in self._affirmed(self._sensitive, text, skip=_not_a_request)
        ]
        threats = [
            Threat(type=key, span=m.group(), source="rule")
            for key, m in self._affirmed(self._threats, text)
        ]

        urgency_spans = _dedupe(m.group() for m in self._urgency.finditer(text))
        urgency = Urgency(
            level=min(10, 2 + 3 * len(urgency_spans)) if urgency_spans else 0,
            spans=urgency_spans,
        )

        injection = InjectionAttempt()
        if m := self._injection.search(text):
            injection = InjectionAttempt(detected=True, span=m.group())

        return MessageFeatures(
            impersonated_entity=self._entity(text),
            urgency=urgency,
            payment_methods=payments,
            sensitive_requests=sensitive,
            claimed_urls=urls,
            claimed_phone_numbers=phones,
            call_to_action=self._call_to_action(text, urls, phones, payments),
            threats=threats,
            injection_attempt=injection,
        )

    def _entity(self, text: str) -> Impersonation | None:
        """The protected brand mentioned first in the text."""
        first: tuple[int, str, str] | None = None
        for name, pattern in self._entities.items():
            m = pattern.search(text)
            if m and (first is None or m.start() < first[0]):
                first = (m.start(), name, m.group())
        if first is None:
            return None
        return Impersonation(value=first[1], span=first[2], source="rule")

    def _affirmed(
        self,
        patterns: Mapping[str, re.Pattern[str]],
        text: str,
        skip: Callable[[str, str, re.Match[str]], bool] | None = None,
    ) -> Iterator[tuple[str, re.Match[str]]]:
        """First non-negated match per category ("we will never ask for your SSN" is skipped).
        `skip(key, text, match)` rules out other matches that aren't requests or demands."""
        for key, pattern in patterns.items():
            for m in pattern.finditer(text):
                if self._negated(text, m.start()) or (skip and skip(key, text, m)):
                    continue
                yield key, m
                break

    def _negated(self, text: str, start: int) -> bool:
        return bool(self._negated_clause.search(text[max(0, start - NEGATION_WINDOW) : start]))

    def _money_received(self, key: str, text: str, m: re.Match[str]) -> bool:
        """'You received $40 from Sam via Zelle' reports incoming money; it isn't a demand."""
        if self._received_clause is None:
            return False
        before = text[max(0, m.start() - NEGATION_WINDOW) : m.start()]
        return bool(self._received_clause.search(before))

    @staticmethod
    def _call_to_action(
        text: str, urls: list[str], phones: list[str], payments: list[PaymentMethod]
    ) -> CallToAction | None:
        if urls:
            m = _CLICK.search(text)
            return CallToAction(value="click_link", span=m.group() if m else urls[0], source="rule")
        if phones and (m := _CALL.search(text)):
            return CallToAction(value="call_number", span=m.group(), source="rule")
        if payments:
            return CallToAction(value="pay", span=payments[0].span, source="rule")
        if m := _REPLY.search(text):
            return CallToAction(value="reply", span=m.group(), source="rule")
        return None


def _not_a_request(key: str, text: str, m: re.Match[str]) -> bool:
    """A code being delivered, or a card or account named by its last four digits."""
    if key == "mfa_code":
        return bool(_CODE_DELIVERED.match(text, m.end()))
    if key in ("card", "bank_account"):
        return bool(_MASKED_REFERENCE.match(text, m.end()))
    return False


def _patterns(groups: Mapping[str, list[str]]) -> dict[str, re.Pattern[str]]:
    return {key: phrase_pattern(phrases) for key, phrases in groups.items()}


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item.casefold() not in seen:
            seen.add(item.casefold())
            unique.append(item)
    return unique
