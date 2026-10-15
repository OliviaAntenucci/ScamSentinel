"""Span grounding for LLM output (FR-14): every quoted span must appear in the input.

A feature whose quote isn't actually in the message is treated as a hallucination
(or an attempt to smuggle evidence in) and dropped.
"""

from __future__ import annotations

import re

from scamsentinel.ingest.phones import normalize_phone
from scamsentinel.ingest.urls import refang
from scamsentinel.message.features import InjectionAttempt, MessageFeatures, Urgency


def _norm(s: str) -> str:
    return " ".join(s.casefold().split())


def ground(features: MessageFeatures, text: str) -> tuple[MessageFeatures, int]:
    """Return a copy keeping only grounded features, and how many were dropped."""
    haystack = _norm(text)
    refanged = _norm(refang(text))
    digits = re.sub(r"\D", "", text)
    dropped = 0

    def grounded(span: str) -> bool:
        return bool(span.strip()) and _norm(span) in haystack

    def keep(items, is_grounded):
        nonlocal dropped
        kept = [item for item in items if is_grounded(item)]
        dropped += len(items) - len(kept)
        return kept

    entity = features.impersonated_entity
    if entity is not None and not grounded(entity.span):
        entity = None
        dropped += 1

    urgency_spans = keep(features.urgency.spans, grounded)
    urgency = Urgency(level=features.urgency.level if urgency_spans else 0, spans=urgency_spans)

    call_to_action = features.call_to_action
    if call_to_action is not None and not grounded(call_to_action.span):
        call_to_action = None
        dropped += 1

    injection = features.injection_attempt
    if injection.detected and not grounded(injection.span):
        injection = InjectionAttempt()
        dropped += 1

    def url_grounded(url: str) -> bool:
        return bool(url.strip()) and (_norm(url) in haystack or _norm(refang(url)) in refanged)

    def phone_grounded(phone: str) -> bool:
        normalized = normalize_phone(phone)
        return normalized is not None and normalized[2:] in digits

    return (
        features.model_copy(
            update={
                "impersonated_entity": entity,
                "urgency": urgency,
                "payment_methods": keep(features.payment_methods, lambda f: grounded(f.span)),
                "sensitive_requests": keep(
                    features.sensitive_requests, lambda f: grounded(f.span)
                ),
                "threats": keep(features.threats, lambda f: grounded(f.span)),
                "claimed_urls": keep(features.claimed_urls, url_grounded),
                "claimed_phone_numbers": keep(features.claimed_phone_numbers, phone_grounded),
                "call_to_action": call_to_action,
                "injection_attempt": injection,
            }
        ),
        dropped,
    )
