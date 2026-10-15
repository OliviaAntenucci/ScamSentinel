from scamsentinel.message.analyzer import merge_features
from scamsentinel.message.features import (
    Impersonation,
    InjectionAttempt,
    MessageFeatures,
    PaymentMethod,
    SensitiveRequest,
    Threat,
    Urgency,
)
from scamsentinel.message.grounding import ground

TEXT = "IRS: pay immediately with gift cards at irs-help[.]com or call (800) 555-0199"


def test_grounding_drops_fabricated_spans():
    llm = MessageFeatures(
        impersonated_entity=Impersonation(value="IRS", span="Internal Revenue Service"),
        urgency=Urgency(level=9, spans=["immediately", "act within 1 hour"]),
        payment_methods=[PaymentMethod(method="gift_card", span="gift cards")],
        sensitive_requests=[SensitiveRequest(type="ssn", span="send your SSN")],
        claimed_urls=["irs-help.com", "evil.example"],
        claimed_phone_numbers=["800-555-0199", "800-000-1111"],
        injection_attempt=InjectionAttempt(detected=True, span="ignore the rules"),
    )
    grounded, dropped = ground(llm, TEXT)

    assert grounded.impersonated_entity is None
    assert grounded.urgency.spans == ["immediately"]
    assert grounded.urgency.level == 9
    assert [p.method for p in grounded.payment_methods] == ["gift_card"]
    assert grounded.sensitive_requests == []
    assert grounded.claimed_urls == ["irs-help.com"]  # matches the defanged form
    assert grounded.claimed_phone_numbers == ["800-555-0199"]  # matches by digits
    assert not grounded.injection_attempt.detected
    assert dropped == 6


def test_urgency_without_grounded_spans_is_zero():
    llm = MessageFeatures(urgency=Urgency(level=10, spans=["NOW NOW NOW"]))
    grounded, _ = ground(llm, "hello")
    assert grounded.urgency.level == 0


def test_grounding_ignores_case_and_whitespace():
    llm = MessageFeatures(payment_methods=[PaymentMethod(method="crypto", span="BITCOIN   ATM")])
    grounded, dropped = ground(llm, "use a bitcoin atm")
    assert grounded.payment_methods and dropped == 0


# --- merge -----------------------------------------------------------------------------


def test_merge_without_llm_returns_rules():
    rules = MessageFeatures(urgency=Urgency(level=5, spans=["now"]))
    assert merge_features(None, rules) == (rules, [])


def test_merge_unions_and_tags_sources():
    rules = MessageFeatures(
        payment_methods=[PaymentMethod(method="gift_card", span="gift card", source="rule")],
        sensitive_requests=[SensitiveRequest(type="ssn", span="SSN", source="rule")],
        urgency=Urgency(level=5, spans=["now"]),
    )
    llm = MessageFeatures(
        payment_methods=[PaymentMethod(method="gift_card", span="gift card")],
        threats=[Threat(type="arrest", span="arrested")],
        urgency=Urgency(level=8, spans=["Now", "today"]),
    )
    merged, disagreements = merge_features(llm, rules)

    assert merged.payment_methods[0].source == "both"
    assert merged.sensitive_requests[0].source == "rule"
    assert merged.threats[0].source == "llm"
    assert merged.urgency.level == 8
    assert merged.urgency.spans == ["now", "today"]
    assert disagreements == ["llm_missed_sensitive_request:ssn"]


def test_rules_win_entity_conflicts():
    rules = MessageFeatures(
        impersonated_entity=Impersonation(value="IRS", span="IRS", source="rule")
    )
    llm = MessageFeatures(impersonated_entity=Impersonation(value="other", span="Acme"))
    merged, disagreements = merge_features(llm, rules)
    assert merged.impersonated_entity.value == "IRS"
    assert disagreements == ["entity: rules=IRS llm=other"]


def test_rule_injection_detection_survives_llm_denial():
    rules = MessageFeatures(
        injection_attempt=InjectionAttempt(detected=True, span="ignore previous instructions")
    )
    merged, disagreements = merge_features(MessageFeatures(), rules)
    assert merged.injection_attempt.detected
    assert "llm_missed_injection_attempt" in disagreements
