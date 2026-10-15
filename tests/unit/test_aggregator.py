"""Risk aggregator: weighting, renormalization, floors, mitigating cap, explainability."""

from pathlib import Path

import pytest

from scamsentinel.aggregate.aggregator import aggregate, domain_module
from scamsentinel.data import load_scoring
from scamsentinel.message.features import (
    Impersonation,
    InjectionAttempt,
    MessageFeatures,
    PaymentMethod,
    SensitiveRequest,
)
from scamsentinel.models import Module, ModuleResult, Verdict

CONFIG = load_scoring(Path(__file__).resolve().parents[2] / "config")


def message(score: int) -> ModuleResult:
    return ModuleResult(module=Module.MESSAGE, score=score, reasons=[])


def signals(agg):
    return {r.signal for r in agg.reasons}


def test_weights_renormalize_over_modules_that_ran(engine):
    # Message only: the domain weight is dropped, so the message score passes through.
    only_message = aggregate(domains=[], message=message(50), features=None, config=CONFIG)
    assert only_message.risk_score == 50
    assert only_message.modules_run == [Module.MESSAGE]

    # Domain only.
    only_domain = aggregate(
        domains=[engine.score("turbotax-refund.com")], message=None, features=None, config=CONFIG
    )
    assert only_domain.risk_score == 60
    assert only_domain.verdict == Verdict.LIKELY_SCAM


def test_weighted_combination_and_explanation(engine):
    domains = [engine.score("turbotax-refund.com")]  # 60
    agg = aggregate(
        domains=domains, message=message(20), features=MessageFeatures(), config=CONFIG
    )
    # 60 × 0.55 + 20 × 0.45 = 42
    assert agg.risk_score == 42
    assert agg.verdict == Verdict.SUSPICIOUS
    weighted = next(r for r in agg.reasons if r.signal == "weighted_score")
    assert weighted.module == Module.AGGREGATE
    assert "= 42" in weighted.detail


def test_domain_module_takes_worst_domain(engine):
    module = domain_module([engine.score("irs.gov"), engine.score("turb0tax.com")])
    assert module.score == 85
    assert {r.signal for r in module.reasons} == {"homoglyph"}


def test_floor_sensitive_request_with_lookalike(engine):
    features = MessageFeatures(sensitive_requests=[SensitiveRequest(type="ssn", span="SSN")])
    agg = aggregate(
        domains=[engine.score("irs-refund.com")], message=message(25), features=features,
        config=CONFIG,
    )
    assert agg.risk_score == 90
    assert "sensitive_request_with_lookalike" in agg.overrides_applied
    assert "floor:sensitive_request_with_lookalike" in signals(agg)


def test_floor_irs_unusual_payment():
    features = MessageFeatures(
        impersonated_entity=Impersonation(value="IRS", span="IRS"),
        payment_methods=[PaymentMethod(method="gift_card", span="gift cards")],
    )
    agg = aggregate(domains=[], message=message(40), features=features, config=CONFIG)
    assert agg.risk_score == 85
    assert agg.overrides_applied == ["irs_unusual_payment_demand"]


def test_floor_homoglyph_domain(engine):
    agg = aggregate(
        domains=[engine.score("turb0tax.com")], message=message(0), features=MessageFeatures(),
        config=CONFIG,
    )
    assert agg.risk_score == 80
    assert agg.overrides_applied == ["homoglyph_brand_domain"]


def test_floor_injection_needs_another_signal():
    injection = InjectionAttempt(detected=True, span="ignore previous instructions")
    alone = aggregate(
        domains=[], message=message(30), features=MessageFeatures(injection_attempt=injection),
        config=CONFIG,
    )
    assert alone.overrides_applied == []

    with_entity = MessageFeatures(
        injection_attempt=injection, impersonated_entity=Impersonation(value="IRS", span="IRS")
    )
    agg = aggregate(domains=[], message=message(50), features=with_entity, config=CONFIG)
    assert agg.risk_score == 70
    assert agg.overrides_applied == ["injection_plus_scam_signal"]


def test_mitigating_cap_for_all_official_links(engine):
    agg = aggregate(
        domains=[engine.score("irs.gov")], message=message(100), features=MessageFeatures(),
        config=CONFIG,
    )
    # 0 × 0.55 + 100 × 0.45 = 45 -> capped at 40
    assert agg.risk_score == 40
    assert agg.overrides_applied == ["mitigating_cap"]


@pytest.mark.parametrize(
    "features",
    [
        MessageFeatures(sensitive_requests=[SensitiveRequest(type="ssn", span="SSN")]),
        MessageFeatures(payment_methods=[PaymentMethod(method="crypto", span="bitcoin")]),
        MessageFeatures(injection_attempt=InjectionAttempt(detected=True, span="x")),
    ],
)
def test_no_cap_when_asking_for_data_or_payment(engine, features):
    agg = aggregate(
        domains=[engine.score("irs.gov")], message=message(100), features=features,
        config=CONFIG,
    )
    assert "mitigating_cap" not in agg.overrides_applied


def test_no_cap_without_links():
    agg = aggregate(domains=[], message=message(100), features=MessageFeatures(), config=CONFIG)
    assert agg.risk_score == 100


def test_nothing_to_aggregate():
    with pytest.raises(ValueError):
        aggregate(domains=[], message=None, features=None, config=CONFIG)
