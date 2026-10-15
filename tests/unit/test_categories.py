"""Brand-agnostic core and the package-delivery category (USPS)."""

import pytest

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.data import load_brands, load_keywords
from scamsentinel.message.analyzer import MessageAnalyzer
from scamsentinel.message.features import Impersonation, MessageFeatures
from scamsentinel.models import Verdict

SMISHING = (
    "USPS: Your package is on hold due to an incomplete address. Update your details "
    "within 12 hours: https://usps-redelivery-center.com"
)


def test_rules_find_usps_and_delivery_hold(make_analyzer):
    features = make_analyzer().analyze(SMISHING).features
    assert features.protected_entity == "USPS"
    assert {t.type for t in features.threats} == {"delivery_hold"}


def test_usps_smishing_is_a_likely_scam(make_service):
    result = make_service().analyze(AnalyzeRequest(text=SMISHING))
    assert result.verdict == Verdict.LIKELY_SCAM
    by_signal = {r.signal: r for r in result.reasons}
    # The verdict cites USPS's own published policy, with its source.
    assert "uspis.gov" in by_signal["contact_channel"].detail
    assert "official_domain_mismatch" in by_signal
    assert "impersonation_with_lookalike" in result.overrides_applied


def test_requested_tracking_text_is_legitimate(make_service):
    text = (
        "USPS: Your item was delivered in or at the mailbox at 2:14 pm on October 14 in "
        "SPRINGFIELD, IL 62701. Reply STOP to cancel."
    )
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert result.verdict == Verdict.LIKELY_LEGITIMATE


def test_official_usps_link_is_mitigating(make_service):
    text = (
        "USPS: We could not deliver your package today because a signature is required. "
        "Schedule a free redelivery at https://www.usps.com/redelivery"
    )
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert result.verdict == Verdict.LIKELY_LEGITIMATE
    assert "official_domain_match" in {r.signal for r in result.reasons}


def test_published_usps_number_is_recognized(make_analyzer):
    analysis = make_analyzer().analyze("USPS: questions? Call 1-800-275-8777.")
    assert any(c.signal == "phone_number_known" for c in analysis.checks)


@pytest.mark.parametrize(
    ("domain", "technique"),
    [
        ("usps-redelivery-center.com", "brand_plus_keywords"),
        ("usрs-delivery.com", "homoglyph"),
        ("usps.com-trackhelp.xyz", "brand_in_subdomain"),
        ("usps.net", "tld_swap"),
    ],
)
def test_usps_lookalikes(engine, domain, technique):
    result = engine.score(domain)
    assert result.brand == "USPS"
    assert technique in result.techniques


@pytest.mark.parametrize("domain", ["usps.com", "tools.usps.com", "uspis.gov", "ups.com"])
def test_usps_official_and_neighbours_score_zero(engine, domain):
    assert engine.score(domain).score == 0


def test_tax_floor_does_not_fire_for_brands_without_payment_facts(make_service):
    # USPS has no published payment-method fact, so the IRS-style floor can't apply.
    text = "USPS: your parcel cannot be delivered. Pay the fee with an Apple gift card."
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert "disallowed_payment_demand" not in result.overrides_applied


def test_irs_gift_card_demand_still_hits_the_floor(make_service):
    # The lookalike link dilutes the weighted score below 85, so the floor has to lift it.
    text = "IRS: pay your balance today with gift cards at irs-help.com"
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert "disallowed_payment_demand" in result.overrides_applied
    assert result.risk_score == 85


# --- the entity list is configuration -------------------------------------------------


def test_unknown_entity_from_an_extractor_is_demoted(make_analyzer, fake_llm):
    llm = fake_llm(
        MessageFeatures(impersonated_entity=Impersonation(value="Acme Bank", span="Acme"))
    )
    analysis = make_analyzer(llm).analyze("Hello from Acme, verify your account")
    assert analysis.features.impersonated_entity.value == "other"
    assert analysis.features.protected_entity is None
    assert not analysis.checks


def test_entity_mentions_must_name_known_brands(settings, engine):
    keywords = load_keywords(settings.data_dir)
    keywords.entity_mentions["Acme Bank"] = ["acme"]
    with pytest.raises(ValueError, match="unknown brands"):
        MessageAnalyzer(
            keywords=keywords,
            brands=load_brands(settings.data_dir),
            facts=[],
            engine=engine,
            message_points={},
            verify_points={},
        )
