"""Bank impersonation category (G2): Chase, Bank of America, Wells Fargo."""

from datetime import date

import pytest

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.data import Fact, load_brands
from scamsentinel.message.features import MessageFeatures, SensitiveRequest
from scamsentinel.models import Verdict
from scamsentinel.verify.checks import Verifier

CODE_REQUEST = (
    "Wells Fargo: we are calling you shortly about a flagged payment. To confirm your "
    "identity, reply with the one-time access code we just sent to your phone."
)


# --- rules ----------------------------------------------------------------------------


def test_rules_find_bank_and_suspicious_activity(make_analyzer):
    text = "Chase Fraud Alert: unusual activity on your account. Sign in at https://x.example"
    features = make_analyzer().analyze(text).features
    assert features.protected_entity == "Chase"
    assert {t.type for t in features.threats} == {"suspicious_activity"}


@pytest.mark.parametrize(
    "text",
    [
        "Coach here: remind the kids not to chase the ball into the parking lot!",
        "Thanks for your purchase! Your order ships tomorrow.",
    ],
)
def test_chase_the_word_is_not_chase_the_bank(make_analyzer, text):
    assert make_analyzer().analyze(text).features.impersonated_entity is None


def test_a_delivered_code_is_not_a_request(make_analyzer):
    text = "Wells Fargo: Your one-time access code is 482913. Do not share this code."
    assert not make_analyzer().analyze(text).features.sensitive_requests


def test_a_requested_code_is_a_request(make_analyzer):
    requests = make_analyzer().analyze(CODE_REQUEST).features.sensitive_requests
    assert [r.type for r in requests] == ["mfa_code"]


def test_a_card_named_by_last_digits_is_not_a_request(make_analyzer):
    text = "Chase: Did you use your debit card ending in 4421 for $84.12? Reply YES or NO."
    assert not make_analyzer().analyze(text).features.sensitive_requests


def test_card_details_are_still_a_request(make_analyzer):
    text = "Chase: confirm your debit card number and your PIN to unlock your account."
    types = {r.type for r in make_analyzer().analyze(text).features.sensitive_requests}
    assert types == {"card", "password"}


def test_money_received_is_not_a_payment_demand(make_analyzer):
    text = "Bank of America: You received $40.00 from JORDAN LEE via Zelle."
    assert not make_analyzer().analyze(text).features.payment_methods


def test_send_with_zelle_is_a_payment_demand(make_analyzer):
    text = "BofA Alert: to protect your funds, send your balance to yourself with Zelle."
    methods = [p.method for p in make_analyzer().analyze(text).features.payment_methods]
    assert methods == ["zelle"]


# --- verification ---------------------------------------------------------------------


def test_code_request_fails_the_banks_published_policy(make_service):
    result = make_service().analyze(AnalyzeRequest(text=CODE_REQUEST))
    assert result.verdict == Verdict.LIKELY_SCAM
    policy = next(r for r in result.reasons if r.signal == "request_policy")
    assert "wellsfargo.com" in policy.detail


def test_bofa_zelle_demand_hits_the_payment_floor(make_service):
    text = "BofA Alert: to protect your funds from fraud, send your balance to yourself with Zelle."
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert "disallowed_payment_demand" in result.overrides_applied
    assert result.verdict == Verdict.LIKELY_SCAM


def test_chase_has_no_request_policy_fact(make_service):
    # Chase doesn't publish a "we never ask for codes" statement we could source, so the
    # check doesn't run for it (the brand_sensitive_request floor still does).
    text = "Chase: reply with the verification code we sent you to keep your account open."
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert "request_policy" not in {r.signal for r in result.reasons}
    assert "brand_sensitive_request" in result.overrides_applied


def test_request_policy_respects_the_facts_channels(settings, engine):
    fact = Fact(
        id="x", entity="Wells Fargo", statement="never by email", source="https://x.example",
        last_reviewed=date(2026, 10, 15),
        data={"disallowed_requests": ["mfa_code"], "channels": ["email"]},
    )
    verifier = Verifier(load_brands(settings.data_dir), [fact], engine)
    features = MessageFeatures.model_validate(
        {"impersonated_entity": {"value": "Wells Fargo", "span": "Wells Fargo"}}
    ).model_copy(update={"sensitive_requests": [SensitiveRequest(type="mfa_code", span="code")]})
    by_text = verifier.run(features, input_type="text")
    by_email = verifier.run(features, input_type="email")
    assert not [c for c in by_text if c.check == "request_policy"]
    assert [c.signal for c in by_email if c.check == "request_policy"] == ["request_policy"]


def test_next_steps_use_the_banks_published_contacts(make_service):
    result = make_service().analyze(AnalyzeRequest(text=CODE_REQUEST))
    text = " ".join(s.text for s in result.next_steps)
    assert "1-866-867-5568" in text
    assert "reportphish@wellsfargo.com" in text


# --- hard negatives -------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Chase Fraud Alert: Did you use your debit card ending in 4421 for $84.12 at BEST BUY "
        "on Oct 14? Reply YES or NO. Reply STOP to opt out.",
        "Bank of America: You received $40.00 from JORDAN LEE via Zelle. View details in the "
        "Mobile Banking app.",
        "Wells Fargo: Your one-time access code is 482913. Do not share this code. We will "
        "never ask for this code by phone, email or text.",
        "Bank of America: Your statement is ready. Sign in at https://www.bankofamerica.com",
    ],
)
def test_real_bank_messages_are_legitimate(make_service, text):
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert result.verdict == Verdict.LIKELY_LEGITIMATE


# --- domains --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("domain", "brand", "technique"),
    [
        ("chase-online-verify.com", "Chase", "brand_plus_keywords"),
        ("chase.com-secure-login.info", "Chase", "brand_in_subdomain"),
        ("chase.us", "Chase", "tld_swap"),
        ("bankofarnerica.com", "Bank of America", "homoglyph"),
        ("bofa-alerts.net", "Bank of America", "brand_plus_keywords"),
        ("wellsfarg0-online.com", "Wells Fargo", "homoglyph"),
        ("wellsfargo-secure-signin.com", "Wells Fargo", "brand_plus_keywords"),
    ],
)
def test_bank_lookalikes(engine, domain, brand, technique):
    result = engine.score(domain)
    assert result.brand == brand
    assert technique in result.techniques


@pytest.mark.parametrize(
    "domain",
    [
        "chase.com",
        "secure.bankofamerica.com",
        "bofa.com",
        "connect.secure.wellsfargo.com",
        # "chase" is an ordinary word: neither containing it nor being one edit away counts.
        "purchase.edu",
        "phaseone.com",
        "chose.com",
        "chaser.com",
    ],
)
def test_bank_official_and_neighbours_score_zero(engine, domain):
    assert engine.score(domain).score == 0
