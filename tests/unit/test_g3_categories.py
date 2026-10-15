"""G3 categories: account takeover (Google, Apple), tech support (Microsoft), job (Indeed)."""

import pytest

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.models import Verdict

APPLE_CODE_REQUEST = (
    "From: \"Apple Support\" <no-reply@apple-id-secure.com>\nTo: you@example.com\n"
    "Subject: New sign-in\nContent-Type: text/plain\n\n"
    "Reply with the verification code we sent to keep your Apple ID active.\n"
)


# --- rules: new threats ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "threat"),
    [
        ("Your password expires today. Keep it at https://x.example", "access_loss"),
        ("Your account will be permanently deleted tonight.", "access_loss"),
        ("Your computer is infected. Call 1-888-555-0147.", "device_infected"),
        ("Pay $50 by Friday or the offer will be withdrawn.", "job_offer_loss"),
    ],
)
def test_new_threats(make_analyzer, text, threat):
    assert threat in {t.type for t in make_analyzer().analyze(text).features.threats}


@pytest.mark.parametrize(
    ("text", "entity"),
    [
        ("Apple: your Apple ID has been locked.", "Apple"),
        ("Google Account: unusual sign-in from a new device.", "Google"),
        ("Microsoft Security Alert: virus detected.", "Microsoft"),
        ("Indeed Recruiter: you've been selected for a remote role.", "Indeed"),
    ],
)
def test_rules_find_new_brands(make_analyzer, text, entity):
    assert make_analyzer().analyze(text).features.protected_entity == entity


@pytest.mark.parametrize(
    "text",
    [
        "Fresh Market: apple cider and pineapples are back in stock!",
        "Indeed, the team loved your presentation.",
        "The weather outlook for the weekend is sunny.",
        "Pay today with Google Play cards.",  # a payment demand, not a claim to be Google
    ],
)
def test_ordinary_words_are_not_brands(make_analyzer, text):
    assert make_analyzer().analyze(text).features.protected_entity is None


# --- rules: what isn't a request ------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "G-482913 is your Google verification code.",
        "Use 482913 as Microsoft account security code",
    ],
)
def test_a_code_before_the_phrase_is_delivered(make_analyzer, text):
    assert not make_analyzer().analyze(text).features.sensitive_requests


def test_a_phone_number_before_the_phrase_is_not_a_code(make_analyzer):
    text = "Call 1-888-555-0143 is your next step: read us your verification code."
    types = [r.type for r in make_analyzer().analyze(text).features.sensitive_requests]
    assert types == ["mfa_code"]


@pytest.mark.parametrize(
    "text",
    [
        "Your Google Account password was changed.",
        "Your network password expires in 7 days.",
        "Someone knows your password.",
        "If you did not reset your password, go to the app.",
        "Try a password manager.",
    ],
)
def test_a_mentioned_password_is_not_a_request(make_analyzer, text):
    assert not make_analyzer().analyze(text).features.sensitive_requests


@pytest.mark.parametrize(
    "text",
    [
        "Confirm your Apple ID password at https://x.example",
        "Keep your current password here: https://x.example",
        "We need to know your password to fix it.",
    ],
)
def test_an_asked_for_password_is_a_request(make_analyzer, text):
    types = [r.type for r in make_analyzer().analyze(text).features.sensitive_requests]
    assert types == ["password"]


# --- verification ---------------------------------------------------------------------


def test_apple_code_request_fails_apples_policy(make_service):
    result = make_service().analyze(AnalyzeRequest(email_raw=APPLE_CODE_REQUEST))
    assert result.verdict == Verdict.LIKELY_SCAM
    policy = next(r for r in result.reasons if r.signal == "request_policy")
    assert "support.apple.com" in policy.detail


def test_microsoft_gift_card_demand_hits_the_payment_floor(make_service):
    text = "Microsoft Support: buy two $100 Google Play cards to activate your firewall."
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert "disallowed_payment_demand" in result.overrides_applied
    assert result.verdict == Verdict.LIKELY_SCAM


def test_indeed_fee_demand_hits_the_payment_floor(make_service):
    text = "Indeed Hiring Team: pay the $850 laptop fee by Zelle to start Monday."
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert "disallowed_payment_demand" in result.overrides_applied


def test_google_password_policy_is_email_only(make_service):
    # Gmail's statement is about email, so a text asking for the password doesn't fail it
    # (the brand_sensitive_request floor still applies).
    text = "Google Account: confirm your password to stop the deletion."
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert "request_policy" not in {r.signal for r in result.reasons}
    assert "brand_sensitive_request" in result.overrides_applied


def test_next_steps_report_apple_phishing(make_service):
    result = make_service().analyze(AnalyzeRequest(email_raw=APPLE_CODE_REQUEST))
    assert "reportphishing@apple.com" in " ".join(s.text for s in result.next_steps)


# --- hard negatives -------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "G-482913 is your Google verification code.",
        "Google: Your Google Account password was changed. If you didn't do this, visit "
        "https://myaccount.google.com to secure your account.",
        "Apple: Your iCloud storage is full. Upgrade your plan in Settings.",
        "Use 482913 as Microsoft account security code",
        "Microsoft 365: your subscription renews on Nov 2. Manage it at "
        "https://account.microsoft.com/services",
        "Indeed: 12 new jobs match your search. View them at https://www.indeed.com/jobs",
    ],
)
def test_real_messages_are_legitimate(make_service, text):
    result = make_service().analyze(AnalyzeRequest(text=text))
    assert result.verdict == Verdict.LIKELY_LEGITIMATE


# --- domains --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("domain", "brand", "technique"),
    [
        ("appleid-unlock-support.com", "Apple", "brand_plus_keywords"),
        ("app1e-id.com", "Apple", "homoglyph"),
        ("icloud-login-recovery.com", "Apple", "brand_plus_keywords"),
        ("g00gle-account-verify.com", "Google", "homoglyph"),
        ("accounts.google.com-security-check.info", "Google", "brand_in_subdomain"),
        ("rnicrosoft-security.com", "Microsoft", "homoglyph"),
        ("microsoft-support-helpdesk.com", "Microsoft", "brand_plus_keywords"),
        ("outlook-verify-account.com", "Microsoft", "brand_plus_keywords"),
        ("indeed-hiring-portal.com", "Indeed", "brand_plus_keywords"),
        ("lndeed-careers.com", "Indeed", "homoglyph"),
    ],
)
def test_g3_lookalikes(engine, domain, brand, technique):
    result = engine.score(domain)
    assert result.brand == brand
    assert technique in result.techniques


@pytest.mark.parametrize(
    "domain",
    [
        "appleid.apple.com",
        "www.icloud.com",
        "myaccount.google.com",
        "login.live.com",
        "outlook.office.com",
        "secure.indeed.com",
        # Ordinary words that contain or neighbour a token.
        "applebees.com",
        "pineapple.com",
        "apply.com",
        "outlookindia.com",
        "lookout.com",
    ],
)
def test_g3_official_and_neighbours_score_zero(engine, domain):
    assert engine.score(domain).score == 0
