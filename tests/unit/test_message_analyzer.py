"""Message analyzer end to end: rules, fake LLM, verification, scoring."""

from email.message import EmailMessage

from scamsentinel.ingest.email import parse_eml
from scamsentinel.message.features import MessageFeatures, Threat
from scamsentinel.models import Module

SCAM = (
    "IRS ALERT: Your refund has been suspended. Verify your identity immediately at "
    "irs-refund-secure.com or your refund will be cancelled. Provide your SSN to continue."
)
LEGIT = (
    "Reminder from the IRS: the deadline to file your tax return is April 15. "
    "The IRS will never ask for your Social Security number or demand payment by gift card. "
    "Visit irs.gov for free filing options."
)


def signals(analysis):
    return {r.signal for r in analysis.result.reasons}


def test_scam_sms_rules_only(make_analyzer):
    analysis = make_analyzer().analyze(SCAM)
    assert analysis.result.module == Module.MESSAGE
    assert analysis.result.score >= 80
    assert not analysis.llm_used
    assert analysis.degraded == ["llm_not_configured"]
    assert {"impersonation", "sensitive_request", "urgency", "threat"} <= signals(analysis)
    assert {"official_domain_mismatch", "contact_channel"} <= signals(analysis)


def test_legit_reminder_scores_low(make_analyzer):
    analysis = make_analyzer().analyze(LEGIT)
    assert analysis.result.score < 30
    assert "official_domain_match" in signals(analysis)
    assert "contact_channel" not in signals(analysis)


def test_score_is_sum_of_reason_points(make_analyzer):
    analysis = make_analyzer().analyze(LEGIT)
    assert analysis.result.score == sum(r.points for r in analysis.result.reasons)


def test_irs_gift_card_demand_breaks_payment_policy(make_analyzer):
    analysis = make_analyzer().analyze("IRS notice: pay your balance today with gift cards.")
    assert "payment_method_policy" in signals(analysis)
    assert "unusual_payment_method" in signals(analysis)


def test_known_and_unknown_irs_numbers(make_analyzer):
    known = make_analyzer().analyze("The IRS phone line is 800-829-1040.")
    unknown = make_analyzer().analyze("IRS agents: call 202-555-0147 now.")
    assert "phone_number_unknown" not in signals(known)
    assert "phone_number_unknown" in signals(unknown)


def test_clean_message(make_analyzer):
    analysis = make_analyzer().analyze("See you at lunch tomorrow!")
    assert analysis.result.score == 0
    assert signals(analysis) == {"no_message_signals"}


def test_llm_adds_grounded_signals(make_analyzer, fake_llm):
    text = "IRS: officers will come to your house unless you settle today."
    without = make_analyzer().analyze(text)
    llm = fake_llm(MessageFeatures(threats=[Threat(type="arrest", span="officers will come")]))
    with_llm = make_analyzer(llm).analyze(text)
    assert with_llm.llm_used
    assert llm.calls == [text]
    assert with_llm.result.score > without.result.score
    assert with_llm.degraded == []


def test_llm_failure_degrades_to_rules(make_analyzer, fake_llm):
    analysis = make_analyzer(fake_llm(error="rate_limited")).analyze(SCAM)
    assert analysis.degraded == ["llm_unavailable:rate_limited"]
    assert analysis.result.score >= 80


def test_email_sender_checks(make_analyzer):
    msg = EmailMessage()
    msg["From"] = "IRS Refunds <refunds@irs-gov-refund.com>"
    msg["Reply-To"] = "claims@gmail.com"
    msg["Subject"] = "Your refund is on hold"
    msg.set_content("Release your refund now.")
    msg.add_alternative(
        "<p>Release your refund at <a href='https://irs-gov-refund.com/x'>irs.gov</a></p>",
        subtype="html",
    )
    parsed = parse_eml(msg.as_bytes())

    analysis = make_analyzer().analyze(
        parsed.analysis_text(), input_type="email", email=parsed, extra_urls=parsed.links
    )
    assert "https://irs-gov-refund.com/x" in analysis.features.claimed_urls
    assert {"sender_brand_mismatch", "reply_to_mismatch", "official_domain_mismatch"} <= signals(
        analysis
    )


def test_dkim_verified_official_sender_is_mitigating(make_analyzer):
    raw = (
        b"From: IRS <alerts@irs.gov>\r\n"
        b"Authentication-Results: mx.example; dkim=pass header.d=irs.gov\r\n"
        b"Subject: Filing reminder\r\n\r\nThe filing deadline is April 15.\r\n"
    )
    parsed = parse_eml(raw)
    analysis = make_analyzer().analyze(parsed.analysis_text(), input_type="email", email=parsed)
    assert "sender_verified" in signals(analysis)
    assert analysis.result.score == 10  # impersonation 20, sender verified -10
