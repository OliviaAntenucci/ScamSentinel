"""E3: fact-check summary (architecture.md §20)."""

from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.data import load_brands, load_facts, load_scoring
from scamsentinel.eval.dataset import load_samples
from scamsentinel.message.scoring import score_message
from scamsentinel.models import AnalysisResult, FactCheck, Verdict
from scamsentinel.security.redaction import SSN_PLACEHOLDER, redact_result
from scamsentinel.verify.checks import Verifier, fact_checks
from scamsentinel.verify.org_facts import OrgFacts

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
CONFIG_DIR = DATA_DIR.parent / "config"


@pytest.fixture
def analyze(make_service):
    service = make_service()
    return lambda **request: service.analyze(AnalyzeRequest(**request))


def by_check(result) -> dict[str, list[FactCheck]]:
    rows: dict[str, list[FactCheck]] = {}
    for row in result.fact_checks:
        rows.setdefault(row.check, []).append(row)
    return rows


# --- outcomes, facts, sources, review dates -----------------------------------------------


def test_irs_gift_card_scam(analyze):
    result = analyze(
        text="IRS: you owe $2,340. Pay today with Google Play gift cards or call 202-555-0183."
    )
    rows = by_check(result)
    payment = rows["payment_method_policy"][0]
    assert payment.outcome == "conflicts"
    assert payment.basis == "published_fact"
    assert payment.fact_id == "irs_no_unusual_payment_methods"
    assert "gift card" in payment.fact
    assert payment.source.startswith("https://www.irs.gov/")
    assert payment.last_reviewed == date(2026, 10, 14)
    assert rows["contact_channel"][0].outcome == "conflicts"

    phone = rows["phone_number"][0]
    assert phone.outcome == "cannot_verify"
    assert phone.claim == "202-555-0183"
    assert phone.fact_id == "irs_individual_phone"


def test_conflicts_come_first(analyze):
    result = analyze(
        text="IRS: pay with gift cards today, call 1-800-829-1040 with questions."
    )
    outcomes = [r.outcome for r in result.fact_checks]
    assert outcomes == sorted(
        outcomes, key=["conflicts", "cannot_verify", "matches"].index
    )
    assert "matches" in outcomes  # the published IRS number


def test_official_link_matches(analyze):
    result = analyze(text="Reminder from the IRS: file by April 15 at https://www.irs.gov/freefile")
    row = by_check(result)["official_domain"][0]
    assert row.outcome == "matches"
    assert row.fact_id == "irs_official_domains"


def test_brand_without_a_domains_fact_falls_back_to_the_brand_list(analyze):
    result = analyze(text="TurboTax: verify your account at https://turbotax-verify.com")
    row = by_check(result)["official_domain"][0]
    assert row.outcome == "conflicts"
    assert row.basis == "brand_list"
    assert "turbotax.com" in row.fact
    assert row.last_reviewed is None


# --- gaps are shown, not hidden -----------------------------------------------------------


def test_payment_without_a_published_policy_cannot_be_verified(analyze):
    result = analyze(text="USPS: your parcel is on hold. Pay the fee with an Apple gift card.")
    row = by_check(result)["payment_method_policy"][0]
    assert row.outcome == "cannot_verify"
    assert row.basis == "no_fact"
    assert "No published USPS payment policy" in row.detail


def test_phone_without_published_numbers_cannot_be_verified(analyze):
    result = analyze(text="TurboTax: call 1-888-555-0143 about your refund.")
    row = by_check(result)["phone_number"][0]
    assert row.outcome == "cannot_verify"
    assert row.basis == "no_fact"


def test_request_without_a_published_statement_cannot_be_verified(analyze):
    result = analyze(text="Chase: reply with the verification code we sent you.")
    row = by_check(result)["request_policy"][0]
    assert row.outcome == "cannot_verify"


def test_email_header_checks_say_so(analyze):
    eml = (
        "From: Wells Fargo <no-reply@wellsfargo.com>\nReply-To: help@wf-secure.co\n"
        "To: you@example.com\nSubject: Hold\nContent-Type: text/plain\n\nPlease reply.\n"
    )
    row = by_check(analyze(email_raw=eml))["sender_alignment"][0]
    assert row.outcome == "conflicts"
    assert row.basis == "email_headers"
    assert "wellsfargo.com" in row.fact


def test_model_knowledge_is_labeled(settings, engine):
    verifier = Verifier(load_brands(settings.data_dir), [], engine)
    checks = verifier.unknown_org_domains(
        "Acme Bank",
        OrgFacts(known=True, canonical_name="Acme Bank", official_domains=["acmebank.com"]),
        ["https://acme-unlock.com"],
        "test-model",
    )
    row = fact_checks(checks)[0]
    assert row.outcome == "conflicts"
    assert row.basis == "model_knowledge"
    assert "test-model" in row.fact
    assert row.source is None


def test_url_only_input_has_no_fact_checks(analyze):
    assert analyze(url="https://turb0tax-refund.com").fact_checks == []


# --- E3 changes no score -------------------------------------------------------------------


def test_cannot_verify_rows_add_no_points(make_analyzer):
    """For every eval sample, dropping the new 'can't verify' checks leaves the message
    score and its reasons unchanged."""
    points = load_scoring(CONFIG_DIR)
    analyzer = make_analyzer()
    checked = 0
    for sample in load_samples(DATA_DIR / "eval" / "samples.jsonl"):
        if sample.input_type != "text":
            continue
        analysis = analyzer.analyze(sample.content)
        kept = [c for c in analysis.checks if not c.signal.endswith("_unverified")]
        without = score_message(
            analysis.features, kept, points.message_points, points.verify_points
        )
        assert without.score == analysis.result.score, sample.id
        assert without.reasons == analysis.result.reasons, sample.id
        checked += 1
    assert checked > 50


def test_unverified_signals_have_no_points():
    verify_points = load_scoring(CONFIG_DIR).verify_points
    for signal in ("payment_method_unverified", "request_unverified", "phone_number_unverified"):
        assert verify_points.get(signal, 0) == 0


def test_every_cited_fact_exists():
    ids = {f.id for f in load_facts(DATA_DIR)}
    assert "irs_official_domains" in ids
    assert "irs_individual_phone" in ids


# --- redaction -----------------------------------------------------------------------------


def test_fact_checks_are_redacted():
    row = FactCheck(
        check="request_policy", claim="IRS asking for 078-05-1120", outcome="cannot_verify",
        detail="x", basis="no_fact",
    )
    result = AnalysisResult(
        analysis_id="an_" + "0" * 32, created_at=datetime.now(UTC), input_type="text",
        verdict=Verdict.SUSPICIOUS, risk_score=40, fact_checks=[row],
    )
    assert redact_result(result).fact_checks[0].claim == f"IRS asking for {SSN_PLACEHOLDER}"
