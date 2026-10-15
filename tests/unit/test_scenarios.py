"""E4: named scenarios (architecture.md §21)."""

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.data import (
    ScenarioCondition,
    ScenarioRule,
    load_brands,
    load_facts,
    load_guidance,
    load_scenarios,
)
from scamsentinel.eval.dataset import NO_SCENARIO, load_samples, load_scenario_labels
from scamsentinel.eval.metrics import Prediction, scenario_score
from scamsentinel.eval.report import markdown
from scamsentinel.guidance.next_steps import MAX_STEPS, NextStepsGuide
from scamsentinel.guidance.scenarios import ScenarioMatcher
from scamsentinel.ingest.phones import extract_phone_numbers
from scamsentinel.ingest.urls import extract_urls
from scamsentinel.message.features import (
    Impersonation,
    MessageFeatures,
    PaymentMethod,
    Threat,
)
from scamsentinel.models import Verdict

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
SCENARIOS = load_scenarios(DATA_DIR)
LABELS = load_scenario_labels(DATA_DIR / "eval" / "scenario_labels.yaml")
SAMPLES = {s.id: s for s in load_samples(DATA_DIR / "eval" / "samples.jsonl")}


@pytest.fixture
def analyze(make_service):
    service = make_service()
    return lambda text: service.analyze(AnalyzeRequest(text=text))


# --- one fresh example per scenario (not eval samples) ----------------------------------

EXAMPLES = {
    "remote_access": "Microsoft Support: install AnyDesk so our technician can fix your PC "
    "today: https://quick-pc-fix-help.com",
    "fake_check_job": "Congrats on the new job! We'll mail you a check for $1,900. Deposit "
    "it and send $1,500 to our supplier by Zelle.",
    "job_upfront_fee": "You're hired for the remote assistant role! Pay the $90 training "
    "fee with a gift card to start today.",
    "job_data_harvest": "Recruiter here: you passed the interview. Send your SSN and a photo "
    "of your driver's license to finish onboarding.",
    "safe_account_transfer": "Bank of America: fraud detected. Move your money to a safe "
    "account immediately at https://bofa-secure-transfer.com",
    "tax_relief_offer": "IRS Fresh Start program: settle your tax debt for pennies. Act now "
    "at https://irs-tax-relief-now.com",
    "back_taxes_threat": "IRS: you owe $3,200 in back taxes. Pay today with gift cards or a "
    "warrant will be issued for your arrest.",
    "stimulus_payment": "IRS: claim your $1,400 stimulus payment at "
    "https://irs-stimulus-claim.com today.",
    "refund_lure": "IRS: your tax refund of $640 is waiting. Confirm your details at "
    "https://irs-refund-claim.com",
    "redelivery_fee": "USPS: pay the $1.99 redelivery fee at https://usps-redeliver-fee.com "
    "to receive your package.",
    "incomplete_address": "USPS: your package could not be delivered due to an incomplete "
    "address. Update your address at https://usps-address-fix.com",
    "package_on_hold": "USPS: your package is on hold. Track it at https://usps-track-hold.com",
    "fake_charge_callback": "Microsoft: your Defender protection plan auto-renewed for "
    "$399.99. To cancel, call 1-888-555-0177 immediately.",
    "fake_virus_alert": "Microsoft Security: virus detected on your computer. Call "
    "1-888-555-0147 now.",
    "verification_code_theft": "Google Account: unusual sign-in on your account. Reply with "
    "the 6-digit code we sent to secure it.",
    "fake_sign_in_alert": "Apple: new sign-in from Moscow, Russia. If this wasn't you, "
    "secure your Apple ID at https://appleid-secure-check.com",
    "fake_fraud_alert": "Chase Fraud Alert: suspicious transaction of $912 on your debit "
    "card. Confirm at https://chase-fraud-review.com",
    "billing_problem": "QuickBooks: your subscription payment failed. Update your credit "
    "card at https://quickbooks-billing-fix.com within 24 hours.",
    "account_deletion": "Gmail Security: your password expires today. Keep it at "
    "https://gmail-keep-password.com",
    "account_locked": "Wells Fargo: your online banking has been suspended. Restore access "
    "at https://wellsfargo-restore-access.com",
    "identity_verification": "IRS: confirm your SSN and date of birth at "
    "https://irs-verify-id.com",
}


def test_every_scenario_has_an_example():
    assert set(EXAMPLES) == {s.id for s in SCENARIOS}


@pytest.mark.parametrize(("scenario_id", "text"), list(EXAMPLES.items()))
def test_example_is_recognized(analyze, scenario_id, text):
    result = analyze(text)
    assert result.verdict != Verdict.LIKELY_LEGITIMATE, result.reasons
    assert result.scenario is not None, result.reasons
    assert result.scenario.id == scenario_id, result.scenario.matched_on
    assert result.scenario.matched_on


# --- priority and gating -----------------------------------------------------------------


def test_a_code_request_beats_the_sign_in_story(analyze):
    # Both match; the code request is the more specific (and more dangerous) one.
    result = analyze(EXAMPLES["verification_code_theft"])
    assert "unusual sign-in" in EXAMPLES["verification_code_theft"]
    assert result.scenario.id == "verification_code_theft"


def test_fake_check_beats_pay_to_work(analyze):
    assert analyze(EXAMPLES["fake_check_job"]).scenario.id == "fake_check_job"


def test_legitimate_results_get_no_scenario(analyze):
    result = analyze(
        "Chase Fraud Alert: Did you use your debit card ending in 4421 for $84.12 at BEST BUY? "
        "Reply YES or NO."
    )
    assert result.verdict == Verdict.LIKELY_LEGITIMATE
    assert result.scenario is None


def test_url_only_input_gets_no_scenario(make_service):
    result = make_service().analyze(AnalyzeRequest(url="https://irs-refund-claim.com"))
    assert result.scenario is None


def test_a_negated_phrase_does_not_match():
    matcher = ScenarioMatcher(SCENARIOS, negations=["never", "not"])
    features = MessageFeatures(
        threats=[Threat(type="suspicious_activity", span="unusual activity", source="rule")]
    )
    text = "Unusual activity on your account. We will never ask you to move your money."
    scenario = matcher.match(
        features=features, text=text, entity=None, category=None, unofficial_link=False
    )
    assert scenario is None or scenario.id != "safe_account_transfer"


# --- what it reports ---------------------------------------------------------------------


_EVIDENCE = re.compile(
    r'^(claims to be [\w .]+ \([\w ]+\)|threat: [a-z ]+|asks for: [a-z ]+|payment: [a-z ]+'
    r'|call to action: [a-z ]+|phrase: "[^"]+"|has a phone number|no phone number'
    r"|links to a site that isn't official|no other links)$"
)


@pytest.mark.parametrize(("scenario_id", "text"), list(EXAMPLES.items()))
def test_matched_on_uses_only_our_vocabulary(analyze, scenario_id, text):
    scenario = analyze(text).scenario
    rule = next(s for s in SCENARIOS if s.id == scenario.id)
    phrases = {p for c in rule.when for p in c.phrases}
    for item in scenario.matched_on:
        assert _EVIDENCE.match(item), item
        if item.startswith("phrase: "):
            phrase = item.removeprefix('phrase: "').removesuffix('"')
            # One of the scenario's own phrases (a trailing plural "s" is allowed).
            assert phrase in phrases or phrase.removesuffix("s") in phrases, phrase


def test_scenario_carries_description_and_source(analyze):
    scenario = analyze(EXAMPLES["refund_lure"]).scenario
    assert scenario.name == "Refund lure"
    assert scenario.category == "tax"
    assert scenario.source.startswith("https://")
    assert "refund" in scenario.description


# --- next steps ----------------------------------------------------------------------------


def test_scenario_step_is_added_before_contact(analyze):
    steps = analyze(EXAMPLES["refund_lure"]).next_steps
    ids = [s.id for s in steps]
    assert "scenario_refund_lure" in ids
    assert ids.index("scenario_refund_lure") < ids.index("contact_brand_with_phone")
    step = steps[ids.index("scenario_refund_lure")]
    assert step.source == "https://www.irs.gov/wheres-my-refund"


def test_scenario_step_replaces_the_generic_steps_it_covers(analyze):
    ids = [s.id for s in analyze(EXAMPLES["fake_virus_alert"]).next_steps]
    assert "scenario_fake_virus_alert" in ids
    assert "dont_call" not in ids


def test_report_step_is_always_last(analyze):
    for text in EXAMPLES.values():
        steps = analyze(text).next_steps
        assert len(steps) <= MAX_STEPS
        assert steps[-1].id.startswith("report")


def test_scenario_steps_contain_no_links_or_numbers_except_official_sites():
    official = {d for b in load_brands(DATA_DIR) for d in b.official_domains}
    for rule in SCENARIOS:
        assert not extract_phone_numbers(rule.step.text), rule.id
        for url in extract_urls(rule.step.text):
            host = url.split("//")[-1].split("/")[0].removeprefix("www.")
            assert host in official, (rule.id, url)


# --- scenarios never change a score ---------------------------------------------------------


def test_scenarios_change_no_score(make_service):
    with_scenarios = make_service()
    without = make_service()
    without._guide = NextStepsGuide(
        load_guidance(DATA_DIR), load_brands(DATA_DIR), load_facts(DATA_DIR)
    )
    checked = 0
    for sample in SAMPLES.values():
        if sample.input_type != "text":
            continue
        a = with_scenarios.analyze(AnalyzeRequest(text=sample.content))
        b = without.analyze(AnalyzeRequest(text=sample.content))
        assert b.scenario is None
        assert (a.risk_score, a.verdict) == (b.risk_score, b.verdict), sample.id
        assert [r.signal for r in a.reasons] == [r.signal for r in b.reasons], sample.id
        checked += 1
    assert checked > 100


# --- data integrity -------------------------------------------------------------------------


def test_every_scenario_has_a_labeled_sample():
    labeled = set(LABELS.values())
    missing = [s.id for s in SCENARIOS if s.id not in labeled]
    assert not missing


def test_labels_name_known_scenarios_and_scam_messages():
    known = {s.id for s in SCENARIOS} | {NO_SCENARIO}
    for sample_id, scenario_id in LABELS.items():
        assert scenario_id in known, (sample_id, scenario_id)
        sample = SAMPLES[sample_id]
        assert sample.label == "scam" and sample.input_type != "url", sample_id


def test_every_scam_message_is_labeled():
    unlabeled = [
        s.id for s in SAMPLES.values()
        if s.label == "scam" and s.input_type != "url" and s.id not in LABELS
    ]
    assert not unlabeled


def test_scenario_categories_are_known():
    categories = {b.category for b in load_brands(DATA_DIR)}
    for rule in SCENARIOS:
        assert rule.category is None or rule.category in categories, rule.id


def test_unknown_category_is_rejected():
    rule = SCENARIOS[0].model_copy(
        update={"when": [ScenarioCondition(category=["no_such_category"], phrases=["x"])]}
    )
    with pytest.raises(ValueError, match="unknown categories"):
        NextStepsGuide(
            load_guidance(DATA_DIR), load_brands(DATA_DIR), load_facts(DATA_DIR), [rule]
        )


@pytest.mark.parametrize(
    "condition",
    [
        {},
        {"threats": ["not_a_threat"]},
        {"phrases": []},
        {"unknown_field": ["x"]},
    ],
)
def test_invalid_conditions_are_rejected(condition):
    with pytest.raises(ValidationError):
        ScenarioCondition.model_validate(condition)


def test_rule_validation():
    base = SCENARIOS[0].model_dump()
    with pytest.raises(ValidationError, match="snake_case"):
        ScenarioRule.model_validate({**base, "id": "none"})
    with pytest.raises(ValidationError, match="https"):
        ScenarioRule.model_validate({**base, "source": "http://example.com"})
    with pytest.raises(ValidationError, match="can't be replaced"):
        ScenarioRule.model_validate(
            {**base, "step": {**base["step"], "replaces": ["contact_brand"]}}
        )


def test_conditions_can_combine_signals():
    # A fee alone isn't a pay-to-work scenario: it needs a job context too.
    matcher = ScenarioMatcher(SCENARIOS)
    features = MessageFeatures(
        impersonated_entity=Impersonation(value="none", span=""),
        payment_methods=[PaymentMethod(method="zelle", span="Zelle", source="rule")],
    )
    scenario = matcher.match(
        features=features, text="Pay $90 with Zelle.", entity=None, category=None,
        unofficial_link=False,
    )
    assert scenario is None


# --- evaluation ------------------------------------------------------------------------------


def _prediction(expected, reported, verdict=Verdict.LIKELY_SCAM, label="scam"):
    return Prediction(
        id="x", input_type="text", label=label, brand="none", synthetic=True,
        verdict=verdict, risk_score=80, scenario=reported, expected_scenario=expected,
    )


def test_scenario_score_counts_each_outcome():
    s = scenario_score(
        [
            _prediction("refund_lure", "refund_lure"),
            _prediction("refund_lure", "account_locked"),
            _prediction("refund_lure", None),
            _prediction("refund_lure", None, verdict=Verdict.LIKELY_LEGITIMATE),
            _prediction("none", None),
            _prediction(None, "refund_lure"),  # unlabeled: ignored
        ]
    )
    assert (s.labeled, s.correct, s.wrong, s.missed, s.undetected) == (5, 2, 1, 1, 1)
    assert s.accuracy == pytest.approx(2 / 5)
    assert s.accuracy_when_detected == pytest.approx(2 / 4)


def test_report_has_a_scenario_section():
    report = markdown(
        [_prediction("refund_lure", "account_locked")],
        split="dev", ablation="rules_only", llm="none", dataset="x",
    )
    assert "## Named scenarios (E4)" in report
    assert "| x | refund_lure | account_locked | likely_scam |" in report
