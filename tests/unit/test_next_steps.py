"""E1: 'What should I do next?' (architecture.md §18)."""

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given
from hypothesis import settings as hsettings
from hypothesis import strategies as st

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.data import Guidance, load_brands, load_facts, load_guidance
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.eval.dataset import load_samples
from scamsentinel.eval.runner import build_service
from scamsentinel.guidance.next_steps import MAX_STEPS, NextStepsGuide
from scamsentinel.ingest.phones import extract_phone_numbers, normalize_phone
from scamsentinel.ingest.urls import extract_urls
from scamsentinel.message.features import Impersonation, MessageFeatures
from scamsentinel.models import Verdict

DATA_DIR = Path(__file__).resolve().parents[2] / "data"


def steps_of(result) -> dict[str, str]:
    return {s.id: s.text for s in result.next_steps}


def all_text(result) -> str:
    return " ".join(s.text for s in result.next_steps)


@pytest.fixture
def analyze(make_service):
    service = make_service()

    def run_(**request):
        return service.analyze(AnalyzeRequest(**request))

    return run_


def test_irs_gift_card_scam(analyze):
    result = analyze(
        text="FINAL NOTICE from the IRS. You owe $2,340. Pay today with Google Play cards or "
        "a warrant will be issued. Call 202-555-0183."
    )
    steps = steps_of(result)
    assert result.verdict == Verdict.LIKELY_SCAM
    assert steps["dont_pay_policy"] == "Don't pay. IRS says it doesn't take payment by gift card."
    assert "dont_call" in steps
    assert "irs.gov" in steps["contact_brand_with_phone"]
    assert "1-800-829-1040" in steps["contact_brand_with_phone"]
    assert "phishing@irs.gov" in steps["report_brand_text"]
    assert "7726" in steps["report_brand_text"]
    assert "already_acted" in steps
    assert "202-555-0183" not in all_text(result)
    sources = {s.id: s.source for s in result.next_steps}
    assert sources["dont_pay_policy"].startswith("https://www.irs.gov/")
    assert sources["report_brand_text"] == "https://www.irs.gov/privacy-disclosure/report-phishing"


def test_usps_smishing(analyze):
    result = analyze(
        text="USPS: Your package is on hold due to an incomplete address. Update within 12 "
        "hours: https://usps-redelivery-center.com"
    )
    steps = steps_of(result)
    assert list(steps)[0] == "dont_open_link_brand"
    assert "official USPS website" in steps["dont_open_link_brand"]
    assert "usps.com" in steps["contact_brand_with_phone"]
    assert "1-800-275-8777" in steps["contact_brand_with_phone"]
    assert "spam@uspis.gov" in steps["report_brand_text"]
    assert "usps-redelivery-center" not in all_text(result)


def test_sensitive_request_names_what_not_to_share(analyze):
    result = analyze(
        text="IRS: confirm your SSN and date of birth at irs-refund-verify.com within 24 hours"
    )
    assert steps_of(result)["dont_share"] == (
        "Don't reply with or type in your Social Security number and your date of birth. "
        "Legitimate organizations don't ask for it this way."
    )


def test_lookalike_url_names_the_brand(analyze):
    result = analyze(url="https://turb0tax-refund.com/login")
    steps = steps_of(result)
    assert "official TurboTax website" in steps["dont_open_link_brand"]
    assert "turbotax.com" in steps["contact_brand"]
    # Not a text message, so no 7726; TurboTax has no curated report address.
    assert "ReportFraud.ftc.gov" in steps["report"]


def test_email_report_has_no_text_forwarding(analyze):
    eml = (
        "From: IRS <alerts@irs-notice.net>\nTo: you@example.com\nSubject: Refund\n"
        "Content-Type: text/plain\n\nIRS: verify your SSN at https://irs-refund-help.com\n"
    )
    steps = steps_of(analyze(email_raw=eml))
    assert steps["report_brand"] == "Report it to phishing@irs.gov, then delete it."


def test_legitimate_gets_one_cautious_step(analyze):
    legit = analyze(text="Reminder from the IRS: file by April 15 at irs.gov/freefile.")
    assert legit.verdict == Verdict.LIKELY_LEGITIMATE
    assert [s.id for s in legit.next_steps] == ["verify_brand"]
    assert "irs.gov" in legit.next_steps[0].text
    assert "safe" not in legit.next_steps[0].text.lower()

    plain = analyze(text="See you at lunch tomorrow?")
    assert [s.id for s in plain.next_steps] == ["verify"]


def test_brandless_scam(analyze):
    result = analyze(
        text="Your account is suspended. Send your password and card number to restore it "
        "immediately at https://secure-account-restore.com"
    )
    steps = steps_of(result)
    assert "dont_open_link" in steps
    assert "contact_sender" in steps
    assert "report_text" in steps


def test_unknown_organization_name_is_never_quoted(make_analyzer, fake_llm, engine):
    # The organization name is attacker-written: here it carries a phone number.
    org = "Acme Bank 1-800-555-0100"
    text = f"{org}: your account is locked. Verify at https://acme-unlock.com now"
    llm = fake_llm(MessageFeatures(impersonated_entity=Impersonation(value="other", span=org)))
    analysis = make_analyzer(llm).analyze(text)
    guide = NextStepsGuide.from_files(DATA_DIR)
    steps = guide.build(
        verdict=Verdict.SUSPICIOUS,
        input_type="text",
        features=analysis.features,
        domains=[engine.score("acme-unlock.com")],
        checks=analysis.checks,
    )
    ids = [s.id for s in steps]
    assert "contact_unknown_org" in ids
    text_out = " ".join(s.text for s in steps)
    assert "Acme" not in text_out
    assert "555" not in text_out


def test_every_result_has_steps_and_at_most_max(make_service):
    service = make_service()
    for request in [
        {"text": "hello"},
        {"url": "https://irs.gov"},
        {
            "text": "IRS: SSN, bank account, password and card number needed. Pay with "
            "bitcoin at irs-pay-now.com or call 202-555-0100 today or face arrest."
        },
    ]:
        steps = service.analyze(AnalyzeRequest(**request)).next_steps
        assert 1 <= len(steps) <= MAX_STEPS


def test_report_step_survives_a_long_list(make_service):
    # Every "don't" step, a scenario step, contact and already-acted: more than fit.
    text = (
        "IRS: you owe back taxes. Confirm your SSN, bank account, password and card number "
        "at irs-pay-now.com, pay with bitcoin, or call 202-555-0100 today or face arrest."
    )
    steps = make_service().analyze(AnalyzeRequest(text=text)).next_steps
    assert len(steps) == MAX_STEPS
    assert steps[-1].id == "report_brand_text"


def test_missing_template_is_rejected():
    guidance = load_guidance(DATA_DIR)
    broken = Guidance(steps={k: v for k, v in guidance.steps.items() if k != "dont_pay"})
    with pytest.raises(ValueError, match="dont_pay"):
        NextStepsGuide(broken, load_brands(DATA_DIR), load_facts(DATA_DIR))


# --- safety: advice never repeats contact details from the input -----------------------


def allowed_contacts(engine) -> tuple[set[str], set[str]]:
    domains: set[str] = set()
    for brand in load_brands(DATA_DIR):
        domains |= set(brand.official_domains)
    phones: set[str] = set()
    for fact in load_facts(DATA_DIR):
        if report := fact.data.get("report_to"):
            domains.add(engine.score(report.split("@")[-1]).registrable)
        for number in fact.data.get("phone_numbers", []):
            phones.add(normalize_phone(number))
    domains.add("ftc.gov")  # ReportFraud.ftc.gov (guidance.yaml references)
    return domains, phones


def assert_only_trusted_contacts(text: str, engine, allowed) -> None:
    domains, phones = allowed
    for url in extract_urls(text):
        assert engine.score(url).registrable in domains, (url, text)
    for phone in extract_phone_numbers(text):
        assert normalize_phone(phone) in phones, (phone, text)


def test_advice_for_every_eval_sample_uses_trusted_contacts_only(settings, tmp_path, engine):
    allowed = allowed_contacts(engine)
    service = build_service(settings, "rules_only", tmp_path / "eval.db")
    samples = load_samples(DATA_DIR / "eval" / "samples.jsonl")
    _field = {"text": "text", "url": "url", "email": "email_raw"}
    checked = 0
    for sample in samples:
        try:
            result = service.analyze(AnalyzeRequest(**{_field[sample.input_type]: sample.content}))
        except InvalidHost:
            continue  # unusable URL inputs are covered by the API tests
        assert result.next_steps, sample.id
        for step in result.next_steps:
            assert_only_trusted_contacts(step.text, engine, allowed)
        checked += 1
    assert checked >= 180


# Trusted strings the advice may legitimately contain; generated scammer details that
# happen to be part of one ("sps.com" inside "usps.com") are skipped.
_TRUSTED = [
    *(d for b in load_brands(DATA_DIR) for d in b.official_domains),
    *(f.data["report_to"] for f in load_facts(DATA_DIR) if "report_to" in f.data),
    "reportfraud.ftc.gov",
    "1-800-829-1040",
    "1-800-275-8777",
]
_DOMAINS = st.from_regex(r"[a-z]{3,10}(-[a-z]{3,8})?\.(com|net|top|info)", fullmatch=True).filter(
    lambda d: not any(d in t for t in _TRUSTED)
)
_PHONES = st.from_regex(r"\(?[2-9]\d{2}\)?[ -]\d{3}-\d{4}", fullmatch=True).filter(
    lambda p: not any(p in t for t in _TRUSTED)
)


@hsettings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    brand=st.sampled_from(["IRS", "USPS", "TurboTax", "Acme Bank", ""]),
    domain=_DOMAINS,
    phone=_PHONES,
    lure=st.sampled_from(["pay with gift cards", "confirm your SSN", "your package is on hold"]),
)
def test_scammer_contact_details_never_reach_the_advice(
    make_service, engine, brand, domain, phone, lure
):
    allowed = allowed_contacts(engine)
    text = f"{brand}: {lure}. Visit https://{domain} or call {phone} right away."
    result = make_service().analyze(AnalyzeRequest(text=text))
    advice = all_text(result)
    assert domain not in advice
    assert phone not in advice
    assert_only_trusted_contacts(advice, engine, allowed)
