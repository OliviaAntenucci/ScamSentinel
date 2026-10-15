"""End-to-end analyses through AnalysisService (no HTTP)."""

import pytest

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.models import Verdict

SCAM = (
    "IRS ALERT: Your refund has been suspended. Verify your identity immediately at "
    "irs-refund-secure.com or your refund will be cancelled. Provide your SSN to continue."
)
LEGIT = (
    "Reminder from the IRS: the deadline to file your tax return is April 15. "
    "The IRS will never ask for your Social Security number or demand payment by gift card. "
    "Visit irs.gov for free filing options."
)


def analyze(service, **kwargs):
    return service.analyze(AnalyzeRequest(**kwargs))


@pytest.mark.parametrize(
    ("kwargs", "verdict"),
    [
        ({"text": SCAM}, Verdict.LIKELY_SCAM),
        ({"text": LEGIT}, Verdict.LIKELY_LEGITIMATE),
        ({"text": "IRS: you will be arrested unless you pay with gift cards today."},
         Verdict.LIKELY_SCAM),
        ({"text": "See you at lunch tomorrow!"}, Verdict.LIKELY_LEGITIMATE),
        ({"url": "https://turb0tax.com/login"}, Verdict.LIKELY_SCAM),
        ({"url": "https://irs-refund-secure.com"}, Verdict.LIKELY_SCAM),
        ({"url": "https://www.irs.gov/refunds"}, Verdict.LIKELY_LEGITIMATE),
        ({"url": "https://example.org"}, Verdict.LIKELY_LEGITIMATE),
    ],
)
def test_verdicts(make_service, kwargs, verdict):
    assert analyze(make_service(), **kwargs).verdict == verdict


def test_scam_text_floor_and_reasons(make_service):
    result = analyze(make_service(), text=SCAM)
    assert result.risk_score == 90
    assert "sensitive_request_with_lookalike" in result.overrides_applied
    modules = {r.module.value for r in result.reasons}
    assert {"domain", "message", "verify", "aggregate"} <= modules


@pytest.mark.parametrize(
    "kwargs",
    [{"text": "ok"}, {"text": SCAM}, {"url": "https://example.org"}, {"url": "irs.gov"}],
)
def test_every_result_has_reasons(make_service, kwargs):
    # AC-6
    assert analyze(make_service(), **kwargs).reasons


def test_result_is_stored(make_service):
    service = make_service()
    result = analyze(service, text=SCAM)
    assert service.get_analysis(result.analysis_id) == result


def test_llm_failure_is_reported(make_service, fake_llm):
    result = analyze(make_service(fake_llm(error="timeout")), text=SCAM)
    assert result.degraded == ["llm_unavailable:timeout"]
    assert not result.llm_used
    assert result.verdict == Verdict.LIKELY_SCAM


def test_text_without_links_runs_message_only(make_service):
    result = analyze(make_service(), text="Your TurboTax account is locked. Reply now.")
    assert [m.value for m in result.modules_run] == ["message"]


def test_link_flood_is_bounded(make_service):
    text = " ".join(f"site{i}.example.com" for i in range(100))
    result = analyze(make_service(), text=text)
    assert result.module_scores  # completes; domain scoring is capped at MAX_DOMAINS
