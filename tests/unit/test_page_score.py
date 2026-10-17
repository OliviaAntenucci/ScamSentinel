"""P2b page scoring (architecture.md §23): combinations count, a field alone barely does."""

from pathlib import Path

import pytest

from scamsentinel.aggregate.aggregator import aggregate
from scamsentinel.data import load_scoring
from scamsentinel.models import Module, ModuleResult, PageFinding, PageReport
from scamsentinel.page.score import credential_harvest, page_module

CONFIG = load_scoring(Path(__file__).resolve().parents[2] / "config")
POINTS = CONFIG.page_points


def report(*signals, brand=None, asks_for=(), status="analyzed"):
    return PageReport(
        requested_url="https://x.example/",
        final_url="https://x.example/",
        status=status,
        brand=brand,
        asks_for=list(asks_for),
        findings=[PageFinding(signal=s, detail=s) for s in signals],
    )


def test_brand_plus_credentials_scores_high():
    phish = report(
        "sensitive_fields", "form_posts_elsewhere", "brand_on_unofficial_page",
        brand="Apple", asks_for=["password", "verification code"],
    )
    module = page_module([phish], POINTS)
    assert module.module == Module.PAGE
    expected = (
        POINTS["field_password"] + POINTS["field_code"]
        + POINTS["form_posts_elsewhere"] + POINTS["brand_on_unofficial_page"]
    )
    assert module.score == expected
    assert {r.signal for r in module.reasons} == {
        "page_sensitive_fields", "page_form_posts_elsewhere", "page_brand_on_unofficial_page"
    }


def test_a_login_form_alone_stays_low():
    login = report("sensitive_fields", asks_for=["password"])
    assert page_module([login], POINTS).score < CONFIG.bands.suspicious


def test_field_points_are_capped():
    everything = report(
        "sensitive_fields",
        asks_for=["password", "card details", "verification code", "Social Security number"],
    )
    assert page_module([everything], POINTS).score == POINTS["fields_cap"]


@pytest.mark.parametrize("status", ["dry_run", "blocked", "failed"])
def test_pages_that_werent_analyzed_add_nothing(status):
    assert page_module([report("sensitive_fields", status=status)], POINTS) is None


def test_the_highest_scoring_page_counts():
    low = report("meta_refresh")
    high = report("brand_on_unofficial_page", brand="IRS")
    assert page_module([low, high], POINTS).score == POINTS["brand_on_unofficial_page"]


def test_credential_harvest_needs_both_brand_and_fields():
    assert credential_harvest([report(brand="Apple", asks_for=["password"])])
    assert not credential_harvest([report(brand="Apple")])
    assert not credential_harvest([report(asks_for=["password"])])


# --- in the aggregator ----------------------------------------------------------------------


def test_page_floor_lifts_a_url_with_no_brand_in_its_name():
    phish = report(
        "sensitive_fields", "brand_on_unofficial_page",
        brand="IRS", asks_for=["Social Security number"],
    )
    result = aggregate(
        domains=[], message=None, features=None, config=CONFIG,
        page=page_module([phish], POINTS), page_reports=[phish],
    )
    assert "page_credential_harvest" in result.overrides_applied
    assert result.risk_score == CONFIG.floors["page_credential_harvest"]


def test_an_empty_page_doesnt_dilute_the_message():
    message = ModuleResult(module=Module.MESSAGE, score=70, reasons=[])
    clean = report()  # analyzed, nothing found: score 0
    with_page = aggregate(
        domains=[], message=message, features=None, config=CONFIG,
        page=page_module([clean], POINTS), page_reports=[clean],
    )
    without = aggregate(domains=[], message=message, features=None, config=CONFIG)
    assert with_page.risk_score == without.risk_score == 70


def test_no_page_means_the_old_behavior():
    message = ModuleResult(module=Module.MESSAGE, score=42, reasons=[])
    result = aggregate(domains=[], message=message, features=None, config=CONFIG)
    assert result.risk_score == 42
    assert Module.PAGE not in result.modules_run
