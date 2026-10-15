"""'Learn more' links (architecture.md §22)."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.data import (
    ResourcesFile,
    load_brands,
    load_categories,
    load_resources,
    load_scenarios,
)
from scamsentinel.eval.dataset import load_samples
from scamsentinel.guidance.resources import ReadingList
from scamsentinel.ingest.urls import extract_urls
from scamsentinel.models import Verdict

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
RESOURCES = load_resources(DATA_DIR)
BRANDS = load_brands(DATA_DIR)

APPLE_LOCKED = (
    "Apple: Your Apple ID has been locked. Verify your identity at "
    "appleid-unlock-support.com within 24 hours."
)


@pytest.fixture
def analyze(make_service):
    service = make_service()
    return lambda **request: service.analyze(AnalyzeRequest(**request))


def links(result) -> list[tuple[str, str]]:
    return [(r.kind, r.url) for r in result.resources]


# --- what an analysis gets ---------------------------------------------------------------


def test_apple_locked_account(analyze):
    result = analyze(text=APPLE_LOCKED)
    assert result.scenario.id == "account_locked"
    assert links(result) == [
        ("scam_type", "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams"),
        # Apple's page for exactly this situation comes before its general phishing page.
        ("official_help", "https://support.apple.com/en-us/102640"),
        ("official_help", "https://support.apple.com/en-us/102568"),
    ]
    apple = result.resources[1]
    assert apple.publisher == "Apple"
    assert apple.title == "If your Apple Account is locked, not active, or disabled"
    assert apple.last_reviewed.isoformat() == "2026-10-15"


def test_irs_refund_lure(analyze):
    result = analyze(text="IRS: your tax refund of $640 is on hold. Confirm at https://irs-refund-claim.com")
    assert [r.url for r in result.resources] == [
        "https://www.irs.gov/newsroom/tax-scams-consumer-alerts",
        "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams",
        "https://www.irs.gov/wheres-my-refund",
        "https://www.irs.gov/privacy-disclosure/report-phishing",
    ]


def test_url_input_uses_the_lookalike_brand(analyze):
    result = analyze(url="https://appleid-unlock-support.com")
    assert result.verdict != Verdict.LIKELY_LEGITIMATE
    kinds = links(result)
    # No message, so no scenario: the category's article, then Apple's general page.
    assert kinds[0] == (
        "scam_type", "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams"
    )
    assert ("official_help", "https://support.apple.com/en-us/102568") in kinds


def test_legitimate_result_gets_only_the_brands_own_help(analyze):
    result = analyze(text="Apple: Your receipt is ready. View it at https://www.apple.com/account")
    assert result.verdict == Verdict.LIKELY_LEGITIMATE
    assert links(result) == [("official_help", "https://support.apple.com/en-us/102568")]


def test_brand_without_help_pages_still_gets_the_scam_article(analyze):
    # Credit Karma has no official help entry.
    result = analyze(
        text="Credit Karma: confirm your SSN at https://creditkarma-verify-id.com today"
    )
    assert [r.kind for r in result.resources] == ["scam_type"]


def test_links_never_come_from_the_message(make_service):
    """For every eval sample: each link is from resources.yaml, never one in the input."""
    curated = {a.url for a in RESOURCES.articles.values()} | {
        p.url for pages in RESOURCES.official_help.values() for p in pages
    }
    service = make_service()
    field = {"text": "text", "url": "url", "email": "email_raw"}
    for sample in load_samples(DATA_DIR / "eval" / "samples.jsonl"):
        try:
            result = service.analyze(AnalyzeRequest(**{field[sample.input_type]: sample.content}))
        except ValueError:
            continue
        in_message = set(extract_urls(sample.content))
        for resource in result.resources:
            assert resource.url in curated, (sample.id, resource.url)
            assert resource.url not in in_message, sample.id
            assert resource.url.startswith("https://")


# --- selection ---------------------------------------------------------------------------


def reading() -> ReadingList:
    return ReadingList(RESOURCES, BRANDS, [s.id for s in load_scenarios(DATA_DIR)])


def test_category_fallback_and_default():
    by_category = reading().build(
        verdict=Verdict.SUSPICIOUS, entity=None, category="job", scenario=None
    )
    assert [r.url for r in by_category] == ["https://consumer.ftc.gov/articles/job-scams"]
    default = reading().build(
        verdict=Verdict.SUSPICIOUS, entity=None, category=None, scenario=None
    )
    assert [r.url for r in default] == [
        "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams"
    ]


def test_legitimate_without_brand_gets_nothing():
    assert reading().build(
        verdict=Verdict.LIKELY_LEGITIMATE, entity=None, category=None, scenario=None
    ) == []


# --- the data file -----------------------------------------------------------------------


def test_every_scenario_and_category_has_an_article():
    assert {s.id for s in load_scenarios(DATA_DIR)} == set(RESOURCES.scam_types.scenarios)
    assert set(load_categories(DATA_DIR)) == set(RESOURCES.scam_types.categories)


def _raw():
    return RESOURCES.model_dump(mode="json")


def test_article_must_be_on_a_trusted_domain():
    raw = _raw()
    raw["articles"]["ftc_phishing"]["url"] = "https://example.com/phishing"
    with pytest.raises(ValidationError, match="trusted domain"):
        ResourcesFile.model_validate(raw)


def test_urls_must_be_https():
    raw = _raw()
    raw["articles"]["ftc_phishing"]["url"] = "http://consumer.ftc.gov/x"
    with pytest.raises(ValidationError, match="https"):
        ResourcesFile.model_validate(raw)


def test_unknown_article_id_is_rejected():
    raw = _raw()
    raw["scam_types"]["default"] = ["no_such_article"]
    with pytest.raises(ValidationError, match="unknown article"):
        ResourcesFile.model_validate(raw)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda r: r["official_help"]["Apple"][0].update(url="https://apple-help.example/x"),
         "official domains"),
        (lambda r: r["official_help"].update({"Acme Bank": []}), "unknown brands"),
        (lambda r: r["scam_types"]["scenarios"].update({"no_such": ["ftc_phishing"]}),
         "unknown scenarios"),
        (lambda r: r["scam_types"]["categories"].update({"no_such": ["ftc_phishing"]}),
         "unknown categories"),
    ],
)
def test_reading_list_validation(change, message):
    raw = _raw()
    change(raw)
    with pytest.raises(ValueError, match=message):
        ReadingList(
            ResourcesFile.model_validate(raw), BRANDS, [s.id for s in load_scenarios(DATA_DIR)]
        )
