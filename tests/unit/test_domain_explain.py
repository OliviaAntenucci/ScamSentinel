"""E2: richer domain explanations (architecture.md §19)."""

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.domain.explain import (
    DomainExplanation,
    SpellingEdit,
    character_swaps,
    spelling_edits,
)
from scamsentinel.models import AnalysisResult, Verdict
from scamsentinel.security.redaction import SSN_PLACEHOLDER, redact_result


def explain(engine, host) -> DomainExplanation:
    explanation = engine.score(host).explanation
    assert explanation is not None, host
    return explanation


def swaps(engine, host) -> list[tuple[str, str]]:
    return [(s.found, s.instead_of) for s in explain(engine, host).swapped_characters]


# --- lookalike characters ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("turb0tax.com", [("0", "o")]),
        ("1rs-refund.com", [("1", "i")]),
        ("bankofarnerica.com", [("rn", "m")]),
        ("wellsfarg0-online.com", [("0", "o")]),
        ("turbоtax.com", [("о", "o")]),  # Cyrillic о
        ("іrs-refund.com", [("і", "i")]),  # Cyrillic і
        ("usрs-delivery.com", [("р", "p")]),  # Cyrillic р
    ],
)
def test_swapped_characters_are_named(engine, host, expected):
    assert swaps(engine, host) == expected


def test_non_ascii_swaps_carry_their_unicode_name(engine):
    swap = explain(engine, "turbоtax.com").swapped_characters[0]
    assert swap.unicode_names == ["CYRILLIC SMALL LETTER O"]
    assert "Cyrillic" in explain(engine, "turbоtax.com").summary[0]


def test_punycode_is_explained_as_the_decoded_characters(engine):
    label = "xn--" + "turbоtax".encode("punycode").decode("ascii")
    assert swaps(engine, f"{label}.com") == [("о", "o")]


def test_ascii_swaps_say_digit(engine):
    assert "the digit '0' instead of 'o'" in explain(engine, "turb0tax.com").summary[0]


# --- misspellings -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "misspelled", "edits"),
    [
        ("turbotxa.com", "turbotxa", [SpellingEdit(kind="swapped", found="xa", expected="ax")]),
        ("quickbook.com", "quickbook", [SpellingEdit(kind="missing", expected="s")]),
        ("turbotaxx.com", "turbotaxx", [SpellingEdit(kind="extra", found="x")]),
        ("quickbooks1.com", "quickbooks1", [SpellingEdit(kind="extra", found="1")]),
        (
            "turbotzx.com",
            "turbotzx",
            [SpellingEdit(kind="replaced", found="z", expected="a")],
        ),
    ],
)
def test_misspellings_are_spelled_out(engine, host, misspelled, edits):
    e = explain(engine, host)
    assert e.misspelled == misspelled
    assert e.spelling_edits == edits


def test_misspelling_summary(engine):
    summary = explain(engine, "turbotxa.com").summary
    assert "Misspells TurboTax: 'turbotxa' has 'a' and 'x' swapped." in summary


def test_misspelling_with_trust_words(engine):
    e = explain(engine, "turbotxa-refund.com")
    assert e.misspelled == "turbotxa"
    assert e.extra_words == ["refund"]


def test_spelling_edits_of_identical_strings_is_empty():
    assert spelling_edits("turbotax", "turbotax") == []


# --- trust words, real owner, wrong ending ----------------------------------------------


def test_extra_words(engine):
    e = explain(engine, "turbotax-refund-secure.com")
    assert e.extra_words == ["refund", "secure"]
    assert not e.swapped_characters and not e.misspelled
    assert "refund, secure" in e.summary[0]


@pytest.mark.parametrize(
    ("host", "owner"),
    [
        ("turbotax.com.evil.net", "evil.net"),
        ("irs.gov.refund-claim.net", "refund-claim.net"),
        ("usps.com-trackhelp.xyz", "com-trackhelp.xyz"),
    ],
)
def test_real_owner_of_a_brand_in_subdomain(engine, host, owner):
    e = explain(engine, host)
    assert e.real_owner == owner
    assert any(f"actually belongs to {owner}" in line for line in e.summary)


def test_wrong_ending(engine):
    e = explain(engine, "turbotax.net")
    assert e.wrong_ending == ".net"
    assert "Uses the TurboTax name with a different ending: .net (turbotax.com)." in e.summary


def test_plain_brand_use_still_explained(engine):
    e = explain(engine, "myturbotaxfiling.com")
    assert e.summary[0] == (
        "Uses the TurboTax name, but myturbotaxfiling.com is not a TurboTax domain."
    )


def test_readme_example(engine):
    e = explain(engine, "turb0tax-refund.com")
    assert e.summary == [
        "Uses lookalike characters to imitate TurboTax: the digit '0' instead of 'o'.",
        "Adds words that sound official to the TurboTax name: refund.",
        "TurboTax's official sites: turbotax.com, intuit.com.",
    ]


def test_summary_ends_with_the_official_sites(engine):
    assert explain(engine, "irs-refund-secure.com").summary[-1] == "IRS's official sites: irs.gov."


@pytest.mark.parametrize("host", ["turbotax.com", "irs.gov", "google.com", "purchase.edu"])
def test_no_explanation_for_official_or_clean_domains(engine, host):
    assert engine.score(host).explanation is None


# --- in an analysis ---------------------------------------------------------------------


def test_analysis_lists_explanations(make_service):
    text = "IRS: confirm at https://1rs-refund.com or https://turbotax.com.evil.net/x today"
    result = make_service().analyze(AnalyzeRequest(text=text))
    domains = [e.domain for e in result.domain_explanations]
    assert set(domains) == {"1rs-refund.com", "evil.net"}


def test_official_links_get_no_explanation(make_service):
    result = make_service().analyze(AnalyzeRequest(url="https://www.irs.gov/refunds"))
    assert result.domain_explanations == []


def test_explanations_are_redacted():
    e = DomainExplanation(
        domain="078-05-1120.com", brand="IRS", official_domains=["irs.gov"],
        summary=["Uses the IRS name, but 078-05-1120.com is not an IRS domain."],
    )
    result = AnalysisResult(
        analysis_id="an_" + "0" * 32, created_at=datetime.now(UTC), input_type="url",
        verdict=Verdict.SUSPICIOUS, risk_score=50, domain_explanations=[e],
    )
    redacted = redact_result(result).domain_explanations[0]
    assert redacted.domain == f"{SSN_PLACEHOLDER}.com"
    assert "078-05-1120" not in redacted.summary[0]


# --- robustness -------------------------------------------------------------------------


@given(st.text(max_size=40), st.sampled_from(["turbotax", "irs", "bankofamerica", "usps"]))
def test_character_swaps_never_crash(engine, label, token):
    for swap in character_swaps(engine._norm, label, token):
        assert swap.found and swap.instead_of
