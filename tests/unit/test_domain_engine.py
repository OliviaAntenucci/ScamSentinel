"""Lookalike-domain engine: one case per technique, a generated lookalike suite (AC-2),
negatives that must stay clean, and fuzzing."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.models import Module

CYRILLIC = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р", "i": "і"}
DIGITS = {"o": "0", "i": "1", "a": "4"}


def punycode(label: str) -> str:
    return "xn--" + label.encode("punycode").decode("ascii")


# --- one example per technique ----------------------------------------------------


@pytest.mark.parametrize(
    ("host", "technique", "brand"),
    [
        ("turbotax-refund-secure.com", "brand_plus_keywords", "TurboTax"),
        ("irs-refund-secure.com", "brand_plus_keywords", "IRS"),
        ("irsgov-refund.com", "brand_plus_keywords", "IRS"),
        ("irs2024-refund.com", "brand_plus_keywords", "IRS"),
        ("turb0tax.com", "homoglyph", "TurboTax"),
        ("turbоtax.com", "homoglyph", "TurboTax"),
        ("turbotxa.com", "typosquat", "TurboTax"),
        ("quickbook.com", "typosquat", "QuickBooks"),
        ("turbotax.com.evil.net", "brand_in_subdomain", "TurboTax"),
        ("irs.gov.refund-claim.net", "brand_in_subdomain", "IRS"),
        ("irs.gov.co", "tld_swap", "IRS"),
        ("turbotax.net", "tld_swap", "TurboTax"),
        ("turbo-tax.com", "exact_brand_unofficial", "TurboTax"),
        ("credit-karma.com", "exact_brand_unofficial", "Credit Karma"),
        ("myturbotaxfiling.com", "brand_in_label", "TurboTax"),
    ],
)
def test_technique_fires(engine, host, technique, brand):
    result = engine.score(host)
    assert technique in result.techniques
    assert result.brand == brand
    assert not result.official
    assert result.score >= 50


@pytest.mark.parametrize(
    ("host", "brand"),
    [("turbotaxx.com", "TurboTax"), ("creditkarmaa.com", "Credit Karma"),
     ("quickbooks1.com", "QuickBooks")],
)
def test_brand_with_stray_characters_is_a_typosquat(engine, host, brand):
    result = engine.score(host)
    assert result.techniques == ["typosquat"]
    assert result.brand == brand
    assert result.score >= 60


def test_brand_inside_a_longer_name_is_not_a_typosquat(engine):
    assert engine.score("myturbotaxfiling.com").techniques == ["brand_in_label"]


def test_mixed_script_adds_bonus(engine):
    result = engine.score("turbоtax.com")
    assert "idn_mixed_script" in result.techniques
    assert result.score == 100


def test_reasons_explain_every_technique(engine):
    result = engine.score("turbotax-refund-secure.com")
    assert {r.signal for r in result.reasons} == set(result.techniques)
    assert all(r.module == Module.DOMAIN for r in result.reasons)
    assert "refund" in result.reasons[0].detail
    assert "secure" in result.reasons[0].detail


def test_keyword_stuffing_scales_with_keywords(engine):
    one = engine.score("turbotax-refund.com").score
    two = engine.score("turbotax-refund-secure.com").score
    three = engine.score("turbotax-refund-secure-login.com").score
    assert one < two < three


def test_ip_literal_is_neutral(engine):
    result = engine.score("http://192.0.2.10/login")
    assert result.score == 0
    assert result.reasons[0].signal == "ip_address_host"


def test_bare_public_suffix_rejected(engine):
    with pytest.raises(InvalidHost):
        engine.score("co.uk")


# --- generated lookalike suite (AC-2: >= 95% recall; we require all of them) -------

LONG_TOKENS = {
    "turbotax": "TurboTax",
    "quickbooks": "QuickBooks",
    "creditkarma": "Credit Karma",
    "intuit": "TurboTax",
}
OFFICIAL = {
    "turbotax": "turbotax.com",
    "quickbooks": "quickbooks.com",
    "creditkarma": "creditkarma.com",
    "intuit": "intuit.com",
}


def _replace_first(token: str, table: dict[str, str]) -> str:
    for i, ch in enumerate(token):
        if ch in table:
            return token[:i] + table[ch] + token[i + 1 :]
    raise AssertionError(f"no substitutable character in {token}")


def _typos(token: str) -> list[str]:
    mid = len(token) // 2
    swap = next(i for i in range(mid, len(token) - 1) if token[i] != token[i + 1])
    return [
        token[:mid] + token[mid + 1 :],  # deletion
        token[:mid] + token[mid] + token[mid:],  # duplication
        token[:swap] + token[swap + 1] + token[swap] + token[swap + 2 :],  # transposition
        token[:mid] + ("z" if token[mid] != "z" else "q") + token[mid + 1 :],  # substitution
    ]


def _generated_cases():
    for token, brand in LONG_TOKENS.items():
        cyr = _replace_first(token, CYRILLIC)
        yield f"{cyr}.com", brand
        yield f"{punycode(cyr)}.com", brand
        yield f"{_replace_first(token, DIGITS)}.com", brand
        for typo in _typos(token):
            yield f"{typo}.com", brand
        yield f"{token}-refund.com", brand
        yield f"{token}-secure-login.com", brand
        yield f"verify-{token}-account.net", brand
        yield f"{OFFICIAL[token]}.account-verify.net", brand
    for host in [
        "1rs-refund.com",
        "іrs-refund.com",
        f"{punycode(chr(0x456) + 'rs-refund')}.com",
        "irs-refund.com",
        "irs-verify-account.net",
        "irsgov.com",
        "secure-irs-gov.com",
        "irs.gov.claim-refund.net",
        "irs.gov.co",
    ]:
        yield host, "IRS"


@pytest.mark.parametrize(("host", "brand"), list(_generated_cases()))
def test_generated_lookalike_is_flagged(engine, host, brand):
    result = engine.score(host)
    assert not result.official
    assert result.brand == brand
    assert result.score >= 60, result.reasons


# --- negatives: legitimate domains that must stay clean -------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "firstbank.com",
        "shirts.com",
        "theirs.net",
        "chairs.org",
        "taxact.com",
        "hrblock.com",
        "intuition.com",
        "tuition.edu",
        "refund-status-center.com",
        "google.com",
        "example.org",
        "turbine-parts.com",
    ],
)
def test_unrelated_domains_stay_clean(engine, host):
    result = engine.score(host)
    assert not result.official
    assert result.score == 0, result.reasons
    assert result.reasons[0].signal == "no_lookalike_signals"


# --- fuzzing ----------------------------------------------------------------------------


@given(st.text(max_size=120))
def test_score_never_crashes(engine, s):
    try:
        result = engine.score(s)
    except InvalidHost:
        return
    assert 0 <= result.score <= 100
    assert result.reasons
