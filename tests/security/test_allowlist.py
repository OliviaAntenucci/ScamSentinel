"""S5: subdomain/suffix tricks never match the official allowlist (AC-2)."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

OFFICIAL_DOMAINS = [
    "irs.gov",
    "turbotax.com",
    "intuit.com",
    "quickbooks.com",
    "creditkarma.com",
]


@pytest.mark.parametrize(
    "host",
    [
        "irs.gov",
        "www.irs.gov",
        "sa.www4.irs.gov",
        "https://www.irs.gov/refunds?lang=en",
        "IRS.GOV.",
        "irs.gov:443",
        "turbotax.intuit.com",
        "quickbooks.intuit.com",
        "accounts.intuit.com",
        "turbotax.com",
        "creditkarma.com",
        "www.creditkarma.com",
    ],
)
def test_official_domains_score_zero(engine, host):
    result = engine.score(host)
    assert result.official
    assert result.score == 0
    assert result.reasons[0].signal == "official_domain"


def _punycode(unicode_label: str) -> str:
    return "xn--" + unicode_label.encode("punycode").decode("ascii")


@pytest.mark.parametrize(
    "host",
    [
        "turbotax.com.evil.net",
        "irs.gov-refund.com",
        "irs.gov.refund-claim.net",
        "irsgov.com",
        "intuit.com.co",
        "creditkarma.com.support",
        _punycode("turbоtax") + ".com",  # Cyrillic о
        "turbotax.com-secure.net",
    ],
)
def test_tricks_are_not_official(engine, host):
    result = engine.score(host)
    assert not result.official
    assert result.score > 0


def test_brand_in_userinfo_does_not_fool_host_parsing(engine):
    # The real host is evil.example; "turbotax.com" is only userinfo.
    result = engine.score("https://turbotax.com@evil.example/")
    assert result.host == "evil.example"
    assert not result.official


subdomain_label = st.from_regex(r"[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", fullmatch=True)


@given(st.lists(subdomain_label, max_size=3), st.sampled_from(OFFICIAL_DOMAINS))
def test_any_subdomain_of_official_domain_is_official(engine, labels, domain):
    result = engine.score(".".join([*labels, domain]))
    assert result.official
    assert result.score == 0


@given(st.sampled_from(OFFICIAL_DOMAINS), st.sampled_from(["net", "co", "support", "evil.com"]))
def test_official_domain_used_as_subdomain_is_never_official(engine, domain, tail):
    result = engine.score(f"{domain}.{tail}")
    assert not result.official
    assert result.score > 0
