"""S5: subdomain/suffix tricks never match the official allowlist (AC-2). Enabled in M1."""

import pytest

from scamsentinel.domain.engine import score_domain

pytestmark = pytest.mark.skip(reason="M1: domain engine not implemented yet")


@pytest.mark.parametrize(
    "host",
    ["irs.gov", "www.irs.gov", "turbotax.intuit.com", "quickbooks.intuit.com", "creditkarma.com"],
)
def test_official_domains_score_zero(host):
    result = score_domain(host)
    assert result.official
    assert result.score == 0


@pytest.mark.parametrize(
    "host",
    [
        "turbotax.com.evil.net",
        "irs.gov-refund.com",
        "irs.gov.refund-claim.net",
        "irsgov.com",
        "intuit.com.co",
        "creditkarma.com.support",
        "xn--trbotax-dza.com",
    ],
)
def test_tricks_are_not_official(host):
    result = score_domain(host)
    assert not result.official
    assert result.score > 0
