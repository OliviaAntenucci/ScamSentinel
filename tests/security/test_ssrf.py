"""S1: SSRF (SECURITY.md T1).

The MVP never fetches user-supplied URLs, so SSRF can't happen there; the M4 test
that proves this lives with the pipeline tests. These guard tests are for post-MVP
page fetching (P2) and are enabled when the URL guard lands.
"""

from pathlib import Path

import pytest

from scamsentinel.security.url_guard import UrlRejected, validate_url

pytestmark = pytest.mark.skip(reason="P2 (post-MVP): URL guard not implemented yet")

PAYLOADS_FILE = Path(__file__).with_name("ssrf_payloads.txt")


def load_payloads() -> list[str]:
    lines = PAYLOADS_FILE.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


@pytest.mark.parametrize("url", load_payloads())
def test_payload_rejected(url):
    with pytest.raises(UrlRejected):
        validate_url(url)


def test_hostname_resolving_to_private_ip_rejected():
    raise NotImplementedError("P2: mock resolver returning 10.0.0.5 for a public-looking name")


def test_dns_rebinding_resolves_once():
    raise NotImplementedError("P2: resolver answering public then private; assert one lookup")


def test_redirect_to_metadata_blocked_mid_chain():
    raise NotImplementedError("P2: local server returning 302 -> http://169.254.169.254/")
