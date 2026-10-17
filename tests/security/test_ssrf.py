"""S6: SSRF URL guard (SECURITY.md T1, architecture.md §23).

Every payload must be rejected, and none of them may even reach DNS. Hostname cases use
a fake resolver; redirect and rebinding cases use a mock transport. No test here makes a
real DNS lookup or connection.
"""

import ipaddress
from pathlib import Path

import httpx
import pytest

from scamsentinel.page.fetch import PageFetcher
from scamsentinel.security.url_guard import UrlRejected, is_public, validate_url

PAYLOADS_FILE = Path(__file__).with_name("ssrf_payloads.txt")
PUBLIC_IP = "93.184.216.34"


def load_payloads() -> list[str]:
    lines = PAYLOADS_FILE.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def no_dns(host: str, port: int):
    raise AssertionError(f"the resolver must not be called for this payload ({host})")


def resolver_for(table: dict[str, list[str]], calls: list[str] | None = None):
    def resolve(host: str, port: int) -> list[str]:
        if calls is not None:
            calls.append(host)
        return table[host]

    return resolve


@pytest.mark.parametrize("url", load_payloads())
def test_payload_rejected_without_dns(url):
    with pytest.raises(UrlRejected):
        validate_url(url, resolver=no_dns)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("2852039166", "169.254.169.254"),
        ("0xA9FEA9FE", "169.254.169.254"),
        ("0251.0376.0251.0376", "169.254.169.254"),
        ("169.254.43518", "169.254.169.254"),
        ("127.1", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
    ],
)
def test_legacy_ipv4_forms_are_read_as_the_address_they_are(host, expected):
    with pytest.raises(UrlRejected) as exc:
        validate_url(f"http://{host}/", resolver=no_dns)
    assert expected in str(exc.value)


def test_hostname_resolving_to_private_ip_rejected():
    resolve = resolver_for({"innocent.example": ["10.0.0.5"]})
    with pytest.raises(UrlRejected) as exc:
        validate_url("https://innocent.example/login", resolver=resolve)
    assert exc.value.reason == "non_public_address"


def test_any_private_address_among_several_is_enough_to_reject():
    resolve = resolver_for({"mixed.example": [PUBLIC_IP, "127.0.0.1"]})
    with pytest.raises(UrlRejected, match="non_public_address"):
        validate_url("https://mixed.example/", resolver=resolve)


@pytest.mark.parametrize(
    "address",
    ["::ffff:127.0.0.1", "::ffff:169.254.169.254", "fd00:ec2::254", "100.64.0.1", "224.0.1.1",
     "2002:a9fe:a9fe::1", "0.0.0.0"],
)
def test_resolved_addresses_that_arent_public(address):
    assert not is_public(ipaddress.ip_address(address))
    resolve = resolver_for({"x.example": [address]})
    with pytest.raises(UrlRejected):
        validate_url("https://x.example/", resolver=resolve)


def test_public_host_is_pinned():
    target = validate_url(
        "https://Example.com/path?q=1#frag", resolver=resolver_for({"example.com": [PUBLIC_IP]})
    )
    assert target.pinned_url == f"https://{PUBLIC_IP}/path?q=1"
    assert target.host_header == "example.com"
    assert target.url == "https://example.com/path?q=1"


def test_unicode_hostname_is_idna_encoded():
    # The Cyrillic "р" lookalike is resolved, and connected to, in its punycode form.
    calls: list[str] = []

    def resolve(host: str, port: int) -> list[str]:
        calls.append(host)
        return [PUBLIC_IP]

    target = validate_url("https://usрs-delivery.com/", resolver=resolve)
    assert calls[0].startswith("xn--") and calls[0].isascii()
    assert target.host == calls[0]
    assert target.host_header == calls[0]


def test_allow_private_is_only_for_local_fixtures():
    target = validate_url(
        "http://fixture.test:8081/", allow_private=True,
        resolver=resolver_for({"fixture.test": ["127.0.0.1"]}), allowed_ports=frozenset({8081}),
    )
    assert str(target.pinned_ip) == "127.0.0.1"


# --- through the fetcher: rebinding and redirects ----------------------------------------


def test_dns_rebinding_resolves_once():
    # A rebinding DNS server answers "public" first and "private" afterwards. The
    # fetcher resolves once, checks that answer, and connects to exactly that IP.
    answers = iter([[PUBLIC_IP], ["127.0.0.1"]])
    calls: list[str] = []

    def rebinding(host: str, port: int) -> list[str]:
        calls.append(host)
        return next(answers)

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<p>hi</p>")

    page = PageFetcher(
        mode="live", resolver=rebinding, transport=httpx.MockTransport(handler)
    ).fetch("https://rebind.example/")
    assert page.error is None
    assert calls == ["rebind.example"]
    assert seen[0].url.host == PUBLIC_IP
    assert seen[0].headers["host"] == "rebind.example"
    assert seen[0].extensions["sni_hostname"] == "rebind.example"


def test_redirect_to_metadata_blocked_mid_chain():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    page = PageFetcher(
        mode="live",
        resolver=resolver_for({"start.example": [PUBLIC_IP]}),
        transport=httpx.MockTransport(handler),
    ).fetch("https://start.example/")
    assert page.error == "blocked:non_public_address"
    assert len(seen) == 1  # the metadata address was never requested
    assert page.redirects == ["http://169.254.169.254/latest/meta-data/"]


def test_redirect_to_a_name_that_resolves_private_is_blocked():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"location": "https://internal.example/admin"})

    page = PageFetcher(
        mode="live",
        resolver=resolver_for({"start.example": [PUBLIC_IP], "internal.example": ["192.168.1.10"]}),
        transport=httpx.MockTransport(handler),
    ).fetch("https://start.example/")
    assert page.error == "blocked:non_public_address"
