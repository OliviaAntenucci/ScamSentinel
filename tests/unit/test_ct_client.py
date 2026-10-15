import json

import httpx
import pytest

from scamsentinel.ct import client as ct_client
from scamsentinel.ct.client import (
    CRTSH_URL,
    USER_AGENT,
    CrtShClient,
    CtUnavailable,
    normalize_name,
    parse_entries,
)


def crtsh_row(cert_id=1, names="turbotax-refund.com", issuer="C=US, O=Let's Encrypt, CN=R11"):
    return {
        "id": cert_id,
        "issuer_name": issuer,
        "common_name": names.splitlines()[0],
        "name_value": names,
        "not_before": "2026-10-14T08:00:00",
        "not_after": "2027-01-12T08:00:00",
    }


class FakeTime:
    """Stands in for time.sleep / time.monotonic, so tests never wait."""

    def __init__(self):
        self.now = 1000.0
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def clock(self) -> float:
        return self.now


def make_client(responses, fake_time=None, **kwargs):
    """CrtShClient over a mock transport that replays `responses` in order."""
    requests: list[httpx.Request] = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        response = queue.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    fake_time = fake_time or FakeTime()
    client = CrtShClient(
        transport=httpx.MockTransport(handler),
        sleep=fake_time.sleep,
        clock=fake_time.clock,
        **kwargs,
    )
    return client, requests, fake_time


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("TurboTax-Refund.com", "turbotax-refund.com"),
        ("*.irs-verify.net", "irs-verify.net"),
        ("login.irs-verify.net.", "login.irs-verify.net"),
        ("xn--trbotax-x2a.com", "xn--trbotax-x2a.com"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("admin@turbotax-refund.com", None),
        ("192.168.0.1", None),
        ("turbotax refund.com", None),
        ("türbotax.com", None),  # certificates carry IDNs as punycode
        ("localhost", None),
        ("-bad-.com", None),
        ("a" * 64 + ".com", None),
        ("", None),
    ],
)
def test_normalize_name(raw, expected):
    assert normalize_name(raw) == expected


def test_parse_entries_splits_sans_and_dedupes():
    rows = [
        crtsh_row(1, "turbotax-refund.com\n*.turbotax-refund.com\nwww.turbotax-refund.com"),
        crtsh_row(2, "irs-verify.net\nadmin@irs-verify.net"),
    ]
    entries = parse_entries(rows)
    assert [(e.cert_id, e.name) for e in entries] == [
        (1, "turbotax-refund.com"),
        (1, "www.turbotax-refund.com"),
        (2, "irs-verify.net"),
    ]
    assert entries[0].issuer == "C=US, O=Let's Encrypt, CN=R11"
    assert entries[0].not_before == "2026-10-14T08:00:00"


def test_parse_entries_skips_malformed_rows():
    rows = [
        "not a row",
        {"id": "7", "name_value": "irs-verify.net"},
        {"id": True, "name_value": "irs-verify.net"},
        {"id": 3},
        {"id": 4, "name_value": "irs-verify.net", "issuer_name": "x" * 10_000},
    ]
    entries = parse_entries(rows)
    assert [(e.cert_id, e.name) for e in entries] == [(4, "irs-verify.net")]
    assert len(entries[0].issuer) == ct_client.MAX_FIELD_CHARS


def test_parse_entries_rejects_non_list():
    with pytest.raises(CtUnavailable, match="malformed_response"):
        parse_entries({"error": "nope"})


def test_search_sends_polite_request():
    client, requests, _ = make_client([httpx.Response(200, json=[crtsh_row()])])
    entries = client.search("%turbotax%")

    assert [e.name for e in entries] == ["turbotax-refund.com"]
    (request,) = requests
    assert str(request.url).startswith(CRTSH_URL + "?")
    assert dict(request.url.params) == {
        "q": "%turbotax%",
        "output": "json",
        "exclude": "expired",
        "deduplicate": "Y",
    }
    assert request.headers["user-agent"] == USER_AGENT


def test_empty_body_means_no_results():
    client, _, _ = make_client([httpx.Response(200, content=b"")])
    assert client.search("%creditkarma%") == []


def test_requests_are_spaced():
    fake_time = FakeTime()
    client, requests, _ = make_client(
        [httpx.Response(200, json=[]), httpx.Response(200, json=[])],
        fake_time,
        spacing=10.0,
    )
    client.search("%turbotax%")
    fake_time.now += 3  # some time passes between queries
    client.search("%quickbooks%")
    assert len(requests) == 2
    assert fake_time.sleeps == [pytest.approx(7.0)]


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_retries_with_exponential_backoff(status):
    client, requests, fake_time = make_client(
        [httpx.Response(status), httpx.Response(status), httpx.Response(200, json=[crtsh_row()])],
        spacing=0,
        backoff_base=30,
    )
    assert len(client.search("%turbotax%")) == 1
    assert len(requests) == 3
    assert fake_time.sleeps == [30, 60]


def test_retry_after_is_honored():
    client, _, fake_time = make_client(
        [httpx.Response(429, headers={"Retry-After": "120"}), httpx.Response(200, json=[])],
        spacing=0,
        backoff_base=30,
    )
    client.search("%turbotax%")
    assert fake_time.sleeps == [120]


def test_backoff_is_capped():
    client, _, fake_time = make_client(
        [httpx.Response(429, headers={"Retry-After": "86400"}), httpx.Response(200, json=[])],
        spacing=0,
    )
    client.search("%turbotax%")
    assert fake_time.sleeps == [ct_client.MAX_BACKOFF_SECONDS]


def test_gives_up_after_max_attempts():
    client, requests, _ = make_client(
        [httpx.Response(503)] * 3, spacing=0, max_attempts=3
    )
    with pytest.raises(CtUnavailable, match="http_503"):
        client.search("%turbotax%")
    assert len(requests) == 3


@pytest.mark.parametrize(
    ("error", "reason"),
    [(httpx.ReadTimeout("slow"), "timeout"), (httpx.ConnectError("down"), "network_error")],
)
def test_network_failures_are_retried_then_reported(error, reason):
    client, requests, _ = make_client([error, error], spacing=0, max_attempts=2)
    with pytest.raises(CtUnavailable, match=reason):
        client.search("%turbotax%")
    assert len(requests) == 2


@pytest.mark.parametrize("status", [301, 400, 403, 404])
def test_other_statuses_fail_without_retry(status):
    client, requests, _ = make_client([httpx.Response(status, headers={"Location": "/x"})])
    with pytest.raises(CtUnavailable, match=f"http_{status}"):
        client.search("%turbotax%")
    assert len(requests) == 1  # redirects are not followed either


def test_malformed_json_is_reported():
    client, _, _ = make_client([httpx.Response(200, content=b"<html>crt.sh is busy</html>")])
    with pytest.raises(CtUnavailable, match="malformed_response"):
        client.search("%turbotax%")


def test_oversized_response_is_refused(monkeypatch):
    monkeypatch.setattr(ct_client, "MAX_RESPONSE_BYTES", 1_000)
    body = json.dumps([crtsh_row(i) for i in range(100)]).encode()
    client, _, _ = make_client([httpx.Response(200, content=body)])
    with pytest.raises(CtUnavailable, match="response_too_large"):
        client.search("%turbotax%")
