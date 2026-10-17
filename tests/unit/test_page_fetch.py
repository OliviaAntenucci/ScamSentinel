"""P2 page fetcher (architecture.md §23).

Live mode is tested only through httpx.MockTransport and fake resolvers: no test here
makes a real DNS lookup or connection.
"""

import gzip
import socket
import sys

import httpx
import pytest

from scamsentinel.page.fetch import USER_AGENT, PageFetcher
from scamsentinel.security.egress import EgressBlocked

PUBLIC_IP = "93.184.216.34"
HTML = {"content-type": "text/html; charset=utf-8"}


def resolver(host: str, port: int) -> list[str]:
    return [PUBLIC_IP]


def live(handler, **kwargs) -> PageFetcher:
    return PageFetcher(
        mode="live", resolver=resolver, transport=httpx.MockTransport(handler), **kwargs
    )


@pytest.fixture
def no_network(monkeypatch):
    def tripwire(*args, **kwargs):
        raise AssertionError(f"network access attempted: {args!r}")

    monkeypatch.setattr(socket, "getaddrinfo", tripwire)
    monkeypatch.setattr(socket, "create_connection", tripwire)
    monkeypatch.setattr(socket.socket, "connect", tripwire)


# --- dry run: the default mode never touches the network ---------------------------------


def test_default_mode_is_dry_run():
    assert PageFetcher().mode == "dry_run"


@pytest.mark.parametrize(
    "url", ["https://appleid-unlock-support.com/login", "http://93.184.216.34/", "https://usрs.com/"]
)
def test_dry_run_checks_but_never_resolves_or_connects(no_network, url):
    page = PageFetcher(mode="dry_run").fetch(url)
    assert page.error == "dry_run"
    assert page.html is None


@pytest.mark.parametrize(
    "url", ["http://169.254.169.254/", "http://2130706433/", "file:///etc/passwd",
            "https://example.com:6379/", "https://user@example.com/"],
)
def test_dry_run_still_reports_blocked_urls(no_network, url):
    assert PageFetcher(mode="dry_run").fetch(url).error.startswith("blocked:")


# --- live mode (mocked) ----------------------------------------------------------------------


def test_fetches_html_with_fixed_headers_only():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, headers=HTML, text="<title>Hi</title>")

    page = live(handler).fetch("https://example.com/login")
    assert page.error is None
    assert page.html == "<title>Hi</title>"
    assert page.final_url == "https://example.com/login"
    request = seen[0]
    assert request.method == "GET"
    assert request.url.host == PUBLIC_IP  # the pinned IP, not the name
    assert request.headers["host"] == "example.com"
    assert request.extensions["sni_hostname"] == "example.com"
    assert request.headers["user-agent"] == USER_AGENT
    assert request.headers["accept-encoding"] == "gzip, deflate"
    assert "cookie" not in request.headers
    assert "authorization" not in request.headers


def test_relative_redirects_are_followed_and_revalidated():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/next"})
        if request.url.path == "/next":
            return httpx.Response(301, headers={"location": "https://final.example/page"})
        return httpx.Response(200, headers=HTML, text="ok")

    page = live(handler).fetch("https://start.example/start")
    assert page.redirects == ["https://start.example/next", "https://final.example/page"]
    assert page.final_url == "https://final.example/page"
    assert page.html == "ok"


def test_too_many_redirects():
    page = live(lambda r: httpx.Response(302, headers={"location": "/again"}), max_redirects=3)
    result = page.fetch("https://loop.example/")
    assert result.error == "too_many_redirects"
    assert len(result.redirects) == 4


def test_cookies_are_never_sent_on_to_the_next_hop():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/b", "set-cookie": "sid=abc; Path=/"})
        return httpx.Response(200, headers=HTML, text="ok")

    live(handler).fetch("https://example.com/")
    assert "cookie" not in seen[1].headers


@pytest.mark.parametrize(
    ("status", "headers", "error"),
    [
        (404, HTML, "http_404"),
        (200, {"content-type": "application/pdf"}, "not_html"),
        (200, {"content-type": "text/html", "content-encoding": "br"}, "unsupported_encoding"),
    ],
)
def test_responses_that_arent_analyzed(status, headers, error):
    page = live(lambda r: httpx.Response(status, headers=headers, content=b"x")).fetch(
        "https://example.com/"
    )
    assert page.error == error
    assert page.html is None


def test_body_is_capped():
    body = b"a" * 50_000
    page = live(lambda r: httpx.Response(200, headers=HTML, content=body), max_bytes=10_000)
    result = page.fetch("https://example.com/")
    assert result.truncated
    assert len(result.html) == 10_000


def test_gzip_bomb_cannot_expand_past_the_cap():
    bomb = gzip.compress(b"\0" * 20_000_000)  # about 20 KB on the wire
    assert len(bomb) < 100_000
    headers = {**HTML, "content-encoding": "gzip"}
    page = live(lambda r: httpx.Response(200, headers=headers, content=bomb), max_bytes=10_000)
    result = page.fetch("https://example.com/")
    assert result.truncated
    assert len(result.html) == 10_000


def test_gzip_page_is_decoded():
    headers = {**HTML, "content-encoding": "gzip"}
    body = gzip.compress(b"<p>Sign in</p>")
    page = live(lambda r: httpx.Response(200, headers=headers, content=body)).fetch(
        "https://example.com/"
    )
    assert page.html == "<p>Sign in</p>"
    assert not page.truncated


@pytest.mark.parametrize(
    ("exception", "error"),
    [(httpx.ConnectTimeout("t"), "timeout"), (httpx.ReadTimeout("t"), "timeout"),
     (httpx.ConnectError("refused"), "unreachable")],
)
def test_network_failures_are_reported(exception, error):
    def handler(request):
        raise exception

    assert live(handler).fetch("https://example.com/").error == error


def test_one_deadline_for_the_whole_fetch():
    ticks = iter([0.0, 0.0, 100.0, 100.0, 100.0])
    page = live(
        lambda r: httpx.Response(200, headers=HTML, text="x"), timeout=5, clock=lambda: next(ticks)
    ).fetch("https://example.com/")
    assert page.error == "timeout"


def test_blocked_url_is_reported_with_the_guard_reason():
    page = PageFetcher(mode="live").fetch("http://169.254.169.254/latest/meta-data/")
    assert page.error == "blocked:non_public_address"
    assert page.html is None


# --- fallbacks: egress lock, circuit breaker, rate limit -------------------------------------


def test_egress_lock_is_active_during_the_request():
    observed: list[str] = []

    def handler(request):
        sys.audit("socket.connect", None, (PUBLIC_IP, 443))  # the pinned address: allowed
        try:
            sys.audit("socket.connect", None, ("10.0.0.1", 80))
        except EgressBlocked:
            observed.append("blocked")
        return httpx.Response(200, headers=HTML, text="ok")

    page = live(handler).fetch("https://example.com/")
    assert observed == ["blocked"]
    assert page.html == "ok"


def test_circuit_breaker_turns_live_fetching_off():
    calls: list[str] = []

    def handler(request):
        calls.append(str(request.url))
        # Something below the guard tried to go elsewhere: the egress lock fires.
        sys.audit("socket.connect", None, ("169.254.169.254", 80))
        return httpx.Response(200, headers=HTML, text="never read")

    fetcher = live(handler)
    first = fetcher.fetch("https://example.com/")
    assert first.error == "blocked:egress"
    assert fetcher.tripped
    second = fetcher.fetch("https://example.com/other")
    assert second.error == "disabled:safety"
    assert len(calls) == 1  # nothing was attempted after the breaker tripped


def test_rate_limit():
    now = [0.0]
    fetcher = live(
        lambda r: httpx.Response(200, headers=HTML, text="ok"),
        max_per_minute=2,
        clock=lambda: now[0],
    )
    assert fetcher.fetch("https://a.example/").error is None
    assert fetcher.fetch("https://b.example/").error is None
    assert fetcher.fetch("https://c.example/").error == "rate_limited"
    now[0] = 61.0
    assert fetcher.fetch("https://d.example/").error is None
