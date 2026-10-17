"""P2 in the pipeline: off by default, dry run never connects, live findings add no points.

No test here makes a real DNS lookup or connection.
"""

import socket
from pathlib import Path

import httpx
import pytest
from pagefixtures import page_response
from pydantic import ValidationError

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.config import Settings
from scamsentinel.data import load_brands, load_keywords
from scamsentinel.page.analyze import PageAnalyzer
from scamsentinel.page.fetch import PageFetcher
from scamsentinel.pipeline import AnalysisService

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
PHISH_URL = "https://appleid-unlock-support.com/login"
PHISH_HTML = (
    "<title>Sign in to your Apple Account</title>"
    '<form action="https://collector.example.net/p"><input type="password"></form>'
)


@pytest.fixture
def no_network(monkeypatch):
    def tripwire(*args, **kwargs):
        raise AssertionError(f"network access attempted: {args!r}")

    monkeypatch.setattr(socket, "getaddrinfo", tripwire)
    monkeypatch.setattr(socket, "create_connection", tripwire)
    monkeypatch.setattr(socket.socket, "connect", tripwire)


def with_live_pages(service, engine, handler, seen=None):
    """Give a service a live fetcher that only ever talks to a mock transport."""

    def record(request):
        if seen is not None:
            seen.append(str(request.headers["host"]))
        return handler(request)

    service._page_fetcher = PageFetcher(
        mode="live",
        resolver=lambda host, port: ["93.184.216.34"],
        transport=httpx.MockTransport(record),
    )
    service._page_analyzer = PageAnalyzer(
        load_brands(DATA_DIR), load_keywords(DATA_DIR).entity_mentions, engine
    )
    return service


def test_page_fetch_is_off_by_default(settings, make_service, no_network):
    assert settings.page_fetch == "off"
    result = make_service().analyze(AnalyzeRequest(url=PHISH_URL))
    assert result.pages == []


def test_dry_run_reports_without_connecting(settings, no_network):
    service = AnalysisService.from_settings(settings.model_copy(update={"page_fetch": "dry_run"}))
    result = service.analyze(
        AnalyzeRequest(text=f"Apple: your account is locked. Verify at {PHISH_URL} today")
    )
    assert [(p.status, p.error) for p in result.pages] == [("dry_run", "dry_run")]
    assert result.pages[0].requested_url == PHISH_URL


def test_dry_run_reports_blocked_links(settings, no_network):
    service = AnalysisService.from_settings(settings.model_copy(update={"page_fetch": "dry_run"}))
    result = service.analyze(AnalyzeRequest(url="http://169.254.169.254/latest/meta-data/"))
    assert result.pages[0].status == "blocked"


def test_live_findings_are_reported(make_service, engine):
    service = with_live_pages(
        make_service(), engine,
        lambda r: page_response(200, {"content-type": "text/html"},PHISH_HTML),
    )
    result = service.analyze(AnalyzeRequest(url=PHISH_URL))
    report = result.pages[0]
    assert report.status == "analyzed"
    assert report.brand == "Apple"
    assert {f.signal for f in report.findings} >= {
        "sensitive_fields", "form_posts_elsewhere", "brand_on_unofficial_page"
    }


def test_page_findings_add_no_points(make_service, engine):
    plain = make_service().analyze(AnalyzeRequest(url=PHISH_URL))
    with_pages = with_live_pages(
        make_service(), engine,
        lambda r: page_response(200, {"content-type": "text/html"},PHISH_HTML),
    ).analyze(AnalyzeRequest(url=PHISH_URL))
    assert with_pages.pages
    assert (with_pages.risk_score, with_pages.verdict) == (plain.risk_score, plain.verdict)
    assert [r.signal for r in with_pages.reasons] == [r.signal for r in plain.reasons]


def test_only_non_official_links_are_fetched_once_per_host(make_service, engine):
    seen: list[str] = []
    service = with_live_pages(
        make_service(), engine,
        lambda r: page_response(200, {"content-type": "text/html"},"<p>x</p>"),
        seen,
    )
    text = (
        "IRS: see https://www.irs.gov/refunds and verify at https://irs-refund-claim.com/a "
        "or https://irs-refund-claim.com/b, then https://tax-help-now.com and "
        "https://third.example and https://fourth.example"
    )
    result = service.analyze(AnalyzeRequest(text=text))
    assert "www.irs.gov" not in seen  # the official site is never fetched
    assert seen.count("irs-refund-claim.com") == 1
    assert len(result.pages) == 3  # page_fetch_max_links


def test_email_sender_domains_are_not_fetched(make_service, engine):
    seen: list[str] = []
    service = with_live_pages(
        make_service(), engine,
        lambda r: page_response(200, {"content-type": "text/html"},"<p>x</p>"),
        seen,
    )
    eml = (
        "From: IRS <notice@irs-sender.net>\nReply-To: claims@other-sender.org\n"
        "To: you@example.com\nSubject: Refund\nContent-Type: text/plain\n\nNo links here.\n"
    )
    result = service.analyze(AnalyzeRequest(email_raw=eml))
    assert seen == []
    assert result.pages == []


def test_an_internal_error_fails_closed(make_service, engine):
    def broken(request):
        raise ValueError("unexpected")

    service = with_live_pages(make_service(), engine, broken)
    result = service.analyze(AnalyzeRequest(url=PHISH_URL))
    # The analysis still completes; the page is reported as not analyzed.
    assert result.verdict
    assert result.pages[0].status == "failed"


def test_page_titles_are_redacted(make_service, engine):
    html = "<title>Confirm SSN 078-05-1120 now</title>"
    service = with_live_pages(
        make_service(), engine,
        lambda r: page_response(200, {"content-type": "text/html"},html),
    )
    result = service.analyze(AnalyzeRequest(url=PHISH_URL))
    assert "078-05-1120" not in result.pages[0].title


def test_settings_accept_only_the_three_modes():
    for mode in ("off", "dry_run", "live"):
        assert Settings(_env_file=None, page_fetch=mode).page_fetch == mode
    with pytest.raises(ValidationError):
        Settings(_env_file=None, page_fetch="yes")


def test_healthz_reports_the_mode(client):
    assert client.get("/healthz").json()["page_fetch"].startswith("off")
