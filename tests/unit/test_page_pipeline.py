"""P2 in the pipeline: off by default, dry run never connects, page evidence is scored
(P2b), and evaluation reads saved snapshots.

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
from scamsentinel.eval.dataset import load_samples
from scamsentinel.eval.runner import build_service
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
        lambda r: page_response(200, {"content-type": "text/html"}, PHISH_HTML),
    )
    result = service.analyze(AnalyzeRequest(url=PHISH_URL))
    report = result.pages[0]
    assert report.status == "analyzed"
    assert report.brand == "Apple"
    assert {f.signal for f in report.findings} >= {
        "sensitive_fields", "form_posts_elsewhere", "brand_on_unofficial_page"
    }


def test_page_evidence_counts(make_service, engine):
    # P2b: a page that presents itself as Apple on another domain and asks for a password.
    plain = make_service().analyze(AnalyzeRequest(url=PHISH_URL))
    with_pages = with_live_pages(
        make_service(), engine,
        lambda r: page_response(200, {"content-type": "text/html"}, PHISH_HTML),
    ).analyze(AnalyzeRequest(url=PHISH_URL))
    assert "page" in with_pages.modules_run
    assert "page_credential_harvest" in with_pages.overrides_applied
    assert with_pages.risk_score >= max(plain.risk_score, 85)
    assert {r.signal for r in with_pages.reasons} >= {
        "page_brand_on_unofficial_page", "page_sensitive_fields"
    }


def test_a_brand_on_the_page_unlocks_the_guidance(make_service, engine):
    # The domain names no brand, so before P2b nothing could say "Apple".
    url = "https://secure-login-check.com/"
    result = with_live_pages(
        make_service(), engine,
        lambda r: page_response(200, {"content-type": "text/html"}, PHISH_HTML),
    ).analyze(AnalyzeRequest(url=url))
    assert result.verdict.value == "likely_scam"
    steps = " ".join(s.text for s in result.next_steps)
    assert "official Apple website" in steps
    assert "apple.com" in steps
    assert any(r.publisher == "Apple" for r in result.resources)


def test_a_redirect_destination_is_scored_like_a_link(make_service, engine):
    def handler(request):
        if request.headers["host"] == "bit.ly":
            return httpx.Response(301, headers={"location": "https://appleid-unlock-support.com/"})
        return page_response(200, {"content-type": "text/html"}, "<p>hello</p>")

    result = with_live_pages(make_service(), engine, handler).analyze(
        AnalyzeRequest(url="https://bit.ly/3abc")
    )
    assert result.module_scores.get("domain", 0) >= 60  # the lookalike it landed on
    assert result.verdict.value != "likely_legitimate"


def test_only_non_official_links_are_fetched_once_per_host(make_service, engine):
    seen: list[str] = []
    service = with_live_pages(
        make_service(), engine,
        lambda r: page_response(200, {"content-type": "text/html"}, "<p>x</p>"),
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
        lambda r: page_response(200, {"content-type": "text/html"}, "<p>x</p>"),
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
        lambda r: page_response(200, {"content-type": "text/html"}, html),
    )
    result = service.analyze(AnalyzeRequest(url=PHISH_URL))
    assert "078-05-1120" not in result.pages[0].title


def test_evaluation_snapshots_never_touch_the_network(settings, tmp_path, no_network):
    """Every eval sample through the snapshot-backed service, with sockets tripwired.
    Samples whose links have no snapshot score exactly as with pages off."""
    with_pages = build_service(settings, "rules_only", tmp_path / "a.db", pages="snapshot")
    without = build_service(settings, "rules_only", tmp_path / "b.db", pages="off")
    field = {"text": "text", "url": "url", "email": "email_raw"}
    changed = 0
    for sample in load_samples(DATA_DIR / "eval" / "samples.jsonl"):
        request = AnalyzeRequest(**{field[sample.input_type]: sample.content})
        try:
            a, b = with_pages.analyze(request), without.analyze(request)
        except ValueError:
            continue
        analyzed = [p for p in a.pages if p.status == "analyzed"]
        if not analyzed:
            assert (a.risk_score, a.verdict) == (b.risk_score, b.verdict), sample.id
        else:
            changed += 1
    assert changed >= 50  # the URL samples with snapshot pages


def test_settings_accept_only_the_three_modes():
    for mode in ("off", "dry_run", "live"):
        assert Settings(_env_file=None, page_fetch=mode).page_fetch == mode
    with pytest.raises(ValidationError):
        Settings(_env_file=None, page_fetch="yes")


def test_healthz_reports_the_mode(client):
    assert client.get("/healthz").json()["page_fetch"].startswith("off")
