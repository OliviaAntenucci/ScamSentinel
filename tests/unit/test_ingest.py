from email.message import EmailMessage

import pytest

from scamsentinel.ingest.email import parse_eml
from scamsentinel.ingest.html import html_to_text
from scamsentinel.ingest.phones import extract_phone_numbers, normalize_phone
from scamsentinel.ingest.urls import extract_urls, refang

# --- URLs ---------------------------------------------------------------------------


def test_refang():
    assert refang("hxxps://irs-refund[.]com") == "https://irs-refund.com"
    assert refang("irs(.)gov and turbotax[dot]com") == "irs.gov and turbotax.com"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "Visit hxxps://irs-refund[.]com/login now, or www.irs.gov.",
            ["https://irs-refund.com/login", "www.irs.gov"],
        ),
        ("(see irs.gov).", ["irs.gov"]),
        ("Email help@turbotax-support.net today", ["turbotax-support.net"]),
        ("Go to turbоtax.com", ["turbоtax.com"]),
        ("Duplicate irs.gov and IRS.GOV", ["irs.gov"]),
    ],
)
def test_extract_urls(text, expected):
    assert extract_urls(text) == expected


@pytest.mark.parametrize("text", ["e.g. this", "open file.txt", "pi is 3.14", "U.S. taxes", ""])
def test_extract_urls_ignores_non_domains(text):
    assert extract_urls(text) == []


# --- phone numbers -------------------------------------------------------------------


def test_extract_phone_numbers_dedupes_formats():
    text = "Call (800) 829-1040 or 1-800-829-1040 or +1 800.829.1040, ref 12345678901234"
    assert extract_phone_numbers(text) == ["(800) 829-1040"]


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [("(800) 829-1040", "+18008291040"), ("1 800 829 1040", "+18008291040"), ("12345", None)],
)
def test_normalize_phone(raw, normalized):
    assert normalize_phone(raw) == normalized


# --- HTML -----------------------------------------------------------------------------


def test_html_to_text_strips_scripts_and_collects_links():
    html = (
        "<html><head><title>t</title><style>p{}</style></head><body>"
        "<p>Your refund &amp; more</p><script>alert(1)</script>"
        '<a href="https://irs-gov-refund.com/login">irs.gov</a>'
        '<a href="javascript:alert(1)">x</a></body></html>'
    )
    text, links = html_to_text(html)
    assert "Your refund & more" in text
    assert "alert" not in text
    assert links == ["https://irs-gov-refund.com/login"]


# --- email ------------------------------------------------------------------------------


def _scam_email() -> bytes:
    msg = EmailMessage()
    msg["From"] = "IRS Refunds <refunds@irs-gov-refund.com>"
    msg["Reply-To"] = "claims@gmail.com"
    msg["Subject"] = "Your refund is on hold"
    msg.set_content("Verify your identity to release your refund.")
    msg.add_alternative(
        "<html><body><p>Verify at <a href='https://irs-gov-refund.com/login'>irs.gov</a></p>"
        "</body></html>",
        subtype="html",
    )
    msg.add_attachment(
        b"MZ\x90\x00", maintype="application", subtype="octet-stream", filename="refund.exe"
    )
    return msg.as_bytes()


def test_parse_eml():
    parsed = parse_eml(_scam_email())
    assert parsed.from_display == "IRS Refunds"
    assert parsed.from_domain == "irs-gov-refund.com"
    assert parsed.reply_to_domain == "gmail.com"
    assert parsed.subject == "Your refund is on hold"
    assert "Verify your identity" in parsed.body_text
    # The href is captured even though the visible text says irs.gov.
    assert parsed.links == ["https://irs-gov-refund.com/login"]
    assert [(a.filename, a.size) for a in parsed.attachments] == [("refund.exe", 4)]
    assert "IRS Refunds" in parsed.analysis_text()


def test_parse_eml_reads_dkim_results():
    raw = (
        b"From: IRS <alerts@irs.gov>\r\n"
        b"Authentication-Results: mx.example; dkim=pass header.d=irs.gov; spf=pass\r\n"
        b"Subject: Hi\r\n\r\nBody\r\n"
    )
    assert parse_eml(raw).dkim_pass_domains == ["irs.gov"]


def test_parse_eml_survives_bad_charset():
    raw = b"From: a@b.com\r\nContent-Type: text/plain; charset=bogus-charset\r\n\r\nhello\r\n"
    assert "hello" in parse_eml(raw).body_text


def test_parse_eml_html_only_body():
    raw = (
        b"From: a@b.com\r\nContent-Type: text/html\r\n\r\n"
        b"<p>Pay <a href='https://evil.example/pay'>here</a></p>\r\n"
    )
    parsed = parse_eml(raw)
    assert "Pay here" in parsed.body_text
    assert parsed.links == ["https://evil.example/pay"]
