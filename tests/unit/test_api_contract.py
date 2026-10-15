"""API surface: health, input validation, analyze/fetch round trip, domain scoring."""

import re
from email.message import EmailMessage

import pytest

SCAM_TEXT = (
    "IRS ALERT: Your refund has been suspended. Verify your identity immediately at "
    "irs-refund-secure.com or your refund will be cancelled. Provide your SSN to continue."
)


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["llm"].startswith("missing_api_key")


def test_frontend_is_served_with_static_assets(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "ScamSentinel" in page.text
    assert client.get("/static/app.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"text": "a", "url": "https://example.com"},
        {"unknown": "field"},
        {"text": "x" * 20_001},
    ],
)
def test_analyze_rejects_invalid_input(client, payload):
    assert client.post("/v1/analyze", json=payload).status_code == 422


def test_analyze_text_and_fetch_it_back(client):
    r = client.post("/v1/analyze", json={"text": SCAM_TEXT})
    assert r.status_code == 200
    body = r.json()
    assert re.fullmatch(r"an_[0-9a-f]{32}", body["analysis_id"])
    assert body["input_type"] == "text"
    assert body["verdict"] == "likely_scam"
    assert body["modules_run"] == ["domain", "message"]
    assert body["degraded"] == ["llm_not_configured"]
    assert body["reasons"]

    fetched = client.get(f"/v1/analysis/{body['analysis_id']}")
    assert fetched.status_code == 200
    assert fetched.json() == body


def test_analyze_url(client):
    body = client.post("/v1/analyze", json={"url": "https://turb0tax-refund.com/login"}).json()
    assert body["input_type"] == "url"
    assert body["modules_run"] == ["domain"]
    assert body["verdict"] == "likely_scam"


def test_analyze_email(client):
    msg = EmailMessage()
    msg["From"] = "IRS Refunds <refunds@irs-gov-refund.com>"
    msg["Subject"] = "Refund on hold"
    msg.set_content("Confirm your Social Security number to release your refund.")
    body = client.post("/v1/analyze", json={"email_raw": msg.as_string()}).json()
    assert body["input_type"] == "email"
    assert body["verdict"] == "likely_scam"
    assert "sender_brand_mismatch" in {r["signal"] for r in body["reasons"]}


@pytest.mark.parametrize("url", ["http://", "not a url", "https://a..com/"])
def test_analyze_rejects_unusable_url(client, url):
    assert client.post("/v1/analyze", json={"url": url}).status_code == 422


def test_unknown_analysis_is_404(client):
    assert client.get(f"/v1/analysis/an_{'0' * 32}").status_code == 404


@pytest.mark.parametrize("analysis_id", ["an_123", "../etc/passwd", "an_" + "g" * 32])
def test_malformed_analysis_id_is_422(client, analysis_id):
    assert client.get(f"/v1/analysis/{analysis_id}").status_code in (404, 422)


def test_domain_score_endpoint(client):
    r = client.get("/v1/domain/score", params={"d": "turb0tax-verify.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["brand"] == "TurboTax"
    assert body["score"] >= 60
    assert body["reasons"]


@pytest.mark.parametrize("d", ["http://", "a..com", "http://[::1"])
def test_domain_score_rejects_invalid_hosts(client, d):
    assert client.get("/v1/domain/score", params={"d": d}).status_code == 422
