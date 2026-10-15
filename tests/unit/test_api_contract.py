"""API surface exists and validates input; unimplemented stages answer 501."""

import pytest


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["llm"].startswith("missing_api_key")


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


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("post", "/v1/analyze", {"json": {"text": "IRS ALERT: verify your refund now"}}),
        ("get", "/v1/analysis/an_123", {}),
    ],
)
def test_unimplemented_stages_return_501(client, method, path, kwargs):
    r = getattr(client, method)(path, **kwargs)
    assert r.status_code == 501
    assert "not implemented" in r.json()["detail"]


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
