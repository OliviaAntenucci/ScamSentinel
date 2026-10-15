"""S6: API is localhost-only and hardened (SECURITY.md T5, NFR-9)."""

import pytest
from fastapi.testclient import TestClient

from scamsentinel.api.app import create_app


@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "127.0.0.1", "localhost"])
def test_loopback_host_headers_accepted(client, host):
    assert client.get("/healthz", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        "attacker.example",  # DNS rebinding: attacker domain re-pointed at 127.0.0.1
        "attacker.example:8000",
        "192.168.1.10:8000",
        "127.0.0.1.attacker.example",
        "0.0.0.0:8000",  # noqa: S104
    ],
)
def test_foreign_host_headers_rejected(client, host):
    assert client.get("/healthz", headers={"Host": host}).status_code == 400


def test_security_headers_on_success(client):
    r = client.get("/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"


def test_security_headers_on_rejected_host(client):
    r = client.get("/healthz", headers={"Host": "attacker.example"})
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_no_cors_headers(client):
    r = client.get("/healthz", headers={"Origin": "https://attacker.example"})
    assert "access-control-allow-origin" not in r.headers


def test_preflight_not_allowed(client):
    r = client.options(
        "/v1/analyze",
        headers={"Origin": "https://attacker.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in r.headers


def test_responses_are_json(client):
    assert client.get("/healthz").headers["content-type"].startswith("application/json")


def test_create_app_uses_settings_hosts(settings):
    app = create_app(settings)
    c = TestClient(app, base_url="http://localhost:8000")
    assert c.get("/healthz").status_code == 200
