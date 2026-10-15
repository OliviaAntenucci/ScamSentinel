"""S4: the local API is loopback-only and hardened (SECURITY.md T4, NFR-9)."""

import pytest
from fastapi.testclient import TestClient

from scamsentinel.api.app import WEB_DIR, create_app
from scamsentinel.api.guards import RateLimiter


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


@pytest.mark.parametrize("path", ["/", "/static/app.js", "/static/app.css"])
def test_frontend_has_strict_csp(client, path):
    csp = client.get(path).headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp


@pytest.mark.parametrize("path", ["/healthz", "/docs"])
def test_csp_only_on_frontend(client, path):
    # /docs loads Swagger UI from a CDN; API responses are JSON with nosniff.
    assert "Content-Security-Policy" not in client.get(path).headers


def test_frontend_never_uses_html_injection_sinks():
    # Reasons quote scammer-written text, so the page must only ever use textContent.
    source = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in source


def test_create_app_uses_settings_hosts(settings):
    app = create_app(settings)
    c = TestClient(app, base_url="http://localhost:8000")
    assert c.get("/healthz").status_code == 200


# --- local CSRF: web pages in the user's browser POSTing to 127.0.0.1 ------------------

BODY = '{"text": "hello"}'


@pytest.mark.parametrize(
    "origin", ["https://attacker.example", "http://192.168.1.10:8000", "null", "file://"]
)
def test_cross_origin_post_refused(client, origin):
    r = client.post(
        "/v1/analyze",
        content=BODY,
        headers={"Content-Type": "application/json", "Origin": origin},
    )
    assert r.status_code == 403


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8000", "http://localhost:8000"])
def test_same_machine_origin_allowed(client, origin):
    # e.g. the /docs page served by this API.
    r = client.post(
        "/v1/analyze",
        content=BODY,
        headers={"Content-Type": "application/json", "Origin": origin},
    )
    assert r.status_code == 200


@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "application/x-www-form-urlencoded", "multipart/form-data"],
)
def test_post_requires_json_content_type(client, content_type):
    # Browsers can send these "simple" content types cross-origin without a preflight.
    headers = {"Content-Type": content_type} if content_type else {}
    r = client.post("/v1/analyze", content=BODY.encode(), headers=headers)
    assert r.status_code == 415


# --- request size --------------------------------------------------------------------------


def small_body_client(settings, limit=1_000):
    app = create_app(settings.model_copy(update={"max_request_bytes": limit}))
    return TestClient(app, base_url="http://127.0.0.1:8000")


def test_oversized_body_rejected_by_content_length(settings):
    r = small_body_client(settings).post("/v1/analyze", json={"text": "x" * 5_000})
    assert r.status_code == 413
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_oversized_chunked_body_rejected_while_streaming(settings):
    def chunks():
        yield b'{"text": "'
        for _ in range(10):
            yield b"x" * 500
        yield b'"}'

    r = small_body_client(settings).post(
        "/v1/analyze", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 413


def test_invalid_content_length_rejected(client):
    r = client.post(
        "/v1/analyze",
        content=BODY,
        headers={"Content-Type": "application/json", "Content-Length": "abc"},
    )
    assert r.status_code == 400


# --- rate limiting -------------------------------------------------------------------------


def test_rate_limit(settings):
    app = create_app(settings.model_copy(update={"rate_limit_per_minute": 2}))
    c = TestClient(app, base_url="http://127.0.0.1:8000")
    codes = [c.post("/v1/analyze", json={"text": "hi"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    r = c.post("/v1/analyze", json={"text": "hi"})
    assert int(r.headers["Retry-After"]) >= 1
    # Reads aren't rate limited.
    assert c.get("/healthz").status_code == 200


def test_rate_limiter_window():
    now = [0.0]
    limiter = RateLimiter(2, window=60, clock=lambda: now[0])
    assert limiter.hit("a") is None
    assert limiter.hit("a") is None
    assert limiter.hit("a") == 60
    assert limiter.hit("b") is None  # per client
    now[0] = 60.0
    assert limiter.hit("a") is None  # window slid
