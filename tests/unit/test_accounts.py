"""Local accounts and opt-in saved-analysis API."""

import pytest
from fastapi.testclient import TestClient

from scamsentinel.api.app import create_app

SAMPLE = "Your account is locked. Verify your password at example-login.test immediately."


def test_registration_login_and_account_scoped_saved_results(client, settings):
    analysis = client.post("/v1/analyze", json={"text": SAMPLE}).json()
    analysis_id = analysis["analysis_id"]

    assert client.post("/v1/saved/" + analysis_id, json={}).status_code == 401
    registered = client.post(
        "/v1/auth/register",
        json={"email": "Example@Local.test", "password": "correct horse battery"},
    )
    assert registered.status_code == 200
    assert registered.json() == {"email": "example@local.test"}
    assert registered.cookies.get("scamsentinel_session")
    assert client.get("/v1/auth/me").json() == {"email": "example@local.test"}

    saved = client.post("/v1/saved/" + analysis_id, json={})
    assert saved.status_code == 200
    assert saved.json() == {"analysis_id": analysis_id}
    assert client.get("/v1/saved").json() == [analysis]
    assert client.get("/v1/saved/" + analysis_id).json() == analysis
    assert client.post(
        "/v1/auth/register",
        json={"email": "example@local.test", "password": "correct horse battery"},
    ).status_code == 409

    other_client = TestClient(create_app(settings), base_url="http://127.0.0.1:8000")
    other_account = other_client.post(
        "/v1/auth/register",
        json={"email": "other@local.test", "password": "another safe password"},
    )
    assert other_account.status_code == 200
    assert other_client.get("/v1/saved").json() == []
    assert other_client.get("/v1/saved/" + analysis_id).status_code == 404

    assert client.post(
        "/v1/auth/logout",
        json={},
    ).status_code == 200
    assert client.get("/v1/saved").status_code == 401
    assert client.post(
        "/v1/auth/login",
        json={"email": "EXAMPLE@LOCAL.TEST", "password": "wrong password 123"},
    ).status_code == 401
    assert client.post(
        "/v1/auth/login",
        json={"email": "EXAMPLE@LOCAL.TEST", "password": "correct horse battery"},
    ).status_code == 200
    assert client.get("/v1/saved/" + analysis_id).json() == analysis
    assert client.delete("/v1/saved/" + analysis_id).json() == {"status": "deleted"}
    assert client.get("/v1/saved").json() == []


EMAIL = "From: alerts@example-bank.test\nSubject: Account notice\n\nPlease verify your account."


@pytest.mark.parametrize(
    ("field", "content"),
    [("text", SAMPLE), ("url", "hxxps://example-login[.]com/verify"), ("email_raw", EMAIL)],
    ids=["text", "url", "email"],
)
def test_saved_analysis_keeps_what_was_submitted(client, field, content):
    analysis = client.post("/v1/analyze", json={field: content}).json()
    assert analysis["submitted"] == {"content": content, "image_mime": None}

    client.post(
        "/v1/auth/register", json={"email": "keep@local.test", "password": "correct horse battery"}
    )
    client.post("/v1/saved/" + analysis["analysis_id"], json={})
    saved = client.get("/v1/saved/" + analysis["analysis_id"]).json()
    assert saved["submitted"]["content"] == content
    assert client.get("/v1/saved").json()[0]["submitted"]["content"] == content


def test_submitted_input_masks_ssn_and_card_numbers(client):
    text = "Confirm your SSN 123-45-6789 and card 4111 1111 1111 1111 at example-login.test."
    analysis = client.post("/v1/analyze", json={"text": text}).json()
    content = analysis["submitted"]["content"]
    assert "123-45-6789" not in content
    assert "4111 1111 1111 1111" not in content
    assert "[REDACTED-SSN]" in content
    assert "[REDACTED-CARD]" in content
    assert client.get("/v1/analysis/" + analysis["analysis_id"]).json() == analysis


def test_text_analysis_has_no_image(client):
    analysis_id = client.post("/v1/analyze", json={"text": SAMPLE}).json()["analysis_id"]
    assert client.get(f"/v1/analysis/{analysis_id}/image").status_code == 404
