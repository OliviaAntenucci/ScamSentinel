"""Local accounts and opt-in saved-analysis API."""

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
