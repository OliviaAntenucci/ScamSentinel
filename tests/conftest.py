from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scamsentinel.api.app import create_app
from scamsentinel.config import Settings

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def settings() -> Settings:
    # _env_file=None: tests never pick up a developer's local .env.
    return Settings(
        _env_file=None,
        env="test",
        anthropic_api_key=None,
        data_dir=REPO_ROOT / "data",
        config_dir=REPO_ROOT / "config",
    )


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings), base_url="http://127.0.0.1:8000")
