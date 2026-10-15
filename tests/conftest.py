from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scamsentinel.api.app import create_app
from scamsentinel.config import Settings
from scamsentinel.data import load_brands, load_facts, load_keywords, load_scoring
from scamsentinel.domain.engine import DomainEngine, get_engine
from scamsentinel.message.analyzer import MessageAnalyzer
from scamsentinel.message.features import MessageFeatures
from scamsentinel.message.llm import LlmUnavailable

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def settings() -> Settings:
    # _env_file=None: tests never pick up a developer's local .env.
    return Settings(
        _env_file=None,
        env="test",
        llm_provider="groq",
        groq_api_key=None,
        anthropic_api_key=None,
        data_dir=REPO_ROOT / "data",
        config_dir=REPO_ROOT / "config",
    )


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings), base_url="http://127.0.0.1:8000")


@pytest.fixture(scope="session")
def engine() -> DomainEngine:
    return get_engine(REPO_ROOT / "data", REPO_ROOT / "config")


class FakeLlm:
    """Stands in for the LLM: returns fixed features, or raises."""

    def __init__(self, features: MessageFeatures | None = None, error: str | None = None):
        self.features = features if features is not None else MessageFeatures()
        self.error = error
        self.calls: list[str] = []

    def extract(self, text: str) -> MessageFeatures:
        self.calls.append(text)
        if self.error:
            raise LlmUnavailable(self.error)
        return self.features


@pytest.fixture
def fake_llm():
    """The FakeLlm class (tests can't import from conftest under importlib mode)."""
    return FakeLlm


@pytest.fixture
def make_analyzer(engine):
    """Build a MessageAnalyzer from the repo's data files with an optional fake LLM."""
    data, config = REPO_ROOT / "data", REPO_ROOT / "config"
    scoring = load_scoring(config)

    def factory(llm=None) -> MessageAnalyzer:
        return MessageAnalyzer(
            keywords=load_keywords(data),
            brands=load_brands(data),
            facts=load_facts(data),
            engine=engine,
            message_points=scoring.message_points,
            verify_points=scoring.verify_points,
            llm=llm,
        )

    return factory
