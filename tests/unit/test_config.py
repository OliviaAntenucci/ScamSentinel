import pytest
from pydantic import ValidationError

from scamsentinel.config import Settings


def make(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def test_defaults_bind_to_loopback():
    s = make()
    assert s.host == "127.0.0.1"
    assert s.port == 8000


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.2"])
def test_loopback_hosts_allowed(host):
    assert make(host=host).host == host


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "example.com"])  # noqa: S104
def test_non_loopback_bind_refused(host):
    with pytest.raises(ValidationError, match="localhost-only"):
        make(host=host)


def test_private_targets_refused_in_production():
    with pytest.raises(ValidationError, match="production"):
        make(env="production", allow_private_targets=True)


def test_llm_key_follows_provider():
    s = make(llm_provider="groq", groq_api_key="gsk_test", anthropic_api_key=None)
    assert s.llm_api_key.get_secret_value() == "gsk_test"
    s = make(llm_provider="anthropic", groq_api_key="gsk_test", anthropic_api_key=None)
    assert s.llm_api_key is None


def test_llm_model_defaults_per_provider():
    assert make(llm_provider="groq").resolved_llm_model == "llama-3.3-70b-versatile"
    assert make(llm_provider="groq", llm_model="other-model").resolved_llm_model == "other-model"


def test_private_targets_allowed_outside_production():
    assert make(env="test", allow_private_targets=True).allow_private_targets
