import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from scamsentinel.message.features import MessageFeatures, Urgency
from scamsentinel.message.llm import CachedExtractor, LlmUnavailable
from scamsentinel.models import AnalysisResult, Verdict
from scamsentinel.store import Store


def make_result(analysis_id="an_" + "a" * 32, created_at=None) -> AnalysisResult:
    return AnalysisResult(
        analysis_id=analysis_id,
        created_at=created_at or datetime.now(UTC),
        input_type="text",
        verdict=Verdict.SUSPICIOUS,
        risk_score=42,
    )


def test_round_trip(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    result = make_result()
    store.save_analysis(result, "hash")
    assert store.get_analysis(result.analysis_id) == result
    assert store.get_analysis("an_" + "b" * 32) is None


def test_expired_analyses_are_hidden_and_purged(tmp_path):
    store = Store(tmp_path / "db.sqlite", retention_days=7)
    old = make_result(created_at=datetime.now(UTC) - timedelta(days=8))
    store.save_analysis(old, "hash")
    assert store.get_analysis(old.analysis_id) is None
    assert store.purge_expired() == 1


def test_purge_runs_on_startup(tmp_path):
    path = tmp_path / "db.sqlite"
    store = Store(path)
    store.save_analysis(make_result(created_at=datetime.now(UTC) - timedelta(days=30)), "h")
    Store(path)  # reopening purges
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0


def test_creates_parent_directory(tmp_path):
    Store(tmp_path / "nested" / "dir" / "db.sqlite")
    assert (tmp_path / "nested" / "dir" / "db.sqlite").exists()


def test_cached_extractor_calls_llm_once_per_text(tmp_path, fake_llm):
    llm = fake_llm(MessageFeatures(urgency=Urgency(level=5, spans=["now"])))
    cached = CachedExtractor(llm, Store(tmp_path / "db.sqlite"), "groq", "model-a")

    first = cached.extract("Act  now")
    second = cached.extract("Act now")  # same text after whitespace normalization
    assert first == second
    assert llm.calls == ["Act  now"]

    cached.extract("Something else")
    assert len(llm.calls) == 2


def test_cache_key_depends_on_model(tmp_path, fake_llm):
    store = Store(tmp_path / "db.sqlite")
    a = CachedExtractor(fake_llm(), store, "groq", "model-a")
    b = CachedExtractor(fake_llm(), store, "groq", "model-b")
    assert a.key("hello") != b.key("hello")


def test_failures_are_not_cached(tmp_path, fake_llm):
    llm = fake_llm(error="rate_limited")
    cached = CachedExtractor(llm, Store(tmp_path / "db.sqlite"), "groq", "m")
    for _ in range(2):
        with pytest.raises(LlmUnavailable):
            cached.extract("hello")
    assert len(llm.calls) == 2
