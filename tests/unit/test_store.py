import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from scamsentinel.message.features import MessageFeatures, Urgency
from scamsentinel.message.llm import CachedExtractor, LlmUnavailable
from scamsentinel.models import AnalysisResult, SubmittedInput, Verdict
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


def test_old_analyses_are_kept(tmp_path):
    path = tmp_path / "db.sqlite"
    store = Store(path, retention_days=7)
    old = make_result(created_at=datetime.now(UTC) - timedelta(days=30))
    store.save_analysis(old, "hash")
    assert store.purge_expired() == 0
    # Reopening purges too, but only the LLM cache.
    assert Store(path).get_analysis(old.analysis_id) == old


def test_purge_removes_only_expired_llm_cache(tmp_path):
    path = tmp_path / "db.sqlite"
    store = Store(path, retention_days=7)
    store.put_llm_features("fresh", "groq", "m", "{}")
    store.put_llm_features("stale", "groq", "m", "{}")
    stale = (datetime.now(UTC) - timedelta(days=8)).isoformat()
    with sqlite3.connect(path) as db:
        db.execute("UPDATE llm_cache SET created_at = ? WHERE key = 'stale'", (stale,))
    assert store.purge_expired() == 1
    assert store.get_llm_features("fresh") == "{}"
    assert store.get_llm_features("stale") is None


def test_submitted_input_and_image_round_trip(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    result = make_result().model_copy(
        update={"submitted": SubmittedInput(content="read from it", image_mime="image/png")}
    )
    store.save_analysis(result, "hash", image=("image/png", b"\x89PNG..."))
    assert store.get_analysis(result.analysis_id).submitted == result.submitted
    assert store.get_input_image(result.analysis_id) == ("image/png", b"\x89PNG...")
    assert store.get_input_image("an_" + "b" * 32) is None


def test_databases_from_before_inputs_were_kept_still_load(tmp_path):
    # Older rows have a real expiry date and no `submitted` field in their JSON.
    path = tmp_path / "db.sqlite"
    Store(path)
    old = make_result(created_at=datetime.now(UTC) - timedelta(days=30))
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO analyses VALUES (?, ?, ?, 'text', 'h', 'suspicious', 42, ?)",
            (
                old.analysis_id,
                old.created_at.isoformat(),
                (old.created_at + timedelta(days=7)).isoformat(),
                old.model_dump_json(exclude={"submitted"}),
            ),
        )
    loaded = Store(path).get_analysis(old.analysis_id)
    assert loaded == old
    assert loaded.submitted is None


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
