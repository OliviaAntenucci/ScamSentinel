from datetime import UTC, datetime, timedelta, timezone

from scamsentinel.ct.store import CtCandidate, CtPoll, CtStore, timestamp
from scamsentinel.store import Store


def candidate(domain="turbotax-refund.com", score=70, seen="2026-10-15T00:00:00+00:00", **kw):
    fields = {
        "domain": domain,
        "registrable": domain,
        "score": score,
        "brand": "TurboTax",
        "techniques": ["brand_plus_keywords"],
        "cert_id": 1,
        "issuer": "C=US, O=Let's Encrypt, CN=R11",
        "not_before": "2026-10-14T08:00:00",
        "first_seen": seen,
        "last_seen": seen,
    }
    return CtCandidate(**(fields | kw))


def test_round_trip(tmp_path):
    store = CtStore(tmp_path / "db.sqlite")
    c = candidate()
    assert store.upsert([c]) == 1
    assert store.list_candidates() == [c]


def test_known_domain_keeps_first_sighting(tmp_path):
    store = CtStore(tmp_path / "db.sqlite")
    store.upsert([candidate(cert_id=1, seen="2026-10-14T00:00:00+00:00")])
    later = candidate(
        cert_id=2, score=90, techniques=["homoglyph"], seen="2026-10-15T06:00:00+00:00"
    )
    assert store.upsert([later]) == 0

    (stored,) = store.list_candidates()
    assert stored.cert_id == 1
    assert stored.first_seen == "2026-10-14T00:00:00+00:00"
    assert stored.last_seen == "2026-10-15T06:00:00+00:00"
    assert (stored.score, stored.techniques) == (90, ["homoglyph"])


def test_filters_and_ordering(tmp_path):
    store = CtStore(tmp_path / "db.sqlite")
    store.upsert(
        [
            candidate("old.com", 90, "2026-10-13T00:00:00+00:00"),
            candidate("low.com", 50, "2026-10-15T00:00:00+00:00"),
            candidate("high.com", 85, "2026-10-15T00:00:00+00:00"),
            candidate("newest.com", 60, "2026-10-15T06:00:00+00:00"),
        ]
    )
    domains = [c.domain for c in store.list_candidates()]
    assert domains == ["newest.com", "high.com", "low.com", "old.com"]

    since = datetime(2026, 10, 14, tzinfo=UTC)
    assert [c.domain for c in store.list_candidates(since=since)] == [
        "newest.com",
        "high.com",
        "low.com",
    ]
    assert [c.domain for c in store.list_candidates(min_score=80)] == ["high.com", "old.com"]
    assert [c.domain for c in store.list_candidates(limit=2)] == ["newest.com", "high.com"]


def test_since_accepts_other_timezones_and_naive_utc(tmp_path):
    store = CtStore(tmp_path / "db.sqlite")
    store.upsert([candidate(seen="2026-10-15T06:00:00+00:00")])
    pacific = timezone(timedelta(hours=-7))
    assert store.list_candidates(since=datetime(2026, 10, 14, 23, 0, tzinfo=pacific))
    assert not store.list_candidates(since=datetime(2026, 10, 15, 0, 0, tzinfo=pacific))
    assert store.list_candidates(since=datetime(2026, 10, 15, 6, 0))


def test_timestamp_is_utc_to_the_second():
    moment = datetime(2026, 10, 15, 1, 2, 3, 456789, tzinfo=timezone(timedelta(hours=2)))
    assert timestamp(moment) == "2026-10-14T23:02:03+00:00"


def test_last_poll(tmp_path):
    store = CtStore(tmp_path / "db.sqlite")
    assert store.last_poll() is None
    first = CtPoll(
        started_at="2026-10-15T00:00:00+00:00",
        finished_at="2026-10-15T00:05:00+00:00",
        queries=9,
        failed_queries=1,
        names_seen=1200,
        candidates=4,
        new_candidates=4,
    )
    second = first.model_copy(update={"started_at": "2026-10-15T06:00:00+00:00"})
    store.record_poll(first)
    store.record_poll(second)
    assert store.last_poll() == second


def test_shares_the_analysis_database(tmp_path):
    path = tmp_path / "db.sqlite"
    Store(path)
    store = CtStore(path)
    store.upsert([candidate()])
    Store(path)  # reopening (and purging expired analyses) leaves CT candidates alone
    assert len(CtStore(path).list_candidates()) == 1
