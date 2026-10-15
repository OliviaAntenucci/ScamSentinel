from datetime import UTC, datetime

import pytest

from scamsentinel.ct.client import CtEntry, CtUnavailable
from scamsentinel.ct.store import CtStore
from scamsentinel.ct.watcher import CtWatcher, run_forever, search_patterns
from scamsentinel.data import Brand, load_brands
from scamsentinel.domain.engine import DomainEngine

NOW = datetime(2026, 10, 15, 6, 0, tzinfo=UTC)


class FakeCrtSh:
    """Answers each pattern with fixed entries, or raises CtUnavailable."""

    def __init__(self, results: dict[str, list[CtEntry] | str]):
        self.results = results
        self.queries: list[str] = []

    def search(self, pattern: str) -> list[CtEntry]:
        self.queries.append(pattern)
        result = self.results.get(pattern, [])
        if isinstance(result, str):
            raise CtUnavailable(result)
        return result


def entry(name: str, cert_id: int = 1) -> CtEntry:
    return CtEntry(cert_id=cert_id, name=name, issuer="Let's Encrypt", not_before="2026-10-14")


@pytest.fixture
def make_watcher(tmp_path, engine: DomainEngine):
    store = CtStore(tmp_path / "db.sqlite")

    def factory(results, patterns=None, min_score=50, now=NOW):
        client = FakeCrtSh(results)
        watcher = CtWatcher(
            client=client,
            store=store,
            engine=engine,
            patterns=patterns or list(results),
            min_score=min_score,
            now=lambda: now,
        )
        return watcher, client, store

    return factory


def test_search_patterns_for_repo_brands(settings):
    assert search_patterns(load_brands(settings.data_dir)) == [
        "irs%",
        "%.irs%",
        "%-irs%",
        "%turbotax%",
        "intuit%",
        "%.intuit%",
        "%-intuit%",
        "%quickbooks%",
        "%creditkarma%",
        "%usps%",
        "chase%",
        "%.chase%",
        "%-chase%",
        "%bankofamerica%",
        "bofa%",
        "%.bofa%",
        "%-bofa%",
        "%wellsfargo%",
        "%google%",
        "%gmail%",
        "apple%",
        "%.apple%",
        "%-apple%",
        "%appleid%",
        "%icloud%",
        "%microsoft%",
        "outlook%",
        "%.outlook%",
        "%-outlook%",
        "%hotmail%",
        "%onedrive%",
        "indeed%",
        "%.indeed%",
        "%-indeed%",
    ]


def test_search_patterns_dedupe_shared_tokens():
    brands = [
        Brand(name="A", category="c", tokens=["shared", "alpha"], official_domains=["a.com"]),
        Brand(name="B", category="c", tokens=["shared"], official_domains=["b.com"]),
    ]
    assert search_patterns(brands) == ["%shared%", "%alpha%"]


def test_poll_stores_lookalikes_only(make_watcher, engine):
    watcher, client, store = make_watcher(
        {
            "%turbotax%": [
                entry("turbotax-refund-secure.com", 11),
                entry("turbotax.com", 12),
                entry("turbotax.intuit.com", 13),
                entry("login.turbotax.com.account-verify.net", 14),
            ],
            "%-irs%": [entry("my-irs-refund.com", 21), entry("theirs-shirts.com", 22)],
        }
    )
    poll = watcher.poll_once()

    assert client.queries == ["%turbotax%", "%-irs%"]
    stored = {c.domain: c for c in store.list_candidates()}
    assert set(stored) == {
        "turbotax-refund-secure.com",
        "login.turbotax.com.account-verify.net",
        "my-irs-refund.com",
    }
    lookalike = stored["turbotax-refund-secure.com"]
    expected = engine.score("turbotax-refund-secure.com")
    assert (lookalike.score, lookalike.brand, lookalike.techniques) == (
        expected.score,
        "TurboTax",
        expected.techniques,
    )
    assert lookalike.cert_id == 11
    assert lookalike.first_seen == lookalike.last_seen == "2026-10-15T06:00:00+00:00"
    assert stored["login.turbotax.com.account-verify.net"].registrable == "account-verify.net"

    assert poll.queries == 2
    assert poll.failed_queries == 0
    assert poll.names_seen == 6
    assert poll.candidates == poll.new_candidates == 3
    assert store.last_poll() == poll


def test_min_score_threshold(make_watcher, engine):
    names = ["turb0tax.com", "turbotax-refund-secure.com"]
    scores = {n: engine.score(n).score for n in names}
    threshold = max(scores.values())
    watcher, _, store = make_watcher(
        {"%turbotax%": [entry(n) for n in names]}, min_score=threshold
    )
    watcher.poll_once()
    assert [c.domain for c in store.list_candidates()] == [
        n for n in names if scores[n] >= threshold
    ]


def test_second_poll_finds_nothing_new(make_watcher):
    results = {"%turbotax%": [entry("turbotax-refund-secure.com")]}
    watcher, _, store = make_watcher(results)
    assert watcher.poll_once().new_candidates == 1

    later = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
    watcher, _, store = make_watcher(results, now=later)
    poll = watcher.poll_once()
    assert (poll.candidates, poll.new_candidates) == (1, 0)
    (stored,) = store.list_candidates()
    assert stored.first_seen == "2026-10-15T06:00:00+00:00"
    assert stored.last_seen == "2026-10-15T12:00:00+00:00"


def test_names_found_by_several_patterns_are_scored_once(make_watcher):
    watcher, _, _ = make_watcher(
        {"irs%": [entry("irs-refund.com", 1)], "%-irs%": [entry("irs-refund.com", 2)]}
    )
    poll = watcher.poll_once()
    assert (poll.names_seen, poll.candidates) == (1, 1)


def test_failed_query_does_not_stop_the_pass(make_watcher):
    watcher, client, store = make_watcher(
        {"%turbotax%": "timeout", "%creditkarma%": [entry("creditkarma-login-verify.com")]}
    )
    poll = watcher.poll_once()
    assert client.queries == ["%turbotax%", "%creditkarma%"]
    assert poll.failed_queries == 1
    assert [c.domain for c in store.list_candidates()] == ["creditkarma-login-verify.com"]


def test_unscorable_names_are_skipped(make_watcher):
    # A bare public suffix has no registrable domain; an IP address scores 0.
    watcher, _, store = make_watcher({"%turbotax%": [entry("co.uk"), entry("10.0.0.1")]})
    poll = watcher.poll_once()
    assert poll.candidates == 0
    assert store.list_candidates() == []


def test_run_forever_sleeps_between_polls_and_survives_errors():
    calls: list[str] = []
    sleeps: list[float] = []

    class FlakyWatcher:
        def poll_once(self):
            calls.append("poll")
            if len(calls) == 1:
                raise RuntimeError("database is locked")

    run_forever(FlakyWatcher(), 3600, sleep=sleeps.append, max_polls=3)
    assert calls == ["poll"] * 3
    assert sleeps == [3600, 3600]


# --- GET /v1/ct/candidates ------------------------------------------------------------


def test_candidates_endpoint_before_first_poll(client):
    response = client.get("/v1/ct/candidates")
    assert response.status_code == 200
    assert response.json() == {"last_poll": None, "count": 0, "candidates": []}


def test_candidates_endpoint(client, settings, engine):
    watcher = CtWatcher(
        client=FakeCrtSh(
            {"%turbotax%": [entry("turbotax-refund-secure.com"), entry("turb0tax.com")]}
        ),
        store=CtStore(settings.db_path),
        engine=engine,
        patterns=["%turbotax%"],
        now=lambda: NOW,
    )
    watcher.poll_once()

    body = client.get("/v1/ct/candidates").json()
    assert body["count"] == 2
    assert body["last_poll"]["new_candidates"] == 2
    assert {c["domain"] for c in body["candidates"]} == {
        "turbotax-refund-secure.com",
        "turb0tax.com",
    }

    top = engine.score("turb0tax.com").score
    body = client.get("/v1/ct/candidates", params={"min_score": top}).json()
    assert [c["domain"] for c in body["candidates"]] == ["turb0tax.com"]

    assert client.get("/v1/ct/candidates", params={"limit": 1}).json()["count"] == 1
    assert client.get("/v1/ct/candidates", params={"since": "2026-10-16"}).json()["count"] == 0
    since = "2026-10-15T06:00:00Z"
    assert client.get("/v1/ct/candidates", params={"since": since}).json()["count"] == 2


@pytest.mark.parametrize(
    "params",
    [{"min_score": -1}, {"min_score": 101}, {"limit": 0}, {"limit": 1001}, {"since": "soon"}],
)
def test_candidates_endpoint_validates_parameters(client, params):
    assert client.get("/v1/ct/candidates", params=params).status_code == 422
