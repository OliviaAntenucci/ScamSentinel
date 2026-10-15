"""CT polling loop: query each brand token, dedupe, score, persist candidates (post-MVP, P1).

The watcher talks to crt.sh only. Candidate names come from public certificates and are
attacker-chosen: they're scored as strings by the domain engine and never visited.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from scamsentinel.config import Settings
from scamsentinel.ct.client import CrtShClient, CtEntry, CtUnavailable
from scamsentinel.ct.store import CtCandidate, CtPoll, CtStore, timestamp
from scamsentinel.data import Brand, load_brands
from scamsentinel.domain.engine import DomainEngine, get_engine
from scamsentinel.domain.normalize import InvalidHost

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 6 * 60 * 60
MIN_CANDIDATE_SCORE = 50
# Upper bound on distinct names scored per pass, so one huge result set stays cheap.
MAX_NAMES_PER_POLL = 50_000


class CtSearcher(Protocol):
    def search(self, pattern: str) -> list[CtEntry]: ...


def search_patterns(brands: list[Brand]) -> list[str]:
    """crt.sh name patterns for every brand token, without duplicates.

    Long tokens match anywhere (`%turbotax%`). A bare `%irs%` would return every
    certificate for "first" or "shirts" and time out on crt.sh, so whole-word tokens are
    anchored to the start of a name or to a `.`/`-` separator instead.
    """
    patterns: list[str] = []
    for brand in brands:
        for token in brand.tokens:
            if token in brand.boundary_tokens:
                candidates = [f"{token}%", f"%.{token}%", f"%-{token}%"]
            else:
                candidates = [f"%{token}%"]
            patterns += [p for p in candidates if p not in patterns]
    return patterns


class CtWatcher:
    def __init__(
        self,
        *,
        client: CtSearcher,
        store: CtStore,
        engine: DomainEngine,
        patterns: list[str],
        min_score: int = MIN_CANDIDATE_SCORE,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._client = client
        self._store = store
        self._engine = engine
        self._patterns = patterns
        self._min_score = min_score
        self._now = now

    @classmethod
    def from_settings(cls, settings: Settings, client: CtSearcher | None = None) -> CtWatcher:
        return cls(
            client=client or CrtShClient(timeout=settings.ct_timeout_seconds),
            store=CtStore(settings.db_path),
            engine=get_engine(settings.data_dir, settings.config_dir),
            patterns=search_patterns(load_brands(settings.data_dir)),
            min_score=settings.ct_min_score,
        )

    def poll_once(self) -> CtPoll:
        """Run one polling pass and record it. A failed query is logged and skipped."""
        started = timestamp(self._now())
        entries: dict[str, CtEntry] = {}
        failed = 0
        for pattern in self._patterns:
            try:
                results = self._client.search(pattern)
            except CtUnavailable as exc:
                logger.warning("crt.sh query %r failed: %s", pattern, exc.reason)
                failed += 1
                continue
            for entry in results:
                if entry.name in entries or len(entries) < MAX_NAMES_PER_POLL:
                    entries.setdefault(entry.name, entry)

        candidates = [
            c for e in entries.values() if (c := self._candidate(e, started)) is not None
        ]
        new = self._store.upsert(candidates)
        poll = CtPoll(
            started_at=started,
            finished_at=timestamp(self._now()),
            queries=len(self._patterns),
            failed_queries=failed,
            names_seen=len(entries),
            candidates=len(candidates),
            new_candidates=new,
        )
        self._store.record_poll(poll)
        logger.info(
            "CT poll: %d queries (%d failed), %d names, %d candidates, %d new",
            poll.queries,
            poll.failed_queries,
            poll.names_seen,
            poll.candidates,
            poll.new_candidates,
        )
        return poll

    def _candidate(self, entry: CtEntry, seen_at: str) -> CtCandidate | None:
        try:
            result = self._engine.score(entry.name)
        except InvalidHost:
            return None
        if result.official or result.score < self._min_score:
            return None
        return CtCandidate(
            domain=result.host,
            registrable=result.registrable,
            score=result.score,
            brand=result.brand,
            techniques=result.techniques,
            cert_id=entry.cert_id,
            issuer=entry.issuer,
            not_before=entry.not_before,
            first_seen=seen_at,
            last_seen=seen_at,
        )


def run_forever(
    watcher: CtWatcher,
    interval_seconds: float = POLL_INTERVAL_SECONDS,
    *,
    sleep: Callable[[float], None] = time.sleep,
    max_polls: int | None = None,
) -> None:
    """Poll, then sleep `interval_seconds`, until interrupted (or `max_polls`, for tests).

    An unexpected error in one pass is logged and the loop carries on.
    """
    polls = 0
    while True:
        try:
            watcher.poll_once()
        except Exception:
            logger.exception("CT poll failed")
        polls += 1
        if max_polls is not None and polls >= max_polls:
            return
        sleep(interval_seconds)
