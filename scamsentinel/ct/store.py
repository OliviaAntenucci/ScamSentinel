"""Persistence for CT candidates (table `ct_candidates`, architecture.md §11, post-MVP P1).

Lives in the same SQLite file as the analyses, with a new connection per call (the API
reads it from FastAPI's thread pool while the watcher process writes it).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

SCHEMA = """
CREATE TABLE IF NOT EXISTS ct_candidates (
    domain      TEXT PRIMARY KEY,
    registrable TEXT NOT NULL,
    score       INTEGER NOT NULL,
    brand       TEXT,
    techniques  TEXT NOT NULL,
    cert_id     INTEGER NOT NULL,
    issuer      TEXT NOT NULL,
    not_before  TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ct_candidates_first_seen ON ct_candidates (first_seen);

CREATE TABLE IF NOT EXISTS ct_polls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT NOT NULL,
    queries         INTEGER NOT NULL,
    failed_queries  INTEGER NOT NULL,
    names_seen      INTEGER NOT NULL,
    candidates      INTEGER NOT NULL,
    new_candidates  INTEGER NOT NULL
);
"""

_CANDIDATE_COLUMNS = (
    "domain, registrable, score, brand, techniques, cert_id, issuer, not_before, "
    "first_seen, last_seen"
)


class CtCandidate(BaseModel):
    """An unverified lead: a newly certified name that resembles a protected brand."""

    domain: str
    registrable: str
    score: int
    brand: str | None
    techniques: list[str]
    cert_id: int
    issuer: str
    not_before: str
    first_seen: str
    last_seen: str


class CtPoll(BaseModel):
    """Summary of one watcher pass."""

    started_at: str
    finished_at: str
    queries: int
    failed_queries: int
    names_seen: int
    candidates: int
    new_candidates: int


class CtCandidateList(BaseModel):
    """Response of GET /v1/ct/candidates. `last_poll` is null until the watcher has run."""

    last_poll: CtPoll | None
    count: int
    candidates: list[CtCandidate]


class CtStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path)) as db, db:
            yield db

    def upsert(self, candidates: list[CtCandidate]) -> int:
        """Insert new candidates; refresh score and last_seen of known ones.

        A known domain keeps its first_seen and the certificate it was first seen in.
        Returns the number of domains that weren't stored before.
        """
        new = 0
        with self._connect() as db:
            for c in candidates:
                inserted = db.execute(
                    f"INSERT INTO ct_candidates ({_CANDIDATE_COLUMNS}) "  # noqa: S608
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (domain) DO NOTHING",
                    (
                        c.domain,
                        c.registrable,
                        c.score,
                        c.brand,
                        json.dumps(c.techniques),
                        c.cert_id,
                        c.issuer,
                        c.not_before,
                        c.first_seen,
                        c.last_seen,
                    ),
                ).rowcount
                if inserted:
                    new += 1
                else:
                    db.execute(
                        "UPDATE ct_candidates SET score = ?, brand = ?, techniques = ?, "
                        "last_seen = ? WHERE domain = ?",
                        (c.score, c.brand, json.dumps(c.techniques), c.last_seen, c.domain),
                    )
        return new

    def list_candidates(
        self, since: datetime | None = None, min_score: int = 0, limit: int = 100
    ) -> list[CtCandidate]:
        """Candidates first seen at or after `since`, newest first, then highest score."""
        query = f"SELECT {_CANDIDATE_COLUMNS} FROM ct_candidates WHERE score >= ?"  # noqa: S608
        params: list[object] = [min_score]
        if since is not None:
            query += " AND first_seen >= ?"
            params.append(timestamp(since))
        query += " ORDER BY first_seen DESC, score DESC, domain LIMIT ?"
        params.append(limit)
        with self._connect() as db:
            rows = db.execute(query, params).fetchall()
        return [
            CtCandidate(
                domain=r[0],
                registrable=r[1],
                score=r[2],
                brand=r[3],
                techniques=json.loads(r[4]),
                cert_id=r[5],
                issuer=r[6],
                not_before=r[7],
                first_seen=r[8],
                last_seen=r[9],
            )
            for r in rows
        ]

    def record_poll(self, poll: CtPoll) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO ct_polls (started_at, finished_at, queries, failed_queries, "
                "names_seen, candidates, new_candidates) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    poll.started_at,
                    poll.finished_at,
                    poll.queries,
                    poll.failed_queries,
                    poll.names_seen,
                    poll.candidates,
                    poll.new_candidates,
                ),
            )

    def last_poll(self) -> CtPoll | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT started_at, finished_at, queries, failed_queries, names_seen, "
                "candidates, new_candidates FROM ct_polls ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return CtPoll(
            started_at=row[0],
            finished_at=row[1],
            queries=row[2],
            failed_queries=row[3],
            names_seen=row[4],
            candidates=row[5],
            new_candidates=row[6],
        )


def timestamp(moment: datetime) -> str:
    """UTC ISO-8601 to the second, so stored timestamps compare correctly as strings.

    A naive datetime is taken to be UTC already.
    """
    moment = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
    return moment.isoformat(timespec="seconds")
