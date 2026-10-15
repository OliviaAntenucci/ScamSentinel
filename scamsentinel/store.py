"""SQLite storage: analysis results (7-day retention) and the LLM response cache.

A new connection per call keeps this safe under FastAPI's thread pool without sharing a
connection across threads.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scamsentinel.models import AnalysisResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    input_type  TEXT NOT NULL,
    input_hash  TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS analyses_expires_at ON analyses (expires_at);

CREATE TABLE IF NOT EXISTS llm_cache (
    key           TEXT PRIMARY KEY,
    provider      TEXT NOT NULL,
    model         TEXT NOT NULL,
    features_json TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path, retention_days: int = 7) -> None:
        self.path = path
        self.retention = timedelta(days=retention_days)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(SCHEMA)
        self.purge_expired()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path)) as db, db:
            yield db

    # --- analyses -------------------------------------------------------------------

    def save_analysis(self, result: AnalysisResult, input_hash: str) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO analyses (id, created_at, expires_at, input_type, input_hash, "
                "verdict, risk_score, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result.analysis_id,
                    result.created_at.isoformat(),
                    (result.created_at + self.retention).isoformat(),
                    result.input_type,
                    input_hash,
                    result.verdict.value,
                    result.risk_score,
                    result.model_dump_json(),
                ),
            )

    def get_analysis(self, analysis_id: str) -> AnalysisResult | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT result_json FROM analyses WHERE id = ? AND expires_at > ?",
                (analysis_id, _now().isoformat()),
            ).fetchone()
        return AnalysisResult.model_validate_json(row[0]) if row else None

    def purge_expired(self) -> int:
        """Delete expired analyses and cache entries (NFR-4). Returns analyses removed.

        Cached LLM features quote the analyzed text, so they expire on the same schedule.
        """
        now = _now()
        cache_cutoff = (now - self.retention).isoformat()
        with self._connect() as db:
            db.execute("DELETE FROM llm_cache WHERE created_at <= ?", (cache_cutoff,))
            return db.execute(
                "DELETE FROM analyses WHERE expires_at <= ?", (now.isoformat(),)
            ).rowcount

    # --- LLM cache ------------------------------------------------------------------

    def get_llm_features(self, key: str) -> str | None:
        with self._connect() as db:
            row = db.execute("SELECT features_json FROM llm_cache WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def put_llm_features(self, key: str, provider: str, model: str, features_json: str) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO llm_cache (key, provider, model, features_json, "
                "created_at) VALUES (?, ?, ?, ?, ?)",
                (key, provider, model, features_json, _now().isoformat()),
            )


def _now() -> datetime:
    return datetime.now(UTC)
