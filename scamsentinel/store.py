"""SQLite storage: analysis results with their inputs, accounts, and the LLM response cache.

Analyses (and the screenshots behind them) are kept until deleted; only the LLM cache
expires. A new connection per call keeps this safe under FastAPI's thread pool without
sharing a connection across threads.
"""

from __future__ import annotations

import hashlib
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

-- The cleaned screenshot (metadata stripped) behind an image analysis.
CREATE TABLE IF NOT EXISTS input_images (
    analysis_id TEXT PRIMARY KEY,
    mime        TEXT NOT NULL,
    data        BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_cache (
    key           TEXT PRIMARY KEY,
    provider      TEXT NOT NULL,
    model         TEXT NOT NULL,
    features_json TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS account_sessions (
    token_hash TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS account_sessions_expires_at ON account_sessions (expires_at);
CREATE TABLE IF NOT EXISTS saved_analyses (
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    analysis_id TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    result_json TEXT NOT NULL,
    PRIMARY KEY (account_id, analysis_id)
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

    def save_analysis(
        self, result: AnalysisResult, input_hash: str, image: tuple[str, bytes] | None = None
    ) -> None:
        """Store a result (its `submitted` input included) and, for a screenshot, the
        cleaned image as (mime, bytes)."""
        with self._connect() as db:
            db.execute(
                "INSERT INTO analyses (id, created_at, expires_at, input_type, input_hash, "
                "verdict, risk_score, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result.analysis_id,
                    result.created_at.isoformat(),
                    "",  # analyses no longer expire; the column stays for older databases
                    result.input_type,
                    input_hash,
                    result.verdict.value,
                    result.risk_score,
                    result.model_dump_json(),
                ),
            )
            if image is not None:
                db.execute(
                    "INSERT INTO input_images (analysis_id, mime, data) VALUES (?, ?, ?)",
                    (result.analysis_id, image[0], image[1]),
                )

    def get_analysis(self, analysis_id: str) -> AnalysisResult | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT result_json FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
        return AnalysisResult.model_validate_json(row[0]) if row else None

    def get_input_image(self, analysis_id: str) -> tuple[str, bytes] | None:
        """The screenshot behind an analysis as (mime, bytes), if it was one."""
        with self._connect() as db:
            row = db.execute(
                "SELECT mime, data FROM input_images WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
        return (row[0], bytes(row[1])) if row else None

    def purge_expired(self) -> int:
        """Delete expired LLM cache entries (NFR-4). Returns the number removed.

        Cached LLM features quote the analyzed text and hold it unredacted, so they still
        expire. Analyses are kept until deleted.
        """
        cache_cutoff = (_now() - self.retention).isoformat()
        with self._connect() as db:
            return db.execute(
                "DELETE FROM llm_cache WHERE created_at <= ?", (cache_cutoff,)
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

    # --- accounts and saved analyses ------------------------------------------------

    def create_account(self, email: str, password_hash: str) -> int | None:
        with self._connect() as db:
            try:
                cursor = db.execute(
                    "INSERT INTO accounts (email, password_hash, created_at) VALUES (?, ?, ?)",
                    (email, password_hash, _now().isoformat()),
                )
            except sqlite3.IntegrityError:
                return None
            return int(cursor.lastrowid)

    def get_account_credentials(self, email: str) -> tuple[int, str] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT id, password_hash FROM accounts WHERE email = ?", (email,)
            ).fetchone()
        return (int(row[0]), row[1]) if row else None

    def create_account_session(self, token: str, account_id: int, expires_at: datetime) -> None:
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._connect() as db:
            db.execute("DELETE FROM account_sessions WHERE expires_at <= ?", (_now().isoformat(),))
            db.execute(
                "INSERT INTO account_sessions (token_hash, account_id, expires_at) "
                "VALUES (?, ?, ?)",
                (token_hash, account_id, expires_at.isoformat()),
            )

    def get_session_account(self, token: str) -> tuple[int, str] | None:
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._connect() as db:
            row = db.execute(
                "SELECT accounts.id, accounts.email FROM account_sessions "
                "JOIN accounts ON accounts.id = account_sessions.account_id "
                "WHERE account_sessions.token_hash = ? AND account_sessions.expires_at > ?",
                (token_hash, _now().isoformat()),
            ).fetchone()
        return (int(row[0]), row[1]) if row else None

    def delete_account_session(self, token: str) -> None:
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._connect() as db:
            db.execute("DELETE FROM account_sessions WHERE token_hash = ?", (token_hash,))

    def save_account_analysis(self, account_id: int, result: AnalysisResult) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO saved_analyses "
                "(account_id, analysis_id, created_at, result_json) VALUES (?, ?, ?, ?)",
                (
                    account_id,
                    result.analysis_id,
                    _now().isoformat(),
                    result.model_dump_json(),
                ),
            )

    def list_account_analyses(self, account_id: int) -> list[AnalysisResult]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT result_json FROM saved_analyses WHERE account_id = ? "
                "ORDER BY created_at DESC",
                (account_id,),
            ).fetchall()
        return [AnalysisResult.model_validate_json(row[0]) for row in rows]

    def get_account_analysis(self, account_id: int, analysis_id: str) -> AnalysisResult | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT result_json FROM saved_analyses "
                "WHERE account_id = ? AND analysis_id = ?",
                (account_id, analysis_id),
            ).fetchone()
        return AnalysisResult.model_validate_json(row[0]) if row else None

    def delete_account_analysis(self, account_id: int, analysis_id: str) -> bool:
        with self._connect() as db:
            cursor = db.execute(
                "DELETE FROM saved_analyses WHERE account_id = ? AND analysis_id = ?",
                (account_id, analysis_id),
            )
        return cursor.rowcount > 0


def _now() -> datetime:
    return datetime.now(UTC)
