"""CT polling loop: query each brand token, dedupe, score, persist candidates (M7)."""

from __future__ import annotations

POLL_INTERVAL_SECONDS = 6 * 60 * 60
MIN_CANDIDATE_SCORE = 50


def poll_once() -> int:
    """Run one polling pass. Returns the number of new candidates stored."""
    raise NotImplementedError("M7: CT watcher")


def run_forever() -> None:
    raise NotImplementedError("M7: CT watcher")
