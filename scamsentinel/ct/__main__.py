"""Run the CT watcher: `python -m scamsentinel.ct` (or `--once` for a single pass)."""

from __future__ import annotations

import argparse

from scamsentinel.config import get_settings
from scamsentinel.ct.watcher import CtWatcher, run_forever
from scamsentinel.security.redaction import configure_logging


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m scamsentinel.ct")
    parser.add_argument("--once", action="store_true", help="run one polling pass and exit")
    args = parser.parse_args()

    settings = get_settings()
    configure_logging()
    watcher = CtWatcher.from_settings(settings)
    if args.once:
        poll = watcher.poll_once()
        print(
            f"{poll.queries} queries ({poll.failed_queries} failed), {poll.names_seen} names, "
            f"{poll.candidates} candidates, {poll.new_candidates} new"
        )
        return
    try:
        run_forever(watcher, settings.ct_poll_interval_hours * 3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
