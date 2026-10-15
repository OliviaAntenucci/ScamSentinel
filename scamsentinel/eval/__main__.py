"""Evaluation harness: `python -m scamsentinel.eval --split test` (architecture.md §11, M8)."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m scamsentinel.eval")
    parser.add_argument("--split", choices=["train", "dev", "test"], default="dev")
    parser.add_argument("--report", type=Path, help="write a markdown report to this path")
    parser.add_argument(
        "--ablation",
        choices=["full", "rules_only", "no_sandbox", "no_verify"],
        default="full",
    )
    parser.parse_args()
    raise SystemExit("evaluation harness not implemented yet (M8)")


if __name__ == "__main__":
    main()
