"""Evaluation harness: `python -m scamsentinel.eval --split test` (architecture.md §10).

Tune rules, weights and prompts on the dev split only. The test split is for the final,
reported numbers.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scamsentinel.config import get_settings
from scamsentinel.eval.dataset import load_samples, select
from scamsentinel.eval.metrics import STRICT, TRIAGE, confusion
from scamsentinel.eval.report import markdown, pct, summary
from scamsentinel.eval.runner import RATE_LIMITED, build_service, run


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m scamsentinel.eval")
    parser.add_argument("--split", choices=["train", "dev", "test", "all"], default="dev")
    parser.add_argument(
        "--ablation", choices=["full", "rules_only", "no_verify"], default="rules_only",
        help="full uses the LLM if GROQ_API_KEY is set (costs API calls; results are cached)",
    )
    parser.add_argument("--data", type=Path, default=Path("data/eval/samples.jsonl"))
    parser.add_argument("--report", type=Path, help="write a markdown report to this path")
    parser.add_argument("--json", type=Path, help="write metrics + predictions as JSON")
    parser.add_argument(
        "--db", type=Path, default=Path("var/eval.db"), help="SQLite file for the LLM cache"
    )
    parser.add_argument(
        "--rate-limit-retries", type=int, default=3,
        help="retries per sample when the LLM is rate limited (free-tier quotas)",
    )
    parser.add_argument(
        "--rate-limit-wait", type=float, default=20.0, help="seconds to wait before a retry"
    )
    args = parser.parse_args()

    settings = get_settings()
    samples = select(load_samples(args.data), args.split)
    service = build_service(settings, args.ablation, args.db)
    retries = args.rate_limit_retries if args.ablation != "rules_only" else 0
    predictions = run(
        samples,
        service,
        rate_limit_retries=retries,
        rate_limit_wait=args.rate_limit_wait,
        progress=lambda line: print(line, flush=True),
    )
    rate_limited = sum(RATE_LIMITED in p.degraded for p in predictions)
    if rate_limited:
        print(f"warning: {rate_limited} samples were still rate limited and scored rules-only")

    llm_calls = sum(p.llm_used for p in predictions)
    llm = (
        f"{settings.llm_provider} {settings.resolved_llm_model} ({llm_calls} samples)"
        if llm_calls
        else "none (rules only)"
    )

    strict, triage = confusion(predictions, STRICT), confusion(predictions, TRIAGE)
    print(f"{args.split} split, {len(predictions)} samples, ablation={args.ablation}, LLM: {llm}")
    for name, c in (("strict", strict), ("triage", triage)):
        print(
            f"  {name:6}  precision {pct(c.precision):>6}  recall {pct(c.recall):>6}  "
            f"F1 {pct(c.f1):>6}  FPR {pct(c.fpr):>6}  (TP {c.tp} FP {c.fp} TN {c.tn} FN {c.fn})"
        )

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            markdown(
                predictions, split=args.split, ablation=args.ablation, llm=llm,
                dataset=str(args.data),
            ),
            encoding="utf-8",
        )
        print(f"report: {args.report}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "split": args.split,
            "ablation": args.ablation,
            "llm": llm,
            "metrics": summary(predictions),
            "predictions": [p.model_dump(mode="json") for p in predictions],
        }
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"json: {args.json}")


if __name__ == "__main__":
    main()
