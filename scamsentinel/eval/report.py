"""Markdown + JSON evaluation reports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from scamsentinel.eval.metrics import STRICT, TRIAGE, Confusion, Prediction, breakdown, confusion
from scamsentinel.models import Verdict


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _row(name: str, c: Confusion) -> str:
    return (
        f"| {name} | {c.n} | {pct(c.precision)} | {pct(c.recall)} | {pct(c.f1)} "
        f"| {pct(c.fpr)} | {c.tp} | {c.fp} | {c.tn} | {c.fn} |"
    )


_HEADER = (
    "| Slice | n | Precision | Recall | F1 | FPR | TP | FP | TN | FN |\n"
    "|---|---|---|---|---|---|---|---|---|---|"
)


def summary(predictions: list[Prediction]) -> dict[str, Any]:
    def metrics(c: Confusion) -> dict[str, Any]:
        return {
            "n": c.n, "tp": c.tp, "fp": c.fp, "tn": c.tn, "fn": c.fn,
            "precision": c.precision, "recall": c.recall, "f1": c.f1,
            "fpr": c.fpr, "accuracy": c.accuracy,
        }

    return {
        "strict": metrics(confusion(predictions, STRICT)),
        "triage": metrics(confusion(predictions, TRIAGE)),
        "by_category": {
            k: metrics(v)
            for k, v in breakdown(predictions, lambda p: p.category, STRICT).items()
        },
        "by_input_type": {
            k: metrics(v)
            for k, v in breakdown(predictions, lambda p: p.input_type, STRICT).items()
        },
        "by_brand": {
            k: metrics(v) for k, v in breakdown(predictions, lambda p: p.brand, STRICT).items()
        },
    }


def markdown(
    predictions: list[Prediction], *, split: str, ablation: str, llm: str, dataset: str
) -> str:
    strict = confusion(predictions, STRICT)
    triage = confusion(predictions, TRIAGE)
    lines = [
        f"# ScamSentinel evaluation: {split} split",
        "",
        f"- Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        f"- Dataset: `{dataset}` ({len(predictions)} samples in this split)",
        f"- Configuration: `{ablation}` · LLM: {llm}",
        "- Positive class: scam. **Strict** counts only `likely_scam` as a detection; "
        "**triage** also counts `suspicious`.",
        "",
        "## Overall",
        "",
        _HEADER,
        _row("strict", strict),
        _row("triage", triage),
        "",
        "## By category (strict)",
        "",
        _HEADER,
        *(_row(k, v) for k, v in breakdown(predictions, lambda p: p.category, STRICT).items()),
        "",
        "## By input type (strict)",
        "",
        _HEADER,
        *(
            _row(k, v)
            for k, v in breakdown(predictions, lambda p: p.input_type, STRICT).items()
        ),
        "",
        "## By brand (strict)",
        "",
        _HEADER,
        *(_row(k, v) for k, v in breakdown(predictions, lambda p: p.brand, STRICT).items()),
        "",
        "## By data source (strict)",
        "",
        _HEADER,
        *(
            _row("synthetic" if k == "True" else "real", v)
            for k, v in breakdown(predictions, lambda p: str(p.synthetic), STRICT).items()
        ),
        "",
        "## Verdicts by label",
        "",
        "| Label | likely_scam | suspicious | likely_legitimate |",
        "|---|---|---|---|",
    ]
    for label in ("scam", "legitimate"):
        counts = [
            sum(1 for p in predictions if p.label == label and p.verdict == v)
            for v in (Verdict.LIKELY_SCAM, Verdict.SUSPICIOUS, Verdict.LIKELY_LEGITIMATE)
        ]
        lines.append(f"| {label} | {' | '.join(map(str, counts))} |")

    errors = [
        p
        for p in predictions
        if (p.label == "scam") != (p.verdict in STRICT) or p.error
    ]
    lines += ["", "## Errors (strict)", ""]
    if not errors:
        lines.append("None.")
    else:
        lines += ["| Sample | Label | Verdict | Score | Signals |", "|---|---|---|---|---|"]
        for p in sorted(errors, key=lambda p: (p.label, p.id)):
            signals = ", ".join(p.signals) or (p.error or "none")
            lines.append(
                f"| {p.id} | {p.label} | {p.verdict.value} | {p.risk_score} | {signals} |"
            )
    return "\n".join(lines) + "\n"
