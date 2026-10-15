"""Precision / recall / F1 / FPR over predictions (positive class = scam)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from pydantic import BaseModel

from scamsentinel.models import Verdict

# "strict": only likely_scam counts as flagging a scam.
# "triage": suspicious counts too (what a cautious user would double-check).
STRICT = frozenset({Verdict.LIKELY_SCAM})
TRIAGE = frozenset({Verdict.LIKELY_SCAM, Verdict.SUSPICIOUS})


class Prediction(BaseModel):
    id: str
    input_type: str
    label: str
    brand: str
    category: str = "tax"
    synthetic: bool
    verdict: Verdict
    risk_score: int
    signals: list[str] = []
    llm_used: bool = False
    degraded: list[str] = []
    error: str | None = None


@dataclass(frozen=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None if p is None or r is None else 0.0
        return 2 * p * r / (p + r)

    @property
    def fpr(self) -> float | None:
        return _ratio(self.fp, self.fp + self.tn)

    @property
    def accuracy(self) -> float | None:
        return _ratio(self.tp + self.tn, self.n)


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def confusion(predictions: Iterable[Prediction], positive: frozenset[Verdict]) -> Confusion:
    tp = fp = tn = fn = 0
    for p in predictions:
        flagged = p.verdict in positive
        if p.label == "scam":
            tp, fn = (tp + 1, fn) if flagged else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if flagged else (fp, tn + 1)
    return Confusion(tp, fp, tn, fn)


def breakdown(
    predictions: list[Prediction], key: Callable[[Prediction], str], positive: frozenset[Verdict]
) -> dict[str, Confusion]:
    groups: dict[str, list[Prediction]] = defaultdict(list)
    for p in predictions:
        groups[key(p)].append(p)
    return {name: confusion(groups[name], positive) for name in sorted(groups)}
