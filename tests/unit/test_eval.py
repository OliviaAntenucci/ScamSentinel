"""Evaluation harness: dataset hygiene, split integrity, metric math, runner, report."""

import re
from collections import Counter
from pathlib import Path

import pytest

from scamsentinel.eval.dataset import Sample, assign_splits, load_samples, select
from scamsentinel.eval.metrics import STRICT, TRIAGE, Prediction, confusion
from scamsentinel.eval.report import markdown, summary
from scamsentinel.eval.runner import build_service, run
from scamsentinel.models import Verdict

DATASET = Path(__file__).resolve().parents[2] / "data" / "eval" / "samples.jsonl"
SAMPLES = load_samples(DATASET)


# --- dataset hygiene ------------------------------------------------------------------------


def test_dataset_size_and_balance():
    counts = Counter((s.input_type, s.label) for s in SAMPLES)
    assert len(SAMPLES) >= 150
    for input_type in ("text", "email", "url"):
        assert counts[(input_type, "scam")] >= 10
        assert counts[(input_type, "legitimate")] >= 10


def test_scam_links_are_defanged():
    # SCOPE.md: never store live, clickable phishing URLs in the repository.
    for s in SAMPLES:
        if s.label == "scam":
            assert not re.search(r"https?://", s.content), s.id


def test_brands_are_known():
    allowed = {"IRS", "TurboTax", "QuickBooks", "Credit Karma", "none"}
    assert {s.brand for s in SAMPLES} <= allowed


def test_duplicate_ids_rejected(tmp_path):
    line = '{"id": "x", "input_type": "text", "label": "scam", "content": "a"}\n'
    path = tmp_path / "dup.jsonl"
    path.write_text(line * 2, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_samples(path)


# --- splits ------------------------------------------------------------------------------


def test_splits_are_deterministic():
    assert assign_splits(SAMPLES) == assign_splits(list(reversed(SAMPLES)))


def test_groups_never_straddle_splits():
    splits = assign_splits(SAMPLES)
    by_group: dict[str, set[str]] = {}
    for s in SAMPLES:
        by_group.setdefault(s.split_key, set()).add(splits[s.id])
    assert all(len(v) == 1 for v in by_group.values())


def test_every_stratum_has_dev_and_test_samples():
    splits = assign_splits(SAMPLES)
    for input_type in ("text", "email", "url"):
        for label in ("scam", "legitimate"):
            seen = {splits[s.id] for s in SAMPLES if (s.input_type, s.label) == (input_type, label)}
            assert {"train", "dev", "test"} <= seen, (input_type, label)


def test_split_fractions_roughly_60_20_20():
    counts = Counter(assign_splits(SAMPLES).values())
    assert 0.5 <= counts["train"] / len(SAMPLES) <= 0.7
    assert 0.12 <= counts["test"] / len(SAMPLES) <= 0.28


def test_select():
    assert len(select(SAMPLES, "all")) == len(SAMPLES)
    parts = sum(len(select(SAMPLES, split)) for split in ("train", "dev", "test"))
    assert parts == len(SAMPLES)


# --- metrics -------------------------------------------------------------------------------


def pred(label: str, verdict: Verdict) -> Prediction:
    return Prediction(
        id="x", input_type="text", label=label, brand="none", synthetic=True,
        verdict=verdict, risk_score=0,
    )


def test_confusion_and_metrics():
    preds = [
        pred("scam", Verdict.LIKELY_SCAM),  # TP
        pred("scam", Verdict.LIKELY_SCAM),  # TP
        pred("scam", Verdict.SUSPICIOUS),  # FN strict, TP triage
        pred("legitimate", Verdict.LIKELY_LEGITIMATE),  # TN
        pred("legitimate", Verdict.SUSPICIOUS),  # TN strict, FP triage
        pred("legitimate", Verdict.LIKELY_SCAM),  # FP
    ]
    strict = confusion(preds, STRICT)
    assert (strict.tp, strict.fp, strict.tn, strict.fn) == (2, 1, 2, 1)
    assert strict.precision == pytest.approx(2 / 3)
    assert strict.recall == pytest.approx(2 / 3)
    assert strict.f1 == pytest.approx(2 / 3)
    assert strict.fpr == pytest.approx(1 / 3)
    triage = confusion(preds, TRIAGE)
    assert (triage.tp, triage.fp, triage.tn, triage.fn) == (3, 2, 1, 0)


def test_metrics_with_empty_denominators():
    c = confusion([pred("legitimate", Verdict.LIKELY_LEGITIMATE)], STRICT)
    assert c.precision is None and c.recall is None and c.f1 is None
    assert c.fpr == 0.0


# --- runner + report -----------------------------------------------------------------------


def test_runner_and_report_on_a_few_samples(settings, tmp_path):
    picked = [s for s in SAMPLES if s.id in {"t-s-001", "t-l-001", "u-s-006", "e-s-002"}]
    service = build_service(settings, "rules_only", tmp_path / "eval.db")
    predictions = run(picked, service)
    assert [p.id for p in predictions] == [s.id for s in picked]
    assert all(not p.llm_used for p in predictions)

    report = markdown(
        predictions, split="dev", ablation="rules_only", llm="none", dataset="x.jsonl"
    )
    assert "## Overall" in report
    assert "| strict |" in report
    assert summary(predictions)["strict"]["n"] == len(predictions)


def test_no_verify_ablation_zeroes_verification(settings, tmp_path):
    sample = Sample(
        id="x", input_type="text", label="scam", brand="IRS",
        content="IRS: pay your balance today with gift cards.",
    )
    full = run([sample], build_service(settings, "rules_only", tmp_path / "a.db"))[0]
    no_verify = run([sample], build_service(settings, "no_verify", tmp_path / "b.db"))[0]
    assert "payment_method_policy" in full.signals
    assert "payment_method_policy" not in no_verify.signals
