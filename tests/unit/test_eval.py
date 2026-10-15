"""Evaluation harness: dataset hygiene, split integrity, metric math, runner, report."""

import re
from collections import Counter
from pathlib import Path

import pytest

from scamsentinel.data import load_brands, load_categories
from scamsentinel.eval.dataset import Sample, assign_splits, load_samples, select
from scamsentinel.eval.metrics import STRICT, TRIAGE, Prediction, confusion
from scamsentinel.eval.report import markdown, summary
from scamsentinel.eval.runner import build_service, run
from scamsentinel.message.features import MessageFeatures
from scamsentinel.message.llm import LlmUnavailable
from scamsentinel.models import Verdict

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DATASET = DATA_DIR / "eval" / "samples.jsonl"
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


BRANDS = {b.name: b for b in load_brands(DATA_DIR)}


def test_brands_and_categories_are_known():
    categories = load_categories(DATA_DIR)
    for s in SAMPLES:
        assert s.category in categories, s.id
        assert s.brand == "none" or s.brand in BRANDS, s.id
        if s.brand != "none":
            assert BRANDS[s.brand].category == s.category, s.id


def test_every_category_is_evaluated():
    # A category isn't claimed as supported until it has labeled scams and hard negatives.
    for category in load_categories(DATA_DIR):
        labels = Counter(s.label for s in SAMPLES if s.category == category)
        assert labels["scam"] >= 15 and labels["legitimate"] >= 15, category


def test_new_categories_never_move_existing_splits():
    # Category is part of the stratum, so the tax test set is the same with or without
    # the samples of other categories.
    tax = [s for s in SAMPLES if s.category == "tax"]
    everything = assign_splits(SAMPLES)
    assert assign_splits(tax) == {s.id: everything[s.id] for s in tax}


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
    for category in {s.category for s in SAMPLES}:
        for input_type in ("text", "email", "url"):
            for label in ("scam", "legitimate"):
                key = (category, input_type, label)
                seen = {
                    splits[s.id]
                    for s in SAMPLES
                    if (s.category, s.input_type, s.label) == key
                }
                assert {"train", "dev", "test"} <= seen, key


def test_split_fractions_roughly_60_20_20():
    counts = Counter(assign_splits(SAMPLES).values())
    assert 0.5 <= counts["train"] / len(SAMPLES) <= 0.7
    assert 0.12 <= counts["test"] / len(SAMPLES) <= 0.28


def test_select():
    assert len(select(SAMPLES, "all")) == len(SAMPLES)
    parts = sum(len(select(SAMPLES, split)) for split in ("train", "dev", "test"))
    assert parts == len(SAMPLES)
    delivery_test = select(SAMPLES, "test", "delivery")
    assert delivery_test
    assert all(s.category == "delivery" for s in delivery_test)
    assert {s.id for s in delivery_test} <= {s.id for s in select(SAMPLES, "test")}


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


class FlakyLlm:
    """Rate limited for the first `failures` calls, then returns empty features."""

    def __init__(self, failures: int):
        self.failures = failures
        self.calls = 0

    def extract(self, text):
        self.calls += 1
        if self.calls <= self.failures:
            raise LlmUnavailable("rate_limited")
        return MessageFeatures()


def test_rate_limited_samples_are_retried(make_service):
    sample = next(s for s in SAMPLES if s.id == "t-s-001")
    llm = FlakyLlm(failures=2)
    waits: list[float] = []
    [prediction] = run(
        [sample], make_service(llm), rate_limit_retries=3, rate_limit_wait=5, sleep=waits.append
    )
    assert prediction.llm_used
    assert prediction.degraded == []
    assert waits == [5, 5]
    assert llm.calls == 3


def test_rate_limit_retries_are_bounded(make_service):
    sample = next(s for s in SAMPLES if s.id == "t-s-001")
    llm = FlakyLlm(failures=99)
    [prediction] = run(
        [sample], make_service(llm), rate_limit_retries=2, rate_limit_wait=1, sleep=lambda s: None
    )
    assert not prediction.llm_used
    assert prediction.degraded == ["llm_unavailable:rate_limited"]
    assert llm.calls == 3


def test_no_verify_ablation_zeroes_verification(settings, tmp_path):
    sample = Sample(
        id="x", input_type="text", label="scam", brand="IRS",
        content="IRS: pay your balance today with gift cards.",
    )
    full = run([sample], build_service(settings, "rules_only", tmp_path / "a.db"))[0]
    no_verify = run([sample], build_service(settings, "no_verify", tmp_path / "b.db"))[0]
    assert "payment_method_policy" in full.signals
    assert "payment_method_policy" not in no_verify.signals
