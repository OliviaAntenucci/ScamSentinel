"""Labeled evaluation samples and deterministic, leak-free splits (architecture.md §10)."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

Label = Literal["scam", "legitimate"]
Split = Literal["train", "dev", "test"]
SPLIT_SEED = "scamsentinel-eval-v1"
SPLIT_FRACTIONS = (("train", 0.6), ("dev", 0.2), ("test", 0.2))


class Sample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    # Variants of the same template share a group, so they always land in the same split.
    group: str | None = None
    input_type: Literal["text", "url", "email"]
    label: Label
    # Scam category from data/brands.yaml. The original 152 samples are all "tax"; every
    # sample of another category must set it.
    category: str = "tax"
    brand: str = "none"
    # URLs in scam samples are stored defanged (hxxps://, [.]); ScamSentinel refangs them.
    content: str
    source: str = "synthetic-handwritten"
    synthetic: bool = True
    notes: str = ""

    @property
    def split_key(self) -> str:
        return self.group or self.id


def load_samples(path: Path) -> list[Sample]:
    samples = [
        Sample.model_validate(json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ids = [s.id for s in samples]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise ValueError(f"duplicate sample ids: {sorted(duplicates)}")
    return samples


def _rank(key: str) -> str:
    return hashlib.sha256(f"{SPLIT_SEED}:{key}".encode()).hexdigest()


def assign_splits(samples: list[Sample]) -> dict[str, Split]:
    """Sample id -> split. Stratified by category × input type × label, grouped by template.

    Within each stratum, groups are ordered by a seeded hash and cut 60/20/20, so the
    assignment is deterministic and a group never straddles two splits. Because category
    is part of the stratum, adding samples of a new category never moves an existing
    category's samples to another split (its test set stays untouched).
    """
    strata: dict[tuple[str, str, str], dict[str, list[Sample]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for s in samples:
        strata[(s.category, s.input_type, s.label)][s.split_key].append(s)

    splits: dict[str, Split] = {}
    for groups in strata.values():
        ordered = sorted(groups, key=_rank)
        total = sum(len(groups[g]) for g in ordered)
        assigned = 0
        for key in ordered:
            position = assigned / total
            cumulative = 0.0
            split: Split = "test"
            for name, fraction in SPLIT_FRACTIONS:
                cumulative += fraction
                if position < cumulative - 1e-9:
                    split = name  # type: ignore[assignment]
                    break
            for s in groups[key]:
                splits[s.id] = split
            assigned += len(groups[key])
    return splits


def select(
    samples: list[Sample], split: Split | Literal["all"], category: str | None = None
) -> list[Sample]:
    """Samples in `split` (and `category`). Splits are assigned over the whole dataset."""
    if split != "all":
        splits = assign_splits(samples)
        samples = [s for s in samples if splits[s.id] == split]
    if category is not None:
        samples = [s for s in samples if s.category == category]
    return samples
