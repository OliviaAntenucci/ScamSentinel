# Evaluation data sources

List every source used in `data/eval/` here, with its license and how samples were filtered or relabeled (SCOPE.md: Evaluation data).

| Slice | Source | License / terms | Filtering | Count |
|---|---|---|---|---|
| _none yet (M6)_ | | | | |

Rules:
- URLs are stored **defanged** (`hxxps://example[.]com`).
- Synthetic samples are marked `synthetic: true` and reviewed by hand before use.
- Raw downloads go in `data/eval/raw/`, which git ignores.
- User submissions are never added without consent.
