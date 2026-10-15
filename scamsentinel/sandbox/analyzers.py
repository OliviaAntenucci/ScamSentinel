"""Turn a SandboxReport into scored signals (architecture.md §8 table, M5)."""

from __future__ import annotations

from scamsentinel.models import ModuleResult
from scamsentinel.sandbox.detonator import SandboxReport


def analyze_report(report: SandboxReport) -> ModuleResult:
    raise NotImplementedError("M5: sandbox page analyzers")
