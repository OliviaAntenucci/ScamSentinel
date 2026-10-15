"""S2: prompt injection (SECURITY.md T2, AC-4). Enabled when the analyzer lands in M2/M3."""

import pytest

pytestmark = pytest.mark.skip(reason="M2/M3: message analyzer + aggregator not implemented yet")


def test_injection_never_lowers_verdict_band():
    raise NotImplementedError("paired corpus: each scam sample with and without ~30 injections")


def test_obedient_llm_still_flags_strong_rule_evidence():
    raise NotImplementedError("mock LLM returning empty features; domain/rules still -> scam")


def test_malformed_llm_output_falls_back_to_rules_only():
    raise NotImplementedError("schema-fuzzed LLM responses -> degraded rules-only, never 'safe'")


def test_ungrounded_spans_dropped():
    raise NotImplementedError("LLM span not present in input is discarded")
