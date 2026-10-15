"""Hostname canonicalization and homoglyph skeletons (FR-6, FR-7, M1)."""

from __future__ import annotations


def canonicalize_host(host_or_url: str) -> str:
    """Lowercase, strip trailing dot and port, decode punycode labels to Unicode."""
    raise NotImplementedError("M1: host canonicalization")


def skeleton(label: str) -> str:
    """UTS #39 confusables skeleton plus ASCII substitutions (0->o, 1->l, rn->m, ...)."""
    raise NotImplementedError("M1: homoglyph skeleton")
