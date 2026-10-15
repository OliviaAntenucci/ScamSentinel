"""URL/domain extraction from free text, including defanged forms (FR-5, M2)."""

from __future__ import annotations


def extract_urls(text: str) -> list[str]:
    """Find URLs and bare domains; refang hxxp:// and example[.]com before returning."""
    raise NotImplementedError("M2: URL extraction")
