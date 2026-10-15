"""URL and domain extraction from free text, including defanged forms (FR-5).

Extracted URLs are only ever analyzed as strings. Nothing here (or anywhere in the
MVP) connects to them.
"""

from __future__ import annotations

import re

from scamsentinel.domain.psl import get_psl_extractor

_REFANG = (
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
)
_URL = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
# Unicode-aware so lookalike domains (Cyrillic letters, ...) are found too. The last
# label must start with a letter and have 2+ characters; the PSL check below confirms
# it's a real public suffix, which filters out "e.g.", "file.txt" and the like.
_DOMAIN = re.compile(r"(?<![\w.-])(?:[^\W_](?:[\w-]{0,61}[^\W_])?\.)+[^\W\d_][\w-]{1,62}(?![\w-])")
_TRAILING = ".,;:!?)]}>'\""


def refang(text: str) -> str:
    """Undo common defanging: hxxp -> http, [.] -> ., [:] -> :."""
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text


def extract_urls(text: str) -> list[str]:
    """URLs (with scheme) and bare domains in order of appearance, deduplicated."""
    text = refang(text)
    found: list[str] = []
    seen: set[str] = set()

    def add(item: str) -> None:
        item = item.rstrip(_TRAILING)
        if item and item.casefold() not in seen:
            seen.add(item.casefold())
            found.append(item)

    for match in _URL.finditer(text):
        add(match.group())

    psl = get_psl_extractor()
    for match in _DOMAIN.finditer(_URL.sub(" ", text)):
        candidate = match.group().rstrip(".").lower()
        parts = psl.extract_str(candidate)
        if parts.domain and parts.suffix:
            add(candidate)
    return found
