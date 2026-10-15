"""North American phone-number extraction and normalization."""

from __future__ import annotations

import re

_PHONE = re.compile(
    r"(?<![\d+])(?:\+?1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]?[2-9]\d{2}[\s.-]?\d{4}(?!\d)"
)


def normalize_phone(raw: str) -> str | None:
    """E.164 form (+1XXXXXXXXXX), or None if it isn't a 10-digit NANP number."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return f"+1{digits}" if len(digits) == 10 else None


def extract_phone_numbers(text: str) -> list[str]:
    """Phone numbers exactly as written, deduplicated by normalized value."""
    found: list[str] = []
    seen: set[str] = set()
    for match in _PHONE.finditer(text):
        normalized = normalize_phone(match.group())
        if normalized and normalized not in seen:
            seen.add(normalized)
            found.append(match.group().strip())
    return found
