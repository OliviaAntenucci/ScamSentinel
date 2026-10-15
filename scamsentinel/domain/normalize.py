"""Hostname canonicalization and homoglyph skeletons (FR-6, FR-7)."""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

MAX_HOST_LENGTH = 253

# Ideographic / fullwidth / halfwidth full stops, which IDNA treats as label separators.
_DOT_VARIANTS = str.maketrans({"。": ".", "．": ".", "｡": "."})
# Zero-width and soft-hyphen characters that render as nothing.
_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿­"))
# Characters that end or split a hostname (including dot variants IDNA treats as dots).
_HOST_DELIMITERS = frozenset("./\\?#@:%[]。．｡")
# Defanged indicators as they appear in threat-intel reports and phishing write-ups.
_DEFANG = (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("hxxp", "http"))


class InvalidHost(ValueError):
    """The input does not contain a usable hostname."""


def canonicalize_host(host_or_url: str) -> str:
    """Return the lowercase Unicode hostname from a URL or bare host.

    Strips scheme, userinfo, port, path and trailing dot; refangs `[.]`/`hxxp`;
    decodes punycode (`xn--`) labels so lookalike characters become visible.
    """
    s = host_or_url.strip().lower()
    for old, new in _DEFANG:
        s = s.replace(old, new)
    s = s.translate(_DOT_VARIANTS).translate(_INVISIBLE)
    if "://" not in s:
        s = "//" + s
    try:
        host = urlsplit(s).hostname
    except ValueError as exc:
        raise InvalidHost(f"cannot parse {host_or_url!r}") from exc
    host = (host or "").rstrip(".")
    if not host:
        raise InvalidHost(f"no hostname in {host_or_url!r}")
    if len(host) > MAX_HOST_LENGTH or any(c.isspace() for c in host):
        raise InvalidHost(f"invalid hostname {host!r}")
    labels = host.split(".")
    if any(not label for label in labels):
        raise InvalidHost(f"empty label in {host!r}")
    return ".".join(_decode_label(label) for label in labels)


def _decode_label(label: str) -> str:
    if not label.startswith("xn--"):
        return label
    try:
        # Plain punycode rather than strict IDNA: we want to see what the attacker
        # registered, even if a registry policy would have rejected it.
        decoded = label[4:].encode("ascii").decode("punycode").lower()
    except UnicodeError:
        return label
    # A decoded label must not smuggle in separators or invisible characters that
    # would change how the host splits; keep the raw form in that case.
    if not decoded or any(
        c in _HOST_DELIMITERS or c.isspace() or not c.isprintable() for c in decoded
    ):
        return label
    return decoded.translate(_INVISIBLE)


def load_confusables(path: Path) -> dict[str, str]:
    """Parse data/confusables.txt (`U+XXXX replacement  # name`)."""
    table: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        code_point, replacement = line.split()
        table[chr(int(code_point.removeprefix("U+"), 16))] = replacement
    return table


def scripts_in(label: str) -> set[str]:
    """Unicode scripts of the letters in `label` (LATIN, CYRILLIC, GREEK, ...)."""
    return {unicodedata.name(c, "UNKNOWN").split(" ", 1)[0] for c in label if c.isalpha()}


class Normalizer:
    """Maps a label to its visual skeleton so lookalikes compare equal to the real name.

    skeleton = NFKC + casefold -> Unicode confusables -> strip combining marks ->
    ASCII lookalike classes (single characters first, then multi-character).
    """

    def __init__(self, confusables: Mapping[str, str], ascii_classes: Mapping[str, str]) -> None:
        self._confusables = dict(confusables)
        self._single = str.maketrans({k: v for k, v in ascii_classes.items() if len(k) == 1})
        self._multi = sorted(
            ((k, v) for k, v in ascii_classes.items() if len(k) > 1),
            key=lambda kv: len(kv[0]),
            reverse=True,
        )

    @staticmethod
    def literal(s: str) -> str:
        """How the text reads with no lookalike folding (NFKC + casefold only)."""
        return unicodedata.normalize("NFKC", s).casefold()

    def fold(self, s: str) -> str:
        """Unicode folding only: confusables and accents, but not the ASCII classes."""
        s = "".join(self._confusables.get(c, c) for c in self.literal(s))
        return "".join(c for c in unicodedata.normalize("NFD", s) if not unicodedata.combining(c))

    def skeleton(self, s: str) -> str:
        s = self.fold(s).translate(self._single)
        for src, dst in self._multi:
            s = s.replace(src, dst)
        return s

    def segments(self, s: str) -> list[tuple[str, str]]:
        """`s` split into (original characters, their skeleton) pairs, for explaining which
        characters imitate which (E2). The skeletons normally concatenate to skeleton(s);
        callers check that before relying on the alignment."""
        segments: list[tuple[str, str]] = []
        for c in s:
            piece = self.fold(c).translate(self._single)
            if not piece and segments:
                # A combining mark folds to nothing: it belongs to the previous character.
                segments[-1] = (segments[-1][0] + c, segments[-1][1])
            else:
                segments.append((c, piece))
        for src, dst in self._multi:
            merged: list[tuple[str, str]] = []
            i = 0
            while i < len(segments):
                window = segments[i : i + len(src)]
                if len(window) == len(src) and "".join(p for _, p in window) == src:
                    merged.append(("".join(o for o, _ in window), dst))
                    i += len(src)
                else:
                    merged.append(segments[i])
                    i += 1
            segments = merged
        return segments
