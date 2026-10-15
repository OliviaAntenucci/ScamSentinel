"""Richer domain explanations (E2, architecture.md §19).

A domain technique says *that* a domain imitates a brand ("homoglyph", "typosquat"). The
explanation says *how*: which characters were swapped in, how the name is misspelled,
which trust words were added, who really owns the site, or which ending was changed.
It's built from data the engine already computes and changes no score.

Everything here describes the domain as written. The domain is attacker-chosen, so it's
quoted as plain text only and never turned into a link.
"""

from __future__ import annotations

import unicodedata
from typing import Literal

from pydantic import BaseModel

from scamsentinel.domain.normalize import Normalizer


class CharacterSwap(BaseModel):
    """Characters in the domain that imitate the brand's, e.g. "0" for "o", "rn" for "m"."""

    found: str
    instead_of: str
    # Unicode names of the non-ASCII characters in `found`, e.g. "CYRILLIC SMALL LETTER O".
    unicode_names: list[str] = []


class SpellingEdit(BaseModel):
    """One edit that turns the brand name into the domain's misspelling."""

    kind: Literal["extra", "missing", "replaced", "swapped"]
    found: str = ""  # as written in the domain ("" for a missing letter)
    expected: str = ""  # as in the brand name ("" for an extra letter)


class DomainExplanation(BaseModel):
    domain: str  # registrable domain as written (Unicode)
    brand: str
    official_domains: list[str]
    swapped_characters: list[CharacterSwap] = []
    # The part of the name that misspells the brand, e.g. "turbotxa".
    misspelled: str | None = None
    spelling_edits: list[SpellingEdit] = []
    # Trust-building words added to the brand name, e.g. ["refund", "secure"].
    extra_words: list[str] = []
    # Who really owns a site that only shows the brand in a subdomain.
    real_owner: str | None = None
    # A brand name used under another ending, e.g. ".net" for turbotax.net.
    wrong_ending: str | None = None
    # Plain-language lines built from the fields above.
    summary: list[str] = []


# --- lookalike characters ---------------------------------------------------------------


def character_swaps(norm: Normalizer, label: str, token: str) -> list[CharacterSwap]:
    """Align `label` with the brand `token` through their skeletons, and list the places
    where the label's characters differ from the token's. [] if they can't be aligned."""
    label_segments = [s for s in norm.segments(label) if s[1] != "-"]
    token_segments = norm.segments(token)
    compact = "".join(skel for _, skel in label_segments)
    target = "".join(skel for _, skel in token_segments)
    # The segments must reproduce the engine's skeleton exactly, or the alignment
    # below could point at the wrong characters.
    if compact != norm.skeleton(label).replace("-", "") or target != norm.skeleton(token):
        return []
    start = compact.find(target)
    if start < 0:
        return []

    # Skeleton offsets where each segment ends, relative to the token's position.
    label_chunks, offset = [], 0
    for src, skel in label_segments:
        seg_start, offset = offset, offset + len(skel)
        if offset <= start:
            continue
        if seg_start >= start + len(target):
            break
        if seg_start < start:
            return []  # the token starts inside a multi-character segment
        label_chunks.append((src, offset - start))
    token_chunks, offset = [], 0
    for src, skel in token_segments:
        offset += len(skel)
        token_chunks.append((src, offset))

    label_ends = {end for _, end in label_chunks}
    token_ends = {end for _, end in token_chunks}
    if len(target) not in label_ends:
        return []
    boundaries = sorted(label_ends & token_ends)

    swaps: list[CharacterSwap] = []
    for found, expected in zip(
        _group(label_chunks, boundaries), _group(token_chunks, boundaries), strict=True
    ):
        if norm.literal(found) != expected:
            swaps.append(
                CharacterSwap(
                    found=found,
                    instead_of=expected,
                    unicode_names=[unicodedata.name(c, "UNKNOWN") for c in found if ord(c) > 127],
                )
            )
    return swaps


def _group(chunks: list[tuple[str, int]], boundaries: list[int]) -> list[str]:
    groups, current, i = [], "", 0
    for src, end in chunks:
        current += src
        if i < len(boundaries) and end == boundaries[i]:
            groups.append(current)
            current, i = "", i + 1
    return groups


# --- misspellings -----------------------------------------------------------------------


def spelling_edits(found: str, expected: str) -> list[SpellingEdit]:
    """Fewest edits (with adjacent swaps) turning `expected` into `found`."""
    n, m = len(found), len(expected)
    d = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        d[i][0] = i
    for j in range(m + 1):
        d[0][j] = j
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = 0 if found[i - 1] == expected[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if (
                i > 1
                and j > 1
                and found[i - 1] == expected[j - 2]
                and found[i - 2] == expected[j - 1]
            ):
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)

    edits: list[SpellingEdit] = []
    i, j = n, m
    while i > 0 or j > 0:
        if i > 0 and j > 0 and found[i - 1] == expected[j - 1] and d[i][j] == d[i - 1][j - 1]:
            i, j = i - 1, j - 1
        elif (
            i > 1
            and j > 1
            and found[i - 1] == expected[j - 2]
            and found[i - 2] == expected[j - 1]
            and d[i][j] == d[i - 2][j - 2] + 1
        ):
            edits.append(
                SpellingEdit(kind="swapped", found=found[i - 2 : i], expected=expected[j - 2 : j])
            )
            i, j = i - 2, j - 2
        elif i > 0 and j > 0 and d[i][j] == d[i - 1][j - 1] + 1:
            edits.append(
                SpellingEdit(kind="replaced", found=found[i - 1], expected=expected[j - 1])
            )
            i, j = i - 1, j - 1
        elif i > 0 and d[i][j] == d[i - 1][j] + 1:
            edits.append(SpellingEdit(kind="extra", found=found[i - 1]))
            i -= 1
        else:
            edits.append(SpellingEdit(kind="missing", expected=expected[j - 1]))
            j -= 1
    return edits[::-1]


# --- plain-language summary -------------------------------------------------------------


def summarize(e: DomainExplanation, registrable_label: str) -> list[str]:
    lines: list[str] = []
    if e.swapped_characters:
        swaps = "; ".join(
            f"{_describe(s)} instead of '{s.instead_of}'" for s in e.swapped_characters
        )
        lines.append(f"Uses lookalike characters to imitate {e.brand}: {swaps}.")
    if e.misspelled and e.spelling_edits:
        edits = ", ".join(_describe_edit(x) for x in e.spelling_edits)
        lines.append(f"Misspells {e.brand}: '{e.misspelled}' has {edits}.")
    if e.extra_words:
        lines.append(
            f"Adds words that sound official to the {e.brand} name: {', '.join(e.extra_words)}."
        )
    if e.real_owner:
        lines.append(
            f"The site actually belongs to {e.real_owner}. The {e.brand} name only appears in "
            f"front of it as a subdomain, which the owner of {e.real_owner} can set to anything."
        )
    if e.wrong_ending:
        same_label = [d for d in e.official_domains if d.split(".", 1)[0] == registrable_label]
        real = f" ({', '.join(same_label)})" if same_label else ""
        lines.append(f"Uses the {e.brand} name with a different ending: {e.wrong_ending}{real}.")
    if not lines:
        lines.append(f"Uses the {e.brand} name, but {e.domain} is not a {e.brand} domain.")
    lines.append(f"{e.brand}'s official sites: {', '.join(e.official_domains)}.")
    return lines


def _describe(swap: CharacterSwap) -> str:
    if swap.unicode_names:
        scripts = sorted({name.split(" ", 1)[0].title() for name in swap.unicode_names})
        return f"'{swap.found}' (a {'/'.join(scripts)} character)"
    if swap.found.isdigit():
        return f"the digit '{swap.found}'"
    return f"'{swap.found}'"


def _describe_edit(edit: SpellingEdit) -> str:
    if edit.kind == "swapped":
        return f"'{edit.expected[0]}' and '{edit.expected[1]}' swapped"
    if edit.kind == "replaced":
        return f"'{edit.found}' instead of '{edit.expected}'"
    if edit.kind == "extra":
        return f"an extra '{edit.found}'"
    return f"a missing '{edit.expected}'"
