"""Lookalike-domain engine (architecture.md §4).

Pipeline: canonicalize -> PSL split -> allowlist -> homoglyph skeleton -> detectors
(homoglyph, brand_plus_keywords, tld_swap, exact_brand_unofficial, brand_in_label,
typosquat, brand_in_subdomain, idn_mixed_script).

Score = max(points of the techniques that fired) + bonuses, capped at 100. Every
technique that fires is returned as a Reason with its own points.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field
from rapidfuzz.distance import DamerauLevenshtein

from scamsentinel.config import get_settings
from scamsentinel.data import Brand, Keywords, load_brands, load_keywords, load_scoring
from scamsentinel.domain.normalize import (
    InvalidHost,
    Normalizer,
    canonicalize_host,
    load_confusables,
    scripts_in,
)
from scamsentinel.domain.psl import get_psl_extractor
from scamsentinel.models import Module, Reason

TYPO_MAX_NORMALIZED_DISTANCE = 0.2
TYPO_MIN_TOKEN_LENGTH = 4
MIN_KEYWORD_LENGTH = 3


class DomainResult(BaseModel):
    input: str
    host: str
    registrable: str
    official: bool
    score: int = Field(ge=0, le=100)
    brand: str | None = None
    techniques: list[str] = []
    # Registrable domain after IDN decoding + lookalike normalization, for explainability.
    normalized: str
    reasons: list[Reason] = []


@dataclass(frozen=True)
class _Token:
    brand: str
    raw: str
    skel: str
    boundary: bool


@dataclass(frozen=True)
class _Hit:
    technique: str
    points: int
    brand: str | None
    detail: str


class DomainEngine:
    def __init__(
        self,
        brands: list[Brand],
        keywords: Keywords,
        points: dict[str, int],
        confusables: dict[str, str],
    ) -> None:
        self._norm = Normalizer(confusables, keywords.ascii_substitutions)
        self._points = points

        self._official: dict[str, str] = {}
        # Labels of official domains per brand ("irs" for irs.gov), for tld_swap.
        self._official_labels: dict[str, set[str]] = {}
        for b in brands:
            for domain in b.official_domains:
                self._official.setdefault(domain, b.name)
                self._official_labels.setdefault(b.name, set()).add(domain.split(".", 1)[0])

        # A token listed by several brands (e.g. "intuit") belongs to the first one.
        self._tokens: list[_Token] = []
        seen: set[str] = set()
        for b in brands:
            for t in b.tokens:
                if t not in seen:
                    seen.add(t)
                    self._tokens.append(
                        _Token(b.name, t, self._norm.skeleton(t), t in b.boundary_tokens)
                    )

        self._keywords = {
            self._norm.skeleton(k): k
            for k in keywords.stuffing_keywords
            if len(k) >= MIN_KEYWORD_LENGTH
        }
        self._vocab = set(self._keywords) | {t.skel for t in self._tokens}
        self._max_vocab_len = max(map(len, self._vocab))

        self._extract = get_psl_extractor()

    @classmethod
    def from_files(cls, data_dir: Path, config_dir: Path) -> DomainEngine:
        return cls(
            brands=load_brands(data_dir),
            keywords=load_keywords(data_dir),
            points=load_scoring(config_dir).domain_points,
            confusables=load_confusables(data_dir / "confusables.txt"),
        )

    # --- public API ---------------------------------------------------------------

    def score(self, host_or_url: str) -> DomainResult:
        host = canonicalize_host(host_or_url)

        if _is_ip(host):
            return DomainResult(
                input=host_or_url,
                host=host,
                registrable=host,
                official=False,
                score=0,
                normalized=host,
                reasons=[
                    _reason(
                        "ip_address_host",
                        0,
                        f"{host} is an IP address, so lookalike-domain analysis does not apply",
                        host,
                    )
                ],
            )

        ext = self._extract.extract_str(host)
        if not ext.domain:
            raise InvalidHost(f"{host!r} has no registrable domain")
        registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

        if registrable in self._official:
            brand = self._official[registrable]
            return DomainResult(
                input=host_or_url,
                host=host,
                registrable=registrable,
                official=True,
                score=0,
                brand=brand,
                normalized=registrable,
                reasons=[
                    _reason(
                        "official_domain",
                        0,
                        f"{registrable} is an official {brand} domain",
                        host,
                    )
                ],
            )

        hits = self._label_hits(ext.domain, ext.suffix) + self._subdomain_hits(
            ext.subdomain, registrable
        )
        bonuses: list[_Hit] = []
        scripts = scripts_in(ext.domain)
        if len(scripts) > 1:
            bonuses.append(
                _Hit(
                    "idn_mixed_script",
                    self._points["idn_mixed_script_bonus"],
                    None,
                    f"'{ext.domain}' mixes {' and '.join(sorted(scripts))} letters",
                )
            )

        best = max(hits, key=lambda h: h.points, default=None)
        score = min(100, (best.points if best else 0) + sum(b.points for b in bonuses))
        fired = hits + bonuses
        reasons = [_reason(h.technique, h.points, h.detail, host) for h in fired] or [
            _reason(
                "no_lookalike_signals",
                0,
                f"{registrable} does not resemble a protected brand",
                host,
            )
        ]
        normalized_label = self._norm.skeleton(ext.domain)
        return DomainResult(
            input=host_or_url,
            host=host,
            registrable=registrable,
            official=False,
            score=score,
            brand=best.brand if best else None,
            techniques=list(dict.fromkeys(h.technique for h in fired)),
            normalized=f"{normalized_label}.{ext.suffix}" if ext.suffix else normalized_label,
            reasons=reasons,
        )

    # --- detectors ----------------------------------------------------------------

    def _label_hits(self, label: str, suffix: str) -> list[_Hit]:
        skel = self._norm.skeleton(label)
        compact = skel.replace("-", "")
        hits: list[_Hit] = []
        for tok in self._tokens:
            if self._contains(tok, label):
                hits += self._brand_hits(tok, label, suffix, compact)
            elif len(tok.skel) >= TYPO_MIN_TOKEN_LENGTH:
                typo = self._typosquat(tok, skel, compact)
                if typo:
                    hits.append(typo)
        return hits

    def _brand_hits(self, tok: _Token, label: str, suffix: str, compact: str) -> list[_Hit]:
        p = self._points
        hits: list[_Hit] = []
        literal = self._norm.literal(label)

        homoglyph = tok.raw not in literal.replace("-", "")
        if homoglyph:
            hits.append(
                _Hit(
                    "homoglyph",
                    p["homoglyph"],
                    tok.brand,
                    f"'{label}' reads as '{tok.raw}' once lookalike characters are normalized",
                )
            )

        keywords = self._keywords_in(compact.replace(tok.skel, " ", 1))
        if keywords:
            per_keyword = p["brand_plus_keywords_per_keyword"]
            points = min(
                p["brand_plus_keywords_cap"],
                p["brand_plus_keywords_base"] + per_keyword * len(keywords),
            )
            hits.append(
                _Hit(
                    "brand_plus_keywords",
                    points,
                    tok.brand,
                    f"'{label}' combines the {tok.brand} name with trust keywords: "
                    + ", ".join(keywords),
                )
            )
        elif not homoglyph:
            if literal in self._official_labels.get(tok.brand, set()):
                hits.append(
                    _Hit(
                        "tld_swap",
                        p["tld_swap"],
                        tok.brand,
                        f"'{label}.{suffix}' uses the {tok.brand} name under a "
                        f"non-official ending (.{suffix})",
                    )
                )
            elif compact == tok.skel:
                hits.append(
                    _Hit(
                        "exact_brand_unofficial",
                        p["exact_brand_unofficial"],
                        tok.brand,
                        f"'{label}' spells the {tok.brand} name, but this is not an "
                        f"official {tok.brand} domain",
                    )
                )
            else:
                hits.append(
                    _Hit(
                        "brand_in_label",
                        p["brand_in_label"],
                        tok.brand,
                        f"'{label}' contains the {tok.brand} name",
                    )
                )
        return hits

    def _typosquat(self, tok: _Token, skel: str, compact: str) -> _Hit | None:
        parts = [part for part in skel.split("-") if part]
        best: tuple[float, int, str] | None = None
        for candidate in _windows([*parts, compact], len(tok.skel)):
            distance = DamerauLevenshtein.distance(candidate, tok.skel)
            if distance == 0:
                # The token is present but failed its word-boundary rule (e.g. "intuition").
                return None
            normalized = distance / max(len(candidate), len(tok.skel))
            if best is None or normalized < best[0]:
                best = (normalized, distance, candidate)

        if best is None or best[0] > TYPO_MAX_NORMALIZED_DISTANCE:
            return None
        normalized, distance, candidate = best
        p = self._points
        lo, hi = p["typosquat_min"], p["typosquat_max"]
        points = round(lo + (hi - lo) * (1 - normalized / TYPO_MAX_NORMALIZED_DISTANCE))
        detail = f"'{candidate}' is {distance} edit(s) away from '{tok.raw}'"

        keywords = self._keywords_in(compact.replace(candidate, " ", 1))
        if keywords:
            points = min(
                p["brand_plus_keywords_cap"],
                points + p["brand_plus_keywords_per_keyword"] * len(keywords),
            )
            detail += f", plus trust keywords: {', '.join(keywords)}"
        return _Hit("typosquat", points, tok.brand, detail)

    def _subdomain_hits(self, subdomain: str, registrable: str) -> list[_Hit]:
        if not subdomain:
            return []
        hits: list[_Hit] = []
        brands_seen: set[str] = set()
        for sublabel in subdomain.split("."):
            for tok in self._tokens:
                if tok.brand not in brands_seen and self._contains(tok, sublabel):
                    brands_seen.add(tok.brand)
                    hits.append(
                        _Hit(
                            "brand_in_subdomain",
                            self._points["brand_in_subdomain"],
                            tok.brand,
                            f"subdomain '{subdomain}' carries the {tok.brand} name, but the "
                            f"site actually belongs to {registrable}",
                        )
                    )
        return hits

    # --- token matching -----------------------------------------------------------

    def _contains(self, tok: _Token, label: str) -> bool:
        skel = self._norm.skeleton(label)
        if not tok.boundary:
            return tok.skel in skel.replace("-", "")
        # Boundary tokens must be a whole word: split on hyphens in the skeleton, and on
        # hyphens/digits in the folded form (so "irs2024" still splits off "irs").
        pieces = skel.split("-") + [
            self._norm.skeleton(run) for run in re.split(r"[-\d]+", self._norm.fold(label))
        ]
        return any(self._bounded(piece, tok.skel) for piece in pieces if piece)

    def _bounded(self, piece: str, token: str) -> bool:
        """True if `token` occurs in `piece` with only known words on either side."""
        start = piece.find(token)
        while start != -1:
            before, after = piece[:start], piece[start + len(token) :]
            if (not before or self._segmentable(before)) and (
                not after or self._segmentable(after)
            ):
                return True
            start = piece.find(token, start + 1)
        return False

    def _segmentable(self, s: str) -> bool:
        """True if `s` splits entirely into brand tokens / stuffing keywords."""
        ok = [True] + [False] * len(s)
        for i in range(1, len(s) + 1):
            ok[i] = any(
                ok[j] and s[j:i] in self._vocab for j in range(max(0, i - self._max_vocab_len), i)
            )
        return ok[-1]

    def _keywords_in(self, text: str) -> list[str]:
        found = [k for k in self._keywords if k in text]
        # Drop keywords that are only part of a longer match ("tax" inside "taxes").
        found = [k for k in found if not any(k != other and k in other for other in found)]
        return [self._keywords[k] for k in sorted(found, key=text.find)]


def _windows(pieces: list[str], n: int):
    """Each piece, plus every substring of length n-1..n+1 (for typos inside compounds)."""
    for piece in pieces:
        yield piece
        for width in (n - 1, n, n + 1):
            for i in range(len(piece) - width + 1):
                yield piece[i : i + width]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _reason(signal: str, points: int, detail: str, host: str) -> Reason:
    return Reason(module=Module.DOMAIN, signal=signal, detail=detail, evidence=host, points=points)


@lru_cache(maxsize=4)
def get_engine(data_dir: Path, config_dir: Path) -> DomainEngine:
    return DomainEngine.from_files(data_dir, config_dir)


def score_domain(host_or_url: str, engine: DomainEngine | None = None) -> DomainResult:
    if engine is None:
        settings = get_settings()
        engine = get_engine(settings.data_dir, settings.config_dir)
    return engine.score(host_or_url)
