"""What a fetched page shows (P2, architecture.md §23).

The HTML is attacker-written, so it's only ever parsed as data, with the standard
library's pure-Python parser (no C parser, no DOM, nothing executed). Scripts, styles and
templates are skipped. From the rest the analyzer reads:

- input fields that ask for a password, a one-time code, card details or an SSN
- forms whose action sends what you type to a different domain
- the curated brand the page presents itself as, when it isn't on that brand's domains
- meta-refresh redirects, and where the link's redirects ended up

Findings are informational: they add no points yet (P2a), so published metrics are
unchanged. Everything quoted from the page is length-capped plain text.
"""

from __future__ import annotations

import contextlib
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from scamsentinel.aggregate.aggregator import LOOKALIKE_THRESHOLD
from scamsentinel.data import Brand
from scamsentinel.domain.engine import DomainEngine
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.message.rules import phrase_pattern
from scamsentinel.models import PageFinding, PageReport
from scamsentinel.page.fetch import FetchedPage

MAX_TEXT_CHARS = 50_000
MAX_TITLE_CHARS = 150
MAX_FORMS = 50
MAX_FIELDS = 500
_SKIPPED = frozenset({"script", "style", "noscript", "template", "svg"})
_FIELDS = frozenset({"input", "select", "textarea"})
_FIELD_ATTRS = ("type", "name", "id", "placeholder", "autocomplete", "aria-label")

# What a field asks for, from its type/name/id/placeholder/autocomplete/aria-label.
_FIELD_KINDS: dict[str, re.Pattern[str]] = {
    "password": re.compile(r"\bpassword\b|current-password|new-password|passcode|passwd|\bpin\b"),
    "verification code": re.compile(
        r"one-time-code|\botp\b|one.?time|verification.?code|security.?code|2fa|auth.?code"
    ),
    "card details": re.compile(
        r"\bcc-|card.?number|cardnumber|ccnum|\bcvv\b|\bcvc\b|cvv2|expir|exp.?date"
    ),
    "Social Security number": re.compile(r"\bssn\b|social.?security"),
}
_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.IGNORECASE)


class _Collector(HTMLParser):
    """Collects the title, visible text, forms and fields. Never raises on bad HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: list[str] = []
        self.text: list[str] = []
        self.text_chars = 0
        self.forms: list[dict] = []
        self.fields: list[tuple[int | None, str, str]] = []  # (form index, type, attr text)
        self.refresh: str | None = None
        self._skip = 0
        self._in_title = False
        self._form: int | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in _SKIPPED:
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "form" and len(self.forms) < MAX_FORMS:
            self.forms.append({"action": a.get("action", "").strip()})
            self._form = len(self.forms) - 1
        elif tag in _FIELDS and len(self.fields) < MAX_FIELDS:
            kind = a.get("type", "text").lower() if tag == "input" else tag
            text = " ".join(a.get(k, "") for k in _FIELD_ATTRS).lower()
            self.fields.append((self._form, kind, text))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            if m := _REFRESH_URL.search(a.get("content", "")):
                self.refresh = m.group(1).strip()
        elif tag == "img" and a.get("alt"):
            self._add_text(a["alt"])  # logos often carry the brand only in alt text

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIPPED and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._in_title:
            self.title.append(data)
        else:
            self._add_text(data)

    def _add_text(self, data: str) -> None:
        if self.text_chars < MAX_TEXT_CHARS:
            chunk = data[: MAX_TEXT_CHARS - self.text_chars]
            self.text.append(chunk)
            self.text_chars += len(chunk)


class PageAnalyzer:
    def __init__(
        self,
        brands: list[Brand],
        entity_mentions: dict[str, list[str]],
        engine: DomainEngine,
    ) -> None:
        self._brands = {b.name: b for b in brands}
        self._engine = engine
        # The curated mention phrases, like the message rules: "Apple ID", not "apple", and
        # "Chase Bank", not "chase". The brand name itself only when it has none.
        self._mentions = {
            b.name: phrase_pattern(entity_mentions.get(b.name) or [b.name]) for b in brands
        }

    def analyze(self, fetched: FetchedPage) -> PageReport:
        report = PageReport(
            requested_url=fetched.requested_url,
            final_url=fetched.final_url,
            redirects=fetched.redirects,
            status="analyzed",
            truncated=fetched.truncated,
        )
        if fetched.html is None:
            error = fetched.error or "failed"
            report.status = (
                "dry_run"
                if error == "dry_run"
                else "blocked"
                if error.startswith("blocked:")
                else "failed"
            )
            report.error = error
            return report

        collector = _Collector()
        # Hostile HTML must never break an analysis; whatever was collected is used.
        with contextlib.suppress(Exception):
            collector.feed(fetched.html)
            collector.close()
        title = " ".join(" ".join(collector.title).split())
        report.title = title[:MAX_TITLE_CHARS] or None
        text = " ".join(collector.text)
        page_domain = self._registrable(fetched.final_url)
        findings: list[PageFinding] = []

        findings += self._redirect_findings(fetched, page_domain)
        findings += self._field_findings(collector)
        findings += self._form_findings(collector, fetched.final_url, page_domain)

        brand = self._brand(title, text)
        if brand and page_domain and page_domain not in self._brands[brand].official_domains:
            report.brand = brand
            findings.append(
                PageFinding(
                    signal="brand_on_unofficial_page",
                    detail=(
                        f"The page presents itself as {brand}, but it's on {page_domain}, not an "
                        f"official {brand} domain ({', '.join(self._brands[brand].official_domains)})"
                    ),
                )
            )
        if collector.refresh and fetched.final_url:
            target = self._registrable(_join(fetched.final_url, collector.refresh))
            if target and target != page_domain:
                findings.append(
                    PageFinding(
                        signal="meta_refresh",
                        detail=f"The page sends you on to {target} automatically (meta refresh)",
                    )
                )
        report.findings = findings
        return report

    # --- findings -----------------------------------------------------------------------

    def _redirect_findings(self, fetched: FetchedPage, page_domain: str | None) -> list[PageFinding]:
        start = self._registrable(fetched.requested_url)
        if not fetched.redirects or not page_domain or page_domain == start:
            return []
        hops = len(fetched.redirects)
        detail = (
            f"The link redirected {hops} time{'s' if hops != 1 else ''} and ended at "
            f"{page_domain}"
        )
        try:
            final = self._engine.score(fetched.final_url or page_domain)
        except InvalidHost:
            final = None
        if final and final.brand and not final.official and final.score >= LOOKALIKE_THRESHOLD:
            article = "an" if final.brand[0].lower() in "aeiou" else "a"
            detail += f", which looks like {article} {final.brand} domain but isn't one"
        return [PageFinding(signal="redirected", detail=detail)]

    def _field_findings(self, collector: _Collector) -> list[PageFinding]:
        asked: list[str] = []
        for _, kind, attrs in collector.fields:
            for label, pattern in _FIELD_KINDS.items():
                if label == "password" and kind == "password":
                    asked.append(label)
                elif kind != "hidden" and pattern.search(attrs):
                    asked.append(label)
        asked = list(dict.fromkeys(asked))
        if not asked:
            return []
        return [
            PageFinding(
                signal="sensitive_fields",
                detail=f"The page asks you to type in: {', '.join(asked)}",
            )
        ]

    def _form_findings(
        self, collector: _Collector, final_url: str | None, page_domain: str | None
    ) -> list[PageFinding]:
        findings = []
        seen: set[str] = set()
        for form in collector.forms:
            action = form["action"]
            if action.lower().startswith("mailto:"):
                if "mailto" not in seen:
                    seen.add("mailto")
                    findings.append(
                        PageFinding(
                            signal="form_posts_elsewhere",
                            detail="A form on the page emails what you type to an address",
                        )
                    )
                continue
            if not action or not final_url:
                continue
            target = self._registrable(_join(final_url, action))
            if target and page_domain and target != page_domain and target not in seen:
                seen.add(target)
                findings.append(
                    PageFinding(
                        signal="form_posts_elsewhere",
                        detail=f"A form sends what you type to {target}, not to {page_domain}",
                    )
                )
        return findings

    # --- helpers --------------------------------------------------------------------------

    def _brand(self, title: str, text: str) -> str | None:
        """The curated brand named in the title, else the one named most in the text."""
        for name, pattern in self._mentions.items():
            if pattern.search(title):
                return name
        counts = {name: len(p.findall(text)) for name, p in self._mentions.items()}
        best = max(counts, key=lambda n: counts[n], default=None)
        return best if best and counts[best] >= 2 else None

    def _registrable(self, url: str | None) -> str | None:
        if not url:
            return None
        try:
            return self._engine.score(url).registrable
        except InvalidHost:
            return None


def _join(base: str, target: str) -> str:
    try:
        joined = urljoin(base, target)
    except ValueError:
        return ""
    return joined if urlsplit(joined).scheme in ("http", "https") else ""
