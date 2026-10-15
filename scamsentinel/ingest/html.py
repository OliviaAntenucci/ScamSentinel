"""HTML email bodies -> plain text + link targets. Parsed, never rendered."""

from __future__ import annotations

import re
from html.parser import HTMLParser

from scamsentinel.ingest.urls import refang

_SKIP = frozenset({"script", "style", "head", "template", "noscript"})
_BLOCK = frozenset(
    {"p", "div", "br", "li", "tr", "td", "h1", "h2", "h3", "h4", "h5", "h6", "table", "hr"}
)


class _TextAndLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP:
            self._skip_depth += 1
        elif tag in _BLOCK:
            self.parts.append("\n")
        if tag == "a":
            # The visible text of a link can say irs.gov while the href goes elsewhere,
            # so the real targets are collected separately. Defanged hrefs (hxxps://…,
            # common in pasted threat reports) are refanged first.
            href = refang((dict(attrs).get("href") or "").strip())
            if href.lower().startswith(("http://", "https://")):
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag in _BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)


def html_to_text(html: str) -> tuple[str, list[str]]:
    parser = _TextAndLinks()
    parser.feed(html)
    parser.close()
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(parser.parts))
    text = re.sub(r"\s*\n\s*", "\n", text).strip()
    return text, list(dict.fromkeys(parser.links))
