"""Saved page snapshots for evaluation (P2b, architecture.md §23).

A drop-in replacement for PageFetcher that never touches the network: it answers from
hand-written synthetic pages in data/eval/pages/. They're plain .txt files on purpose, so
nothing opens them as web pages, and they're stored defanged (hxxps://, [.]). They're
refanged in memory only, as the input to the same text-only HTML analyzer.

File format:

    # comment lines
    url: hxxps://appleid-unlock-support[.]com/login
    final_url: hxxps://... (optional; defaults to url)
    redirects: hxxps://a[.]com/x -> hxxps://b[.]com/y (optional)
    status: 200 (optional; default 200)
    content_type: text/html (optional)
    ---
    <html>...</html>
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from scamsentinel.ingest.urls import refang
from scamsentinel.page.fetch import HTML_TYPES, FetchedPage

SNAPSHOT_SUFFIX = ".txt"


@dataclass
class Snapshot:
    name: str
    url: str
    final_url: str
    redirects: list[str] = field(default_factory=list)
    status: int = 200
    content_type: str = "text/html; charset=utf-8"
    html: str = ""


def parse_snapshot(text: str, name: str) -> Snapshot:
    header, sep, body = text.partition("\n---\n")
    if not sep:
        raise ValueError(f"{name}: missing the '---' line between header and page")
    fields: dict[str, str] = {}
    for line in header.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, colon, value = line.partition(":")
        if not colon:
            raise ValueError(f"{name}: bad header line {line!r}")
        fields[key.strip().lower()] = value.strip()
    unknown = set(fields) - {"url", "final_url", "redirects", "status", "content_type"}
    if unknown:
        raise ValueError(f"{name}: unknown header fields {sorted(unknown)}")
    if "url" not in fields:
        raise ValueError(f"{name}: missing url")
    url = refang(fields["url"])
    redirects = [refang(r.strip()) for r in fields.get("redirects", "").split("->") if r.strip()]
    return Snapshot(
        name=name,
        url=url,
        final_url=refang(fields.get("final_url") or (redirects[-1] if redirects else url)),
        redirects=redirects,
        status=int(fields.get("status", "200")),
        content_type=fields.get("content_type", "text/html; charset=utf-8"),
        html=refang(body),
    )


def snapshot_key(url: str) -> str:
    """How a URL is matched to a snapshot: refanged, https by default, lowercase scheme
    and host, no trailing slash."""
    url = refang(url.strip())
    if "://" not in url:
        url = f"https://{url}"
    parts = urlsplit(url)
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


class SnapshotFetcher:
    """Same interface as PageFetcher.fetch(), answered from data/eval/pages/ only."""

    mode = "snapshot"

    def __init__(self, pages_dir: Path, max_bytes: int = 2_000_000) -> None:
        self._max_bytes = max_bytes
        self._pages: dict[str, Snapshot] = {}
        for path in sorted(pages_dir.iterdir()):
            if path.is_dir():
                continue
            if path.suffix != SNAPSHOT_SUFFIX:
                raise ValueError(f"page snapshots must be .txt files, not {path.name}")
            snapshot = parse_snapshot(path.read_text(encoding="utf-8"), path.name)
            key = snapshot_key(snapshot.url)
            if key in self._pages:
                raise ValueError(f"{path.name}: duplicate snapshot for {snapshot.url}")
            self._pages[key] = snapshot

    @property
    def snapshots(self) -> list[Snapshot]:
        return list(self._pages.values())

    def fetch(self, url: str) -> FetchedPage:
        snapshot = self._pages.get(snapshot_key(url))
        page = FetchedPage(requested_url=url)
        if snapshot is None:
            page.error = "not_in_snapshots"  # like a link nobody saved: no evidence
            return page
        page.redirects = list(snapshot.redirects)
        page.final_url = snapshot.final_url
        page.status_code = snapshot.status
        if snapshot.status >= 400:
            page.error = f"http_{snapshot.status}"
            return page
        if not snapshot.content_type.lower().startswith(HTML_TYPES):
            page.error = "not_html"
            return page
        html = snapshot.html
        page.truncated = len(html.encode("utf-8")) > self._max_bytes
        page.html = html.encode("utf-8")[: self._max_bytes].decode("utf-8", errors="ignore")
        return page
