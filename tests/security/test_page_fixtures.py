"""S11: the hand-written page snapshots are inert (architecture.md §23).

They're plain .txt files so nothing opens them as web pages. They contain no scripts,
frames, embedded objects, stylesheets, images with a source, links, event handlers or
live URLs. Reading and analyzing every one of them makes no DNS lookup or connection.
"""

import re
import socket
from pathlib import Path

import pytest

from scamsentinel.data import load_brands, load_keywords
from scamsentinel.domain.engine import get_engine
from scamsentinel.eval.dataset import load_samples
from scamsentinel.page.analyze import PageAnalyzer
from scamsentinel.page.snapshots import SnapshotFetcher, snapshot_key

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
PAGES_DIR = DATA_DIR / "eval" / "pages"
FILES = sorted(p for p in PAGES_DIR.iterdir() if p.is_file())

# Anything that could load, run or link to something if the text were ever rendered.
FORBIDDEN = [
    (re.compile(r"<\s*script", re.I), "<script>"),
    (re.compile(r"<\s*i?frame", re.I), "<iframe>/<frame>"),
    (re.compile(r"<\s*(object|embed|applet|link|base|style|svg|video|audio|source)\b", re.I),
     "embedding or styling element"),
    (re.compile(r"<\s*a\b", re.I), "<a> link"),
    (re.compile(r"\b(src|href|srcset|poster|background|formaction)\s*=", re.I), "URL attribute"),
    (re.compile(r"\bon[a-z]+\s*=", re.I), "event handler"),
    (re.compile(r"javascript:|vbscript:|data:", re.I), "script or data URL"),
    (re.compile(r"url\s*\(", re.I), "CSS url()"),
    (re.compile(r"https?://", re.I), "live (non-defanged) URL"),
    (re.compile(r"http-equiv", re.I), "meta refresh"),
]


def test_there_are_snapshots():
    assert len(FILES) >= 80


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_snapshot_is_a_plain_text_file(path):
    assert path.suffix == ".txt", f"{path.name}: snapshots must be .txt, never .html"


def test_no_html_files_anywhere_under_eval():
    web_suffixes = (".html", ".htm", ".xhtml", ".svg", ".shtml", ".mht")
    web = [p for p in (DATA_DIR / "eval").rglob("*") if p.suffix.lower() in web_suffixes]
    assert web == []


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_snapshot_contains_nothing_active(path):
    text = path.read_text(encoding="utf-8")
    for pattern, what in FORBIDDEN:
        assert not pattern.search(text), f"{path.name} contains a {what}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_snapshot_says_what_it_is(path):
    assert "Synthetic page fixture" in path.read_text(encoding="utf-8").splitlines()[0]


def test_every_snapshot_belongs_to_an_eval_sample():
    samples = {
        snapshot_key(s.content)
        for s in load_samples(DATA_DIR / "eval" / "samples.jsonl")
        if s.input_type == "url"
    }
    fetcher = SnapshotFetcher(PAGES_DIR)
    orphans = [s.name for s in fetcher.snapshots if snapshot_key(s.url) not in samples]
    assert orphans == []


def test_every_non_official_url_sample_has_a_snapshot():
    """The rule for which samples get a page, fixed before evaluation: every URL input whose
    domain isn't official (official sites are never fetched), scam or legitimate alike."""
    engine = get_engine(DATA_DIR, DATA_DIR.parent / "config")
    fetcher = SnapshotFetcher(PAGES_DIR)
    have = {snapshot_key(s.url) for s in fetcher.snapshots}
    missing = [
        s.id for s in load_samples(DATA_DIR / "eval" / "samples.jsonl")
        if s.input_type == "url"
        and not engine.score(s.content).official
        and snapshot_key(s.content) not in have
    ]
    assert missing == []


def test_reading_and_analyzing_every_snapshot_never_touches_the_network(monkeypatch):
    def tripwire(*args, **kwargs):
        raise AssertionError(f"network access attempted: {args!r}")

    engine = get_engine(DATA_DIR, DATA_DIR.parent / "config")
    analyzer = PageAnalyzer(load_brands(DATA_DIR), load_keywords(DATA_DIR).entity_mentions, engine)
    monkeypatch.setattr(socket, "getaddrinfo", tripwire)
    monkeypatch.setattr(socket, "create_connection", tripwire)
    monkeypatch.setattr(socket.socket, "connect", tripwire)

    fetcher = SnapshotFetcher(PAGES_DIR)
    for snapshot in fetcher.snapshots:
        report = analyzer.analyze(fetcher.fetch(snapshot.url))
        assert report.status in ("analyzed", "failed")
