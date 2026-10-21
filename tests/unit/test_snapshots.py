"""P2b snapshot reader (architecture.md §23): saved pages instead of the network."""

from pathlib import Path

import pytest

from scamsentinel.page.snapshots import SnapshotFetcher, parse_snapshot, snapshot_key

SAMPLE = """# Synthetic page fixture
url: hxxps://appleid-unlock-support[.]com/login
status: 200
---
<html><head><title>Sign in to your Apple Account</title></head>
<form action="hxxps://collector[.]net/p"><input type="password"></form></html>
"""


def write(tmp_path: Path, name: str, text: str) -> Path:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_parse_refangs_in_memory_only():
    snap = parse_snapshot(SAMPLE, "x.txt")
    assert snap.url == "https://appleid-unlock-support.com/login"
    assert snap.final_url == snap.url
    assert 'action="https://collector.net/p"' in snap.html


def test_redirects_set_the_final_url():
    text = SAMPLE.replace("status: 200", "redirects: hxxps://a[.]com/1 -> hxxps://b[.]com/2")
    snap = parse_snapshot(text, "x.txt")
    assert snap.redirects == ["https://a.com/1", "https://b.com/2"]
    assert snap.final_url == "https://b.com/2"


@pytest.mark.parametrize(
    "text",
    ["url: hxxps://x[.]com\n<html></html>", "status: 200\n---\n<p>", "url: x\nbogus: 1\n---\n<p>"],
)
def test_malformed_snapshots_are_rejected(text):
    with pytest.raises(ValueError):
        parse_snapshot(text, "bad.txt")


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("hxxps://Example[.]com/Path/", "https://example.com/Path"),
        ("example.com", "https://example.com"),
        ("HTTPS://EXAMPLE.COM", "https://example.com"),
    ],
)
def test_keys_match_regardless_of_defanging_case_and_trailing_slash(a, b):
    assert snapshot_key(a) == snapshot_key(b)


def test_fetch_from_snapshots(tmp_path):
    fetcher = SnapshotFetcher(write(tmp_path, "a.txt", SAMPLE))
    page = fetcher.fetch("https://appleid-unlock-support.com/login/")
    assert page.error is None
    assert "Apple Account" in page.html
    assert fetcher.fetch("https://unknown.example/").error == "not_in_snapshots"


def test_offline_snapshot(tmp_path):
    offline = SAMPLE.replace("status: 200", "status: 404")
    fetcher = SnapshotFetcher(write(tmp_path, "a.txt", offline))
    page = fetcher.fetch("https://appleid-unlock-support.com/login")
    assert page.error == "http_404"
    assert page.html is None


def test_only_txt_files_are_accepted(tmp_path):
    write(tmp_path, "page.html", SAMPLE)
    with pytest.raises(ValueError, match=r"\.txt"):
        SnapshotFetcher(tmp_path)


def test_duplicate_urls_are_rejected(tmp_path):
    write(tmp_path, "a.txt", SAMPLE)
    write(tmp_path, "b.txt", SAMPLE)
    with pytest.raises(ValueError, match="duplicate"):
        SnapshotFetcher(tmp_path)
