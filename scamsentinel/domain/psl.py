"""Shared Public Suffix List splitter."""

from __future__ import annotations

from functools import lru_cache

import tldextract


@lru_cache(maxsize=1)
def get_psl_extractor() -> tldextract.TLDExtract:
    # Bundled PSL snapshot: no network fetch, no disk cache. Private domains (e.g.
    # netlify.app) count as suffixes, so the attacker-controlled label is analyzed.
    # The reserved test endings (RFC 2606) aren't in the PSL; without them,
    # "northstar.example" would parse as the name "example".
    return tldextract.TLDExtract(
        cache_dir=None,
        suffix_list_urls=(),
        include_psl_private_domains=True,
        extra_suffixes=("example", "invalid", "test", "localhost"),
    )
