"""Shared Public Suffix List splitter."""

from __future__ import annotations

from functools import lru_cache

import tldextract


@lru_cache(maxsize=1)
def get_psl_extractor() -> tldextract.TLDExtract:
    # Bundled PSL snapshot: no network fetch, no disk cache. Private domains (e.g.
    # netlify.app) count as suffixes, so the attacker-controlled label is analyzed.
    return tldextract.TLDExtract(
        cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True
    )
