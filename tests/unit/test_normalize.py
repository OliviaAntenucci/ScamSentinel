from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scamsentinel.data import load_keywords
from scamsentinel.domain.normalize import (
    InvalidHost,
    Normalizer,
    canonicalize_host,
    load_confusables,
    scripts_in,
)

DATA = Path(__file__).resolve().parents[2] / "data"
CONFUSABLES = load_confusables(DATA / "confusables.txt")
NORM = Normalizer(CONFUSABLES, load_keywords(DATA).ascii_substitutions)


@pytest.mark.parametrize(
    ("raw", "host"),
    [
        ("irs.gov", "irs.gov"),
        ("HTTPS://User:pw@WWW.IRS.GOV:443/path?q=1#x", "www.irs.gov"),
        ("irs.gov.", "irs.gov"),
        ("  irs.gov  ", "irs.gov"),
        ("irs[.]gov", "irs.gov"),
        ("hxxps://irs[.]gov/refund", "irs.gov"),
        ("irs。gov", "irs.gov"),  # ideographic full stop
        ("tur​botax.com", "turbotax.com"),  # zero-width space
        (  # punycode decoded so the Cyrillic о becomes visible
            "xn--" + "turbоtax".encode("punycode").decode("ascii") + ".com",
            "turbоtax.com",
        ),
        ("http://[::1]:8000/", "::1"),
    ],
)
def test_canonicalize_host(raw, host):
    assert canonicalize_host(raw) == host


@pytest.mark.parametrize("raw", ["", "   ", "http://", "a..com", "http://[::1", "//:80", "a b.com"])
def test_canonicalize_rejects_invalid(raw):
    with pytest.raises(InvalidHost):
        canonicalize_host(raw)


@pytest.mark.parametrize(
    ("lookalike", "real"),
    [
        ("turb0tax", "turbotax"),
        ("turbоtax", "turbotax"),  # Cyrillic о
        ("türbotax", "turbotax"),  # ü (combining mark stripped)
        ("ｔurbotax", "turbotax"),  # fullwidth t (NFKC)
        ("1rs", "irs"),
        ("lrs", "irs"),
        ("іrs", "irs"),  # Cyrillic і
        ("creditkarrna", "creditkarma"),  # rn -> m
        ("cred1tkarma", "creditkarma"),
        ("quıckbooks", "quickbooks"),  # dotless ı
        ("quickb00ks", "quickbooks"),
    ],
)
def test_lookalikes_share_a_skeleton(lookalike, real):
    assert NORM.skeleton(lookalike) == NORM.skeleton(real)


def test_literal_does_not_fold_lookalikes():
    assert NORM.literal("TURB0TAX") == "turb0tax"
    assert NORM.literal("turbоtax") != "turbotax"


def test_scripts_in():
    assert scripts_in("turbotax") == {"LATIN"}
    assert scripts_in("turbоtax") == {"LATIN", "CYRILLIC"}
    assert scripts_in("irs-2024") == {"LATIN"}


def test_confusables_file_maps_to_ascii():
    assert CONFUSABLES
    assert all(v.isascii() and v.isalpha() for v in CONFUSABLES.values())


lookalike_text = st.text(
    alphabet=st.sampled_from([*"abcdefghijklmnopqrstuvwxyz0123456789-", *CONFUSABLES]),
    max_size=30,
)


@given(lookalike_text)
def test_skeleton_is_idempotent(s):
    once = NORM.skeleton(s)
    assert NORM.skeleton(once) == once


@given(st.text(max_size=100))
def test_canonicalize_never_crashes(s):
    try:
        host = canonicalize_host(s)
    except InvalidHost:
        return
    assert host == host.strip()
    assert host
