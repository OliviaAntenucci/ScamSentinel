"""The versioned YAML files load and pass schema validation."""

import pytest
from pydantic import ValidationError

from scamsentinel.data import (
    Brand,
    BrandsFile,
    load_brands,
    load_categories,
    load_facts,
    load_keywords,
    load_scoring,
)
from scamsentinel.models import Module


def test_brands_load(settings):
    brands = {b.name: b for b in load_brands(settings.data_dir)}
    assert set(brands) == {
        "IRS", "TurboTax", "QuickBooks", "Credit Karma", "USPS",
        "Chase", "Bank of America", "Wells Fargo",
        "Google", "Apple", "Microsoft", "Indeed",
    }
    assert "irs.gov" in brands["IRS"].official_domains
    assert brands["IRS"].boundary_tokens == ["irs"]
    assert {b.category for b in brands.values()} == CATEGORIES
    assert brands["USPS"].category == "delivery"
    assert brands["Chase"].no_typo_tokens == ["chase"]
    assert brands["Microsoft"].category == "tech_support"


CATEGORIES = {"tax", "delivery", "bank", "account_takeover", "tech_support", "job"}


def test_categories_load(settings):
    assert set(load_categories(settings.data_dir)) == CATEGORIES


def test_no_typo_tokens_must_be_tokens():
    with pytest.raises(ValidationError, match="no_typo_tokens not in tokens"):
        Brand(
            name="X", category="c", tokens=["x"], no_typo_tokens=["y"],
            official_domains=["x.com"],
        )


def brand(**overrides) -> dict:
    base = {"name": "X", "category": "c", "tokens": ["x"], "official_domains": ["x.com"]}
    return base | overrides


def test_boundary_tokens_must_be_tokens():
    with pytest.raises(ValidationError, match="boundary_tokens"):
        Brand(**brand(boundary_tokens=["y"]))


@pytest.mark.parametrize(
    "domain", ["https://irs.gov", "IRS.gov", "irs.gov/refund", ".irs.gov", "irs.gov:443"]
)
def test_brand_rejects_non_registrable_official_domain(domain):
    with pytest.raises(ValidationError, match="official domain"):
        Brand(**brand(official_domains=[domain]))


@pytest.mark.parametrize(
    ("brands", "message"),
    [
        ([brand(category="unknown")], "undefined categories"),
        ([brand(), brand()], "unique"),
        ([brand(name="other")], "reserved"),
    ],
)
def test_brands_file_consistency(brands, message):
    with pytest.raises(ValidationError, match=message):
        BrandsFile.model_validate({"categories": {"c": {"description": "d"}}, "brands": brands})


def test_keywords_load(settings):
    kw = load_keywords(settings.data_dir)
    assert "refund" in kw.stuffing_keywords
    assert "gift_card" in kw.payment_methods
    assert kw.ascii_substitutions["0"] == "o"


def test_entity_mentions_name_known_brands(settings):
    names = {b.name for b in load_brands(settings.data_dir)}
    assert set(load_keywords(settings.data_dir).entity_mentions) <= names


def test_facts_have_sources_and_known_entities(settings):
    facts = load_facts(settings.data_dir)
    names = {b.name for b in load_brands(settings.data_dir)}
    assert facts
    assert all(f.source.startswith("https://") for f in facts)
    assert {f.entity for f in facts} <= names


def test_every_category_has_facts(settings):
    # A category without trusted facts would only have brand lookalike detection.
    brands = load_brands(settings.data_dir)
    entities = {f.entity for f in load_facts(settings.data_dir)}
    for category in load_categories(settings.data_dir):
        assert any(b.name in entities for b in brands if b.category == category), category


def test_scoring_config_loads(settings):
    cfg = load_scoring(settings.config_dir)
    assert set(cfg.weights) == {Module.DOMAIN, Module.MESSAGE, Module.PAGE}
    assert cfg.bands.suspicious == 30
    assert cfg.bands.likely_scam == 60
