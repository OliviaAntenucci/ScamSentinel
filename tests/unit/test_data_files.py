"""The versioned YAML files load and pass schema validation."""

import pytest
from pydantic import ValidationError

from scamsentinel.data import Brand, load_brands, load_facts, load_keywords, load_scoring
from scamsentinel.models import Module


def test_brands_load(settings):
    brands = {b.name: b for b in load_brands(settings.data_dir)}
    assert set(brands) == {"IRS", "TurboTax", "QuickBooks", "Credit Karma"}
    assert "irs.gov" in brands["IRS"].official_domains
    assert brands["IRS"].short_token


@pytest.mark.parametrize(
    "domain", ["https://irs.gov", "IRS.gov", "irs.gov/refund", ".irs.gov", "irs.gov:443"]
)
def test_brand_rejects_non_registrable_official_domain(domain):
    with pytest.raises(ValidationError):
        Brand(name="X", tokens=["x"], official_domains=[domain])


def test_keywords_load(settings):
    kw = load_keywords(settings.data_dir)
    assert "refund" in kw.stuffing_keywords
    assert "gift_card" in kw.payment_methods
    assert kw.ascii_substitutions["0"] == "o"


def test_facts_have_sources(settings):
    facts = load_facts(settings.data_dir)
    assert facts
    assert all(f.source.startswith("https://") for f in facts)


def test_scoring_config_loads(settings):
    cfg = load_scoring(settings.config_dir)
    assert set(cfg.weights) == {Module.DOMAIN, Module.MESSAGE, Module.SANDBOX}
    assert cfg.bands.suspicious == 30
    assert cfg.bands.likely_scam == 60
