"""The feature schema is strict: the LLM can't smuggle in a verdict or score (SECURITY.md T2)."""

import pytest
from pydantic import ValidationError

from scamsentinel.message.features import MessageFeatures


def test_empty_features_are_valid():
    f = MessageFeatures()
    assert f.urgency.level == 0
    assert not f.injection_attempt.detected


@pytest.mark.parametrize("field", ["verdict", "score", "risk_score", "is_safe"])
def test_verdict_like_fields_rejected(field):
    with pytest.raises(ValidationError):
        MessageFeatures.model_validate({field: "safe"})


def test_out_of_range_urgency_rejected():
    with pytest.raises(ValidationError):
        MessageFeatures.model_validate({"urgency": {"level": 11}})


def test_unknown_payment_method_rejected():
    with pytest.raises(ValidationError):
        MessageFeatures.model_validate(
            {"payment_methods": [{"method": "carrier_pigeon", "span": "x"}]}
        )
