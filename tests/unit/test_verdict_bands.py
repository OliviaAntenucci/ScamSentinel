import pytest

from scamsentinel.aggregate.aggregator import verdict_for_score
from scamsentinel.data import Bands
from scamsentinel.models import Verdict

BANDS = Bands(suspicious=30, likely_scam=60)


@pytest.mark.parametrize(
    ("score", "verdict"),
    [
        (0, Verdict.LIKELY_LEGITIMATE),
        (29, Verdict.LIKELY_LEGITIMATE),
        (30, Verdict.SUSPICIOUS),
        (59, Verdict.SUSPICIOUS),
        (60, Verdict.LIKELY_SCAM),
        (100, Verdict.LIKELY_SCAM),
    ],
)
def test_band_edges(score, verdict):
    assert verdict_for_score(score, BANDS) == verdict


@pytest.mark.parametrize(("suspicious", "likely_scam"), [(0, 60), (60, 30), (30, 30), (30, 101)])
def test_bands_must_be_ordered(suspicious, likely_scam):
    with pytest.raises(ValueError):
        Bands(suspicious=suspicious, likely_scam=likely_scam)
