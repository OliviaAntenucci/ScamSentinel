import logging
import sys
from datetime import UTC, datetime

import pytest

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.message.features import MessageFeatures, SensitiveRequest
from scamsentinel.models import AnalysisResult, Module, Reason, Verdict
from scamsentinel.security.redaction import (
    CARD_PLACEHOLDER,
    SSN_PLACEHOLDER,
    RedactingFilter,
    redact,
    redact_result,
)


@pytest.mark.parametrize(
    "text",
    ["SSN 123-45-6789", "SSN 123 45 6789", "SSN 123456789", "(123-45-6789)"],
)
def test_ssn_like_numbers_redacted(text):
    assert SSN_PLACEHOLDER in redact(text)
    assert "6789" not in redact(text)


@pytest.mark.parametrize(
    "text",
    [
        "000-12-3456",  # never-issued area numbers
        "666-12-3456",
        "912-34-5678",
        "123-00-4567",
        "123-45-0000",
        "123-45 6789",  # inconsistent separators
        "Call 800-829-1040",  # phone numbers are kept as evidence
        "order 1234567890",
        "2024-01-15",
    ],
)
def test_non_ssn_numbers_kept(text):
    assert redact(text) == text


@pytest.mark.parametrize(
    "card", ["4111 1111 1111 1111", "4111-1111-1111-1111", "5500005555555559", "378282246310005"]
)
def test_luhn_valid_cards_redacted(card):
    assert redact(f"card {card} exp") == f"card {CARD_PLACEHOLDER} exp"


def test_luhn_invalid_digit_runs_kept():
    assert redact("tracking 4111 1111 1111 1112") == "tracking 4111 1111 1111 1112"


def test_redact_result():
    result = AnalysisResult(
        analysis_id="an_" + "a" * 32,
        created_at=datetime.now(UTC),
        input_type="text",
        verdict=Verdict.LIKELY_SCAM,
        risk_score=90,
        reasons=[
            Reason(
                module=Module.MESSAGE,
                signal="sensitive_request",
                detail='Asks for a Social Security number: "SSN 123-45-6789"',
                evidence="SSN 123-45-6789",
                points=25,
            )
        ],
    )
    redacted = redact_result(result)
    assert "123-45-6789" not in redacted.model_dump_json()
    assert redacted.reasons[0].points == 25


def test_logging_filter_redacts_message_args_and_exceptions():
    record = logging.LogRecord(
        "x", logging.INFO, __file__, 1, "user sent %s", ("123-45-6789",), None
    )
    try:
        raise ValueError("card 4111 1111 1111 1111")
    except ValueError:
        record.exc_info = sys.exc_info()
    assert RedactingFilter().filter(record)
    assert record.getMessage() == f"user sent {SSN_PLACEHOLDER}"
    assert "4111" not in record.exc_text
    assert record.exc_info is None


def test_pipeline_redacts_before_responding_and_storing(make_service, fake_llm):
    # The LLM quotes the card number as evidence; it must not survive into the result.
    text = "IRS: settle your balance with card 4111 1111 1111 1111 today."
    llm = fake_llm(
        MessageFeatures(
            sensitive_requests=[SensitiveRequest(type="card", span="card 4111 1111 1111 1111")]
        )
    )
    service = make_service(llm)
    result = service.analyze(AnalyzeRequest(text=text))
    stored = service.get_analysis(result.analysis_id)
    for dumped in (result.model_dump_json(), stored.model_dump_json()):
        assert "4111" not in dumped
        assert CARD_PLACEHOLDER in dumped
