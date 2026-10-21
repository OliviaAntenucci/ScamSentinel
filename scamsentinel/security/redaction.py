"""PII redaction (NFR-4): SSN-like and payment-card-like numbers.

Applied to analysis results before they are returned or stored, and to every log record.
Phone numbers are kept: they are evidence (e.g. "not a published IRS number").
"""

from __future__ import annotations

import logging
import re
from typing import Any

from scamsentinel.models import AnalysisResult

SSN_PLACEHOLDER = "[REDACTED-SSN]"
CARD_PLACEHOLDER = "[REDACTED-CARD]"

# 3-2-4 digits with consistent separators, excluding never-issued area/group/serial
# numbers (000, 666, 9xx / 00 / 0000), and not part of a longer number.
_SSN = re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}([- ]?)(?!00)\d{2}\1(?!0000)\d{4}(?![\d-])")
# 13-19 digits, optionally grouped by spaces or dashes; confirmed with the Luhn check.
_CARD = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _redact_card(match: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", match.group())
    return CARD_PLACEHOLDER if _luhn_ok(digits) else match.group()


def redact(text: str) -> str:
    return _SSN.sub(SSN_PLACEHOLDER, _CARD.sub(_redact_card, text))


def redact_result(result: AnalysisResult) -> AnalysisResult:
    """Copy of `result` with SSN/card numbers removed from every reason, domain explanation
    (a hostname can carry digits too), fact check (claims quote the message), page report
    and the submitted input itself."""
    reasons = [
        r.model_copy(
            update={
                "detail": redact(r.detail),
                "evidence": redact(r.evidence) if r.evidence is not None else None,
            }
        )
        for r in result.reasons
    ]
    explanations = [
        type(e).model_validate(_redact_strings(e.model_dump())) for e in result.domain_explanations
    ]
    checks = [type(c).model_validate(_redact_strings(c.model_dump())) for c in result.fact_checks]
    # Page titles, URLs and findings quote attacker-written pages (P2).
    pages = [type(p).model_validate(_redact_strings(p.model_dump())) for p in result.pages]
    submitted = result.submitted
    if submitted is not None:
        submitted = submitted.model_copy(update={"content": redact(submitted.content)})
    return result.model_copy(
        update={
            "reasons": reasons,
            "domain_explanations": explanations,
            "fact_checks": checks,
            "pages": pages,
            "submitted": submitted,
        }
    )


def _redact_strings(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_redact_strings(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_strings(v) for k, v in value.items()}
    return value


class RedactingFilter(logging.Filter):
    """Handler filter that redacts the formatted message and any exception text."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        if record.exc_info:
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


def configure_logging(level: int = logging.INFO) -> None:
    """Root handler with redaction. Uvicorn's loggers propagate here (log_config=None)."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
