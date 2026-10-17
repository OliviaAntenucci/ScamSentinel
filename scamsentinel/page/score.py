"""Page evidence as a score (P2b, architecture.md §23).

Turns page reports into a PAGE module result for the aggregator. Points come from
config/scoring.yaml (page_points). The page with the highest score counts; its findings
become reasons. A page that couldn't be analyzed (dry run, blocked, offline) adds nothing,
because "no page" is never evidence either way.
"""

from __future__ import annotations

from scamsentinel.models import Module, ModuleResult, PageReport, Reason

# Field labels (page/analyze.py) -> page_points keys.
_FIELD_POINTS = {
    "password": "field_password",
    "card details": "field_card",
    "verification code": "field_code",
    "Social Security number": "field_ssn",
}


def page_module(reports: list[PageReport], points: dict[str, int]) -> ModuleResult | None:
    scored = [s for s in (_score(r, points) for r in reports) if s is not None]
    if not scored:
        return None
    score, reasons = max(scored, key=lambda s: s[0])
    return ModuleResult(module=Module.PAGE, score=score, reasons=reasons)


def credential_harvest(reports: list[PageReport]) -> PageReport | None:
    """A page that presents itself as a brand on a domain that isn't the brand's, and asks
    for a password, card, verification code or SSN (the page_credential_harvest floor)."""
    for report in reports:
        if report.status == "analyzed" and report.brand and report.asks_for:
            return report
    return None


def _score(report: PageReport, points: dict[str, int]) -> tuple[int, list[Reason]] | None:
    if report.status != "analyzed" or not points:
        return None
    where = report.final_url or report.requested_url
    reasons: list[Reason] = []
    for finding in report.findings:
        if finding.signal == "sensitive_fields":
            value = min(
                points.get("fields_cap", 30),
                sum(points.get(_FIELD_POINTS[label], 0) for label in report.asks_for),
            )
        else:
            value = points.get(finding.signal, 0)
        reasons.append(
            Reason(
                module=Module.PAGE,
                signal=f"page_{finding.signal}",
                detail=finding.detail,
                evidence=where,
                points=value,
            )
        )
    score = max(0, min(100, sum(r.points for r in reasons)))
    return score, reasons
