"""Deterministic message scoring: features + verification checks -> reasons -> score.

The message score is the sum of reason points, clamped to 0-100, so every point traces
to a reason (NFR-1). Points come from config/scoring.yaml.
"""

from __future__ import annotations

from scamsentinel.message.features import UNUSUAL_PAYMENT_METHODS, MessageFeatures
from scamsentinel.models import Module, ModuleResult, Reason
from scamsentinel.verify.checks import CheckResult

_LABELS = {
    # sensitive requests
    "ssn": "a Social Security number",
    "bank_account": "bank account details",
    "password": "a password or PIN",
    "mfa_code": "a verification (MFA) code",
    "card": "card details",
    "id_photo": "a photo of an ID",
    "dob": "a date of birth",
    # payment methods
    "gift_card": "gift cards",
    "crypto": "cryptocurrency",
    "wire": "wire transfer",
    "zelle": "Zelle",
    "cash_app": "Cash App",
    "venmo": "Venmo",
    # threats
    "arrest": "arrest",
    "account_suspension": "account suspension",
    "refund_loss": "losing your refund",
    "delivery_hold": "a held or undeliverable package",
    "suspicious_activity": "suspicious activity on your account",
    "penalty": "penalties",
    "legal_action": "legal action",
    # calls to action
    "click_link": "click a link",
    "call_number": "call a phone number",
    "reply": "reply",
    "pay": "pay",
}
MAX_QUOTE = 120


def _quote(span: str) -> str:
    span = " ".join(span.split())
    return f'"{span[:MAX_QUOTE]}…"' if len(span) > MAX_QUOTE else f'"{span}"'


def _reason(signal: str, detail: str, points: int, evidence: str | None = None) -> Reason:
    return Reason(
        module=Module.MESSAGE, signal=signal, detail=detail, evidence=evidence, points=points
    )


def message_reasons(features: MessageFeatures, points: dict[str, int]) -> list[Reason]:
    reasons: list[Reason] = []

    if entity := features.protected_entity:
        span = features.impersonated_entity.span  # type: ignore[union-attr]
        reasons.append(
            _reason(
                "impersonation",
                f"Presents itself as {entity}: {_quote(span)}",
                points["impersonation"],
                span,
            )
        )

    level = features.urgency.level
    if level > 0:
        key = "urgency_high" if level >= 7 else "urgency_medium" if level >= 4 else "urgency_low"
        quotes = ", ".join(_quote(s) for s in features.urgency.spans[:3])
        reasons.append(
            _reason("urgency", f"Creates time pressure: {quotes}", points[key], quotes or None)
        )

    used = 0
    for request in features.sensitive_requests:
        awarded = max(0, min(points["sensitive_request"], points["sensitive_request_cap"] - used))
        used += awarded
        reasons.append(
            _reason(
                "sensitive_request",
                f"Asks for {_LABELS[request.type]}: {_quote(request.span)}",
                awarded,
                request.span,
            )
        )

    unusual = [pm for pm in features.payment_methods if pm.method in UNUSUAL_PAYMENT_METHODS]
    if unusual:
        methods = ", ".join(_LABELS[pm.method] for pm in unusual)
        reasons.append(
            _reason(
                "unusual_payment_method",
                f"Demands payment by {methods}: {_quote(unusual[0].span)}",
                points["unusual_payment_method"],
                unusual[0].span,
            )
        )

    used = 0
    for threat in features.threats:
        awarded = max(0, min(points["threat"], points["threat_cap"] - used))
        used += awarded
        reasons.append(
            _reason(
                "threat",
                f"Threatens {_LABELS[threat.type]}: {_quote(threat.span)}",
                awarded,
                threat.span,
            )
        )

    cta = features.call_to_action
    if cta is not None and cta.value != "none":
        reasons.append(
            _reason(
                "call_to_action",
                f"Pushes you to {_LABELS[cta.value]}: {_quote(cta.span)}",
                points["call_to_action"],
                cta.span,
            )
        )

    if features.injection_attempt.detected:
        span = features.injection_attempt.span
        reasons.append(
            _reason(
                "injection_attempt",
                f"Contains instructions aimed at an AI classifier: {_quote(span)}",
                points["injection_attempt"],
                span,
            )
        )
    return reasons


def verification_reasons(checks: list[CheckResult], points: dict[str, int]) -> list[Reason]:
    """One reason per signal (the first check), and mitigation only if nothing failed."""
    failed = any(c.verified is False for c in checks)
    reasons: list[Reason] = []
    seen: set[str] = set()
    for check in checks:
        value = points.get(check.signal, 0)
        if value == 0 or check.signal in seen or (value < 0 and failed):
            continue
        seen.add(check.signal)
        others = sum(1 for c in checks if c.signal == check.signal) - 1
        detail = check.detail + (f" (+{others} more)" if others else "")
        if check.source:
            detail += f" [source: {check.source}]"
        reasons.append(
            Reason(
                module=Module.VERIFY,
                signal=check.signal,
                detail=detail,
                evidence=check.claim,
                points=value,
            )
        )
    return reasons


def score_message(
    features: MessageFeatures,
    checks: list[CheckResult],
    message_points: dict[str, int],
    verify_points: dict[str, int],
) -> ModuleResult:
    reasons = message_reasons(features, message_points) + verification_reasons(
        checks, verify_points
    )
    if not reasons:
        reasons = [
            _reason("no_message_signals", "No scam indicators found in the message text", 0)
        ]
    score = max(0, min(100, sum(r.points for r in reasons)))
    return ModuleResult(module=Module.MESSAGE, score=score, reasons=reasons)
