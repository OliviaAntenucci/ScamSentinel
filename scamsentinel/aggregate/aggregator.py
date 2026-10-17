"""Risk aggregator (architecture.md §9): renormalized weights, mitigating cap, floors.

    risk = Σ (w_m / Σ w_active) · score_m      over the modules that ran
    then the mitigating cap, then floors (minimum scores for high-confidence combos)

The aggregator explains itself with AGGREGATE reasons (points 0) so the final number
can be traced: the weighting, and any cap or floor that changed it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from scamsentinel.data import Bands, ScoringConfig
from scamsentinel.domain.engine import DomainResult
from scamsentinel.message.features import MessageFeatures
from scamsentinel.models import Module, ModuleResult, PageReport, Reason, Verdict
from scamsentinel.page.score import credential_harvest
from scamsentinel.verify.checks import CheckResult

LOOKALIKE_THRESHOLD = 60
# Domain reasons are listed for at most this many domains, highest-scoring first.
MAX_DOMAINS_IN_REASONS = 5


def verdict_for_score(score: int, bands: Bands) -> Verdict:
    if score >= bands.likely_scam:
        return Verdict.LIKELY_SCAM
    if score >= bands.suspicious:
        return Verdict.SUSPICIOUS
    return Verdict.LIKELY_LEGITIMATE


@dataclass
class Aggregate:
    risk_score: int
    verdict: Verdict
    module_scores: dict[Module, int]
    modules_run: list[Module]
    reasons: list[Reason]
    overrides_applied: list[str] = field(default_factory=list)


def domain_module(domains: list[DomainResult]) -> ModuleResult | None:
    """Combine per-domain results: the score is the worst (highest) domain's score."""
    if not domains:
        return None
    ranked = sorted(domains, key=lambda d: d.score, reverse=True)
    flagged = [d for d in ranked if d.score > 0][:MAX_DOMAINS_IN_REASONS]
    shown = flagged or ranked[:MAX_DOMAINS_IN_REASONS]
    return ModuleResult(
        module=Module.DOMAIN,
        score=ranked[0].score,
        reasons=[reason for d in shown for reason in d.reasons],
    )


def aggregate(
    *,
    domains: list[DomainResult],
    message: ModuleResult | None,
    features: MessageFeatures | None,
    config: ScoringConfig,
    checks: list[CheckResult] | None = None,
    page: ModuleResult | None = None,
    page_reports: list[PageReport] | None = None,
) -> Aggregate:
    modules = [m for m in (domain_module(domains), message, page) if m is not None]
    if not modules:
        raise ValueError("nothing to aggregate")

    # "No link looks like a brand" isn't evidence that a message is legitimate (only
    # official links are, and those are handled by the mitigating cap). So a domain
    # module that found nothing doesn't dilute the message score; it's still reported.
    # The same goes for a page that showed nothing (P2b).
    weighted_modules = [
        m
        for m in modules
        if m.score > 0
        or m.module == Module.MESSAGE
        or (m.module == Module.DOMAIN and message is None and page is None)
    ]
    if not weighted_modules:
        weighted_modules = [m for m in modules if m.module == Module.DOMAIN] or modules[:1]
    weights = {m.module: config.weights.get(m.module, 0.0) for m in weighted_modules}
    total_weight = sum(weights.values())
    weighted = sum(m.score * weights[m.module] / total_weight for m in weighted_modules)
    risk = math.floor(weighted + 0.5)

    terms = " + ".join(
        f"{m.module.value} {m.score} × {weights[m.module] / total_weight:.2f}"
        for m in weighted_modules
    )
    skipped = [m.module.value for m in modules if m not in weighted_modules]
    if skipped:
        terms += f" ({' and '.join(skipped)} 0 not weighted: nothing found)"
    reasons = [r for m in modules for r in m.reasons]
    reasons.append(
        _reason("weighted_score", f"Weighted score: {terms} = {risk}", evidence=None)
    )
    overrides: list[str] = []

    if _mitigating(domains, features) and risk > config.mitigating_cap:
        risk = config.mitigating_cap
        overrides.append("mitigating_cap")
        reasons.append(
            _reason(
                "mitigating_cap",
                f"Capped at {risk}: every link is official and nothing sensitive or payment "
                "related is requested",
            )
        )

    floors = _floors(domains, features, checks or [])
    harvest = credential_harvest(page_reports or [])
    floors.append(
        (
            "page_credential_harvest",
            harvest is not None,
            f"the linked page presents itself as {harvest.brand} on a domain that isn't "
            f"{harvest.brand}'s and asks for {', '.join(harvest.asks_for)}"
            if harvest
            else "",
        )
    )
    for name, applies, why in floors:
        floor = config.floors.get(name)
        if floor is not None and applies and risk < floor:
            risk = floor
            overrides.append(name)
            reasons.append(_reason(f"floor:{name}", f"Raised to at least {floor}: {why}"))

    return Aggregate(
        risk_score=risk,
        verdict=verdict_for_score(risk, config.bands),
        module_scores={m.module: m.score for m in modules},
        modules_run=[m.module for m in modules],
        reasons=reasons,
        overrides_applied=overrides,
    )


def _floors(
    domains: list[DomainResult], features: MessageFeatures | None, checks: list[CheckResult]
) -> list[tuple[str, bool, str]]:
    lookalike = any(not d.official and d.score >= LOOKALIKE_THRESHOLD for d in domains)
    homoglyph = any("homoglyph" in d.techniques for d in domains)
    floors = [
        ("homoglyph_brand_domain", homoglyph, "a link uses lookalike characters of a brand name"),
    ]
    if features is not None:
        # The brand's own trusted facts say it never takes this payment method (e.g. the
        # IRS and gift cards). Only brands with such facts can trigger it.
        disallowed_payment = any(
            c.check == "payment_method_policy" and c.verified is False for c in checks
        )
        other_signal = bool(
            lookalike
            or features.protected_entity
            or features.sensitive_requests
            or features.payment_methods
            or features.threats
            or features.urgency.level
        )
        entity = features.protected_entity
        same_brand_lookalike = any(
            not d.official and d.score >= LOOKALIKE_THRESHOLD and d.brand == entity
            for d in domains
        )
        floors += [
            (
                "impersonation_with_lookalike",
                entity is not None and same_brand_lookalike,
                f"claims to be {entity} and links to a lookalike of {entity}'s domain",
            ),
            (
                "brand_sensitive_request",
                entity is not None and bool(features.sensitive_requests),
                f"claims to be {entity} and asks for sensitive information",
            ),
            (
                "sensitive_request_with_lookalike",
                bool(features.sensitive_requests) and lookalike,
                "asks for sensitive information and links to a lookalike domain",
            ),
            (
                "disallowed_payment_demand",
                entity is not None and disallowed_payment,
                f"claims to be {entity} and demands a payment method {entity} says it never "
                "uses",
            ),
            (
                "injection_plus_scam_signal",
                features.injection_attempt.detected and other_signal,
                "tries to manipulate an AI classifier and shows other scam signals",
            ),
        ]
    return floors


def _mitigating(domains: list[DomainResult], features: MessageFeatures | None) -> bool:
    """At least one link, all official, and no request for data, payment or AI instructions."""
    if not domains or not all(d.official for d in domains):
        return False
    if features is None:
        return True
    return not (
        features.sensitive_requests
        or features.payment_methods
        or features.injection_attempt.detected
    )


def _reason(signal: str, detail: str, evidence: str | None = None) -> Reason:
    return Reason(
        module=Module.AGGREGATE, signal=signal, detail=detail, evidence=evidence, points=0
    )
