"""'What should I do next?' (E1, architecture.md §18) and named scenarios (E4, §21).

Turns the evidence behind a verdict into a few short, cautious steps. The wording comes
from data/guidance.yaml and data/scenarios.yaml, and every value filled into it comes from
data files: curated brand names and official sites, published phone numbers and report
addresses, and sourced references. Nothing from the analyzed content is inserted (not a
link, a phone number, or the name of an uncurated organization), so the advice can't be
turned into a scammer's "call this number to confirm". Advice never says something is safe.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from scamsentinel.aggregate.aggregator import LOOKALIKE_THRESHOLD
from scamsentinel.data import (
    Brand,
    Fact,
    Guidance,
    ResourcesFile,
    ScenarioRule,
    load_brands,
    load_facts,
    load_guidance,
    load_keywords,
    load_resources,
    load_scenarios,
)
from scamsentinel.domain.engine import DomainResult
from scamsentinel.guidance.resources import ReadingList
from scamsentinel.guidance.scenarios import ScenarioMatcher
from scamsentinel.ingest.phones import normalize_phone
from scamsentinel.message.features import OTHER_ENTITY, UNUSUAL_PAYMENT_METHODS, MessageFeatures
from scamsentinel.models import InputType, NextStep, Resource, Scenario, Verdict
from scamsentinel.verify.checks import CheckResult

# The report step is always kept; when there are more steps than this, "already acted"
# goes first, then the list is cut before the report step.
MAX_STEPS = 7

REQUIRED_STEPS = frozenset(
    {
        "dont_open_link_brand", "dont_open_link", "dont_share", "dont_pay_policy", "dont_pay",
        "dont_call", "contact_brand_with_phone", "contact_brand", "contact_unknown_org",
        "contact_sender", "report_brand_text", "report_brand", "report_text", "report",
        "already_acted", "verify_brand", "verify",
    }
)

_REQUESTED = {
    "ssn": "your Social Security number",
    "bank_account": "your bank account details",
    "password": "your password or PIN",
    "mfa_code": "verification codes",
    "card": "your card details",
    "id_photo": "photos of your ID",
    "dob": "your date of birth",
}
_PAYMENT = {
    "gift_card": "gift card",
    "crypto": "cryptocurrency",
    "wire": "wire transfer",
    "zelle": "Zelle",
    "cash_app": "Cash App",
    "venmo": "Venmo",
}
_LINK_CONFLICTS = frozenset({"official_domain_mismatch", "org_domain_mismatch_unverified"})


@dataclass(frozen=True)
class _Contact:
    site: str
    site_source: str | None
    phone: str | None
    phone_source: str | None
    report_to: str | None
    report_source: str | None


class NextStepsGuide:
    def __init__(
        self,
        guidance: Guidance,
        brands: list[Brand],
        facts: list[Fact],
        scenarios: Sequence[ScenarioRule] = (),
        negations: Sequence[str] = (),
        resources: ResourcesFile | None = None,
    ) -> None:
        missing = REQUIRED_STEPS - set(guidance.steps)
        if missing:
            raise ValueError(f"guidance.yaml is missing steps: {sorted(missing)}")
        categories = {b.category for b in brands}
        unknown = {
            c for s in scenarios for c in [s.category, *(x for w in s.when for x in w.category)]
            if c is not None and c not in categories
        }
        if unknown:
            raise ValueError(f"scenarios.yaml uses unknown categories: {sorted(unknown)}")
        self._steps = guidance.steps
        self._refs = guidance.references
        self._contacts = {b.name: _contact_for(b, facts) for b in brands}
        self._categories = {b.name: b.category for b in brands}
        self._policy_sources = {
            f.entity: f.source for f in facts if "disallowed_payment_methods" in f.data
        }
        self._scenarios = ScenarioMatcher(scenarios, negations)
        self._scenario_steps = {s.id: s.step for s in scenarios}
        self._reading = (
            ReadingList(resources, brands, [s.id for s in scenarios])
            if resources is not None
            else None
        )

    @classmethod
    def from_files(cls, data_dir: Path) -> NextStepsGuide:
        return cls(
            load_guidance(data_dir),
            load_brands(data_dir),
            load_facts(data_dir),
            load_scenarios(data_dir),
            load_keywords(data_dir).negations,
            load_resources(data_dir),
        )

    def resources(
        self,
        *,
        verdict: Verdict,
        features: MessageFeatures | None,
        domains: list[DomainResult],
        scenario: Scenario | None,
        page_brand: str | None = None,
    ) -> list[Resource]:
        """Where to read more: the type of scam, and the claimed brand's own help pages."""
        if self._reading is None:
            return []
        entity = self._entity(features or MessageFeatures(), domains, page_brand)
        return self._reading.build(
            verdict=verdict,
            entity=entity,
            category=self._categories.get(entity) if entity else None,
            scenario=scenario,
        )

    def scenario(
        self,
        *,
        verdict: Verdict,
        features: MessageFeatures | None,
        domains: list[DomainResult],
        text: str,
        page_brand: str | None = None,
    ) -> Scenario | None:
        """The named scenario (E4) of a suspicious or likely-scam message. A likely-
        legitimate result never gets one, so a real alert isn't labeled as a scam story."""
        if verdict == Verdict.LIKELY_LEGITIMATE or features is None or not text:
            return None
        entity = self._entity(features, domains, page_brand)
        return self._scenarios.match(
            features=features,
            text=text,
            entity=entity,
            category=self._categories.get(entity) if entity else None,
            unofficial_link=any(not d.official for d in domains),
        )

    def build(
        self,
        *,
        verdict: Verdict,
        input_type: InputType,
        features: MessageFeatures | None,
        domains: list[DomainResult],
        checks: list[CheckResult],
        scenario: Scenario | None = None,
        page_brand: str | None = None,
    ) -> list[NextStep]:
        features = features or MessageFeatures()
        entity = self._entity(features, domains, page_brand)
        if verdict == Verdict.LIKELY_LEGITIMATE:
            if entity:
                contact = self._contacts[entity]
                return [self._step("verify_brand", contact.site_source, site=contact.site)]
            return [self._step("verify")]

        signals = {c.signal for c in checks}
        steps: list[NextStep] = []

        lookalike = [d for d in domains if not d.official and d.score >= LOOKALIKE_THRESHOLD]
        brand_link_conflict = entity is not None and (
            "official_domain_mismatch" in signals
            or any(d.brand == entity for d in lookalike)
            # The linked page presents itself as this brand on a domain that isn't its own.
            or entity == page_brand
        )
        if brand_link_conflict:
            steps.append(self._step("dont_open_link_brand", entity=entity))
        elif lookalike or signals & _LINK_CONFLICTS or any(not d.official for d in domains):
            steps.append(self._step("dont_open_link"))

        requested = [_REQUESTED[r.type] for r in features.sensitive_requests]
        if requested:
            steps.append(self._step("dont_share", requested=_join(requested)))

        unusual = [
            p.method for p in features.payment_methods if p.method in UNUSUAL_PAYMENT_METHODS
        ]
        if unusual:
            if entity and "payment_method_policy" in signals:
                methods = _join([_PAYMENT[m] for m in dict.fromkeys(unusual)], "or")
                steps.append(
                    self._step(
                        "dont_pay_policy", self._policy_sources.get(entity),
                        entity=entity, methods=methods,
                    )
                )
            else:
                steps.append(self._step("dont_pay"))

        cta = features.call_to_action
        unverified_phone = "phone_number_unknown" in signals or (
            cta is not None and cta.value == "call_number" and "phone_number_known" not in signals
        )
        if unverified_phone:
            steps.append(self._step("dont_call"))

        if scenario is not None and scenario.id in self._scenario_steps:
            # The scenario's own advice, after the "don't" steps it may stand in for.
            own = self._scenario_steps[scenario.id]
            steps = [s for s in steps if s.id not in own.replaces]
            steps.append(NextStep(id=f"scenario_{scenario.id}", text=own.text, source=own.source))

        steps.append(self._contact_step(entity, features))

        if verdict == Verdict.LIKELY_SCAM and (requested or features.payment_methods):
            steps.append(self._step("already_acted"))

        if len(steps) > MAX_STEPS - 1:
            steps = [s for s in steps if s.id != "already_acted"]
        return [*steps[: MAX_STEPS - 1], self._report_step(entity, input_type)]

    # --- helpers --------------------------------------------------------------------

    def _entity(
        self,
        features: MessageFeatures,
        domains: list[DomainResult],
        page_brand: str | None = None,
    ) -> str | None:
        """The curated brand the advice can name: the claimed one, else the brand that a
        lookalike or official link belongs to, else the brand the linked page presents
        itself as (P2b)."""
        if features.protected_entity in self._contacts:
            return features.protected_entity
        ranked = sorted(domains, key=lambda d: d.score, reverse=True)
        for d in ranked:
            if d.brand in self._contacts and (d.official or d.score >= LOOKALIKE_THRESHOLD):
                return d.brand
        return page_brand if page_brand in self._contacts else None

    def _contact_step(self, entity: str | None, features: MessageFeatures) -> NextStep:
        if entity:
            c = self._contacts[entity]
            if c.phone:
                return self._step(
                    "contact_brand_with_phone", c.phone_source,
                    entity=entity, site=c.site, phone=c.phone,
                )
            return self._step("contact_brand", c.site_source, entity=entity, site=c.site)
        claimed = features.impersonated_entity
        if claimed is not None and claimed.value == OTHER_ENTITY:
            # The organization's name is attacker-written, so it's deliberately not quoted.
            return self._step("contact_unknown_org")
        return self._step("contact_sender")

    def _report_step(self, entity: str | None, input_type: InputType) -> NextStep:
        report_to = self._contacts[entity].report_to if entity else None
        if entity and report_to:
            key = "report_brand_text" if input_type == "text" else "report_brand"
            return self._step(key, self._contacts[entity].report_source, report_to=report_to)
        key = "report_text" if input_type == "text" else "report"
        return self._step(key, self._refs.get("ftc_spam_text"))

    def _step(self, step_id: str, source: str | None = None, **values: str) -> NextStep:
        return NextStep(id=step_id, text=self._steps[step_id].format(**values), source=source)


def _contact_for(brand: Brand, facts: list[Fact]) -> _Contact:
    own = [f for f in facts if f.entity == brand.name]
    phone = next((f for f in own if f.data.get("phone_numbers")), None)
    report = next((f for f in own if f.data.get("report_to")), None)
    return _Contact(
        site=brand.official_domains[0],
        site_source=brand.sources[0] if brand.sources else None,
        phone=_format_phone(phone.data["phone_numbers"][0]) if phone else None,
        phone_source=phone.source if phone else None,
        report_to=report.data["report_to"] if report else None,
        report_source=report.source if report else None,
    )


def _format_phone(number: str) -> str:
    normalized = normalize_phone(number) or number
    digits = normalized.removeprefix("+1")
    if len(digits) == 10 and digits.isdigit():
        return f"1-{digits[:3]}-{digits[3:6]}-{digits[6:]}"
    return number


def _join(items: list[str], conjunction: str = "and") -> str:
    items = list(dict.fromkeys(items))
    if len(items) <= 1:
        return "".join(items)
    return f"{', '.join(items[:-1])} {conjunction} {items[-1]}"
