"""Verification layer: check message claims against data/facts.yaml (architecture.md §6).

Each check records the claim, whether it held up (True / False / None = can't tell),
and the source of the fact it was checked against.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Literal

from pydantic import BaseModel

from scamsentinel.data import Brand, Fact
from scamsentinel.domain.engine import DomainEngine
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.ingest.email import ParsedEmail
from scamsentinel.ingest.phones import normalize_phone
from scamsentinel.message.features import UNUSUAL_PAYMENT_METHODS, MessageFeatures
from scamsentinel.message.rules import phrase_pattern
from scamsentinel.models import FactBasis, FactCheck, InputType
from scamsentinel.verify.org_facts import OrgFacts

CheckName = Literal[
    "official_domain",
    "contact_channel",
    "payment_method_policy",
    "request_policy",
    "phone_number",
    "sender_alignment",
    "org_official_domain",
]

# How each input type reached the user, in the vocabulary of facts.yaml.
# A screenshot could show a text, an email or a social post; any of them counts.
_CHANNELS: dict[str, set[str]] = {
    "text": {"sms"},
    "email": {"email"},
    "image": {"sms", "email", "social"},
}


class CheckResult(BaseModel):
    check: CheckName
    # Key into verify_points in config/scoring.yaml. Signals without points (the
    # "_unverified" ones) only appear in the fact-check summary (E3).
    signal: str
    claim: str
    verified: bool | None  # None = can't tell
    source: str | None = None
    detail: str = ""
    # What the claim was compared with (E3): a fact from facts.yaml (statement, id,
    # review date), the brand list, the email's own headers, or an LLM's knowledge.
    basis: FactBasis = "published_fact"
    fact: str | None = None
    fact_id: str | None = None
    last_reviewed: date | None = None


class Verifier:
    def __init__(
        self,
        brands: list[Brand],
        facts: list[Fact],
        engine: DomainEngine,
        entity_mentions: dict[str, list[str]] | None = None,
    ) -> None:
        self._brands = {b.name: b for b in brands}
        self._facts = facts
        self._engine = engine
        # How each brand is named in a sender's display name ("IRS", "Internal Revenue
        # Service", "Intuit", ...), falling back to the brand name itself.
        mentions = entity_mentions or {}
        self._display_patterns = {
            name: phrase_pattern([name, *mentions.get(name, [])]) for name in self._brands
        }

    def run(
        self,
        features: MessageFeatures,
        *,
        input_type: InputType,
        email: ParsedEmail | None = None,
    ) -> list[CheckResult]:
        entity = features.protected_entity
        checks: list[CheckResult] = []
        if entity:
            domain_checks = self._official_domains(entity, features.claimed_urls)
            checks += domain_checks
            unofficial_link = any(c.verified is False for c in domain_checks)
            checks += self._contact_channel(entity, features, input_type, unofficial_link)
            checks += self._payment_policy(entity, features)
            checks += self._request_policy(entity, features, input_type)
            checks += self._phone_numbers(entity, features.claimed_phone_numbers)
        if email is not None:
            checks += self._sender_alignment(email)
        return checks

    def unknown_org_domains(
        self, org_name: str, facts: OrgFacts, urls: list[str], model: str
    ) -> list[CheckResult]:
        """Links checked against an LLM's (unverified) list of an organization's domains.

        Only conflicts matter: a match is recorded with verified=None and earns nothing,
        because the model's answer isn't a published source.
        """
        if not facts.known:
            return []
        official = {r for d in facts.official_domains if (r := self._registrable(d))}
        if not official:
            return []
        name = facts.canonical_name or org_name
        provenance = f"according to the {model} model's knowledge, not a published source"
        checks = []
        for url in urls:
            registrable = self._registrable(url)
            if registrable is None:
                continue
            match = registrable in official
            checks.append(
                CheckResult(
                    check="org_official_domain",
                    signal=(
                        "org_domain_match_unverified" if match else "org_domain_mismatch_unverified"
                    ),
                    claim=url,
                    verified=None if match else False,
                    basis="model_knowledge",
                    fact=f"{name}'s sites, according to the {model} model: "
                    f"{', '.join(sorted(official))}",
                    detail=(
                        f"{registrable} may belong to {name} ({provenance})"
                        if match
                        else f"Claims to be {name}, but links to {registrable}; {name}'s sites "
                        f"are {', '.join(sorted(official))} ({provenance})"
                    ),
                )
            )
        return checks

    # --- checks ---------------------------------------------------------------------

    def _official_domains(self, entity: str, urls: list[str]) -> list[CheckResult]:
        brand = self._brands[entity]
        checks = []
        for url in urls:
            registrable = self._registrable(url)
            if registrable is None:
                continue
            official = registrable in brand.official_domains
            checks.append(
                CheckResult(
                    check="official_domain",
                    signal="official_domain_match" if official else "official_domain_mismatch",
                    claim=url,
                    verified=official,
                    **self._domains_basis(entity),
                    detail=(
                        f"{registrable} is an official {entity} domain"
                        if official
                        else f"Claims to be {entity}, but links to {registrable}, which is not "
                        f"an official {entity} domain ({', '.join(brand.official_domains)})"
                    ),
                )
            )
        return checks

    def _contact_channel(
        self,
        entity: str,
        features: MessageFeatures,
        input_type: InputType,
        unofficial_link: bool,
    ) -> list[CheckResult]:
        # The fact is about unsolicited requests for information or payment. A reminder
        # that only links to the official site, or points to an ordinary official payment
        # channel ("pay through IRS Direct Pay"), isn't one.
        unusual_payment = any(
            p.method in UNUSUAL_PAYMENT_METHODS for p in features.payment_methods
        )
        asks = bool(features.sensitive_requests or unusual_payment or unofficial_link)
        channels = _CHANNELS.get(input_type, set())
        if not asks or not channels:
            return []
        for fact in self._facts_with(entity, "disallowed_first_contact_channels"):
            if channels & set(fact.data["disallowed_first_contact_channels"]):
                return [
                    CheckResult(
                        check="contact_channel",
                        signal="contact_channel",
                        claim=f"{entity} contacting you by {input_type} and asking you to act",
                        verified=False,
                        detail=fact.statement,
                        **_cite(fact),
                    )
                ]
        return []

    def _payment_policy(self, entity: str, features: MessageFeatures) -> list[CheckResult]:
        disallowed: dict[str, Fact] = {}
        for fact in self._facts_with(entity, "disallowed_payment_methods"):
            for method in fact.data["disallowed_payment_methods"]:
                disallowed.setdefault(method, fact)
        checks = []
        for pm in features.payment_methods:
            method = pm.method.replace("_", " ")
            claim = f"{entity} asking for payment by {method}"
            if pm.method in disallowed:
                checks.append(
                    CheckResult(
                        check="payment_method_policy",
                        signal="payment_method_policy",
                        claim=claim,
                        verified=False,
                        detail=f"{entity} does not demand payment by {method}",
                        **_cite(disallowed[pm.method]),
                    )
                )
            elif pm.method in UNUSUAL_PAYMENT_METHODS:
                # Not evidence either way: the gap is shown, not scored (E3).
                checks.append(
                    CheckResult(
                        check="payment_method_policy",
                        signal="payment_method_unverified",
                        claim=claim,
                        verified=None,
                        basis="no_fact",
                        detail=f"No published {entity} payment policy to check this against",
                    )
                )
        return checks

    def _request_policy(
        self, entity: str, features: MessageFeatures, input_type: InputType
    ) -> list[CheckResult]:
        """Requests for data the brand says it never asks for (e.g. a bank and one-time
        codes). A fact can limit its statement to some channels ("by email or text")."""
        channels = _CHANNELS.get(input_type, set())
        checks = []
        for request in features.sensitive_requests:
            claim = f"{entity} asking for {request.type.replace('_', ' ')}"
            for fact in self._facts_with(entity, "disallowed_requests"):
                limited_to = fact.data.get("channels")
                if request.type not in fact.data["disallowed_requests"]:
                    continue
                if limited_to is not None and not channels & set(limited_to):
                    continue
                checks.append(
                    CheckResult(
                        check="request_policy",
                        signal="request_policy",
                        claim=claim,
                        verified=False,
                        detail=fact.statement,
                        **_cite(fact),
                    )
                )
                break
            else:
                checks.append(
                    CheckResult(
                        check="request_policy",
                        signal="request_unverified",
                        claim=claim,
                        verified=None,
                        basis="no_fact",
                        detail=(
                            f"No published {entity} statement about asking for this to "
                            "check it against"
                        ),
                    )
                )
        return checks

    def _phone_numbers(self, entity: str, phones: list[str]) -> list[CheckResult]:
        known: dict[str, Fact] = {}
        for fact in self._facts_with(entity, "phone_numbers"):
            for number in fact.data["phone_numbers"]:
                if normalized := normalize_phone(number):
                    known[normalized] = fact
        checks = []
        for phone in phones:
            normalized = normalize_phone(phone)
            if normalized is None:
                continue
            if not known:
                checks.append(
                    CheckResult(
                        check="phone_number",
                        signal="phone_number_unverified",
                        claim=phone,
                        verified=None,
                        basis="no_fact",
                        detail=f"No published {entity} phone numbers to compare {phone} with",
                    )
                )
                continue
            match = normalized in known
            checks.append(
                CheckResult(
                    check="phone_number",
                    signal="phone_number_known" if match else "phone_number_unknown",
                    claim=phone,
                    # Only a short list of numbers is known, so a miss means "can't verify".
                    verified=True if match else None,
                    **_cite(known[normalized] if match else next(iter(known.values()))),
                    detail=(
                        f"{phone} is a published {entity} number"
                        if match
                        else f"{phone} is not among the {entity} numbers we can verify"
                    ),
                )
            )
        return checks

    def _sender_alignment(self, email: ParsedEmail) -> list[CheckResult]:
        checks = []
        from_registrable = self._registrable(email.from_domain)
        # Only a sender that *presents itself* as a brand is checked against that brand's
        # domains. A friend's email that merely mentions TurboTax isn't impersonation.
        entity = self._brand_in_display(email.from_display)

        if entity and from_registrable:
            brand = self._brands[entity]
            official = from_registrable in brand.official_domains
            dkim_ok = any(
                self._registrable(d) == from_registrable for d in email.dkim_pass_domains
            )
            if not official:
                checks.append(
                    CheckResult(
                        check="sender_alignment",
                        signal="sender_brand_mismatch",
                        claim=email.from_address or from_registrable,
                        verified=False,
                        **self._domains_basis(entity),
                        detail=f"Claims to be {entity}, but was sent from {from_registrable}",
                    )
                )
            elif dkim_ok:
                checks.append(
                    CheckResult(
                        check="sender_alignment",
                        signal="sender_verified",
                        claim=email.from_address or from_registrable,
                        verified=True,
                        basis="email_headers",
                        fact=f"Official {entity} domains: {', '.join(brand.official_domains)}",
                        detail=f"Sent from {from_registrable} with a passing DKIM signature",
                    )
                )

        reply_registrable = self._registrable(email.reply_to_domain)
        if from_registrable and reply_registrable and reply_registrable != from_registrable:
            checks.append(
                CheckResult(
                    check="sender_alignment",
                    signal="reply_to_mismatch",
                    claim=email.reply_to_address or reply_registrable,
                    verified=False,
                    basis="email_headers",
                    fact=f"The sender's own domain: {from_registrable}",
                    detail=(
                        f"Replies go to {reply_registrable}, not the sender's domain "
                        f"{from_registrable}"
                    ),
                )
            )
        return checks

    # --- helpers --------------------------------------------------------------------

    def _brand_in_display(self, display: str | None) -> str | None:
        if not display:
            return None
        for name, pattern in self._display_patterns.items():
            if pattern.search(display):
                return name
        return None

    def _facts_with(self, entity: str, key: str) -> list[Fact]:
        return [f for f in self._facts if f.entity == entity and key in f.data]

    def _domains_basis(self, entity: str) -> dict[str, Any]:
        """The brand's official-domains fact if facts.yaml has one, else brands.yaml."""
        facts = self._facts_with(entity, "official_domains")
        if facts:
            return _cite(facts[0])
        brand = self._brands[entity]
        return {
            "basis": "brand_list",
            "fact": f"Official {entity} domains: {', '.join(brand.official_domains)}",
            "source": brand.sources[0] if brand.sources else None,
        }

    def _registrable(self, host_or_url: str | None) -> str | None:
        if not host_or_url:
            return None
        try:
            return self._engine.score(host_or_url).registrable
        except InvalidHost:
            return None


def _cite(fact: Fact) -> dict[str, Any]:
    return {
        "basis": "published_fact",
        "fact": fact.statement,
        "fact_id": fact.id,
        "source": fact.source,
        "last_reviewed": fact.last_reviewed,
    }


# --- fact-check summary (E3) ----------------------------------------------------------

MAX_FACT_CHECKS = 30
_OUTCOME_ORDER = {"conflicts": 0, "cannot_verify": 1, "matches": 2}


def fact_checks(checks: list[CheckResult]) -> list[FactCheck]:
    """Every check as a claim → fact → outcome row, conflicts first."""
    rows = [
        FactCheck(
            check=c.check,
            claim=c.claim,
            outcome="matches" if c.verified else "conflicts" if c.verified is False
            else "cannot_verify",
            detail=c.detail,
            basis=c.basis,
            fact=c.fact,
            fact_id=c.fact_id,
            source=c.source,
            last_reviewed=c.last_reviewed,
        )
        for c in checks
    ]
    rows.sort(key=lambda r: _OUTCOME_ORDER[r.outcome])
    return rows[:MAX_FACT_CHECKS]
