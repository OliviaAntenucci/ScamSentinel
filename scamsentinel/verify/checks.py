"""Verification layer: check message claims against data/facts.yaml (architecture.md §6).

Each check records the claim, whether it held up (True / False / None = can't tell),
and the source of the fact it was checked against.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from scamsentinel.data import Brand, Fact
from scamsentinel.domain.engine import DomainEngine
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.ingest.email import ParsedEmail
from scamsentinel.ingest.phones import normalize_phone
from scamsentinel.message.features import MessageFeatures

InputType = Literal["text", "url", "email", "image"]

CheckName = Literal[
    "official_domain",
    "contact_channel",
    "payment_method_policy",
    "phone_number",
    "sender_alignment",
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
    # Key into verify_points in config/scoring.yaml.
    signal: str
    claim: str
    verified: bool | None  # None = can't tell
    source: str | None = None
    detail: str = ""


class Verifier:
    def __init__(self, brands: list[Brand], facts: list[Fact], engine: DomainEngine) -> None:
        self._brands = {b.name: b for b in brands}
        self._facts = facts
        self._engine = engine

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
            checks += self._phone_numbers(entity, features.claimed_phone_numbers)
        if email is not None:
            checks += self._sender_alignment(entity, email)
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
                    source=brand.sources[0] if brand.sources else None,
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
        # that only links to the official site isn't one.
        asks = bool(features.sensitive_requests or features.payment_methods or unofficial_link)
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
                        source=fact.source,
                        detail=fact.statement,
                    )
                ]
        return []

    def _payment_policy(self, entity: str, features: MessageFeatures) -> list[CheckResult]:
        disallowed: dict[str, str] = {}
        for fact in self._facts_with(entity, "disallowed_payment_methods"):
            for method in fact.data["disallowed_payment_methods"]:
                disallowed.setdefault(method, fact.source)
        return [
            CheckResult(
                check="payment_method_policy",
                signal="payment_method_policy",
                claim=f"{entity} asking for payment by {pm.method.replace('_', ' ')}",
                verified=False,
                source=disallowed[pm.method],
                detail=f"{entity} does not demand payment by {pm.method.replace('_', ' ')}",
            )
            for pm in features.payment_methods
            if pm.method in disallowed
        ]

    def _phone_numbers(self, entity: str, phones: list[str]) -> list[CheckResult]:
        known: dict[str, str] = {}
        for fact in self._facts_with(entity, "phone_numbers"):
            for number in fact.data["phone_numbers"]:
                if normalized := normalize_phone(number):
                    known[normalized] = fact.source
        if not known:
            return []
        checks = []
        for phone in phones:
            normalized = normalize_phone(phone)
            if normalized is None:
                continue
            match = normalized in known
            checks.append(
                CheckResult(
                    check="phone_number",
                    signal="phone_number_known" if match else "phone_number_unknown",
                    claim=phone,
                    # Only a short list of numbers is known, so a miss means "can't verify".
                    verified=True if match else None,
                    source=known.get(normalized),
                    detail=(
                        f"{phone} is a published {entity} number"
                        if match
                        else f"{phone} is not among the {entity} numbers we can verify"
                    ),
                )
            )
        return checks

    def _sender_alignment(self, entity: str | None, email: ParsedEmail) -> list[CheckResult]:
        checks = []
        from_registrable = self._registrable(email.from_domain)

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
                        source=brand.sources[0] if brand.sources else None,
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
                    detail=(
                        f"Replies go to {reply_registrable}, not the sender's domain "
                        f"{from_registrable}"
                    ),
                )
            )
        return checks

    # --- helpers --------------------------------------------------------------------

    def _facts_with(self, entity: str, key: str) -> list[Fact]:
        return [f for f in self._facts if f.entity == entity and key in f.data]

    def _registrable(self, host_or_url: str | None) -> str | None:
        if not host_or_url:
            return None
        try:
            return self._engine.score(host_or_url).registrable
        except InvalidHost:
            return None
