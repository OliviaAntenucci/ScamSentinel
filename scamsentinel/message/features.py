"""Message feature schema (architecture.md §6.1, FR-17).

Shared by the LLM extractor and the rule extractor. There is deliberately no verdict or
score field: the LLM extracts, the rules decide (SECURITY.md T2).
"""

from __future__ import annotations

from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, Field

Source = Literal["llm", "rule", "both"]

# Values of impersonated_entity that aren't a protected brand.
OTHER_ENTITY = "other"
NO_ENTITY = "none"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Span(_Strict):
    """A verbatim quote from the input. Spans not found in the input are dropped (FR-18)."""

    span: str
    source: Source = "llm"


class Impersonation(Span):
    # A protected brand name from data/brands.yaml, "other" or "none". The brand list is
    # configuration, so it's validated where the features are produced: the LLM parser
    # maps unknown names to "other", and the analyzer re-checks merged features.
    value: str = Field(min_length=1, max_length=64)


class Urgency(_Strict):
    level: int = Field(ge=0, le=10)
    spans: list[str] = []


PaymentType = Literal["gift_card", "crypto", "wire", "zelle", "cash_app", "venmo", "other"]
SensitiveType = Literal["ssn", "bank_account", "password", "mfa_code", "card", "id_photo", "dob"]
CtaType = Literal["click_link", "call_number", "reply", "pay", "none"]


class PaymentMethod(Span):
    method: PaymentType


class SensitiveRequest(Span):
    type: SensitiveType


ThreatType = Literal[
    "arrest",
    "account_suspension",
    "refund_loss",
    "delivery_hold",
    "suspicious_activity",
    "access_loss",
    "device_infected",
    "job_offer_loss",
    "penalty",
    "legal_action",
]
THREAT_TYPES: tuple[str, ...] = get_args(ThreatType)


class Threat(Span):
    type: ThreatType


class CallToAction(Span):
    value: CtaType


class InjectionAttempt(_Strict):
    detected: bool = False
    span: str = ""


# Payment methods that legitimate organizations (tax agencies, carriers, banks) don't
# demand from consumers. "other" (e.g. "IRS Direct Pay", a bank transfer through an
# official site) is deliberately not included.
UNUSUAL_PAYMENT_METHODS = frozenset({"gift_card", "crypto", "wire", "zelle", "cash_app", "venmo"})


class MessageFeatures(_Strict):
    impersonated_entity: Impersonation | None = None
    urgency: Urgency = Urgency(level=0)
    payment_methods: list[PaymentMethod] = []
    sensitive_requests: list[SensitiveRequest] = []
    claimed_urls: list[str] = []
    claimed_phone_numbers: list[str] = []
    call_to_action: CallToAction | None = None
    threats: list[Threat] = []
    injection_attempt: InjectionAttempt = InjectionAttempt()

    @property
    def protected_entity(self) -> str | None:
        """The protected brand the message claims to be from, if any."""
        entity = self.impersonated_entity
        if entity is None or entity.value in (OTHER_ENTITY, NO_ENTITY):
            return None
        return entity.value

    def restrict_entity(self, brands: set[str]) -> MessageFeatures:
        """Copy in which an impersonated entity that isn't a known brand becomes "other"."""
        entity = self.impersonated_entity
        if entity is None or entity.value in brands or entity.value == OTHER_ENTITY:
            return self
        return self.model_copy(
            update={"impersonated_entity": entity.model_copy(update={"value": OTHER_ENTITY})}
        )

    def with_source(self, source: Source) -> MessageFeatures:
        """Copy with every span-bearing feature tagged as coming from `source`."""

        def tag(items):
            return [item.model_copy(update={"source": source}) for item in items]

        return self.model_copy(
            update={
                "impersonated_entity": tag([self.impersonated_entity])[0]
                if self.impersonated_entity
                else None,
                "payment_methods": tag(self.payment_methods),
                "sensitive_requests": tag(self.sensitive_requests),
                "threats": tag(self.threats),
                "call_to_action": tag([self.call_to_action])[0] if self.call_to_action else None,
            }
        )
