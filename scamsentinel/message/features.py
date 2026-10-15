"""Message feature schema (architecture.md §6.1, FR-17).

Shared by the LLM extractor and the rule extractor. There is deliberately no verdict or
score field: the LLM extracts, the rules decide (SECURITY.md T2).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Source = Literal["llm", "rule", "both"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Span(_Strict):
    """A verbatim quote from the input. Spans not found in the input are dropped (FR-18)."""

    span: str
    source: Source = "llm"


class Impersonation(Span):
    value: Literal["IRS", "TurboTax", "QuickBooks", "Credit Karma", "other", "none"]


class Urgency(_Strict):
    level: int = Field(ge=0, le=10)
    spans: list[str] = []


class PaymentMethod(Span):
    method: Literal["gift_card", "crypto", "wire", "zelle", "cash_app", "venmo", "other"]


class SensitiveRequest(Span):
    type: Literal["ssn", "bank_account", "password", "mfa_code", "card", "id_photo", "dob"]


class Threat(Span):
    type: Literal["arrest", "account_suspension", "refund_loss", "penalty", "legal_action"]


class CallToAction(Span):
    value: Literal["click_link", "call_number", "reply", "pay", "none"]


class InjectionAttempt(_Strict):
    detected: bool = False
    span: str = ""


PROTECTED_ENTITIES = ("IRS", "TurboTax", "QuickBooks", "Credit Karma")

# Payment methods no tax agency or tax-software company demands. "other" (e.g. "IRS
# Direct Pay", a bank transfer through an official site) is deliberately not included.
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
        return entity.value if entity and entity.value in PROTECTED_ENTITIES else None

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
