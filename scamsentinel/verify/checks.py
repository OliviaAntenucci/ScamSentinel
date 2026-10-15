"""Verification layer: check message/page claims against data/facts.yaml (§7, M2)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from scamsentinel.message.features import MessageFeatures

CheckName = Literal[
    "official_domain",
    "contact_channel",
    "payment_method_policy",
    "phone_number",
    "sender_alignment",
    "page_brand_mismatch",
]


class CheckResult(BaseModel):
    check: CheckName
    claim: str
    verified: bool | None  # None = unknown
    source: str | None = None
    detail: str = ""


def run_checks(
    features: MessageFeatures, input_type: str, domains: list[str]
) -> list[CheckResult]:
    raise NotImplementedError("M2: verification checks")
