"""SSRF guard (SECURITY.md T1). Post-MVP (P2): only needed once ScamSentinel fetches pages.

Strict parse (http/https, ports 80/443, no userinfo) -> resolve A/AAAA -> reject if ANY
address is not globally routable -> return the pinned IP so the caller connects to
exactly what was checked (no second DNS lookup, so no rebinding).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})


class UrlRejected(ValueError):
    """Raised when a URL must not be fetched. `reason` is a stable code for logs/tests."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class ValidatedUrl:
    url: str
    host: str
    port: int
    pinned_ip: ipaddress.IPv4Address | ipaddress.IPv6Address


def validate_url(url: str, *, allow_private: bool = False) -> ValidatedUrl:
    raise NotImplementedError("P2: SSRF URL guard")
