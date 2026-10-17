"""SSRF guard (SECURITY.md T1, architecture.md §23). Used by the page fetcher (P2).

validate_url():
  strict parse   http/https only, ports 80/443, no userinfo, valid IDNA hostname
  IP literal     including legacy forms (2852039166, 0xA9FEA9FE, 0251.0376.0251.0376,
                 127.1), which are parsed here instead of being left to the OS resolver
  resolve        every A/AAAA address of the hostname, once
  check          reject if ANY address isn't globally routable (private, loopback,
                 link-local such as 169.254.169.254, CGNAT, multicast, reserved,
                 IPv4-mapped IPv6 of any of those)
  pin            return the checked IP, so the caller connects to exactly what was
                 checked: no second DNS lookup, so no DNS rebinding

Redirects are the caller's job: every hop must go through validate_url() again.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import idna

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})
DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_URL_LENGTH = 2_048

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
# hostname, port -> the addresses it resolves to (strings, as getaddrinfo returns them).
Resolver = Callable[[str, int], Iterable[str]]


class UrlRejected(ValueError):
    """Raised when a URL must not be fetched. `reason` is a stable code for logs/tests."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class ValidatedUrl:
    url: str  # normalized: ASCII (IDNA) host, no userinfo, no fragment
    scheme: str
    host: str  # ASCII hostname, or the IP literal
    port: int
    path: str  # path + query, at least "/"
    pinned_ip: IPAddress

    @property
    def pinned_url(self) -> str:
        """The URL with the checked IP in place of the hostname: what to connect to."""
        ip = f"[{self.pinned_ip}]" if self.pinned_ip.version == 6 else str(self.pinned_ip)
        netloc = ip if self.port == DEFAULT_PORTS[self.scheme] else f"{ip}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path}"

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == DEFAULT_PORTS[self.scheme] else f"{host}:{self.port}"


def system_resolver(host: str, port: int) -> list[str]:
    """Every address the system resolver returns for host (IPv4 and IPv6)."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise UrlRejected("dns_failed", host) from exc
    # IPv6 link-local results can carry a scope id ("fe80::1%3"); the address is what matters.
    return [str(info[4][0]).split("%", 1)[0] for info in infos]


def validate_url(
    url: str,
    *,
    allow_private: bool = False,
    resolver: Resolver = system_resolver,
    allowed_ports: frozenset[int] = ALLOWED_PORTS,
) -> ValidatedUrl:
    """Check a URL and resolve it to one pinned, globally routable IP.

    `allow_private` (tests and local fixtures only; refused in production by the
    settings) skips the address check. `allowed_ports` is for local test servers.
    """
    if not isinstance(url, str) or len(url) > MAX_URL_LENGTH:
        raise UrlRejected("invalid_url", "too long")
    if any(c.isspace() or ord(c) < 0x20 for c in url.strip()):
        raise UrlRejected("invalid_url", "whitespace or control characters")
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise UrlRejected("invalid_url", str(exc)) from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlRejected("scheme_not_allowed", scheme or "(none)")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise UrlRejected("userinfo_not_allowed")
    if port is None:
        port = DEFAULT_PORTS[scheme]
    if port not in allowed_ports:
        raise UrlRejected("port_not_allowed", str(port))

    raw_host = (parts.hostname or "").rstrip(".")
    if not raw_host:
        raise UrlRejected("invalid_host", "empty")

    literal = _ip_literal(raw_host)
    if literal is not None:
        host = str(literal)
        addresses: list[IPAddress] = [literal]
    else:
        host = _ascii_host(raw_host)
        addresses = [_parse_resolved(a) for a in resolver(host, port)]
        if not addresses:
            raise UrlRejected("dns_failed", host)

    if not allow_private:
        for address in addresses:
            if not is_public(address):
                raise UrlRejected("non_public_address", f"{host} -> {address}")

    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"
    netloc_host = f"[{host}]" if literal is not None and literal.version == 6 else host
    netloc = netloc_host if port == DEFAULT_PORTS[scheme] else f"{netloc_host}:{port}"
    return ValidatedUrl(
        url=urlunsplit((scheme, netloc, parts.path or "/", parts.query, "")),
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        pinned_ip=addresses[0],
    )


def is_public(address: IPAddress) -> bool:
    """Globally routable unicast only. IPv4-mapped/compatible IPv6 is judged by its IPv4."""
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped or _ipv4_compatible(address)
        if mapped is not None:
            return is_public(mapped)
        if address.sixtofour is not None or address.teredo is not None:
            return False  # tunnels to an arbitrary IPv4 address
    return address.is_global and not address.is_multicast


def _ipv4_compatible(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    # ::a.b.c.d (deprecated, but still parsed by some stacks)
    if int(address) >> 32 == 0 and int(address) > 1:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def _parse_resolved(value: str) -> IPAddress:
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise UrlRejected("dns_failed", f"unexpected address {value!r}") from exc


def _ascii_host(host: str) -> str:
    try:
        ascii_host = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise UrlRejected("invalid_host", host) from exc
    if len(ascii_host) > 253:
        raise UrlRejected("invalid_host", "too long")
    return ascii_host.lower()


def _ip_literal(host: str) -> IPAddress | None:
    """The host as an IP address, if it is one, including the legacy IPv4 forms that
    inet_aton accepts (decimal integer, octal and hex parts, fewer than four parts)."""
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(_numeric(p) for p in parts):
        return None
    values = [_number(p) for p in parts]
    *head, last = values
    if any(v > 0xFF for v in head) or last >= 256 ** (5 - len(values)):
        raise UrlRejected("invalid_host", f"malformed IPv4 address {host!r}")
    number = 0
    for v in head:
        number = number << 8 | v
    number = number << 8 * (5 - len(values)) | last
    return ipaddress.IPv4Address(number)


def _numeric(part: str) -> bool:
    p = part.lower()
    if p.startswith("0x"):
        return len(p) > 2 and all(c in "0123456789abcdef" for c in p[2:])
    return p.isdigit()


def _number(part: str) -> int:
    p = part.lower()
    if p.startswith("0x"):
        return int(p, 16)
    if len(p) > 1 and p.startswith("0"):
        return int(p, 8) if all(c in "01234567" for c in p) else _bad_octal(part)
    return int(p)


def _bad_octal(part: str) -> int:
    raise UrlRejected("invalid_host", f"malformed octal part {part!r}")
