"""Egress lock: the last line of defense for page fetching (P2, architecture.md §23).

The URL guard decides which single IP a fetch may connect to. This module makes the
process *enforce* that: inside `only_connect_to(...)`, a Python audit hook checks every
socket name lookup and connection, and anything other than the allowed address and port
raises EgressBlocked before the system call is made. So even if the guard, httpx or a
dependency had a bug (a proxy setting, an unexpected redirect, a second DNS lookup),
nothing else can be reached during a fetch.

Outside the context nothing is restricted, so LLM calls and the CT watcher are
unaffected. The allow-list lives in a ContextVar, so it applies to the current thread
(or async task) only.
"""

from __future__ import annotations

import ipaddress
import sys
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

# (ip, port) pairs the current context may reach; None means unrestricted.
_allowed: ContextVar[frozenset[tuple[str, int]] | None] = ContextVar(
    "scamsentinel_egress_allowed", default=None
)
_install_lock = threading.Lock()
_installed = False

# Lookups that would reveal or reach something by name: never needed during a fetch.
_ALWAYS_BLOCKED = frozenset({"socket.gethostbyname", "socket.gethostbyaddr"})


class EgressBlocked(RuntimeError):
    """A socket operation during a fetch tried to reach a non-allowed destination."""


@contextmanager
def only_connect_to(destinations: Iterable[tuple[str, int]]) -> Iterator[None]:
    """Allow socket lookups and connections only to these (ip, port) pairs."""
    _install()
    allowed = frozenset((_normalize(ip), int(port)) for ip, port in destinations)
    token = _allowed.set(allowed)
    try:
        yield
    finally:
        _allowed.reset(token)


def _install() -> None:
    global _installed
    with _install_lock:
        if not _installed:
            sys.addaudithook(_hook)  # audit hooks can't be removed; it's a no-op when idle
            _installed = True


def _hook(event: str, args: tuple) -> None:
    if not event.startswith("socket."):
        return
    allowed = _allowed.get()
    if allowed is None:
        return
    if event in _ALWAYS_BLOCKED:
        raise EgressBlocked(f"{event} is not allowed during a page fetch")
    if event == "socket.getaddrinfo":
        host, port = args[0], args[1]
        if not _permitted(host, port, allowed):
            raise EgressBlocked(f"name lookup for {host!r} is not allowed during a page fetch")
    elif event in ("socket.connect", "socket.sendto"):
        address = args[1] if event == "socket.connect" else args[-1]
        if not isinstance(address, tuple) or len(address) < 2:
            raise EgressBlocked(f"connection to {address!r} is not allowed during a page fetch")
        if not _permitted(address[0], address[1], allowed):
            raise EgressBlocked(f"connection to {address[0]}:{address[1]} is not allowed")


def _permitted(host: object, port: object, allowed: frozenset[tuple[str, int]]) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", errors="replace")
    try:
        ip = _normalize(str(host))
        port_number = int(port) if port is not None else None
    except (ValueError, TypeError):
        return False  # not an IP literal (a hostname) or a named port: never allowed
    if port_number is None:
        return any(ip == a for a, _ in allowed)
    return (ip, port_number) in allowed


def _normalize(host: str) -> str:
    """Canonical text form of an IP literal; raises ValueError for anything else."""
    return str(ipaddress.ip_address(host.strip("[]").split("%", 1)[0]))
