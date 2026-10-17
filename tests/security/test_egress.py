"""S10: egress lock (architecture.md §23). During a page fetch, the process may only look
up or connect to the one checked IP and port.

These tests raise the same audit events a real socket would (sys.audit), so they
exercise the installed hook without creating any socket: nothing here touches the network.
"""

import sys

import pytest

from scamsentinel.security.egress import EgressBlocked, only_connect_to

PINNED = ("93.184.216.34", 443)


def connect(host, port):
    sys.audit("socket.connect", None, (host, port))


def lookup(host, port):
    sys.audit("socket.getaddrinfo", host, port, 0, 0, 0)


def test_the_pinned_address_is_allowed():
    with only_connect_to([PINNED]):
        lookup("93.184.216.34", 443)
        connect("93.184.216.34", 443)


@pytest.mark.parametrize(
    "destination",
    [
        ("169.254.169.254", 80),  # cloud metadata
        ("127.0.0.1", 443),  # loopback
        ("10.0.0.1", 443),  # private
        ("93.184.216.34", 22),  # right IP, wrong port
        ("93.184.216.35", 443),  # a different public IP
    ],
)
def test_any_other_connection_is_blocked(destination):
    with only_connect_to([PINNED]), pytest.raises(EgressBlocked):
        connect(*destination)


@pytest.mark.parametrize("host", ["example.com", "attacker.example", b"rebind.example"])
def test_name_lookups_are_blocked(host):
    # A fetch connects to an IP literal; a lookup by name would be a second DNS query
    # (the rebinding hole), so it's refused.
    with only_connect_to([PINNED]), pytest.raises(EgressBlocked):
        lookup(host, 443)


def test_reverse_and_legacy_lookups_are_blocked():
    with only_connect_to([PINNED]), pytest.raises(EgressBlocked):
        sys.audit("socket.gethostbyname", "example.com")


def test_ipv6_forms_are_compared_canonically():
    with only_connect_to([("2606:2800:220:1::1", 443)]):
        connect("2606:2800:0220:0001:0000:0000:0000:0001", 443)
        with pytest.raises(EgressBlocked):
            connect("::1", 443)


def test_unix_sockets_are_blocked_during_a_fetch():
    with only_connect_to([PINNED]), pytest.raises(EgressBlocked):
        sys.audit("socket.connect", None, "/var/run/docker.sock")


def test_nothing_is_restricted_outside_a_fetch():
    # LLM calls and the CT watcher run outside the lock.
    connect("127.0.0.1", 8000)
    lookup("api.groq.com", 443)


def test_the_lock_is_released_after_an_error():
    with pytest.raises(EgressBlocked), only_connect_to([PINNED]):
        connect("10.0.0.1", 80)
    connect("10.0.0.1", 80)  # no longer inside a fetch
