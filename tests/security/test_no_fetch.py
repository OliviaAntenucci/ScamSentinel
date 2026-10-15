"""S1: the MVP never connects to a user-supplied URL (SECURITY.md T1, AC-3).

All socket-level network functions are replaced with tripwires, then every SSRF payload
is analyzed as a URL input and inside a text message. Nothing may try to connect.
"""

import json
import socket
from pathlib import Path

import httpx
import pytest

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.ct.client import CRTSH_URL, CrtShClient
from scamsentinel.ct.watcher import CtWatcher
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.message.llm import GROQ_CHAT_URL, GroqExtractor

PAYLOADS = [
    line.strip()
    for line in (Path(__file__).with_name("ssrf_payloads.txt")).read_text("utf-8").splitlines()
    if line.strip() and not line.startswith("#")
]


@pytest.fixture
def network_tripwire(monkeypatch):
    attempts: list[tuple] = []

    def tripwire(*args, **kwargs):
        attempts.append(args)
        raise AssertionError(f"network access attempted: {args!r}")

    monkeypatch.setattr(socket, "getaddrinfo", tripwire)
    monkeypatch.setattr(socket, "gethostbyname", tripwire)
    monkeypatch.setattr(socket, "create_connection", tripwire)
    monkeypatch.setattr(socket.socket, "connect", tripwire)
    monkeypatch.setattr(socket.socket, "connect_ex", tripwire)
    return attempts


@pytest.mark.parametrize("url", PAYLOADS)
def test_url_input_never_connects(make_service, network_tripwire, url):
    service = make_service()
    try:
        result = service.analyze(AnalyzeRequest(url=url))
    except InvalidHost:
        pass  # rejected as unusable (e.g. file:// or javascript:) without any lookup
    else:
        assert result.modules_run
    assert network_tripwire == []


def test_text_full_of_payloads_never_connects(make_service, network_tripwire):
    text = "IRS notice. Verify at " + " or ".join(PAYLOADS)
    result = make_service().analyze(AnalyzeRequest(text=text[:20_000]))
    assert result.reasons
    assert network_tripwire == []


def test_only_outbound_request_is_to_the_llm_provider(make_service):
    # With an LLM configured, the single outbound request goes to the fixed provider
    # endpoint, never to anything taken from the input.
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        content = json.dumps({"claimed_urls": []})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    llm = GroqExtractor("gsk_test", "openai/gpt-oss-20b", transport=httpx.MockTransport(handler))
    text = "Verify at http://169.254.169.254/latest/meta-data/ and http://127.0.0.1:6379/"
    make_service(llm).analyze(AnalyzeRequest(text=text))
    assert [str(r.url) for r in requests] == [GROQ_CHAT_URL]


def test_ct_watcher_only_contacts_crtsh(settings, network_tripwire):
    # Certificate names are attacker-chosen. The watcher scores them as strings and only
    # ever talks to the fixed crt.sh endpoint, never to the domains it finds.
    requests: list[httpx.Request] = []
    names = "\n".join(
        ["turbotax-refund-secure.com", "*.irs-verify-account.net", "169.254.169.254", *PAYLOADS]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=[{"id": 1, "name_value": names, "issuer_name": "x"}])

    client = CrtShClient(transport=httpx.MockTransport(handler), spacing=0)
    watcher = CtWatcher.from_settings(settings, client=client)
    poll = watcher.poll_once()

    assert poll.new_candidates >= 2
    assert {r.url.host for r in requests} == {httpx.URL(CRTSH_URL).host}
    assert network_tripwire == []
