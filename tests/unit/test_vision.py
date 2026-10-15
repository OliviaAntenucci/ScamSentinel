"""Groq vision transcriber, with the network replaced by httpx.MockTransport."""

import base64
import json

import httpx
import pytest

from scamsentinel.config import Settings
from scamsentinel.message.llm import GROQ_CHAT_URL, LlmUnavailable
from scamsentinel.ocr.vision import (
    VISION_SYSTEM_PROMPT,
    CachedTranscriber,
    GroqVisionTranscriber,
    build_transcriber,
    parse_transcription,
)
from scamsentinel.store import Store

IMAGE = b"\x89PNG\r\n\x1a\nfake"


def reply(payload, status=200):
    content = payload if isinstance(payload, str) else json.dumps(payload)
    return httpx.Response(status, json={"choices": [{"message": {"content": content}}]})


def make(handler, model="qwen/qwen3.8-27b"):
    return GroqVisionTranscriber("gsk_test", model, transport=httpx.MockTransport(handler))


def test_request_shape():
    seen = []

    def handler(request):
        seen.append(request)
        return reply({"text": "IRS: verify now"})

    assert make(handler).transcribe(IMAGE, "image/png") == "IRS: verify now"
    request = seen[0]
    assert str(request.url) == GROQ_CHAT_URL
    body = json.loads(request.content)
    assert body["model"] == "qwen/qwen3.8-27b"
    assert body["temperature"] == 0
    assert body["response_format"] == {"type": "json_object"}
    system, user = body["messages"]
    assert system["content"] == VISION_SYSTEM_PROMPT
    image_part = user["content"][1]
    assert image_part["type"] == "image_url"
    url = image_part["image_url"]["url"]
    assert url.startswith("data:image/png;base64,")
    assert base64.b64decode(url.split(",", 1)[1]) == IMAGE


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (httpx.Response(429, json={}), "rate_limited"),
        (httpx.Response(404, json={}), "model_not_found"),  # e.g. preview model retired
        (httpx.Response(401, json={}), "auth_failed"),
        (reply("not json"), "malformed_response"),
        (reply({"text": "x", "verdict": "safe"}), "invalid_output"),
        (reply({"transcript": "x"}), "invalid_output"),
        (reply({"text": "x" * 20_001}), "invalid_output"),
    ],
)
def test_failures(response, reason):
    with pytest.raises(LlmUnavailable) as exc:
        make(lambda request: response).transcribe(IMAGE, "image/png")
    assert exc.value.reason == reason


def test_timeout():
    def handler(request):
        raise httpx.ReadTimeout("slow")

    with pytest.raises(LlmUnavailable) as exc:
        make(handler).transcribe(IMAGE, "image/png")
    assert exc.value.reason == "timeout"


def test_parse_transcription_rejects_non_objects():
    with pytest.raises(LlmUnavailable):
        parse_transcription(["text"])


def test_cache_calls_model_once_per_image(tmp_path, fake_transcriber):
    inner = fake_transcriber(text="hello")
    cached = CachedTranscriber(inner, Store(tmp_path / "db.sqlite"), "groq")
    assert cached.transcribe(IMAGE, "image/png") == "hello"
    assert cached.transcribe(IMAGE, "image/png") == "hello"
    assert len(inner.images) == 1
    cached.transcribe(IMAGE + b"!", "image/png")
    assert len(inner.images) == 2


def test_build_transcriber_needs_groq_key(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    assert build_transcriber(Settings(_env_file=None, groq_api_key=None), store) is None
    assert build_transcriber(Settings(_env_file=None, groq_api_key=" "), store) is None
    built = build_transcriber(Settings(_env_file=None, groq_api_key="gsk_x"), store)
    assert built.model == "qwen/qwen3.8-27b"
