"""crt.sh client (post-MVP P1). Polite: sequential, spaced, backoff, descriptive UA.

The client only ever talks to the fixed crt.sh endpoint. Certificate names are public but
attacker-chosen, so they're validated as plain hostnames here and are never resolved or
connected to (SECURITY.md T1).
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from typing import Any

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
USER_AGENT = "ScamSentinel-CT-Watcher/0.1 (educational lookalike-domain research)"

# crt.sh is a free community service: one request at a time, at least this far apart.
MIN_REQUEST_SPACING_SECONDS = 10.0
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 30.0
MAX_BACKOFF_SECONDS = 600.0
# Popular tokens return large result sets; anything beyond this is refused, not buffered.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_FIELD_CHARS = 512
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

# Lowercase ASCII hostname (IDNs appear in certificates as punycode). Underscores occur in
# real certificate names, so labels may contain them.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$"
)


class CtUnavailable(Exception):
    """A crt.sh query failed. `reason` is a short stable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class CtEntry(BaseModel):
    cert_id: int
    name: str
    issuer: str
    not_before: str


def normalize_name(raw: str) -> str | None:
    """A certificate name as a bare hostname, or None if it isn't one.

    Wildcards (`*.example.com`) become the domain they cover. Email addresses, IP
    addresses and anything with odd characters are dropped.
    """
    name = raw.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    return name if _HOSTNAME.match(name) else None


def parse_entries(data: Any) -> list[CtEntry]:
    """One entry per (certificate, hostname) from crt.sh's JSON output.

    `name_value` holds every SAN of a certificate, one per line. Malformed rows are skipped.
    """
    if not isinstance(data, list):
        raise CtUnavailable("malformed_response")
    entries: list[CtEntry] = []
    seen: set[tuple[int, str]] = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        cert_id = row.get("id")
        if not isinstance(cert_id, int) or isinstance(cert_id, bool):
            continue
        raw_names = [
            *str(row.get("name_value") or "").splitlines(),
            str(row.get("common_name") or ""),
        ]
        for raw in raw_names:
            name = normalize_name(raw)
            if name is None or (cert_id, name) in seen:
                continue
            seen.add((cert_id, name))
            entries.append(
                CtEntry(
                    cert_id=cert_id,
                    name=name,
                    issuer=str(row.get("issuer_name") or "")[:MAX_FIELD_CHARS],
                    not_before=str(row.get("not_before") or "")[:MAX_FIELD_CHARS],
                )
            )
    return entries


class CrtShClient:
    """Sequential crt.sh searches with request spacing and exponential backoff."""

    def __init__(
        self,
        *,
        timeout: float = 120.0,
        transport: httpx.BaseTransport | None = None,
        spacing: float = MIN_REQUEST_SPACING_SECONDS,
        max_attempts: int = MAX_ATTEMPTS,
        backoff_base: float = BACKOFF_BASE_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = httpx.Client(
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=timeout,
            transport=transport,
            follow_redirects=False,
        )
        self._spacing = spacing
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        self._sleep = sleep
        self._clock = clock
        self._last_request: float | None = None

    def close(self) -> None:
        self._client.close()

    def search(self, pattern: str) -> list[CtEntry]:
        """Certificates (unexpired) whose names match `pattern`, e.g. "%turbotax%".

        Raises CtUnavailable once retries are exhausted or on a non-retryable error.
        """
        params = {"q": pattern, "output": "json", "exclude": "expired", "deduplicate": "Y"}
        for attempt in range(1, self._max_attempts + 1):
            self._wait_turn()
            retry_after: float | None = None
            try:
                status, body, retry_after = self._get(params)
            except httpx.TimeoutException:
                reason = "timeout"
            except httpx.HTTPError:
                reason = "network_error"
            else:
                if status == 200:
                    return parse_entries(_loads(body))
                if status not in RETRYABLE_STATUS:
                    raise CtUnavailable(f"http_{status}")
                reason = f"http_{status}"

            if attempt == self._max_attempts:
                raise CtUnavailable(reason)
            delay = self._backoff(attempt, retry_after)
            logger.info(
                "crt.sh query %r failed (%s), retrying in %.0f s", pattern, reason, delay
            )
            self._sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover

    def _wait_turn(self) -> None:
        if self._last_request is not None:
            wait = self._spacing - (self._clock() - self._last_request)
            if wait > 0:
                self._sleep(wait)
        self._last_request = self._clock()

    def _get(self, params: dict[str, str]) -> tuple[int, bytes, float | None]:
        with self._client.stream("GET", CRTSH_URL, params=params) as response:
            if response.status_code != 200:
                return response.status_code, b"", _retry_after(response)
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise CtUnavailable("response_too_large")
                chunks.append(chunk)
            return 200, b"".join(chunks), None

    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(MAX_BACKOFF_SECONDS, max(retry_after, self._backoff_base))
        return min(MAX_BACKOFF_SECONDS, self._backoff_base * 2 ** (attempt - 1))


def _loads(body: bytes) -> Any:
    if not body.strip():
        return []  # crt.sh sometimes answers "no results" with an empty body
    try:
        return json.loads(body)
    except ValueError as exc:
        raise CtUnavailable("malformed_response") from exc


def _retry_after(response: httpx.Response) -> float | None:
    try:
        seconds = float(response.headers.get("retry-after", ""))
    except ValueError:
        return None
    return seconds if seconds >= 0 else None
