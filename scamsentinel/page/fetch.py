"""Lightweight page fetch (P2, architecture.md §23).

One plain GET, like curl, not a browser: nothing on the page runs and nothing else on it
is loaded. Layers of protection, each a fallback for the one before:

  1. mode       "off" (default) never gets here; "dry_run" checks the URL but never
                resolves or connects; only "live" touches the network
  2. URL guard  validate_url(): parse, resolve once, reject non-public addresses, pin
                the IP; every redirect hop goes through it again
  3. egress     only_connect_to(pinned ip, port): an audit hook blocks any other socket
     lock       lookup or connection during the request, whatever the cause
  4. breaker    if the egress lock ever fires, a lower layer failed: live fetching turns
                itself off for the rest of the process
  5. fail       every failure is reported as "not fetched" and the analysis carries on
     closed     with links as strings. Nothing is retried with weaker settings: no
                http after https, no unverified TLS, no second lookup
  plus limits   one deadline per fetch, max_bytes counted after decompression, text/html
                only, no cookies, no environment proxies, and a global rate limit
"""

from __future__ import annotations

import codecs
import logging
import threading
import time
import zlib
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urljoin

import httpx

from scamsentinel import __version__
from scamsentinel.security.egress import EgressBlocked, only_connect_to
from scamsentinel.security.url_guard import (
    ALLOWED_PORTS,
    Resolver,
    UrlRejected,
    system_resolver,
    validate_url,
)

logger = logging.getLogger(__name__)

FetchMode = Literal["dry_run", "live"]
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
HTML_TYPES = ("text/html", "application/xhtml+xml")
# Descriptive, like the CT watcher's. Some phishing kits hide from non-browser clients;
# that's a known limitation (architecture.md §23), not something to disguise.
USER_AGENT = f"ScamSentinel/{__version__} (local scam analyzer; one request per analysis)"
CHUNK_BYTES = 16_384


@dataclass
class FetchedPage:
    requested_url: str
    final_url: str | None = None
    # Every URL after the first, in order.
    redirects: list[str] = field(default_factory=list)
    status_code: int | None = None
    html: str | None = None
    truncated: bool = False
    # Stable code when there's no page to analyze:
    #   dry_run                    URL checks passed; nothing was resolved or fetched
    #   blocked:<guard reason>     the URL guard refused it (e.g. non_public_address)
    #   blocked:egress             the egress lock stopped a socket operation
    #   disabled:safety            the circuit breaker has turned live fetching off
    #   rate_limited, timeout, unreachable, too_many_redirects, http_<status>,
    #   not_html, unsupported_encoding, bad_redirect, failed
    error: str | None = None


class _Deadline(Exception):
    pass


class _UnsupportedEncoding(Exception):
    pass


class _NoResolve(Exception):
    """Raised by the dry-run resolver: a dry run never looks names up."""


def _dry_run_resolver(host: str, port: int) -> list[str]:
    raise _NoResolve(host)


class PageFetcher:
    def __init__(
        self,
        *,
        mode: FetchMode = "dry_run",
        timeout: float = 8.0,
        max_bytes: int = 2_000_000,
        max_redirects: int = 5,
        max_per_minute: int = 20,
        allow_private: bool = False,
        resolver: Resolver = system_resolver,
        allowed_ports: frozenset[int] = ALLOWED_PORTS,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.mode = mode
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._max_redirects = max_redirects
        self._max_per_minute = max_per_minute
        self._allow_private = allow_private
        self._resolver = resolver
        self._allowed_ports = allowed_ports
        self._transport = transport
        self._clock = clock
        self._recent: deque[float] = deque()
        self._lock = threading.Lock()
        self._tripped = False  # circuit breaker

    @property
    def tripped(self) -> bool:
        return self._tripped

    def fetch(self, url: str) -> FetchedPage:
        if self.mode == "dry_run":
            return self._dry_run(url)
        page = FetchedPage(requested_url=url)
        if self._tripped:
            page.error = "disabled:safety"
            return page
        if not self._take_slot():
            page.error = "rate_limited"
            return page
        try:
            return self._fetch(url, page)
        except EgressBlocked as exc:
            # Should be impossible: the guard pinned the address. Something below it
            # misbehaved, so stop fetching altogether rather than trust it again.
            self._tripped = True
            logger.error("egress lock blocked a page fetch; live page fetching disabled: %s", exc)
            page.error = "blocked:egress"
            return page

    # --- modes -------------------------------------------------------------------------

    def _dry_run(self, url: str) -> FetchedPage:
        """Check the URL like a live fetch would, without any DNS lookup or connection."""
        page = FetchedPage(requested_url=url)
        try:
            validate_url(
                url,
                allow_private=self._allow_private,
                resolver=_dry_run_resolver,
                allowed_ports=self._allowed_ports,
            )
        except _NoResolve:
            pass  # a hostname: its addresses would be checked in live mode
        except UrlRejected as exc:
            page.error = f"blocked:{exc.reason}"
            return page
        page.error = "dry_run"
        return page

    def _fetch(self, url: str, page: FetchedPage) -> FetchedPage:
        deadline = self._clock() + self._timeout
        current = url
        with httpx.Client(
            transport=self._transport,
            trust_env=False,  # never use proxy settings from the environment
            follow_redirects=False,  # every hop is validated here instead
            verify=True,  # never relaxed, not even as a fallback
        ) as client:
            for _ in range(self._max_redirects + 1):
                try:
                    target = validate_url(
                        current,
                        allow_private=self._allow_private,
                        resolver=self._resolver,
                        allowed_ports=self._allowed_ports,
                    )
                except UrlRejected as exc:
                    page.error = f"blocked:{exc.reason}"
                    return page
                remaining = deadline - self._clock()
                if remaining <= 0:
                    page.error = "timeout"
                    return page
                headers = {
                    "Host": target.host_header,
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                }
                extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
                client.cookies.clear()  # nothing one hop sets is sent to the next
                try:
                    with (
                        only_connect_to([(str(target.pinned_ip), target.port)]),
                        client.stream(
                            "GET",
                            target.pinned_url,
                            headers=headers,
                            extensions=extensions,
                            timeout=httpx.Timeout(remaining),
                        ) as response,
                    ):
                        page.status_code = response.status_code
                        location = response.headers.get("location")
                        if response.status_code in REDIRECT_STATUSES and location:
                            try:
                                current = urljoin(target.url, location.strip())
                            except ValueError:
                                page.error = "bad_redirect"
                                return page
                            page.redirects.append(current)
                            continue
                        page.final_url = target.url
                        if response.status_code >= 400:
                            page.error = f"http_{response.status_code}"
                            return page
                        content_type = response.headers.get("content-type", "").lower()
                        if not content_type.startswith(HTML_TYPES):
                            page.error = "not_html"
                            return page
                        body, page.truncated = self._read(response, deadline)
                        page.html = body.decode(_charset(response), errors="replace")
                        return page
                except (httpx.TimeoutException, _Deadline):
                    page.error = "timeout"
                    return page
                except _UnsupportedEncoding:
                    page.error = "unsupported_encoding"
                    return page
                except httpx.ConnectError:
                    page.error = "unreachable"  # includes TLS certificate failures
                    return page
                except httpx.HTTPError:
                    page.error = "failed"
                    return page
        page.error = "too_many_redirects"
        return page

    # --- limits ------------------------------------------------------------------------

    def _take_slot(self) -> bool:
        """Global rate limit on live fetches (a sliding one-minute window)."""
        now = self._clock()
        with self._lock:
            while self._recent and now - self._recent[0] >= 60:
                self._recent.popleft()
            if len(self._recent) >= self._max_per_minute:
                return False
            self._recent.append(now)
            return True

    def _read(self, response: httpx.Response, deadline: float) -> tuple[bytes, bool]:
        """At most max_bytes of the decoded body. The decompressor is bounded too, so a
        small gzip "bomb" can't expand past the limit in memory."""
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding in ("", "identity"):
            decompressor = None
        elif encoding in ("gzip", "x-gzip", "deflate"):
            decompressor = zlib.decompressobj(wbits=47)  # gzip or zlib header
        else:
            raise _UnsupportedEncoding(encoding)
        body = bytearray()
        for chunk in response.iter_raw(chunk_size=CHUNK_BYTES):
            if self._clock() > deadline:
                raise _Deadline
            room = self._max_bytes - len(body)
            if decompressor is None:
                body += chunk[: room + 1]
            else:
                try:
                    body += decompressor.decompress(chunk, room + 1)
                except zlib.error:
                    break
                if decompressor.unconsumed_tail:
                    return bytes(body[: self._max_bytes]), True
            if len(body) > self._max_bytes:
                return bytes(body[: self._max_bytes]), True
        return bytes(body), False


def _charset(response: httpx.Response) -> str:
    charset = response.charset_encoding or "utf-8"
    try:
        codecs.lookup(charset)
    except LookupError:
        return "utf-8"
    return charset
