"""Request guards for the local API (SECURITY.md T4/T5).

- BodySizeLimitMiddleware: 413 for oversized bodies, enforced while streaming.
- require_local_post: blocks cross-site requests from web pages in the user's browser
  (local CSRF). A page can POST to 127.0.0.1 without CORS, but browsers always send an
  Origin header on cross-origin POSTs, and requiring application/json forces a CORS
  preflight that this API never answers.
- RateLimiter: per-client sliding window, so a runaway script can't burn the LLM quota.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from scamsentinel.config import is_loopback_host


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        detail = f"request body larger than {self.max_bytes} bytes"
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                too_large = int(declared) > self.max_bytes
            except ValueError:
                await _error(400, "invalid Content-Length")(scope, receive, send)
                return
            if too_large:
                await _error(413, detail)(scope, receive, send)
                return

        # Chunked bodies (no Content-Length) are counted as they stream in. FastAPI
        # re-raises HTTPExceptions from body reading, so this becomes a clean 413.
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(status_code=413, detail=detail)
            return message

        await self.app(scope, limited_receive, send)


def _error(status: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": detail})


def require_local_post(*allowed_types: str) -> Callable[[Request], None]:
    """Dependency: same-machine Origin (or none) and an allowed Content-Type."""

    def check(request: Request) -> None:
        origin = request.headers.get("origin")
        if origin is not None:
            host = urlsplit(origin).hostname or ""
            if not is_loopback_host(host):
                raise HTTPException(status_code=403, detail="cross-origin request refused")
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type not in allowed_types:
            raise HTTPException(
                status_code=415, detail=f"Content-Type must be one of: {', '.join(allowed_types)}"
            )

    return check


class RateLimiter:
    """Sliding-window limiter: at most `limit` hits per `window` seconds per key."""

    def __init__(
        self, limit: int, window: float = 60.0, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.limit = limit
        self.window = window
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> float | None:
        """Record a hit. Returns seconds to wait if over the limit, else None."""
        now = self._clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return self.window - (now - hits[0])
            hits.append(now)
            return None


def rate_limited(request: Request) -> None:
    """Dependency using the app's RateLimiter, keyed by client address."""
    limiter: RateLimiter = request.app.state.rate_limiter
    client = request.client.host if request.client else "unknown"
    retry_after = limiter.hit(client)
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="too many analyses; slow down",
            headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
        )
