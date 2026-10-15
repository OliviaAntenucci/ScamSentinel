"""Response hardening applied to every API response (SECURITY.md T5)."""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


# Strict CSP for the bundled frontend: same-origin scripts, styles and API calls only;
# screenshot previews use blob: URLs. Not applied to /docs, whose Swagger UI loads from
# a CDN and serves JSON-only API responses anyway.
FRONTEND_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def _is_frontend(path: str) -> bool:
    return path == "/" or path.startswith("/static/")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                if _is_frontend(scope["path"]):
                    headers["Content-Security-Policy"] = FRONTEND_CSP
            await send(message)

        await self.app(scope, receive, send_with_headers)
