"""FastAPI application factory. API-only, localhost-only (NFR-9)."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scamsentinel import __version__
from scamsentinel.api.errors import install_error_handlers
from scamsentinel.api.guards import BodySizeLimitMiddleware, RateLimiter
from scamsentinel.api.middleware import SecurityHeadersMiddleware
from scamsentinel.api.routes import router
from scamsentinel.config import Settings, get_settings
from scamsentinel.ct.store import CtStore
from scamsentinel.pipeline import AnalysisService

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


def create_app(
    settings: Settings | None = None, service: AnalysisService | None = None
) -> FastAPI:
    settings = settings or get_settings()

    app = FastAPI(title="ScamSentinel", version=__version__)
    app.state.settings = settings
    app.state.service = service or AnalysisService.from_settings(settings)
    # Read-only here: the CT watcher runs as its own process and writes the candidates.
    app.state.ct_store = CtStore(settings.db_path)
    app.state.rate_limiter = RateLimiter(settings.rate_limit_per_minute)

    # Middleware added later wraps earlier ones, so the order below is innermost first.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    # Reject foreign Host headers so a website open in the user's browser can't
    # reach this API via DNS rebinding. No CORS middleware on purpose.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    # Outermost, so it also covers the 400/413 responses from the guards above.
    app.add_middleware(SecurityHeadersMiddleware)

    install_error_handlers(app)
    app.include_router(router)
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def frontend() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    return app
