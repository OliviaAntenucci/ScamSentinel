"""FastAPI application factory. API-only, localhost-only (NFR-9)."""

from __future__ import annotations

from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scamsentinel import __version__
from scamsentinel.api.errors import install_error_handlers
from scamsentinel.api.middleware import SecurityHeadersMiddleware
from scamsentinel.api.routes import router
from scamsentinel.config import Settings, get_settings
from scamsentinel.pipeline import AnalysisService


def create_app(
    settings: Settings | None = None, service: AnalysisService | None = None
) -> FastAPI:
    settings = settings or get_settings()

    app = FastAPI(title="ScamSentinel", version=__version__)
    app.state.settings = settings
    app.state.service = service or AnalysisService.from_settings(settings)

    # Reject foreign Host headers so a website open in the user's browser can't
    # reach this API via DNS rebinding. No CORS middleware on purpose.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    # Added last so it is outermost and also covers TrustedHost's 400 responses.
    app.add_middleware(SecurityHeadersMiddleware)

    install_error_handlers(app)
    app.include_router(router)
    return app
