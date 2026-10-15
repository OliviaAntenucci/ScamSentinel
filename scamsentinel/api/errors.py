"""Shared exception handlers for the API and the worker apps."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


async def _not_implemented(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=501, content={"detail": f"not implemented yet ({exc})"})


def install_error_handlers(app: FastAPI) -> None:
    # Stubs raise NotImplementedError("M<n>: ...") until their milestone lands.
    app.add_exception_handler(NotImplementedError, _not_implemented)
