"""Internal HTTP worker inside the OCR container (internal network only, no egress)."""

from __future__ import annotations

from fastapi import FastAPI, Request

from scamsentinel.api.errors import install_error_handlers
from scamsentinel.ocr.pipeline import OcrResult, ocr_image

app = FastAPI(title="ScamSentinel OCR worker", docs_url=None, redoc_url=None)
install_error_handlers(app)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/ocr")
async def ocr_job(request: Request) -> OcrResult:
    # TODO(M6): cap the body size while streaming instead of buffering it whole.
    return ocr_image(await request.body())
