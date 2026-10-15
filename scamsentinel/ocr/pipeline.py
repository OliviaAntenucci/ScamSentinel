"""Decode -> re-encode (strip metadata/polyglots) -> Tesseract (architecture.md §9, M6).
Runs only inside the no-network OCR container."""

from __future__ import annotations

from pydantic import BaseModel

LOW_CONFIDENCE_THRESHOLD = 60


class OcrResult(BaseModel):
    text: str
    mean_confidence: float


def reencode_png(data: bytes) -> bytes:
    raise NotImplementedError("M6: image re-encode")


def ocr_image(data: bytes) -> OcrResult:
    raise NotImplementedError("M6: OCR")
