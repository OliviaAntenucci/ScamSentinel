"""Screenshot OCR (architecture.md §8, M5).

Validate (upload_guard) -> decode -> re-encode PNG (strips metadata and polyglot
payloads) -> Tesseract. Runs in-process; pytesseract runs the tesseract binary as a
separate process with a timeout.
"""

from __future__ import annotations

from pydantic import BaseModel

LOW_CONFIDENCE_THRESHOLD = 60
OCR_TIMEOUT_SECONDS = 15


class OcrResult(BaseModel):
    text: str
    mean_confidence: float


def reencode_png(data: bytes) -> bytes:
    raise NotImplementedError("M5: image re-encode")


def ocr_image(data: bytes) -> OcrResult:
    raise NotImplementedError("M5: OCR")
