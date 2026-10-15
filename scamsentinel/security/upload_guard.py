"""Upload validation (SECURITY.md T3, M4): size cap, magic-byte allowlist, pixel cap.
Client Content-Type and filename are ignored."""

from __future__ import annotations

ALLOWED_IMAGE_TYPES = ("image/png", "image/jpeg", "image/webp")


class UploadRejected(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def validate_image_upload(data: bytes, *, max_bytes: int, max_pixels: int) -> str:
    """Return the detected MIME type, or raise UploadRejected."""
    raise NotImplementedError("M4: upload guard")
