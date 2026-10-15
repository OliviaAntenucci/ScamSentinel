"""Upload validation (SECURITY.md T3): size cap, magic-byte allowlist, pixel cap.

Everything here reads raw header bytes only. Width and height come straight from the
PNG/JPEG/WebP headers, so a decompression bomb is rejected before any image decoder
runs. The client's Content-Type and filename are never consulted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ALLOWED_IMAGE_TYPES = ("image/png", "image/jpeg", "image/webp")

# JPEG start-of-frame markers (they carry the image size). C4, C8 and CC are not frames.
_JPEG_SOF = frozenset(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}
# Markers without a length field.
_JPEG_STANDALONE = frozenset({0x01, *range(0xD0, 0xD8)})


class UploadRejected(ValueError):
    """`reason` is a stable code: empty, too_large, unsupported_type, malformed_header,
    too_many_pixels."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class ImageInfo:
    mime: str
    width: int
    height: int


def sniff_image_type(data: bytes) -> str | None:
    if data.startswith(PNG_SIGNATURE):
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def validate_image_upload(data: bytes, *, max_bytes: int, max_pixels: int) -> ImageInfo:
    """Return the detected type and size, or raise UploadRejected."""
    if not data:
        raise UploadRejected("empty")
    if len(data) > max_bytes:
        raise UploadRejected("too_large", f"{len(data)} bytes > {max_bytes}")
    mime = sniff_image_type(data)
    if mime is None:
        raise UploadRejected("unsupported_type", "only PNG, JPEG and WebP are accepted")
    try:
        width, height = _dimensions(data, mime)
    except (struct.error, IndexError) as exc:
        raise UploadRejected("malformed_header", "truncated image header") from exc
    if width <= 0 or height <= 0:
        raise UploadRejected("malformed_header", f"invalid size {width}x{height}")
    if width * height > max_pixels:
        raise UploadRejected("too_many_pixels", f"{width}x{height} > {max_pixels} pixels")
    return ImageInfo(mime, width, height)


def _dimensions(data: bytes, mime: str) -> tuple[int, int]:
    if mime == "image/png":
        return _png_dimensions(data)
    if mime == "image/jpeg":
        return _jpeg_dimensions(data)
    return _webp_dimensions(data)


def _png_dimensions(data: bytes) -> tuple[int, int]:
    # IHDR must be the first chunk: length(4) "IHDR"(4) width(4) height(4).
    if data[12:16] != b"IHDR":
        raise UploadRejected("malformed_header", "PNG without a leading IHDR chunk")
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def _jpeg_dimensions(data: bytes) -> tuple[int, int]:
    i = 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            raise UploadRejected("malformed_header", "JPEG marker expected")
        marker = data[i + 1]
        if marker == 0xFF:  # fill byte
            i += 1
            continue
        if marker in _JPEG_STANDALONE:
            i += 2
            continue
        if marker in (0xD9, 0xDA):  # end of image / start of scan before any frame
            break
        (length,) = struct.unpack(">H", data[i + 2 : i + 4])
        if length < 2:
            raise UploadRejected("malformed_header", "bad JPEG segment length")
        if marker in _JPEG_SOF:
            height, width = struct.unpack(">HH", data[i + 5 : i + 9])
            return width, height
        i += 2 + length
    raise UploadRejected("malformed_header", "JPEG without a frame header")


def _webp_dimensions(data: bytes) -> tuple[int, int]:
    chunk = data[12:16]
    if chunk == b"VP8 ":  # lossy: 3-byte frame tag, start code 9d 01 2a, then sizes
        if data[23:26] != b"\x9d\x01\x2a":
            raise UploadRejected("malformed_header", "bad VP8 start code")
        width, height = struct.unpack("<HH", data[26:30])
        return width & 0x3FFF, height & 0x3FFF
    if chunk == b"VP8L":  # lossless: signature 0x2f, then 14-bit (size - 1) fields
        if data[20] != 0x2F:
            raise UploadRejected("malformed_header", "bad VP8L signature")
        (bits,) = struct.unpack("<I", data[21:25])
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if chunk == b"VP8X":  # extended: 24-bit (size - 1) fields
        if len(data) < 30:
            raise UploadRejected("malformed_header", "truncated VP8X header")
        width = int.from_bytes(data[24:27], "little") + 1
        height = int.from_bytes(data[27:30], "little") + 1
        return width, height
    raise UploadRejected("malformed_header", "unknown WebP chunk")
