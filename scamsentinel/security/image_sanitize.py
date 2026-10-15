"""Byte-level image sanitizing (SECURITY.md T3). No image decoder runs.

Rebuilds PNG / JPEG / WebP files from only the chunks needed to display them:
- metadata is dropped (EXIF incl. GPS, XMP, text chunks, comments, ICC profiles), which
  matters because the image is sent to a third-party vision model;
- everything after the end-of-image marker is dropped, which neutralizes polyglots
  (e.g. a valid PNG with a ZIP archive appended).

Runs after upload_guard.validate_image_upload, so type and size are already known.
"""

from __future__ import annotations

import struct
import zlib

from scamsentinel.security.upload_guard import PNG_SIGNATURE, UploadRejected

# Chunks needed to render a PNG correctly. Text (tEXt/zTXt/iTXt), eXIf, tIME, iCCP and
# any unknown ancillary chunk are dropped.
_PNG_KEEP = frozenset(
    {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND", b"gAMA", b"cHRM", b"sRGB"}
)

# JPEG: drop APP1-APP13 and APP15 (EXIF, XMP, ICC, Photoshop IRB, ...) and COM.
# APP0 (JFIF) and APP14 (Adobe color transform) affect how the image decodes, so they stay.
_JPEG_DROP = frozenset({*range(0xE1, 0xEE), 0xEF, 0xFE})
_JPEG_STANDALONE = frozenset({0x01, *range(0xD0, 0xD8)})

# WebP: keep image data and animation chunks; drop EXIF, XMP and ICCP.
_WEBP_KEEP = frozenset({b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ANIM", b"ANMF"})
_VP8X_METADATA_FLAGS = 0x20 | 0x08 | 0x04  # ICC, EXIF, XMP


def sanitize_image(data: bytes, mime: str) -> bytes:
    try:
        if mime == "image/png":
            return _sanitize_png(data)
        if mime == "image/jpeg":
            return _sanitize_jpeg(data)
        if mime == "image/webp":
            return _sanitize_webp(data)
    except (struct.error, IndexError) as exc:
        raise UploadRejected("malformed_header", "truncated image structure") from exc
    raise UploadRejected("unsupported_type", mime)


def _malformed(detail: str) -> UploadRejected:
    return UploadRejected("malformed_header", detail)


def _sanitize_png(data: bytes) -> bytes:
    out = [PNG_SIGNATURE]
    i = len(PNG_SIGNATURE)
    while i + 8 <= len(data):
        length, chunk_type = struct.unpack(">I4s", data[i : i + 8])
        end = i + 12 + length
        if end > len(data):
            raise _malformed("truncated PNG chunk")
        (crc,) = struct.unpack(">I", data[end - 4 : end])
        if zlib.crc32(data[i + 4 : end - 4]) != crc:
            raise _malformed(f"bad CRC in PNG {chunk_type!r} chunk")
        if chunk_type in _PNG_KEEP:
            out.append(data[i:end])
        if chunk_type == b"IEND":
            return b"".join(out)  # anything after IEND is dropped
        i = end
    raise _malformed("PNG without IEND")


def _sanitize_jpeg(data: bytes) -> bytes:
    out = bytearray(b"\xff\xd8")
    i = 2
    while i + 1 < len(data):
        if data[i] != 0xFF:
            raise _malformed("JPEG marker expected")
        marker = data[i + 1]
        if marker == 0xFF:  # fill byte
            i += 1
            continue
        if marker in _JPEG_STANDALONE:
            out += data[i : i + 2]
            i += 2
            continue
        if marker == 0xD9:
            return bytes(out + b"\xff\xd9")
        (length,) = struct.unpack(">H", data[i + 2 : i + 4])
        segment_end = i + 2 + length
        if length < 2 or segment_end > len(data):
            raise _malformed("bad JPEG segment length")
        if marker == 0xDA:
            # Entropy-coded data stuffs every 0xFF with 0x00, so the first FF D9 after the
            # scan header is the real end of image. Later scans (progressive) are kept.
            eoi = data.find(b"\xff\xd9", segment_end)
            if eoi == -1:
                raise _malformed("JPEG without end-of-image marker")
            return bytes(out + data[i : eoi + 2])  # anything after EOI is dropped
        if marker not in _JPEG_DROP:
            out += data[i:segment_end]
        i = segment_end
    raise _malformed("JPEG without image data")


def _sanitize_webp(data: bytes) -> bytes:
    (riff_size,) = struct.unpack("<I", data[4:8])
    end = 8 + riff_size
    if end > len(data):
        raise _malformed("truncated WebP")
    chunks: list[bytes] = []
    i = 12
    while i < end:
        if i + 8 > end:
            raise _malformed("truncated WebP chunk header")
        chunk_type = data[i : i + 4]
        (size,) = struct.unpack("<I", data[i + 4 : i + 8])
        payload_end = i + 8 + size
        if payload_end > end:
            raise _malformed("truncated WebP chunk")
        padded_end = payload_end + (size & 1)
        if chunk_type in _WEBP_KEEP:
            chunk = bytearray(data[i:payload_end])
            if chunk_type == b"VP8X":
                chunk[8] &= ~_VP8X_METADATA_FLAGS & 0xFF
            if size & 1:
                chunk += b"\x00"
            chunks.append(bytes(chunk))
        i = padded_end
    # Anything after the RIFF end is dropped.
    body = b"WEBP" + b"".join(chunks)
    return b"RIFF" + struct.pack("<I", len(body)) + body
