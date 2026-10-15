"""S3: malicious uploads (SECURITY.md T3, AC-5)."""

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st
from imagefixtures import EXIF_SAMPLE, ZIP_SIGNATURE, jpeg_segment
from imagefixtures import jpeg as fixture_jpeg
from imagefixtures import png as fixture_png

from scamsentinel.ocr.vision import OcrUnavailable
from scamsentinel.security.image_sanitize import sanitize_image
from scamsentinel.security.upload_guard import (
    PNG_SIGNATURE,
    ImageInfo,
    UploadRejected,
    validate_image_upload,
)

LIMITS = {"max_bytes": 5 * 1024 * 1024, "max_pixels": 25_000_000}


def png(width: int, height: int) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return PNG_SIGNATURE + struct.pack(">I", 13) + b"IHDR" + ihdr + b"\x00" * 4


def jpeg(width: int, height: int) -> bytes:
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00" + b"\x01\x01\x00" + b"\x00" * 6
    sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 17, 8, height, width, 3) + b"\x00" * 9
    return b"\xff\xd8" + app0 + sof0 + b"\xff\xd9"


def _riff(chunk: bytes) -> bytes:
    return b"RIFF" + struct.pack("<I", 4 + len(chunk)) + b"WEBP" + chunk


def webp_lossy(width: int, height: int) -> bytes:
    frame = b"\x00\x00\x00" + b"\x9d\x01\x2a" + struct.pack("<HH", width, height)
    return _riff(b"VP8 " + struct.pack("<I", len(frame)) + frame)


def webp_lossless(width: int, height: int) -> bytes:
    bits = (width - 1) | ((height - 1) << 14)
    return _riff(b"VP8L" + struct.pack("<I", 5) + b"\x2f" + struct.pack("<I", bits))


def webp_extended(width: int, height: int) -> bytes:
    body = b"\x00" * 4 + (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")
    return _riff(b"VP8X" + struct.pack("<I", len(body)) + body)


# --- accepted ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "mime"),
    [
        (png(800, 600), "image/png"),
        (jpeg(800, 600), "image/jpeg"),
        (webp_lossy(800, 600), "image/webp"),
        (webp_lossless(800, 600), "image/webp"),
        (webp_extended(800, 600), "image/webp"),
    ],
)
def test_valid_headers_accepted(data, mime):
    assert validate_image_upload(data, **LIMITS) == ImageInfo(mime, 800, 600)


# --- rejected ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b"MZ\x90\x00" + b"\x00" * 64,  # Windows executable
        b"<html><script>alert(1)</script></html>",
        b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        b"%PDF-1.7\n",
        b"PK\x03\x04" + b"\x00" * 64,  # ZIP
        b"GIF89a" + b"\x00" * 64,  # real image, but not on the allowlist
    ],
)
def test_wrong_magic_bytes_rejected(data):
    # The client's Content-Type and filename are never consulted.
    with pytest.raises(UploadRejected) as exc:
        validate_image_upload(data, **LIMITS)
    assert exc.value.reason == "unsupported_type"


def test_empty_upload_rejected():
    with pytest.raises(UploadRejected) as exc:
        validate_image_upload(b"", **LIMITS)
    assert exc.value.reason == "empty"


def test_oversized_upload_rejected():
    data = png(10, 10) + b"\x00" * (6 * 1024 * 1024)
    with pytest.raises(UploadRejected) as exc:
        validate_image_upload(data, **LIMITS)
    assert exc.value.reason == "too_large"


@pytest.mark.parametrize(
    "bomb",
    [
        png(100_000, 100_000),  # ~60 bytes on disk, 10 billion pixels decoded
        jpeg(65_535, 65_535),
        webp_lossless(16_384, 16_384),
        webp_extended(16_384, 16_384),
        webp_lossy(16_383, 16_383),
    ],
)
def test_decompression_bombs_rejected_before_decoding(bomb):
    assert len(bomb) < 200
    with pytest.raises(UploadRejected) as exc:
        validate_image_upload(bomb, **LIMITS)
    assert exc.value.reason == "too_many_pixels"


@pytest.mark.parametrize(
    "data",
    [
        PNG_SIGNATURE + b"\x00\x00",  # truncated
        PNG_SIGNATURE + struct.pack(">I", 13) + b"tEXt" + b"\x00" * 20,  # IHDR not first
        png(0, 600),  # zero width
        b"\xff\xd8\xff",  # truncated JPEG
        b"\xff\xd8\xff\xe0\x00\x01",  # JPEG segment length < 2
        b"\xff\xd8\xff\xda\x00\x08" + b"\x00" * 16,  # scan before any frame header
        b"\xff\xd8\xff\xe0\x00\x04\x00\x00" + b"\x00" * 32,  # no marker after a segment
        _riff(b"VP8 " + b"\x00" * 16),  # bad VP8 start code
        _riff(b"VP8L" + b"\x00" * 4 + b"\x00" * 5),  # bad VP8L signature
        _riff(b"VP8X" + b"\x00" * 6),  # truncated VP8X
        _riff(b"ABCD" + b"\x00" * 16),  # unknown WebP chunk
    ],
)
def test_malformed_headers_rejected(data):
    with pytest.raises(UploadRejected) as exc:
        validate_image_upload(data, **LIMITS)
    assert exc.value.reason == "malformed_header"


@given(
    st.sampled_from([PNG_SIGNATURE, b"\xff\xd8\xff", b"RIFF\x00\x00\x00\x00WEBP"]),
    st.binary(max_size=200),
)
def test_arbitrary_bytes_never_crash(prefix, tail):
    try:
        info = validate_image_upload(prefix + tail, **LIMITS)
    except UploadRejected:
        return
    assert info.width > 0
    assert info.height > 0
    assert info.width * info.height <= LIMITS["max_pixels"]


# --- after validation: sanitizing and transcription (M5) ---------------------------------


def test_polyglot_png_zip_neutralized():
    data = fixture_png() + ZIP_SIGNATURE + b"\x14\x00evil.html<script>alert(1)</script>"
    assert ZIP_SIGNATURE not in sanitize_image(data, "image/png")


def test_exif_gps_stripped():
    data = fixture_jpeg(extra_segments=[jpeg_segment(0xE1, EXIF_SAMPLE)])
    assert b"GPS" not in sanitize_image(data, "image/jpeg")


def test_vision_timeout_is_an_error_not_a_verdict(make_service, fake_transcriber):
    service = make_service(transcriber=fake_transcriber(error="timeout"))
    with pytest.raises(OcrUnavailable) as exc:
        service.analyze_image(fixture_png())
    assert exc.value.reason == "timeout"
