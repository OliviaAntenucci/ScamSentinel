"""S3: malicious uploads (SECURITY.md T3, AC-5). Enabled when the upload guard lands in M4."""

import pytest

from scamsentinel.security.upload_guard import UploadRejected, validate_image_upload

pytestmark = pytest.mark.skip(reason="M4: upload guard not implemented yet")

LIMITS = {"max_bytes": 5 * 1024 * 1024, "max_pixels": 25_000_000}


@pytest.mark.parametrize(
    "data",
    [
        b"MZ\x90\x00" + b"\x00" * 64,  # Windows executable
        b"<html><script>alert(1)</script></html>",
        b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        b"%PDF-1.7\n",
        b"PK\x03\x04" + b"\x00" * 64,  # ZIP
        b"",
    ],
)
def test_wrong_magic_bytes_rejected(data):
    with pytest.raises(UploadRejected):
        validate_image_upload(data, **LIMITS)


def test_oversized_upload_rejected():
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * (6 * 1024 * 1024)
    with pytest.raises(UploadRejected):
        validate_image_upload(data, **LIMITS)


def test_decompression_bomb_rejected():
    raise NotImplementedError("M4: tiny PNG with a huge IHDR width/height")


def test_polyglot_png_zip_neutralized_by_reencode():
    raise NotImplementedError("M5: re-encoded bytes contain no ZIP signature")


def test_exif_gps_stripped():
    raise NotImplementedError("M5: re-encoded image has no EXIF")


def test_upload_never_written_under_client_filename():
    raise NotImplementedError("M5: ../../etc/passwd.png is never used as a path")


def test_ocr_timeout_returns_degraded():
    raise NotImplementedError("M5: tesseract killed after OCR_TIMEOUT_SECONDS -> degraded")
