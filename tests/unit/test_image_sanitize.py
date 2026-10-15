"""Byte-level image sanitizing: metadata and polyglot payloads are removed, no decoding."""

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st
from imagefixtures import (
    PNG_SIGNATURE,
    ZIP_SIGNATURE,
    jpeg,
    jpeg_segment,
    png,
    png_chunk,
    riff_chunk,
    webp,
)

from scamsentinel.security.image_sanitize import sanitize_image
from scamsentinel.security.upload_guard import UploadRejected, validate_image_upload

GPS = b"GPSLatitude 37.7749 N GPSLongitude 122.4194 W"
EXIF = b"Exif\x00\x00MM\x00*" + GPS
ZIP_PAYLOAD = ZIP_SIGNATURE + b"\x14\x00evil.html<script>alert(1)</script>"


def png_chunk_types(data: bytes) -> list[bytes]:
    types, i = [], len(PNG_SIGNATURE)
    while i < len(data):
        (length,) = struct.unpack(">I", data[i : i + 4])
        types.append(data[i + 4 : i + 8])
        i += 12 + length
    return types


# --- PNG ----------------------------------------------------------------------------------


def test_png_metadata_and_trailing_payload_removed():
    original = (
        png(
            extra_chunks=[
                png_chunk(b"tEXt", b"Comment\x00" + GPS),
                png_chunk(b"eXIf", EXIF),
                png_chunk(b"tIME", b"\x07\xea\x0a\x0e\x00\x00\x00"),
                png_chunk(b"iCCP", b"profile\x00\x00data"),
            ]
        )
        + ZIP_PAYLOAD  # polyglot: a valid PNG that is also a ZIP archive
    )
    clean = sanitize_image(original, "image/png")
    assert png_chunk_types(clean) == [b"IHDR", b"IDAT", b"IEND"]
    assert GPS not in clean
    assert ZIP_SIGNATURE not in clean
    assert clean.endswith(png_chunk(b"IEND", b""))


def test_png_clean_file_is_unchanged():
    assert sanitize_image(png(), "image/png") == png()


@pytest.mark.parametrize(
    "data",
    [
        png()[:-12],  # IEND missing
        png()[:40],  # truncated chunk
        png().replace(b"IDAT", b"IDAX"),  # CRC no longer matches
    ],
)
def test_png_malformed_rejected(data):
    with pytest.raises(UploadRejected) as exc:
        sanitize_image(data, "image/png")
    assert exc.value.reason == "malformed_header"


# --- JPEG -----------------------------------------------------------------------------------


def test_jpeg_metadata_and_trailing_payload_removed():
    original = (
        jpeg(
            extra_segments=[
                jpeg_segment(0xE1, EXIF),  # APP1 EXIF
                jpeg_segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta/>"),  # XMP
                jpeg_segment(0xE2, b"ICC_PROFILE\x00\x01\x01data"),
                jpeg_segment(0xFE, b"comment: " + GPS),
            ]
        )
        + ZIP_PAYLOAD
    )
    clean = sanitize_image(original, "image/jpeg")
    assert clean == jpeg()
    assert GPS not in clean
    assert ZIP_SIGNATURE not in clean


def test_jpeg_keeps_adobe_segment():
    adobe = jpeg_segment(0xEE, b"Adobe\x00\x64\x00\x00\x00\x00\x01")
    assert adobe in sanitize_image(jpeg(extra_segments=[adobe]), "image/jpeg")


@pytest.mark.parametrize(
    "data",
    [
        jpeg()[:-2],  # no end-of-image marker
        b"\xff\xd8\xff\xe0\x00\x01",  # bad segment length
        b"\xff\xd8\x00\x00",  # not a marker
        b"\xff\xd8",  # nothing at all
    ],
)
def test_jpeg_malformed_rejected(data):
    with pytest.raises(UploadRejected):
        sanitize_image(data, "image/jpeg")


# --- WebP -----------------------------------------------------------------------------------


def test_webp_metadata_chunks_and_flags_removed():
    metadata_flags = 0x20 | 0x08 | 0x04
    original = (
        webp(
            flags=metadata_flags | 0x10,  # + alpha flag, which must survive
            extra=[
                riff_chunk(b"ICCP", b"profile"),
                riff_chunk(b"EXIF", EXIF),
                riff_chunk(b"XMP ", b"<x:xmpmeta/>"),
            ],
        )
        + ZIP_PAYLOAD
    )
    clean = sanitize_image(original, "image/webp")
    assert GPS not in clean
    assert ZIP_SIGNATURE not in clean
    assert b"EXIF" not in clean and b"XMP " not in clean and b"ICCP" not in clean
    assert clean[20] == 0x10  # VP8X flags: metadata bits cleared, alpha kept
    (riff_size,) = struct.unpack("<I", clean[4:8])
    assert riff_size == len(clean) - 8
    assert validate_image_upload(clean, max_bytes=10**6, max_pixels=10**6).width == 64


def test_webp_truncated_rejected():
    data = webp()
    with pytest.raises(UploadRejected):
        sanitize_image(data[:-4], "image/webp")


# --- general --------------------------------------------------------------------------------


def test_unsupported_type_rejected():
    with pytest.raises(UploadRejected):
        sanitize_image(b"GIF89a", "image/gif")


@given(st.sampled_from([png(), jpeg(), webp()]), st.integers(0, 200), st.binary(max_size=64))
def test_mangled_files_never_crash(base, cut, garbage):
    data = base[: max(12, len(base) - cut)] + garbage
    mime = {b"\x89P": "image/png", b"\xff\xd8": "image/jpeg", b"RI": "image/webp"}[base[:2]]
    try:
        sanitize_image(data, mime)
    except UploadRejected:
        pass
