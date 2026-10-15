"""Hand-built image files for tests. Valid structure (chunk CRCs, markers, RIFF sizes)
without needing an image library; the pixel data itself is never decoded."""

import struct
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ZIP_SIGNATURE = b"PK\x03\x04"
EXIF_SAMPLE = b"Exif\x00\x00MM\x00*GPSLatitude 37.7749 N GPSLongitude 122.4194 W"


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data)
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def png(width: int = 64, height: int = 32, *, extra_chunks: list[bytes] = ()) -> bytes:
    ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    idat = png_chunk(b"IDAT", zlib.compress(b"\x00" * 16))
    return PNG_SIGNATURE + ihdr + b"".join(extra_chunks) + idat + png_chunk(b"IEND", b"")


def jpeg(width: int = 64, height: int = 32, *, extra_segments: list[bytes] = ()) -> bytes:
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00" + b"\x00" * 6
    sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 17, 8, height, width, 3) + b"\x00" * 9
    sos = b"\xff\xda" + struct.pack(">H", 12) + b"\x03" + b"\x00" * 9
    scan = b"\x12\x34\xff\x00\x56"  # entropy-coded data with a stuffed 0xFF
    return b"\xff\xd8" + app0 + b"".join(extra_segments) + sof0 + sos + scan + b"\xff\xd9"


def jpeg_segment(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def riff_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    pad = b"\x00" if len(payload) % 2 else b""
    return chunk_type + struct.pack("<I", len(payload)) + payload + pad


def webp(width: int = 64, height: int = 32, *, flags: int = 0, extra: list[bytes] = ()) -> bytes:
    vp8x = riff_chunk(
        b"VP8X",
        bytes([flags, 0, 0, 0])
        + (width - 1).to_bytes(3, "little")
        + (height - 1).to_bytes(3, "little"),
    )
    vp8l = riff_chunk(
        b"VP8L", b"\x2f" + struct.pack("<I", (width - 1) | ((height - 1) << 14)) + b"\x00"
    )
    body = b"WEBP" + vp8x + b"".join(extra) + vp8l
    return b"RIFF" + struct.pack("<I", len(body)) + body
