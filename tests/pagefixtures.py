"""Mock HTTP responses for the page-fetch tests (P2).

httpx eagerly reads a Response built with `content=`/`text=` (or a ByteStream), so the
fetcher's raw, bounded streaming would find it already consumed. A real network response
is never pre-read; this streams the body in chunks the same way.
"""

import httpx


class ChunkedBody(httpx.SyncByteStream):
    def __init__(self, data: bytes, chunk_size: int = 4096) -> None:
        self._data = data
        self._chunk_size = chunk_size

    def __iter__(self):
        for i in range(0, len(self._data), self._chunk_size):
            yield self._data[i : i + self._chunk_size]


def page_response(
    status: int = 200, headers: dict[str, str] | None = None, body: bytes | str = b""
) -> httpx.Response:
    data = body.encode("utf-8") if isinstance(body, str) else body
    return httpx.Response(status, headers=headers or {}, stream=ChunkedBody(data))
