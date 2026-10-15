"""Run the API: `python -m scamsentinel` (listens on 127.0.0.1:8000 by default)."""

import uvicorn

from scamsentinel.config import get_settings


def main() -> None:
    settings = get_settings()  # refuses non-loopback hosts unless explicitly allowed
    uvicorn.run(
        "scamsentinel.api.app:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
