# Playwright's image ships Chromium + its system deps. The tag must match the
# `playwright` version pinned in pyproject.toml ([project.optional-dependencies].sandbox).
FROM mcr.microsoft.com/playwright/python:v1.49.1-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY scamsentinel ./scamsentinel
# Ubuntu's system Python is "externally managed"; this image is single-purpose.
RUN pip install --break-system-packages ".[sandbox]"

COPY data ./data

# Non-root user provided by the Playwright image. Chromium's own sandbox stays enabled.
USER pwuser

EXPOSE 8100
CMD ["uvicorn", "scamsentinel.sandbox.worker:app", "--host", "0.0.0.0", "--port", "8100"]
