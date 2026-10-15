FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY scamsentinel ./scamsentinel
RUN pip install ".[ocr]"

RUN useradd --create-home --uid 10002 ocr
USER ocr

EXPOSE 8200
CMD ["uvicorn", "scamsentinel.ocr.worker:app", "--host", "0.0.0.0", "--port", "8200"]
