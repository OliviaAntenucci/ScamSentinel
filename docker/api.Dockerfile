FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY scamsentinel ./scamsentinel
RUN pip install .

COPY config ./config
COPY data ./data

RUN useradd --create-home --uid 10001 app && mkdir -p /app/var && chown app /app/var
USER app

EXPOSE 8000
CMD ["python", "-m", "scamsentinel"]
