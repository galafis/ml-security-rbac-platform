# ML Security RBAC Platform - Dockerfile
# Author: Gabriel Demetrios Lafis

FROM python:3.12-slim AS base

LABEL maintainer="Gabriel Demetrios Lafis <gabriel.lafis@gmail.com>"
LABEL description="ML Security RBAC Platform"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY src/ src/
COPY main.py .
COPY config/ config/

# Create data directory
RUN mkdir -p /app/data /app/logs

# Non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "src.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
