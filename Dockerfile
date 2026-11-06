# CyberMemory AI dashboard and API image
FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

RUN groupadd -r cybersec && useradd -r -g cybersec cybersec

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py streamlit_app.py ./
COPY cybermemory/ ./cybermemory/
COPY data/ ./data/
COPY static/ ./static/
COPY templates/ ./templates/
COPY tests/ ./tests/

RUN chown -R cybersec:cybersec /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=5000 \
    OPERATIONAL_MODE=READ_ONLY_ANALYSIS

USER cybersec

EXPOSE 5000

# The dashboard is the default entrypoint; Compose overrides this for the API.
CMD ["python", "app.py"]
