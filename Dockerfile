# Multi-stage Dockerfile for CyberMemory AI
FROM python:3.11-slim AS base

# Install system dependencies & security updates
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Create non-root user for cybersecurity least-privilege compliance
RUN groupadd -r cybersec && useradd -r -g cybersec cybersec

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source tree and data
COPY cybermemory/ /app/cybermemory/
COPY data/ /app/data/
COPY tests/ /app/tests/

# Set ownership to non-root user
RUN chown -R cybersec:cybersec /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=5000 \
    OPERATIONAL_MODE=READ_ONLY_ANALYSIS

# Switch to non-root user
USER cybersec

# Healthcheck definition
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/api/health || exit 1

EXPOSE 5000

# Run Flask backend via Gunicorn WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "cybermemory.api.app:create_app()"]

