# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000

# Install minimal OS utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy dependency definition and documentation needed for build
COPY pyproject.toml README.md ./

# Copy application source code and test servers
COPY mcpaudit/ mcpaudit/
COPY test_servers/ test_servers/
COPY run_demo.py .
COPY .env.example .

# Install dependencies and project in editable mode
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-build-isolation -e .

# Create volume mount directories
RUN mkdir -p /app/s3_bucket_storage /app/reports

# Expose Web Dashboard port
EXPOSE 8000

# Health check to verify web server is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/servers || exit 1

# Default command starts the FastAPI Web Dashboard
CMD ["uvicorn", "mcpaudit.web_app:app", "--host", "0.0.0.0", "--port", "8000"]
