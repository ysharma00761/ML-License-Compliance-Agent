# ML Inference Service — Dockerfile
# SaaS deployment context: containerized network service
#
# LICENSE VIOLATION CONTEXT:
#   This Dockerfile, combined with ultralytics (AGPL-3.0) in requirements.txt
#   and FastAPI in app.py, confirms SaaS deployment of AGPL-licensed software.
#   The scanner uses the presence of a Dockerfile + AGPL package + FastAPI/uvicorn
#   to escalate the ultralytics finding to CRITICAL severity.

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose inference service port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the FastAPI server
# NOTE: Running ultralytics (AGPL-3.0) as a network service via uvicorn
# triggers AGPL Section 13 source disclosure requirement.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
