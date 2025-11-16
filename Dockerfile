# Dockerfile for Agape V1 (login.py legacy backend)
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY login.py .
COPY client_secret.json* ./

# Expose port 5002 (internal Docker network)
EXPOSE 5002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5002/health', timeout=5)" || exit 1

# Run with gunicorn + gevent workers
CMD ["gunicorn", "--bind", "0.0.0.0:5002", "--workers", "4", "--worker-class", "gevent", "--worker-connections", "1000", "--timeout", "120", "login:app"]
