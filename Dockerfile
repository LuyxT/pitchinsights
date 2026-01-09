# PitchInsights Docker Image
# ==========================
# Optimized for Railway deployment with volume support

FROM python:3.11-slim

# System-Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Arbeitsverzeichnis
WORKDIR /app

# Dependencies zuerst (für besseres Caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App-Code kopieren
COPY . .

# Datenverzeichnis erstellen (wird von Railway Volume überschrieben)
RUN mkdir -p /app/data/uploads /app/data/videos /app/data/backups

# NOTE: Running as root on Railway because volume is mounted with root ownership
# This is necessary for volume write access

# Health Check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Port (Railway uses 8080)
EXPOSE 8080

# Start
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
