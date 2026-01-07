# PitchInsights Docker Image
# ==========================
# Multi-Stage Build für minimale Image-Größe

FROM python:3.11-slim AS base

# Sicherheit: Non-root User
RUN groupadd -r pitchinsights && useradd -r -g pitchinsights pitchinsights

# System-Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Arbeitsverzeichnis
WORKDIR /app

# Dependencies zuerst (für besseres Caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production Stage
FROM python:3.11-slim AS production

# Sicherheit: Non-root User
RUN groupadd -r pitchinsights && useradd -r -g pitchinsights pitchinsights

WORKDIR /app

# Kopiere nur die installierten Packages
COPY --from=base /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=base /usr/local/bin /usr/local/bin

# App-Code kopieren
COPY --chown=pitchinsights:pitchinsights . .

# Datenverzeichnis erstellen
RUN mkdir -p /app/data/uploads /app/data/backups \
    && chown -R pitchinsights:pitchinsights /app/data

# Wechsle zu non-root User
USER pitchinsights

# Health Check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Port
EXPOSE 8000

# Start
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
