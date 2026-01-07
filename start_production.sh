#!/bin/bash
# ============================================
# PitchInsights - Production Start Script
# ============================================
# Dieses Script startet die App sicher in Produktion
#
# Verwendung:
#   chmod +x start_production.sh
#   ./start_production.sh
#
# Mit Caddy (HTTPS):
#   ./start_production.sh --with-caddy
# ============================================

set -e  # Bei Fehlern abbrechen

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================"
echo "  PitchInsights Production Launcher"
echo "============================================"
echo ""

# .env laden falls vorhanden
if [ -f .env ]; then
    echo -e "${GREEN}✓${NC} .env Datei gefunden, lade Konfiguration..."
    set -a
    source .env
    set +a
else
    echo -e "${RED}✗${NC} FEHLER: .env Datei nicht gefunden!"
    echo ""
    echo "  Erstelle eine .env Datei basierend auf .env.example:"
    echo "    cp .env.example .env"
    echo "    nano .env"
    echo ""
    exit 1
fi

# Prüfe kritische Umgebungsvariablen
if [ "$PITCHINSIGHTS_SECRET_KEY" = "CHANGE_ME_TO_RANDOM_VALUE" ] || [ -z "$PITCHINSIGHTS_SECRET_KEY" ]; then
    echo -e "${RED}✗${NC} FEHLER: PITCHINSIGHTS_SECRET_KEY muss gesetzt werden!"
    echo ""
    echo "  Generiere einen sicheren Key mit:"
    echo "    python3 -c \"import secrets; print(secrets.token_hex(32))\""
    echo ""
    exit 1
fi

echo -e "${GREEN}✓${NC} Secret Key konfiguriert"

# Prüfe Produktionsmodus
if [ "$PITCHINSIGHTS_ENV" != "production" ]; then
    echo -e "${YELLOW}⚠${NC} WARNUNG: PITCHINSIGHTS_ENV ist nicht 'production'"
fi

# Prüfe Cookie-Sicherheit
if [ "$PITCHINSIGHTS_COOKIE_SECURE" != "True" ] && [ "$PITCHINSIGHTS_COOKIE_SECURE" != "true" ]; then
    echo -e "${YELLOW}⚠${NC} WARNUNG: PITCHINSIGHTS_COOKIE_SECURE sollte 'true' sein für HTTPS"
fi

# Erstelle Verzeichnisse
mkdir -p data/uploads
mkdir -p data/backups

# Datenbank-Backup vor Start
if [ -f data/pitchinsights.db ]; then
    BACKUP_NAME="data/backups/pitchinsights_$(date +%Y%m%d_%H%M%S).db"
    cp data/pitchinsights.db "$BACKUP_NAME"
    echo -e "${GREEN}✓${NC} Datenbank-Backup erstellt: $BACKUP_NAME"
    
    # Alte Backups löschen (behalte letzte 10)
    ls -t data/backups/*.db 2>/dev/null | tail -n +11 | xargs -r rm
fi

echo ""
echo "============================================"
echo "  Starte PitchInsights..."
echo "============================================"
echo ""

# Mit Caddy starten?
if [ "$1" = "--with-caddy" ]; then
    echo -e "${GREEN}→${NC} Starte mit Caddy (HTTPS)..."
    echo ""
    
    # Prüfe ob Caddy installiert ist
    if ! command -v caddy &> /dev/null; then
        echo -e "${RED}✗${NC} Caddy ist nicht installiert!"
        echo "  macOS:  brew install caddy"
        echo "  Ubuntu: sudo apt install caddy"
        exit 1
    fi
    
    # Starte Python App im Hintergrund
    echo "Starte Python App auf Port 8000..."
    python3 -m uvicorn main:app --host 127.0.0.1 --port 8000 --workers 2 &
    PYTHON_PID=$!
    
    # Warte kurz
    sleep 2
    
    # Starte Caddy
    echo "Starte Caddy (HTTPS auf Port 443)..."
    DOMAIN=${PITCHINSIGHTS_DOMAIN:-localhost} caddy run --config Caddyfile
    
    # Cleanup wenn Caddy beendet wird
    kill $PYTHON_PID 2>/dev/null
else
    echo -e "${YELLOW}⚠${NC} Starte ohne HTTPS (nur für Tests!)"
    echo ""
    echo "  Für Produktion mit HTTPS:"
    echo "    ./start_production.sh --with-caddy"
    echo ""
    
    # Direkt starten
    python3 -m uvicorn main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --workers 2 \
        --access-log \
        --log-level info
fi
