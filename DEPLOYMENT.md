# 🚀 PitchInsights Deployment Guide

## Schnellstart (5 Minuten)

### Option 1: Docker (Empfohlen)

```bash
# 1. Repository klonen
git clone https://github.com/dein-repo/pitchinsights.git
cd pitchinsights

# 2. Konfiguration erstellen
cp .env.example .env

# 3. Secret Key generieren und in .env eintragen
python3 -c "import secrets; print(secrets.token_hex(32))"

# 4. Domain in .env setzen
nano .env
# PITCHINSIGHTS_DOMAIN=app.dein-verein.de
# PITCHINSIGHTS_SECRET_KEY=<dein-generierter-key>

# 5. Starten!
docker-compose up -d

# 6. Logs prüfen
docker-compose logs -f
```

**Fertig!** Die App läuft jetzt mit automatischem HTTPS auf `https://deine-domain.de`

---

### Option 2: Manuell (ohne Docker)

```bash
# 1. Python 3.11+ und Caddy installieren
brew install python@3.11 caddy  # macOS
# oder
sudo apt install python3.11 caddy  # Ubuntu

# 2. Dependencies installieren
pip3 install -r requirements.txt

# 3. Konfiguration
cp .env.example .env
nano .env

# 4. Starten
chmod +x start_production.sh
./start_production.sh --with-caddy
```

---

## Checkliste für Produktion

### ✅ Vor dem Launch

- [ ] **Secret Key** generiert und in `.env` eingetragen
- [ ] **Domain** konfiguriert (DNS A-Record zeigt auf Server)
- [ ] **PITCHINSIGHTS_ENV** auf `production` gesetzt
- [ ] **PITCHINSIGHTS_COOKIE_SECURE** auf `true` gesetzt
- [ ] Firewall: Nur Ports 80, 443 offen
- [ ] SSL-Zertifikat wird automatisch von Caddy geholt

### ✅ Nach dem Launch

- [ ] HTTPS funktioniert (`https://deine-domain.de`)
- [ ] Login funktioniert
- [ ] Security Headers prüfen: https://securityheaders.com
- [ ] Backup-Script einrichten (siehe unten)

---

## Backup

### Automatisches Backup (Cronjob)

```bash
# Backup-Script erstellen
cat > /home/pitchinsights/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/home/pitchinsights/backups"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Docker-Variante
docker cp pitchinsights-app:/app/data/pitchinsights.db $BACKUP_DIR/pitchinsights_$DATE.db

# Alte Backups löschen (behalte 30 Tage)
find $BACKUP_DIR -name "*.db" -mtime +30 -delete
EOF

chmod +x /home/pitchinsights/backup.sh

# Täglich um 3:00 Uhr
crontab -e
# 0 3 * * * /home/pitchinsights/backup.sh
```

---

## Server-Anforderungen

| Komponente | Minimum | Empfohlen |
|------------|---------|-----------|
| RAM | 512 MB | 1 GB |
| CPU | 1 Core | 2 Cores |
| Disk | 10 GB | 20 GB |
| OS | Ubuntu 22.04+ | Ubuntu 24.04 |

### Empfohlene Hosting-Anbieter

- **Hetzner Cloud** (ab €4/Monat) - Deutsch, DSGVO-konform
- **DigitalOcean** (ab $6/Monat)
- **Netcup** (ab €3/Monat) - Deutsch

---

## Troubleshooting

### App startet nicht

```bash
# Logs prüfen
docker-compose logs app

# Manuell starten zum Debuggen
docker-compose run --rm app python main.py
```

### Kein HTTPS

```bash
# Caddy Logs prüfen
docker-compose logs caddy

# DNS prüfen
dig +short deine-domain.de

# Ports prüfen
sudo lsof -i :80
sudo lsof -i :443
```

### Datenbank-Fehler

```bash
# Backup wiederherstellen
docker cp backup.db pitchinsights-app:/app/data/pitchinsights.db
docker-compose restart app
```

---

## Support

Bei Fragen: [Dein Support-Kanal]
