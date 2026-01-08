"""
Security Configuration Module
=============================
Zentrale Konfiguration für alle sicherheitsrelevanten Einstellungen.
SECURITY AUDIT: Alle Secrets müssen über Umgebungsvariablen gesetzt werden.
"""

import os
import secrets
import hashlib
from typing import List


class SecurityConfig:
    """
    Zentrale Security-Konfiguration.
    SECURITY AUDIT: Überprüfen, dass alle Werte in Produktion über ENV gesetzt sind.
    """

    # Umgebung
    IS_PRODUCTION: bool = os.environ.get("PITCHINSIGHTS_ENV") == "production"

    # Secret Key für Session-Tokens - MUSS in Produktion gesetzt werden
    # SECURITY: In Produktion NIEMALS den Fallback-Key verwenden!
    _DEFAULT_DEV_KEY = "DEVELOPMENT-ONLY-KEY-NOT-FOR-PRODUCTION-USE-12345"
    SECRET_KEY: str = os.environ.get("PITCHINSIGHTS_SECRET_KEY", "")
    if not SECRET_KEY:
        if IS_PRODUCTION:
            raise RuntimeError(
                "KRITISCH: PITCHINSIGHTS_SECRET_KEY muss in Produktion gesetzt sein!")
        SECRET_KEY = _DEFAULT_DEV_KEY
        print(
            "⚠️  WARNUNG: Kein PITCHINSIGHTS_SECRET_KEY gesetzt. Verwende Development-Key.")
        print("⚠️  In Produktion MUSS PITCHINSIGHTS_SECRET_KEY als Umgebungsvariable gesetzt sein!")

    # CSRF Secret (separater Key für CSRF-Tokens)
    CSRF_SECRET: str = os.environ.get("PITCHINSIGHTS_CSRF_SECRET", "")
    if not CSRF_SECRET:
        # Generiere CSRF-Secret aus dem Haupt-Secret
        CSRF_SECRET = hashlib.sha256(f"{SECRET_KEY}_csrf".encode()).hexdigest()

    # Password Pepper - zusätzliche Sicherheitsschicht für Passwort-Hashing
    # SECURITY: Selbst bei DB-Leak sind Passwörter ohne Pepper nicht crackbar
    PASSWORD_PEPPER: str = os.environ.get("PITCHINSIGHTS_PASSWORD_PEPPER", "")
    if not PASSWORD_PEPPER:
        PASSWORD_PEPPER = hashlib.sha256(
            f"{SECRET_KEY}_pepper".encode()).hexdigest()[:32]

    # Cookie-Einstellungen
    # SECURITY: In Produktion werden sichere Cookies erzwungen!
    COOKIE_SECURE: bool = IS_PRODUCTION or os.environ.get(
        "PITCHINSIGHTS_COOKIE_SECURE", "False"
    ).lower() in ("1", "true", "yes")
    COOKIE_SAMESITE: str = "Strict" if IS_PRODUCTION else os.environ.get(
        "PITCHINSIGHTS_COOKIE_SAMESITE", "Lax")
    COOKIE_HTTPONLY: bool = True
    SESSION_MAX_AGE_SECONDS: int = int(os.environ.get(
        "PITCHINSIGHTS_SESSION_MAX_AGE", "86400"))  # 24h default

    # Session-Sicherheit
    SESSION_BIND_IP: bool = os.environ.get(
        "PITCHINSIGHTS_SESSION_BIND_IP", "True"
    ).lower() in ("1", "true", "yes")
    SESSION_ROTATE_ON_LOGIN: bool = True

    # CORS - Nur explizit erlaubte Origins
    ALLOWED_ORIGINS: List[str] = [
        origin.strip()
        for origin in os.environ.get("PITCHINSIGHTS_ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    ]
    # Fallback für lokale Entwicklung - in Produktion muss es gesetzt sein
    if not ALLOWED_ORIGINS:
        if IS_PRODUCTION:
            raise RuntimeError(
                "KRITISCH: PITCHINSIGHTS_ALLOWED_ORIGINS muss in Produktion gesetzt sein!")
        ALLOWED_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000"]
        print(
            "⚠️  WARNUNG: Keine PITCHINSIGHTS_ALLOWED_ORIGINS gesetzt. Verwende localhost.")

    # Passwort-Policy
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # Rate Limiting - verschärft
    LOGIN_MAX_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_SECONDS: int = 900  # 15 Minuten
    LOGIN_LOCKOUT_ESCALATION: int = 3600  # 1 Stunde bei wiederholtem Lockout
    REGISTER_MAX_PER_HOUR: int = 3  # Reduziert von 5
    REGISTER_MAX_PER_IP_PER_DAY: int = 5  # Max Registrierungen pro IP pro Tag
    API_RATE_LIMIT_PER_MINUTE: int = 60  # Allgemeines API Rate Limit
    SENSITIVE_RATE_LIMIT_PER_MINUTE: int = 10  # Für sensible Endpoints
    PASSWORD_CHANGE_RATE_LIMIT: int = 3  # Max Passwort-Änderungen pro Stunde

    # Token-Einstellungen
    TOKEN_EXPIRY_SECONDS: int = 86400  # 24h
    INVITATION_DEFAULT_DAYS: int = 7
    INVITATION_MAX_USES: int = 50
    CSRF_TOKEN_EXPIRY: int = 3600  # 1 Stunde

    # Data Directory - Railway Volume oder lokal
    # Suche nach schreibbarem Verzeichnis
    @staticmethod
    def _find_data_dir():
        """Findet ein schreibbares Datenverzeichnis."""
        # 1. Explizit gesetzt
        if os.environ.get("PITCHINSIGHTS_DATA_DIR"):
            return os.environ.get("PITCHINSIGHTS_DATA_DIR")

        # 2. Railway Volume Mount Path
        if os.environ.get("RAILWAY_VOLUME_MOUNT_PATH"):
            return os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")

        # 3. Suche Railway Volume unter bekannten Pfaden
        railway_paths = [
            "/app/data",
            "/data",
            "/var/data",
            "/tmp/pitchinsights_data",  # Fallback - immer schreibbar
        ]

        # Auch dynamisch gefundene Railway Volumes
        bind_mount_base = "/var/lib/containers/railwayapp/bind-mounts"
        if os.path.exists(bind_mount_base):
            try:
                for d in os.listdir(bind_mount_base):
                    vol_path = os.path.join(bind_mount_base, d)
                    if os.path.isdir(vol_path):
                        for v in os.listdir(vol_path):
                            if v.startswith("vol_"):
                                railway_paths.insert(
                                    0, os.path.join(vol_path, v))
            except (PermissionError, OSError):
                pass

        # Teste welcher Pfad schreibbar ist
        for path in railway_paths:
            try:
                os.makedirs(path, exist_ok=True)
                test_file = os.path.join(path, ".write_test")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
                return path
            except (PermissionError, OSError):
                continue

        # 4. Lokales Verzeichnis (Development)
        return "data"

    DATA_DIR: str = _find_data_dir.__func__()

    # Database
    DATABASE_PATH: str = os.environ.get(
        "PITCHINSIGHTS_DB_PATH", f"{DATA_DIR}/pitchinsights.db")

    # Logging
    LOG_LEVEL: str = os.environ.get("PITCHINSIGHTS_LOG_LEVEL", "INFO")
    LOG_FILE: str = os.environ.get(
        "PITCHINSIGHTS_LOG_FILE", f"{DATA_DIR}/security.log")


class AppPermissions:
    """Definiert alle verfügbaren App-Berechtigungen (Whitelist)."""

    ALL_APPS: List[str] = [
        'dashboard', 'kalender', 'spieler', 'video', 'training', 'spieltag',
        'taktik', 'toranalyse', 'kommunikation', 'teamchat', 'dokumente',
        'vereinsanbindung', 'saisonplanung', 'verwaltung', 'profil'
    ]

    @classmethod
    def is_valid_app(cls, app_id: str) -> bool:
        """Prüft ob eine App-ID gültig ist (Whitelist-Check)."""
        return app_id in cls.ALL_APPS


class AllowedRoles:
    """Whitelist der erlaubten Rollen-Namen."""

    ALLOWED_ROLES: List[str] = [
        "Admin", "Trainer", "Co-Trainer", "Spieler", "Eltern", "Betreuer",
        "Physio", "Torwarttrainer", "Jugendleiter", "Vorstand"
    ]

    @classmethod
    def is_valid_role(cls, role_name: str) -> bool:
        """Prüft ob ein Rollen-Name erlaubt ist."""
        return role_name in cls.ALLOWED_ROLES
