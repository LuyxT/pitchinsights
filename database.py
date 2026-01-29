"""
Database Module - Security Hardened Version
============================================
SECURITY AUDIT: Alle Queries nutzen parameterisierte Statements.
Keine dynamischen SQL-Strings mit User-Input.
"""

import sqlite3
import os
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from contextlib import contextmanager

from config import SecurityConfig, AppPermissions

# Security Logger - ohne sensible Daten
logger = logging.getLogger("pitchinsights.security")


@contextmanager
def get_db_connection():
    """
    Context Manager für sichere Datenbankverbindungen.
    SECURITY: Garantiert Schließen der Verbindung.
    PERFORMANCE: Optimierte SQLite-Einstellungen für Multi-Tenant.
    """
    conn = None
    try:
        # BULLETPROOF: Nutze DATA_DIR direkt, ignoriere DATABASE_PATH
        db_path = os.path.join(SecurityConfig.DATA_DIR, "pitchinsights.db")
        db_dir = os.path.dirname(db_path)
        try:
            os.makedirs(db_dir, exist_ok=True)
        except (PermissionError, OSError):
            pass  # Volume might not be mounted yet
        conn = sqlite3.connect(
            db_path,
            timeout=30.0,  # Längerer Timeout für konkurrierende Zugriffe
            check_same_thread=False  # Für async-Kompatibilität
        )
        conn.row_factory = sqlite3.Row
        # SECURITY: Foreign Keys aktivieren
        conn.execute("PRAGMA foreign_keys = ON")
        # PERFORMANCE: Optimierungen für viele gleichzeitige Leser
        conn.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging
        conn.execute("PRAGMA synchronous = NORMAL")  # Schneller, noch sicher
        conn.execute("PRAGMA cache_size = -64000")  # 64MB Cache
        conn.execute("PRAGMA temp_store = MEMORY")  # Temp Tables im RAM
        yield conn
    finally:
        if conn:
            conn.close()


def get_db():
    """
    Legacy-Funktion für Kompatibilität.
    WARNUNG: Aufrufer MUSS Verbindung schließen!
    """
    db_path = os.path.join(SecurityConfig.DATA_DIR, "pitchinsights.db")
    db_dir = os.path.dirname(db_path)
    try:
        os.makedirs(db_dir, exist_ok=True)
    except (PermissionError, OSError):
        pass  # Volume might not be mounted yet
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """
    Initialisiert die Datenbank mit gehärteten Tabellen.
    SECURITY AUDIT: Alle Constraints prüfen.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Users Tabelle - Auth-Daten
        # SECURITY: Strikte Constraints, Soft Delete via deleted_at
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL CHECK(length(email) >= 5 AND length(email) <= 254),
                password_hash TEXT NOT NULL CHECK(length(password_hash) >= 50),
                
                -- Profilfelder mit Längenbeschränkungen
                vorname TEXT DEFAULT '' CHECK(length(vorname) <= 100),
                nachname TEXT DEFAULT '' CHECK(length(nachname) <= 100),
                
                -- Team-Zugehörigkeit
                team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL,
                role_id INTEGER REFERENCES roles(id) ON DELETE SET NULL,
                is_admin INTEGER DEFAULT 0 CHECK(is_admin IN (0, 1)),
                
                -- Legacy/Kompatibilität
                teamname TEXT DEFAULT '' CHECK(length(teamname) <= 200),
                rolle TEXT DEFAULT '' CHECK(length(rolle) <= 50),
                verein TEXT DEFAULT '' CHECK(length(verein) <= 200),
                mannschaft TEXT DEFAULT '' CHECK(length(mannschaft) <= 200),
                
                -- Status
                onboarding_complete INTEGER DEFAULT 0 CHECK(onboarding_complete IN (0, 1)),
                is_active INTEGER DEFAULT 1 CHECK(is_active IN (0, 1)),
                
                -- Payment Status (Stripe)
                payment_status TEXT DEFAULT 'unpaid' CHECK(payment_status IN ('unpaid', 'pending', 'paid', 'refunded')),
                stripe_customer_id TEXT NULL,
                stripe_payment_id TEXT NULL,
                paid_at TIMESTAMP NULL,
                
                -- DSGVO: Soft Delete
                deleted_at TIMESTAMP NULL,
                
                -- Audit
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                last_login_at TIMESTAMP NULL
            )
        """)

        # E-Mail Verifizierung
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL CHECK(length(token) >= 20),
                expires_at TIMESTAMP NOT NULL,
                used_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_email_verifications_token
            ON email_verifications(token)
        """)

        # Index für schnelle Email-Lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE deleted_at IS NULL
        """)

        # Rate Limiting Tabelle
        # SECURITY: Für Brute-Force-Schutz
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                success INTEGER DEFAULT 0 CHECK(success IN (0, 1))
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_login_attempts_email 
            ON login_attempts(email, attempted_at)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_login_attempts_ip 
            ON login_attempts(ip_address, attempted_at)
        """)

        # Waitlist Tabelle (Landing Page)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS waitlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL CHECK(length(email) >= 5 AND length(email) <= 254),
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                contacted_at TIMESTAMP NULL
            )
        """)

        # Pilotphasen-Anmeldungen (Landing Page)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pilot_signups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vereinsname TEXT NOT NULL CHECK(length(vereinsname) >= 2 AND length(vereinsname) <= 200),
                ansprechpartner TEXT NOT NULL CHECK(length(ansprechpartner) >= 2 AND length(ansprechpartner) <= 100),
                email TEXT UNIQUE NOT NULL CHECK(length(email) >= 5 AND length(email) <= 254),
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                contacted_at TIMESTAMP NULL,
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'contacted', 'accepted', 'declined'))
            )
        """)

        # Teams Tabelle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS teams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL CHECK(length(name) >= 1 AND length(name) <= 200),
                verein TEXT DEFAULT '' CHECK(length(verein) <= 200),
                mannschaft TEXT DEFAULT '' CHECK(length(mannschaft) <= 200),
                admin_user_id INTEGER NOT NULL,
                
                -- DSGVO: Soft Delete
                deleted_at TIMESTAMP NULL,
                is_active INTEGER DEFAULT 1 CHECK(is_active IN (0, 1)),
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                
                FOREIGN KEY (admin_user_id) REFERENCES users(id) ON DELETE RESTRICT
            )
        """)

        # Rollen Tabelle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                name TEXT NOT NULL CHECK(length(name) >= 1 AND length(name) <= 100),
                description TEXT DEFAULT '' CHECK(length(description) <= 500),
                is_default INTEGER DEFAULT 0 CHECK(is_default IN (0, 1)),
                is_deletable INTEGER DEFAULT 1 CHECK(is_deletable IN (0, 1)),
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                UNIQUE(team_id, name)
            )
        """)

        # Berechtigungen Tabelle
        # SECURITY: app_id wird gegen Whitelist validiert
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role_id INTEGER NOT NULL,
                app_id TEXT NOT NULL CHECK(length(app_id) >= 1 AND length(app_id) <= 50),
                can_view INTEGER DEFAULT 0 CHECK(can_view IN (0, 1)),
                can_edit INTEGER DEFAULT 0 CHECK(can_edit IN (0, 1)),
                
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                UNIQUE(role_id, app_id)
            )
        """)

        # Team-Mitglieder Tabelle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS team_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT,
                UNIQUE(team_id, user_id)
            )
        """)

        # Einladungen Tabelle
        # SECURITY: Token ist kryptographisch sicher
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS invitations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL CHECK(length(token) >= 20),
                created_by INTEGER NOT NULL,
                max_uses INTEGER DEFAULT 10 CHECK(max_uses > 0 AND max_uses <= 1000),
                uses INTEGER DEFAULT 0 CHECK(uses >= 0),
                expires_at TIMESTAMP NOT NULL,
                is_active INTEGER DEFAULT 1 CHECK(is_active IN (0, 1)),
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_invitations_token 
            ON invitations(token) WHERE is_active = 1
        """)

        # User Sessions (serverseitiger Team-Kontext)
        # SECURITY: Session-Hash statt Token speichern
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_hash TEXT PRIMARY KEY CHECK(length(session_hash) <= 128),
                user_id INTEGER NOT NULL,
                active_team_id INTEGER NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (active_team_id) REFERENCES teams(id) ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_sessions_user
            ON user_sessions(user_id)
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mobile_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                access_token_hash TEXT UNIQUE NOT NULL CHECK(length(access_token_hash) = 64),
                refresh_token_hash TEXT UNIQUE NOT NULL CHECK(length(refresh_token_hash) = 64),
                access_expires_at TIMESTAMP NOT NULL,
                refresh_expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_mobile_tokens_access_hash
            ON mobile_tokens(access_token_hash)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_mobile_tokens_refresh_hash
            ON mobile_tokens(refresh_token_hash)
        """)

        # Audit Log Tabelle (erweitert für Security Events)
        # SECURITY AUDIT: Alle sicherheitsrelevanten Aktionen
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL CHECK(length(event_type) <= 50),
                user_id INTEGER,
                action TEXT NOT NULL CHECK(length(action) <= 100),
                resource_type TEXT CHECK(length(resource_type) <= 50),
                resource_id INTEGER,
                details TEXT CHECK(length(details) <= 5000),
                ip_address TEXT CHECK(length(ip_address) <= 45),
                user_agent TEXT CHECK(length(user_agent) <= 500),
                severity TEXT DEFAULT 'INFO' CHECK(severity IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')),
                request_id TEXT CHECK(length(request_id) <= 50),
                session_id TEXT CHECK(length(session_id) <= 100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_log_user 
            ON audit_log(user_id, created_at)
        """)

        # Note: event_type und severity indexes werden in _run_migrations erstellt
        # da diese Spalten bei bestehenden DBs erst migriert werden müssen

        # Two-Factor Authentication Tabelle
        # SECURITY: TOTP-Secrets und Backup-Codes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_2fa (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                totp_secret TEXT CHECK(length(totp_secret) = 32),
                is_enabled INTEGER DEFAULT 0 CHECK(is_enabled IN (0, 1)),
                backup_codes TEXT,  -- JSON array, gehashed
                last_used_code TEXT,  -- Replay-Schutz
                last_verified_at TIMESTAMP,
                enabled_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_2fa_user 
            ON user_2fa(user_id) WHERE is_enabled = 1
        """)

        # Security Events Tabelle (High-Volume Events)
        # SECURITY: IP Blacklists, Rate Limits etc.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL CHECK(length(event_type) <= 50),
                ip_address TEXT NOT NULL CHECK(length(ip_address) <= 45),
                user_agent TEXT CHECK(length(user_agent) <= 500),
                details TEXT CHECK(length(details) <= 2000),
                blocked INTEGER DEFAULT 0 CHECK(blocked IN (0, 1)),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_ip 
            ON security_events(ip_address, created_at)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_type 
            ON security_events(event_type, created_at)
        """)

        # Spieler/Kader Tabelle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS players (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                user_id INTEGER NULL,
                name TEXT NOT NULL CHECK(length(name) >= 1 AND length(name) <= 200),
                position TEXT DEFAULT '' CHECK(length(position) <= 50),
                trikotnummer INTEGER CHECK(trikotnummer >= 0 AND trikotnummer <= 99),
                status TEXT DEFAULT 'Fit' CHECK(status IN ('Fit', 'Belastet', 'Angeschlagen', 'Verletzt', 'Reha', 'Ausfall')),
                email TEXT CHECK(length(email) <= 254),
                telefon TEXT CHECK(length(telefon) <= 30),
                geburtsdatum DATE,
                notizen TEXT CHECK(length(notizen) <= 1000),
                starker_fuss TEXT DEFAULT '' CHECK(length(starker_fuss) <= 30),
                werdegang TEXT CHECK(length(werdegang) <= 1000),
                verletzungshistorie TEXT CHECK(length(verletzungshistorie) <= 1000),
                groesse INTEGER NULL,
                gewicht INTEGER NULL,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                deleted_at TIMESTAMP NULL,
                
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_players_team 
            ON players(team_id) WHERE deleted_at IS NULL
        """)

        # PERFORMANCE: Kritische Indizes für Multi-Tenant-Skalierung
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_team_members_team_user
            ON team_members(team_id, user_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_team_members_user
            ON team_members(user_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_permissions_role
            ON permissions(role_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_team
            ON users(team_id) WHERE deleted_at IS NULL AND is_active = 1
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_roles_team
            ON roles(team_id)
        """)

        # Kalender-Events Tabelle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS calendar_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                title TEXT NOT NULL CHECK(length(title) >= 1 AND length(title) <= 200),
                description TEXT CHECK(length(description) <= 1000),
                event_type TEXT DEFAULT 'training' CHECK(event_type IN ('training', 'match', 'meeting', 'other')),
                event_date DATE NOT NULL,
                start_time TIME,
                end_time TIME,
                location TEXT CHECK(length(location) <= 200),
                created_by INTEGER,
                visibility TEXT DEFAULT 'private' CHECK(visibility IN ('private', 'team')),
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                deleted_at TIMESTAMP NULL,
                
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_team_date 
            ON calendar_events(team_id, event_date) WHERE deleted_at IS NULL
        """)

        # Event RSVP Tabelle (Zu-/Absagen für Team-Events)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_rsvps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('yes', 'no', 'maybe')),
                comment TEXT CHECK(length(comment) <= 200),
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                
                FOREIGN KEY (event_id) REFERENCES calendar_events(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(event_id, user_id)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_rsvps_event 
            ON event_rsvps(event_id)
        """)

        # Event Kader Tabelle (wer darf zu-/absagen)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_roster (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                
                FOREIGN KEY (event_id) REFERENCES calendar_events(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(event_id, user_id)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_event_roster_event
            ON event_roster(event_id)
        """)

        # Messenger-Nachrichten Tabelle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER,  -- NULL = Team-Chat
                content TEXT NOT NULL CHECK(length(content) >= 1 AND length(content) <= 5000),
                attachment_name TEXT NULL,
                attachment_type TEXT NULL,
                attachment_path TEXT NULL,
                attachment_size INTEGER NULL,
                is_read INTEGER DEFAULT 0 CHECK(is_read IN (0, 1)),
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                deleted_at TIMESTAMP NULL,
                
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_team 
            ON messages(team_id, created_at) WHERE deleted_at IS NULL
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_team_recipient_read
            ON messages(team_id, recipient_id, is_read, created_at) WHERE deleted_at IS NULL
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_team_sender_recipient
            ON messages(team_id, sender_id, recipient_id, created_at) WHERE deleted_at IS NULL
        """)

        # Taktik-Formationen Tabelle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS formations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                name TEXT NOT NULL CHECK(length(name) >= 1 AND length(name) <= 100),
                formation_data TEXT NOT NULL,  -- JSON mit Spielerpositionen
                created_by INTEGER,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                deleted_at TIMESTAMP NULL,
                
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        # Videos Tabelle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                title TEXT NOT NULL CHECK(length(title) >= 1 AND length(title) <= 200),
                description TEXT CHECK(length(description) <= 1000),
                filename TEXT NOT NULL CHECK(length(filename) >= 1 AND length(filename) <= 255),
                file_size INTEGER,
                duration INTEGER,  -- Sekunden
                uploaded_by INTEGER NOT NULL,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                deleted_at TIMESTAMP NULL,
                
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_videos_team 
            ON videos(team_id) WHERE deleted_at IS NULL
        """)

        # Video-Clips Tabelle (Ausschnitte aus Videos)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS video_clips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                video_id INTEGER NOT NULL,
                team_id INTEGER NOT NULL,
                title TEXT NOT NULL CHECK(length(title) >= 1 AND length(title) <= 200),
                start_time INTEGER NOT NULL,  -- Sekunden
                end_time INTEGER NOT NULL,    -- Sekunden
                note TEXT CHECK(length(note) <= 500),
                created_by INTEGER NOT NULL,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                deleted_at TIMESTAMP NULL,
                
                FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE,
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_clips_video 
            ON video_clips(video_id) WHERE deleted_at IS NULL
        """)

        # Video-Sharing Tabelle (Clips an Spieler senden)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS video_shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                clip_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                message TEXT CHECK(length(message) <= 500),
                is_viewed INTEGER DEFAULT 0 CHECK(is_viewed IN (0, 1)),
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                viewed_at TIMESTAMP NULL,
                
                FOREIGN KEY (clip_id) REFERENCES video_clips(id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_shares_recipient 
            ON video_shares(recipient_id, is_viewed)
        """)

        # Video-Marker Tabelle (Zeitmarken auf Videos)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS video_markers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                video_id INTEGER NOT NULL,
                team_id INTEGER NOT NULL,
                time_seconds REAL NOT NULL,
                label TEXT CHECK(length(label) <= 100),
                color TEXT DEFAULT '#ef4444' CHECK(length(color) <= 20),
                created_by INTEGER NOT NULL,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                deleted_at TIMESTAMP NULL,
                
                FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE,
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_markers_video 
            ON video_markers(video_id) WHERE deleted_at IS NULL
        """)

        # Mannschaftskasse Tabelle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS kasse_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
                description TEXT CHECK(length(description) <= 200),
                created_by INTEGER NOT NULL,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                deleted_at TIMESTAMP NULL,
                
                FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_kasse_team 
            ON kasse_transactions(team_id) WHERE deleted_at IS NULL
        """)

        # ============================================
        # Trainer Hub (vereinsuebergreifend)
        # ============================================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trainer_hub_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                vorname TEXT DEFAULT '' CHECK(length(vorname) <= 100),
                nachname TEXT DEFAULT '' CHECK(length(nachname) <= 100),
                verein TEXT DEFAULT '' CHECK(length(verein) <= 200),
                mannschaft TEXT DEFAULT '' CHECK(length(mannschaft) <= 200),
                liga TEXT DEFAULT '' CHECK(length(liga) <= 100),
                trainerrolle TEXT DEFAULT '' CHECK(length(trainerrolle) <= 100),
                kurzbeschreibung TEXT DEFAULT '' CHECK(length(kurzbeschreibung) <= 1000),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trainer_hub_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL CHECK(length(content) >= 1 AND length(content) <= 4000),
                media_url TEXT CHECK(length(media_url) <= 500),
                media_type TEXT DEFAULT '' CHECK(length(media_type) <= 20),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trainer_hub_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL CHECK(length(content) >= 1 AND length(content) <= 2000),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (post_id) REFERENCES trainer_hub_posts(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trainer_hub_test_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                mannschaft TEXT NOT NULL CHECK(length(mannschaft) <= 200),
                altersklasse TEXT NOT NULL CHECK(length(altersklasse) <= 50),
                zeitraum_von DATE NOT NULL,
                zeitraum_bis DATE NOT NULL,
                ort_typ TEXT NOT NULL CHECK(ort_typ IN ('heim', 'auswaerts', 'neutral')),
                ort_details TEXT DEFAULT '' CHECK(length(ort_details) <= 200),
                zusatzinfos TEXT DEFAULT '' CHECK(length(zusatzinfos) <= 1000),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trainer_hub_test_match_interest (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                match_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                message TEXT DEFAULT '' CHECK(length(message) <= 1000),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE(match_id, user_id),
                FOREIGN KEY (match_id) REFERENCES trainer_hub_test_matches(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trainer_hub_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id INTEGER NOT NULL,
                target_type TEXT NOT NULL CHECK(target_type IN ('post', 'comment', 'test_match', 'profile')),
                target_id INTEGER NOT NULL,
                reason TEXT NOT NULL CHECK(length(reason) >= 3 AND length(reason) <= 500),
                status TEXT DEFAULT 'open' CHECK(status IN ('open', 'reviewed')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_trainer_hub_posts_created
            ON trainer_hub_posts(created_at DESC)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_trainer_hub_comments_post
            ON trainer_hub_comments(post_id, created_at)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_trainer_hub_test_matches_created
            ON trainer_hub_test_matches(created_at DESC)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_trainer_hub_test_matches_filters
            ON trainer_hub_test_matches(altersklasse, ort_typ, zeitraum_von)
        """)

        conn.commit()

        # Migrations für bestehende Datenbanken
        _run_migrations(conn)


def _run_migrations(conn):
    """
    Führt sichere Migrationen durch.
    SECURITY: Alle ALTERs in Try-Catch für Idempotenz.
    """
    cursor = conn.cursor()

    migrations = [
        ("users", "vorname", "TEXT DEFAULT ''"),
        ("users", "nachname", "TEXT DEFAULT ''"),
        ("users", "teamname", "TEXT DEFAULT ''"),
        ("users", "rolle", "TEXT DEFAULT ''"),
        ("users", "verein", "TEXT DEFAULT ''"),
        ("users", "mannschaft", "TEXT DEFAULT ''"),
        ("users", "onboarding_complete", "INTEGER DEFAULT 0"),
        ("users", "is_admin", "INTEGER DEFAULT 0"),
        ("users", "team_id", "INTEGER"),
        ("users", "role_id", "INTEGER"),
        ("users", "is_active", "INTEGER DEFAULT 1"),
        ("users", "deleted_at", "TIMESTAMP NULL"),
        ("users", "updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("users", "last_login_at", "TIMESTAMP NULL"),
        # Payment Status (Stripe)
        ("users", "payment_status", "TEXT DEFAULT 'unpaid'"),
        ("users", "stripe_customer_id", "TEXT NULL"),
        ("users", "stripe_payment_id", "TEXT NULL"),
        ("users", "paid_at", "TIMESTAMP NULL"),
        # Profil-Erweiterungen
        ("users", "telefon", "TEXT DEFAULT ''"),
        ("users", "geburtsdatum", "DATE NULL"),
        ("users", "groesse", "INTEGER NULL"),
        ("users", "position", "TEXT DEFAULT ''"),
        ("users", "starker_fuss", "TEXT DEFAULT ''"),
        ("users", "werdegang", "TEXT DEFAULT ''"),
        # Spieler-spezifische Felder
        ("users", "nebenpositionen", "TEXT DEFAULT ''"),  # JSON array
        ("users", "gewicht", "INTEGER NULL"),  # in kg
        ("users", "jahrgang", "INTEGER NULL"),  # z.B. 2005
        # Trainer-spezifische Felder
        ("users", "spielsystem", "TEXT DEFAULT ''"),  # z.B. 4-3-3
        ("users", "taktische_grundidee", "TEXT DEFAULT ''"),
        ("users", "trainingsschwerpunkte", "TEXT DEFAULT ''"),
        ("users", "bisherige_stationen", "TEXT DEFAULT ''"),
        ("users", "lizenzen", "TEXT DEFAULT ''"),  # z.B. A-Lizenz
        # Player-User Verknüpfung
        ("players", "user_id", "INTEGER NULL"),
        ("players", "groesse", "INTEGER NULL"),
        ("players", "gewicht", "INTEGER NULL"),
        ("players", "starker_fuss", "TEXT DEFAULT ''"),
        ("players", "werdegang", "TEXT DEFAULT ''"),
        ("players", "verletzungshistorie", "TEXT DEFAULT ''"),
        ("messages", "attachment_name", "TEXT NULL"),
        ("messages", "attachment_type", "TEXT NULL"),
        ("messages", "attachment_path", "TEXT NULL"),
        ("messages", "attachment_size", "INTEGER NULL"),
        # Audit Log Erweiterungen
        ("audit_log", "event_type", "TEXT DEFAULT ''"),
        ("audit_log", "severity", "TEXT DEFAULT 'INFO'"),
        ("audit_log", "request_id", "TEXT"),
        ("audit_log", "session_id", "TEXT"),
    ]

    for table, column, definition in migrations:
        try:
            cursor.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError:
            pass  # Column existiert bereits

    # Index-Migrations (ignoriere Fehler bei existierenden Indexes)
    index_migrations = [
        "CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_severity ON audit_log(severity, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_messages_team_recipient_read ON messages(team_id, recipient_id, is_read, created_at) WHERE deleted_at IS NULL",
        "CREATE INDEX IF NOT EXISTS idx_messages_team_sender_recipient ON messages(team_id, sender_id, recipient_id, created_at) WHERE deleted_at IS NULL",
    ]

    for index_sql in index_migrations:
        try:
            cursor.execute(index_sql)
        except sqlite3.OperationalError:
            pass  # Index existiert bereits oder Spalte fehlt

    conn.commit()


def init_team_tables():
    """Alias für init_db() - Team-Tabellen sind inkludiert."""
    init_db()


# ============================================
# Rate Limiting Functions
# ============================================

def record_login_attempt(email: str, ip_address: str, success: bool) -> None:
    """
    Zeichnet einen Login-Versuch auf.
    SECURITY: Für Brute-Force-Erkennung.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO login_attempts (email, ip_address, success)
            VALUES (?, ?, ?)
        """, (email.lower(), ip_address, 1 if success else 0))
        conn.commit()


def is_login_blocked(email: str, ip_address: str) -> tuple:
    """
    Prüft ob Login geblockt ist (Rate Limiting).
    Returns: (is_blocked, remaining_seconds)
    SECURITY: Verhindert Brute-Force-Angriffe.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        lockout_threshold = datetime.now(
        ) - timedelta(seconds=SecurityConfig.LOGIN_LOCKOUT_SECONDS)

        # SECURITY FIX: SQLite CURRENT_TIMESTAMP format ist 'YYYY-MM-DD HH:MM:SS'
        # Verwende strftime für konsistentes Format
        lockout_str = lockout_threshold.strftime('%Y-%m-%d %H:%M:%S')

        # Fehlgeschlagene Versuche in Zeitfenster zählen
        cursor.execute("""
            SELECT COUNT(*) as count, MAX(attempted_at) as last_attempt
            FROM login_attempts
            WHERE (email = ? OR ip_address = ?)
            AND success = 0
            AND attempted_at > ?
        """, (email.lower(), ip_address, lockout_str))

        result = cursor.fetchone()
        count = result["count"] if result else 0
        last_attempt = result["last_attempt"] if result else None

        if count >= SecurityConfig.LOGIN_MAX_ATTEMPTS:
            if last_attempt:
                # SECURITY FIX: Beide Formate unterstützen (ISO und SQLite)
                try:
                    # Versuche SQLite-Format zuerst (YYYY-MM-DD HH:MM:SS)
                    last_dt = datetime.strptime(
                        last_attempt, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    # Fallback auf ISO-Format
                    last_dt = datetime.fromisoformat(
                        last_attempt.replace(' ', 'T'))
                remaining = SecurityConfig.LOGIN_LOCKOUT_SECONDS - \
                    int((datetime.now() - last_dt).total_seconds())
                return (True, max(0, remaining))
            return (True, SecurityConfig.LOGIN_LOCKOUT_SECONDS)

        return (False, 0)


def clear_login_attempts(email: str) -> None:
    """
    Löscht erfolgreiche Login-Versuche (nach erfolgreichem Login).
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Alte Einträge löschen (älter als 24h)
        cursor.execute("""
            DELETE FROM login_attempts
            WHERE email = ? OR attempted_at < datetime('now', '-1 day')
        """, (email.lower(),))
        conn.commit()


# ============================================
# User Functions - SECURITY HARDENED
# ============================================

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """
    Holt User sicher per Email.
    SECURITY: Nur aktive, nicht-gelöschte User.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM users 
            WHERE email = ? AND is_active = 1 AND deleted_at IS NULL
        """, (email.lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_email_any(email: str) -> Optional[Dict[str, Any]]:
    """
    Holt User per Email, auch wenn nicht aktiv.
    SECURITY: Nur nicht-gelöschte User.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM users 
            WHERE email = ? AND deleted_at IS NULL
        """, (email.lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Holt User sicher per ID.
    SECURITY: Nur aktive, nicht-gelöschte User.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM users 
            WHERE id = ? AND is_active = 1 AND deleted_at IS NULL
        """, (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def update_last_login(user_id: int) -> None:
    """Aktualisiert den letzten Login-Zeitpunkt."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?
        """, (user_id,))
        conn.commit()


# ============================================
# Team Functions - SECURITY HARDENED
# ============================================

def create_team(verein: str, mannschaft: str, admin_user_id: int) -> int:
    """
    Erstellt ein neues Team mit Standard-Rollen.
    SECURITY: Validierung erfolgt in Aufrufer, hier nur parameterisierte Queries.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        team_name = f"{verein} - {mannschaft}"

        # Team erstellen
        cursor.execute("""
            INSERT INTO teams (name, verein, mannschaft, admin_user_id)
            VALUES (?, ?, ?, ?)
        """, (team_name, verein, mannschaft, admin_user_id))
        team_id = cursor.lastrowid

        # Standard-Rollen erstellen
        default_roles = [
            ("Admin", "Vollzugriff auf alle Funktionen", 1, 0),
            ("Trainer", "Kann Trainingseinheiten und Spieler verwalten", 1, 0),
            ("Co-Trainer", "Kann Trainingseinheiten einsehen und unterstützen", 1, 1),
            ("Spieler", "Kann eigene Daten und Termine einsehen", 1, 1),
            ("Eltern", "Kann Termine und Infos einsehen", 1, 1),
            ("Betreuer", "Kann Termine und Mannschaftsinfos einsehen", 1, 1)
        ]

        # Berechtigungs-Matrix (nur Whitelist-Apps)
        role_permissions = {
            "Admin": {app: {"view": True, "edit": True} for app in AppPermissions.ALL_APPS},
            "Trainer": {app: {"view": True, "edit": app in ['dashboard', 'kalender', 'spieler', 'training', 'spieltag', 'taktik', 'teamchat', 'profil']} for app in AppPermissions.ALL_APPS if app != 'verwaltung'},
            "Co-Trainer": {app: {"view": True, "edit": app in ['training', 'profil']} for app in ['dashboard', 'kalender', 'spieler', 'training', 'teamchat', 'profil']},
            "Spieler": {app: {"view": True, "edit": app == 'profil'} for app in ['dashboard', 'kalender', 'teamchat', 'profil']},
            "Eltern": {app: {"view": True, "edit": app == 'profil'} for app in ['dashboard', 'kalender', 'profil']},
            "Betreuer": {app: {"view": True, "edit": app == 'profil'} for app in ['dashboard', 'kalender', 'teamchat', 'profil']}
        }

        admin_role_id = None

        for role_name, desc, is_default, is_deletable in default_roles:
            cursor.execute("""
                INSERT INTO roles (team_id, name, description, is_default, is_deletable)
                VALUES (?, ?, ?, ?, ?)
            """, (team_id, role_name, desc, is_default, is_deletable))
            role_id = cursor.lastrowid

            if role_name == "Admin":
                admin_role_id = role_id

            # Berechtigungen setzen - nur für Whitelist-Apps
            if role_name in role_permissions:
                for app_id, perms in role_permissions[role_name].items():
                    if AppPermissions.is_valid_app(app_id):
                        cursor.execute("""
                            INSERT INTO permissions (role_id, app_id, can_view, can_edit)
                            VALUES (?, ?, ?, ?)
                        """, (role_id, app_id, 1 if perms["view"] else 0, 1 if perms["edit"] else 0))

        # Admin als Mitglied hinzufügen
        cursor.execute("""
            INSERT INTO team_members (team_id, user_id, role_id)
            VALUES (?, ?, ?)
        """, (team_id, admin_user_id, admin_role_id))

        conn.commit()

        logger.info(
            f"Team created: id={team_id}, admin_user_id={admin_user_id}")
        return team_id


def verify_user_team_access(user_id: int, team_id: int) -> bool:
    """
    Prüft ob ein User Zugriff auf ein Team hat.
    SECURITY: Verhindert IDOR.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 1 FROM team_members
            WHERE user_id = ? AND team_id = ?
        """, (user_id, team_id))
        return cursor.fetchone() is not None


def verify_user_is_team_admin(user_id: int, team_id: int) -> bool:
    """
    Prüft ob ein User Admin eines Teams ist.
    SECURITY: Für privilegierte Operationen.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 1
            FROM team_members tm
            JOIN roles r ON tm.role_id = r.id
            JOIN users u ON tm.user_id = u.id
            WHERE tm.user_id = ? AND tm.team_id = ? AND u.is_active = 1
              AND LOWER(r.name) = 'admin'
        """, (user_id, team_id))
        row = cursor.fetchone()
        return bool(row)


# ============================================
# Invitation Functions - SECURITY HARDENED
# ============================================

def create_invitation(team_id: int, role_id: int, created_by: int,
                      max_uses: int = 10, days_valid: int = 7) -> str:
    """
    Erstellt einen sicheren Einladungslink.
    SECURITY: Kryptographisch sicherer Token.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # SECURITY: Prüfen ob User Admin des Teams ist
        if not verify_user_is_team_admin(created_by, team_id):
            raise PermissionError(
                "Keine Berechtigung zum Erstellen von Einladungen")

        # SECURITY: Prüfen ob Rolle zum Team gehört
        cursor.execute("""
            SELECT id FROM roles WHERE id = ? AND team_id = ?
        """, (role_id, team_id))
        if not cursor.fetchone():
            raise ValueError("Rolle gehört nicht zum Team")

        # Kryptographisch sicherer Token
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now() + timedelta(days=days_valid)).isoformat()

        # Limits anwenden
        max_uses = min(max_uses, SecurityConfig.INVITATION_MAX_USES)
        days_valid = min(days_valid, 30)

        cursor.execute("""
            INSERT INTO invitations (team_id, role_id, token, created_by, max_uses, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (team_id, role_id, token, created_by, max_uses, expires_at))

        conn.commit()

        logger.info(
            f"Invitation created: team_id={team_id}, role_id={role_id}, created_by={created_by}")
        return token


def use_invitation(token: str, user_id: int) -> Dict[str, Any]:
    """
    Nutzt eine Einladung zum Team-Beitritt.
    SECURITY: Alle Prüfungen serverseitig.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Einladung prüfen
        cursor.execute("""
            SELECT * FROM invitations WHERE token = ? AND is_active = 1
        """, (token,))
        invitation = cursor.fetchone()

        if not invitation:
            logger.warning(
                f"Invalid invitation token attempted: user_id={user_id}")
            return {"success": False, "error": "Ungültige Einladung"}

        # Ablauf prüfen
        if invitation["expires_at"]:
            expires = datetime.fromisoformat(invitation["expires_at"])
            if expires < datetime.now():
                return {"success": False, "error": "Einladung abgelaufen"}

        # Nutzungslimit prüfen
        if invitation["uses"] >= invitation["max_uses"]:
            return {"success": False, "error": "Einladungslimit erreicht"}

        # Bereits im Team?
        cursor.execute("""
            SELECT id FROM team_members WHERE team_id = ? AND user_id = ?
        """, (invitation["team_id"], user_id))
        if cursor.fetchone():
            return {"success": False, "error": "Du bist bereits Mitglied dieses Teams"}

        # Rolle serverseitig festschreiben (Spieler fuer Einladungsbeitritt)
        cursor.execute("""
            SELECT id FROM roles WHERE team_id = ? AND LOWER(name) = 'spieler'
        """, (invitation["team_id"],))
        player_role = cursor.fetchone()
        role_id = player_role["id"] if player_role else invitation["role_id"]

        # Team beitreten
        cursor.execute("""
            INSERT INTO team_members (team_id, user_id, role_id)
            VALUES (?, ?, ?)
        """, (invitation["team_id"], user_id, role_id))

        # Nutzung erhöhen
        cursor.execute("""
            UPDATE invitations SET uses = uses + 1 WHERE id = ?
        """, (invitation["id"],))

        conn.commit()

        logger.info(
            f"User joined team: user_id={user_id}, team_id={invitation['team_id']}")
        return {"success": True}


# ============================================
# Audit Log Functions (Erweitert)
# ============================================

def log_audit_event(user_id: Optional[int], action: str, resource_type: str = None,
                    resource_id: int = None, details: str = None,
                    ip_address: str = None, user_agent: str = None,
                    event_type: str = None, severity: str = "INFO",
                    request_id: str = None, session_id: str = None) -> None:
    """
    Loggt ein Security-relevantes Event.
    SECURITY AUDIT: Alle wichtigen Aktionen protokollieren.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (event_type, user_id, action, resource_type, resource_id, 
                                   details, ip_address, user_agent, severity, request_id, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_type[:50] if event_type else action[:50],
            user_id,
            action[:100] if action else None,
            resource_type[:50] if resource_type else None,
            resource_id,
            details[:5000] if details else None,
            ip_address[:45] if ip_address else None,
            user_agent[:500] if user_agent else None,
            severity,
            request_id[:50] if request_id else None,
            session_id[:100] if session_id else None
        ))
        conn.commit()


def log_security_event(event_type: str, ip_address: str,
                       user_agent: str = None, details: str = None,
                       blocked: bool = False) -> None:
    """
    Loggt ein Security-Event (Rate Limits, IP Blocks, etc.).
    SECURITY: Für High-Volume Events.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_events (event_type, ip_address, user_agent, details, blocked)
            VALUES (?, ?, ?, ?, ?)
        """, (
            event_type[:50] if event_type else None,
            ip_address[:45] if ip_address else "",
            user_agent[:500] if user_agent else None,
            details[:2000] if details else None,
            1 if blocked else 0
        ))
        conn.commit()


def get_audit_log(user_id: int = None, event_type: str = None,
                  severity: str = None, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Holt Audit-Log Einträge mit Filtern.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


# ============================================
# Two-Factor Authentication Functions
# ============================================

def setup_2fa(user_id: int, totp_secret: str, backup_codes_hash: str) -> bool:
    """
    Richtet 2FA für einen User ein.
    SECURITY: Secret wird im Klartext gespeichert (nur mit DB-Zugriff lesbar).
    Backup-Codes werden gehashed gespeichert.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Prüfe ob bereits existiert
        cursor.execute("SELECT id FROM user_2fa WHERE user_id = ?", (user_id,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE user_2fa SET 
                    totp_secret = ?,
                    backup_codes = ?,
                    is_enabled = 0,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (totp_secret, backup_codes_hash, user_id))
        else:
            cursor.execute("""
                INSERT INTO user_2fa (user_id, totp_secret, backup_codes, is_enabled)
                VALUES (?, ?, ?, 0)
            """, (user_id, totp_secret, backup_codes_hash))

        conn.commit()
        logger.info(f"2FA setup initiated for user_id={user_id}")
        return True


def enable_2fa(user_id: int) -> bool:
    """
    Aktiviert 2FA nach erfolgreicher Verifikation.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE user_2fa SET 
                is_enabled = 1,
                enabled_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND totp_secret IS NOT NULL
        """, (user_id,))
        conn.commit()

        log_audit_event(user_id, "2FA_ENABLED", "user", user_id,
                        severity="INFO", event_type="2FA_ENABLED")
        return cursor.rowcount > 0


def disable_2fa(user_id: int) -> bool:
    """
    Deaktiviert 2FA für einen User.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE user_2fa SET 
                is_enabled = 0,
                totp_secret = NULL,
                backup_codes = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        """, (user_id,))
        conn.commit()

        log_audit_event(user_id, "2FA_DISABLED", "user", user_id,
                        severity="WARNING", event_type="2FA_DISABLED")
        return True


def get_user_2fa(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Holt 2FA-Daten für einen User.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT totp_secret, is_enabled, backup_codes, last_used_code, 
                   last_verified_at, enabled_at
            FROM user_2fa 
            WHERE user_id = ?
        """, (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def is_2fa_enabled(user_id: int) -> bool:
    """
    Prüft ob 2FA für einen User aktiviert ist.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT is_enabled FROM user_2fa WHERE user_id = ? AND is_enabled = 1
        """, (user_id,))
        return cursor.fetchone() is not None


def update_2fa_last_used(user_id: int, code: str) -> None:
    """
    Aktualisiert den zuletzt verwendeten Code (Replay-Schutz).
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE user_2fa SET 
                last_used_code = ?,
                last_verified_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        """, (code, user_id))
        conn.commit()


def check_replay_attack(user_id: int, code: str) -> bool:
    """
    Prüft ob ein TOTP-Code bereits verwendet wurde.
    SECURITY: Verhindert Replay-Attacks.
    Returns: True wenn Replay-Attack erkannt.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT last_used_code FROM user_2fa WHERE user_id = ?
        """, (user_id,))
        row = cursor.fetchone()

        if row and row["last_used_code"] == code:
            logger.warning(f"Replay attack detected for user_id={user_id}")
            return True
        return False


def use_backup_code(user_id: int, code: str, codes_hash: str) -> bool:
    """
    Markiert einen Backup-Code als verwendet.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE user_2fa SET 
                backup_codes = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        """, (codes_hash, user_id))
        conn.commit()

        log_audit_event(user_id, "BACKUP_CODE_USED", "user", user_id,
                        severity="WARNING", event_type="2FA_BACKUP")
        return cursor.rowcount > 0


# ============================================
# DSGVO Functions - Soft Delete & Anonymization
# ============================================

def soft_delete_user(user_id: int) -> bool:
    """
    Führt Soft Delete eines Users durch.
    DSGVO: Daten werden anonymisiert, nicht gelöscht.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Anonymisieren statt Löschen
        cursor.execute("""
            UPDATE users SET
                email = 'deleted_' || id || '@deleted.local',
                password_hash = 'DELETED_HASH_PLACEHOLDER_XXXXXXXXXXXXXXXXXXXXXXXXX',
                vorname = '',
                nachname = '',
                is_active = 0,
                deleted_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND deleted_at IS NULL
        """, (user_id,))

        # Aus Teams entfernen
        cursor.execute("""
            DELETE FROM team_members WHERE user_id = ?
        """, (user_id,))

        conn.commit()

        log_audit_event(user_id, "USER_DELETED", "user", user_id)
        logger.info(f"User soft-deleted: user_id={user_id}")

        return cursor.rowcount > 0


def export_user_data(user_id: int) -> Dict[str, Any]:
    """
    Exportiert alle Daten eines Users.
    DSGVO: Auskunftsrecht.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # User-Daten
        cursor.execute("""
            SELECT id, email, vorname, nachname, verein, mannschaft, rolle,
                   created_at, last_login_at
            FROM users WHERE id = ?
        """, (user_id,))
        user = cursor.fetchone()

        if not user:
            return {}

        # Team-Mitgliedschaften
        cursor.execute("""
            SELECT t.name, r.name as role_name, tm.joined_at
            FROM team_members tm
            JOIN teams t ON tm.team_id = t.id
            JOIN roles r ON tm.role_id = r.id
            WHERE tm.user_id = ?
        """, (user_id,))
        memberships = cursor.fetchall()

        return {
            "user": dict(user),
            "team_memberships": [dict(m) for m in memberships]
        }


# ============================================
# PERFORMANCE: Log Cleanup & Maintenance
# ============================================

def cleanup_old_logs(days_to_keep: int = 30) -> Dict[str, int]:
    """
    Löscht alte Log-Einträge für Performance.
    SECURITY: Behält kritische Events länger.

    Args:
        days_to_keep: Tage für normale Logs (kritische: 90 Tage)

    Returns:
        Anzahl gelöschter Einträge pro Tabelle
    """
    deleted = {}

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Login Attempts älter als 7 Tage
        cursor.execute("""
            DELETE FROM login_attempts 
            WHERE attempted_at < datetime('now', '-7 days')
        """)
        deleted["login_attempts"] = cursor.rowcount

        # Security Events älter als 30 Tage (außer blocked)
        cursor.execute("""
            DELETE FROM security_events 
            WHERE created_at < datetime('now', '-30 days')
            AND blocked = 0
        """)
        deleted["security_events"] = cursor.rowcount

        # Audit Log: Normale Events nach X Tagen, kritische nach 90
        cursor.execute(f"""
            DELETE FROM audit_log 
            WHERE created_at < datetime('now', '-{days_to_keep} days')
            AND severity IN ('DEBUG', 'INFO')
        """)
        deleted["audit_log_normal"] = cursor.rowcount

        cursor.execute("""
            DELETE FROM audit_log 
            WHERE created_at < datetime('now', '-90 days')
            AND severity IN ('WARNING', 'ERROR', 'CRITICAL')
        """)
        deleted["audit_log_critical"] = cursor.rowcount

        conn.commit()

        # VACUUM für Speicherfreigabe (nur periodisch)
        try:
            conn.execute("VACUUM")
        except:
            pass  # Kann bei laufenden Transaktionen fehlschlagen

    logger.info(f"Log cleanup completed: {deleted}")
    return deleted


def get_database_stats() -> Dict[str, Any]:
    """
    Gibt Datenbank-Statistiken für Monitoring zurück.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        stats = {}

        # Tabellen-Größen
        tables = [
            "users", "teams", "team_members", "players",
            "calendar_events", "messages", "videos",
            "audit_log", "security_events", "login_attempts"
        ]

        for table in tables:
            try:
                cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                stats[f"{table}_count"] = cursor.fetchone()["count"]
            except:
                stats[f"{table}_count"] = 0

        # Aktive Vereine (Teams)
        cursor.execute("""
            SELECT COUNT(*) as count FROM teams 
            WHERE deleted_at IS NULL AND is_active = 1
        """)
        stats["active_teams"] = cursor.fetchone()["count"]

        # Aktive User
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE deleted_at IS NULL AND is_active = 1
        """)
        stats["active_users"] = cursor.fetchone()["count"]

        return stats
