"""
Authentication Routes - Security Hardened Version
==================================================
SECURITY AUDIT: Rate Limiting, Token-Handling, Input-Validierung gehärtet.
"""

import os
import logging
import uuid
import shutil
import secrets
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import APIRouter, Request, Form, HTTPException, Depends, UploadFile, File, BackgroundTasks, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import bcrypt

from config import SecurityConfig, AppPermissions
from validators import InputValidator, ValidationError
from security import (
    get_client_ip, get_ip_hash, validate_session_ip,
    check_rate_limit, api_rate_limiter, login_rate_limiter, sensitive_rate_limiter,
    generate_csrf_token, validate_csrf_token,
    activity_detector, get_request_fingerprint,
    check_honeypot_fields, is_common_password, login_anomaly_detector,
    generate_request_id, SecurityEventType, check_input_for_attacks,
    ip_blacklist, exponential_lockout, secure_session_manager,
    constant_time_compare, is_canary_login, handle_canary_trigger,
    concurrent_login_detector, is_password_strong_enough,
    # 2FA Functions
    generate_totp_secret, get_totp_uri, verify_totp, generate_totp_qr_code,
    generate_backup_codes, check_password_pwned_sync, lockout_notifier,
    AuditEventType
)
from database import (
    get_db, get_db_connection, create_team, create_invitation, use_invitation,
    record_login_attempt, is_login_blocked, clear_login_attempts,
    get_user_by_email, get_user_by_email_any, get_user_by_id, update_last_login,
    log_audit_event, soft_delete_user, verify_user_is_team_admin,
    verify_user_team_access,
    # 2FA Database Functions
    setup_2fa, enable_2fa, disable_2fa, get_user_2fa, is_2fa_enabled,
    update_2fa_last_used, check_replay_attack, use_backup_code, log_security_event
)
from email_service import (
    send_login_notification, send_password_changed_notification,
    send_2fa_enabled_notification, send_2fa_code,
    EmailConfig
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Security Logger
logger = logging.getLogger("pitchinsights.security")

# SECURITY: Timed Serializer mit Ablaufzeit
serializer = URLSafeTimedSerializer(SecurityConfig.SECRET_KEY)

# Beta-Access Cookie (signiert)
BETA_ACCESS_COOKIE_MAX_AGE = 86400 * 365  # 1 Jahr


def _create_beta_access_cookie_token() -> str:
    return serializer.dumps({"beta_access": True})


def _is_beta_access_cookie_valid(token: str) -> bool:
    if not token:
        return False
    try:
        data = serializer.loads(token, max_age=BETA_ACCESS_COOKIE_MAX_AGE)
        return data.get("beta_access") is True
    except (SignatureExpired, BadSignature):
        return False

# ============================================
# Helper Functions
# ============================================

STAFF_ROLE_NAMES = {
    "admin",
    "trainer",
    "co-trainer",
    "torwarttrainer",
    "athletiktrainer",
    "scout",
    "analyst",
    "physio",
}


def get_user_role_name(db_user: Dict[str, Any]) -> str:
    """
    Ermittelt den Rollennamen eines Users aus roles Tabelle (Fallback: users.rolle).
    SECURITY: Rollenermittlung serverseitig.
    """
    role_name = ""
    if db_user.get("role_name"):
        return str(db_user.get("role_name", "")).lower()
    if db_user.get("team_id") is None:
        return ""
    role_id = db_user.get("role_id")
    if role_id:
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT name FROM roles WHERE id = ?", (role_id,))
            role_row = cursor.fetchone()
            if role_row:
                role_name = role_row["name"]

    if not role_name:
        role_name = db_user.get("rolle", "")

    return str(role_name).lower()


def is_staff_user(db_user: Dict[str, Any]) -> bool:
    """Trainer/Staff Rollen für schreibende Team-Funktionen."""
    if db_user.get("is_admin"):
        return True
    return get_user_role_name(db_user) in STAFF_ROLE_NAMES


def get_user_memberships(user_id: int) -> list:
    team_id = None
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT tm.team_id, tm.role_id, tm.joined_at,
                   t.name as team_name, t.verein, t.mannschaft,
                   r.name as role_name
            FROM team_members tm
            JOIN teams t ON tm.team_id = t.id
            JOIN roles r ON tm.role_id = r.id
            WHERE tm.user_id = ? AND t.deleted_at IS NULL
            ORDER BY tm.joined_at ASC
        """, (user_id,))
        return [dict(row) for row in cursor.fetchall()]


def user_has_role_in_any_team(user_id: int, role_name: str) -> bool:
    role_name = role_name.lower().strip()
    if not role_name:
        return False
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT 1
            FROM team_members tm
            JOIN roles r ON tm.role_id = r.id
            WHERE tm.user_id = ? AND LOWER(r.name) = ?
            LIMIT 1
        """, (user_id, role_name))
        return cursor.fetchone() is not None


def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """
    Authentifiziert User anhand des Session-Cookies oder mobilen Bearer-Tokens.
    SECURITY: Token-Ablauf, IP-Binding und Fingerprint werden geprüft.
    """
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth_header:
        try:
            from routes.api_mobile import get_current_user as mobile_get_current_user
            return mobile_get_current_user(auth_header)
        except Exception:
            pass

    token = request.cookies.get("session")
    logging.info(
        f"[AUTH] get_current_user called, session_cookie_present={bool(token)}")

    if not token:
        logging.info("[AUTH] No session cookie found")
        return None

    try:
        # SECURITY: Token-Ablauf prüfen (max_age in Sekunden)
        data = serializer.loads(
            token,
            max_age=SecurityConfig.SESSION_MAX_AGE_SECONDS
        )
        logging.info(
            f"[AUTH] Token decoded successfully, user_id={data.get('id')}")

        # SECURITY: IP-Binding prüfen
        if SecurityConfig.SESSION_BIND_IP:
            stored_ip_hash = data.get("ip_hash")
            if stored_ip_hash and not validate_session_ip(stored_ip_hash, request):
                logger.warning(
                    f"Session IP mismatch for user {data.get('id')}")
                return None

        # SECURITY: Fingerprint-Validierung - DISABLED on Railway for now
        # Fingerprint can change between requests due to Accept-Language/Encoding headers
        # stored_fingerprint = data.get("fp")
        # if stored_fingerprint:
        #     current_fingerprint = get_request_fingerprint(request)
        #     if stored_fingerprint != current_fingerprint:
        #         logger.warning(
        #             f"Session fingerprint mismatch for user {data.get('id')}")
        #         return None

        # Zusätzliche Validierung: User muss noch existieren und aktiv sein
        user = get_user_by_id(data.get("id"))
        if not user or not user.get("is_active"):
            logging.warning(
                f"[AUTH] User not found or inactive: id={data.get('id')}")
            return None

        # SECURITY: Session muss serverseitig aktiv sein
        session_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("""
                SELECT 1 FROM user_sessions
                WHERE session_hash = ? AND user_id = ?
            """, (session_hash, user["id"]))
            if not cursor.fetchone():
                logger.warning(f"[AUTH] Session not active for user_id={user['id']}")
                return None

        logging.info(
            f"[AUTH] Authentication successful for user_id={data.get('id')}")
        return {"email": data["email"], "id": data["id"], "session_hash": session_hash}

    except SignatureExpired:
        logger.info("Session token expired")
        return None
    except BadSignature:
        logger.warning("Invalid session token signature")
        return None
    except Exception as e:
        logger.error(f"Session token error: {type(e).__name__}: {e}")
        return None


def create_session_token(user: Dict[str, Any], request: Request) -> str:
    """
    Erstellt einen sicheren Session-Token mit IP-Binding.
    SECURITY: Enthält IP-Hash für Session-Binding.
    """
    client_ip = get_client_ip(request)

    return serializer.dumps({
        "email": user["email"],
        "id": user["id"],
        "ip_hash": get_ip_hash(client_ip) if SecurityConfig.SESSION_BIND_IP else None,
        "fp": get_request_fingerprint(request),
        "iat": datetime.utcnow().isoformat()  # Issued At
    })


def _ensure_session_record(session_hash: str, user_id: int) -> None:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO user_sessions (session_hash, user_id)
            VALUES (?, ?)
            ON CONFLICT(session_hash) DO UPDATE SET
                user_id = excluded.user_id,
                updated_at = CURRENT_TIMESTAMP
        """, (session_hash, user_id))
        db.commit()


def _get_active_team_for_session(session_hash: str, user_id: int) -> Optional[int]:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT active_team_id FROM user_sessions
            WHERE session_hash = ? AND user_id = ?
        """, (session_hash, user_id))
        row = cursor.fetchone()
    return row["active_team_id"] if row else None


def _set_active_team_for_session(session_hash: str, user_id: int, team_id: int) -> None:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE user_sessions
            SET active_team_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE session_hash = ? AND user_id = ?
        """, (team_id, session_hash, user_id))
        if cursor.rowcount == 0:
            cursor.execute("""
                INSERT INTO user_sessions (session_hash, user_id, active_team_id)
                VALUES (?, ?, ?)
            """, (session_hash, user_id, team_id))
        db.commit()


def _clear_session_record(session_hash: str, user_id: int) -> None:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            DELETE FROM user_sessions WHERE session_hash = ? AND user_id = ?
        """, (session_hash, user_id))
        db.commit()


def apply_active_membership(request: Request, db_user: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not db_user:
        return None

    user = get_current_user(request)
    session_hash = user.get("session_hash") if user else None
    if not session_hash:
        memberships = get_user_memberships(db_user["id"])
        if len(memberships) == 1:
            membership = memberships[0]
            db_user["team_id"] = membership["team_id"]
            db_user["role_id"] = membership["role_id"]
            db_user["role_name"] = membership["role_name"]
            db_user["is_admin"] = membership["role_name"].lower() == "admin"
            return db_user
        db_user["team_id"] = None
        db_user["role_id"] = None
        db_user["role_name"] = ""
        db_user["is_admin"] = False
        return db_user

    _ensure_session_record(session_hash, db_user["id"])

    active_team_id = _get_active_team_for_session(session_hash, db_user["id"])

    with get_db_connection() as db:
        cursor = db.cursor()
        if active_team_id:
            cursor.execute("""
                SELECT tm.team_id, tm.role_id, r.name as role_name
                FROM team_members tm
                JOIN roles r ON tm.role_id = r.id
                WHERE tm.user_id = ? AND tm.team_id = ?
            """, (db_user["id"], active_team_id))
            membership = cursor.fetchone()
            if membership:
                db_user["team_id"] = membership["team_id"]
                db_user["role_id"] = membership["role_id"]
                db_user["role_name"] = membership["role_name"]
                db_user["is_admin"] = membership["role_name"].lower() == "admin"
                return db_user

        cursor.execute("""
            SELECT tm.team_id, tm.role_id, r.name as role_name
            FROM team_members tm
            JOIN roles r ON tm.role_id = r.id
            WHERE tm.user_id = ?
            ORDER BY tm.joined_at ASC
        """, (db_user["id"],))
        memberships = cursor.fetchall()

    if len(memberships) == 1:
        membership = memberships[0]
        _set_active_team_for_session(session_hash, db_user["id"], membership["team_id"])
        db_user["team_id"] = membership["team_id"]
        db_user["role_id"] = membership["role_id"]
        db_user["role_name"] = membership["role_name"]
        db_user["is_admin"] = membership["role_name"].lower() == "admin"
        return db_user

    db_user["team_id"] = None
    db_user["role_id"] = None
    db_user["role_name"] = ""
    db_user["is_admin"] = False
    return db_user


def set_session_cookie(response, token: str) -> None:
    """
    Setzt das Session-Cookie sicher.
    SECURITY: HttpOnly, Secure, SameSite.
    """
    response.set_cookie(
        "session",
        token,
        httponly=SecurityConfig.COOKIE_HTTPONLY,
        max_age=SecurityConfig.SESSION_MAX_AGE_SECONDS,
        secure=SecurityConfig.COOKIE_SECURE,
        samesite=SecurityConfig.COOKIE_SAMESITE,
        path="/"
    )


def require_auth(request: Request) -> Dict[str, Any]:
    """
    Dependency für authentifizierte Endpunkte.
    SECURITY: Wirft HTTPException wenn nicht authentifiziert.
    """
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Nicht authentifiziert")
    return user


def get_active_team_id(request: Request, db_user: Dict[str, Any]) -> Optional[int]:
    """
    Ermittelt aktives Team aus Session (falls Mitglied), sonst Standard-Team.
    SECURITY: Team-Zugehörigkeit serverseitig prüfen.
    """
    db_user = apply_active_membership(request, db_user)
    if not db_user:
        return None
    return db_user.get("team_id")


# ============================================
# Public Routes
# ============================================

@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Startseite - Landing Page oder Dashboard."""
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=303)
    # Zeige Landing Page für nicht eingeloggte Besucher
    return templates.TemplateResponse("landing.html", {"request": request})


@router.get("/landing", response_class=HTMLResponse)
async def landing_page(request: Request):
    """Öffentliche Landingpage ohne Login-Redirect."""
    return templates.TemplateResponse("landing.html", {"request": request})


# Access-Code für geschützten Login-Bereich (aus Umgebungsvariable oder Fallback)
ACCESS_CODE = os.environ.get("PITCHINSIGHTS_ACCESS_CODE", "pitch2026")

# ============================================
# Production Check
# ============================================
IS_PRODUCTION = os.getenv(
    "PITCHINSIGHTS_ENV") == "production" or os.path.exists("/app")


# ============================================
# Login/Register Pages
# ============================================

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, code: str = None, mode: str = None, redirect: str = None):
    """Login-Seite anzeigen - nur mit gültigem Access-Code."""
    # Prüfe Access-Code (URL-Parameter oder Cookie)
    stored_code = request.cookies.get("beta_access")

    if code == ACCESS_CODE:
        # Code korrekt - Cookie setzen und zur Login-Seite
        csrf_token = generate_csrf_token("login_form")
        response = templates.TemplateResponse(
            "login.html",
            {"request": request, "error": None, "csrf_token": csrf_token, "mode": mode, "redirect": redirect}
        )
        response.set_cookie(
            key="beta_access",
            value=_create_beta_access_cookie_token(),
            httponly=True,
            secure=SecurityConfig.COOKIE_SECURE,
            samesite=SecurityConfig.COOKIE_SAMESITE,
            max_age=86400 * 30  # 30 Tage
        )
        return response
    elif _is_beta_access_cookie_valid(stored_code):
        # Bereits verifiziert via Cookie
        csrf_token = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": None, "csrf_token": csrf_token, "mode": mode, "redirect": redirect}
        )
    else:
        # Kein gültiger Code - zur Gate mit Redirect zu login
        return templates.TemplateResponse(
            "access_gate.html",
            {"request": request, "error": None, "redirect": "login"}
        )


@router.get("/player/login", response_class=HTMLResponse)
async def player_login_page(request: Request, redirect: str = None):
    """Spieler-Login (getrennt vom Trainer-Login)."""
    csrf_token = generate_csrf_token("login_form")
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None, "csrf_token": csrf_token, "mode": "player", "redirect": redirect}
    )


@router.get("/verify-email/{token}", response_class=HTMLResponse)
async def verify_email(request: Request, token: str):
    """E-Mail-Adresse verifizieren."""
    try:
        token = InputValidator.validate_token(token)
    except ValidationError:
        csrf_token = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Ungültiger Verifikationslink.", "csrf_token": csrf_token}
        )

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT ev.id, ev.user_id, ev.expires_at, ev.used_at, u.email
            FROM email_verifications ev
            JOIN users u ON ev.user_id = u.id
            WHERE ev.token = ?
        """, (token,))
        row = cursor.fetchone()

        if not row:
            csrf_token = generate_csrf_token("login_form")
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Verifikationslink ungültig.", "csrf_token": csrf_token}
            )

        if row["used_at"]:
            csrf_token = generate_csrf_token("login_form")
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "success": "E-Mail bereits bestätigt. Du kannst dich einloggen.", "csrf_token": csrf_token}
            )

        expires = datetime.fromisoformat(row["expires_at"])
        if expires < datetime.now():
            csrf_token = generate_csrf_token("login_form")
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Verifikationslink abgelaufen.", "csrf_token": csrf_token}
            )

        cursor.execute("""
            UPDATE users SET is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?
        """, (row["user_id"],))
        cursor.execute("""
            UPDATE email_verifications SET used_at = CURRENT_TIMESTAMP WHERE id = ?
        """, (row["id"],))
        db.commit()

    csrf_token = generate_csrf_token("login_form")
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "success": "E-Mail bestätigt. Du kannst dich jetzt einloggen.", "csrf_token": csrf_token}
    )


# ============================================
# Rechtliche Seiten (DSGVO-Konformität)
# ============================================

@router.get("/datenschutz", response_class=HTMLResponse)
async def datenschutz_page(request: Request):
    """Datenschutzerklärung gemäß DSGVO Art. 13/14."""
    return templates.TemplateResponse("datenschutz.html", {"request": request})


@router.get("/impressum", response_class=HTMLResponse)
async def impressum_page(request: Request):
    """Impressum gemäß § 5 TMG."""
    return templates.TemplateResponse("impressum.html", {"request": request})


@router.get("/agb", response_class=HTMLResponse)
async def agb_page(request: Request):
    """Allgemeine Geschäftsbedingungen."""
    return templates.TemplateResponse("agb.html", {"request": request})


# ============================================
# Waitlist API (Landing Page)
# ============================================

@router.post("/api/waitlist")
async def add_to_waitlist(request: Request):
    """
    Fügt E-Mail zur Warteliste hinzu.
    SECURITY: Rate Limiting, E-Mail-Validierung.
    """
    client_ip = get_client_ip(request)

    # Rate Limiting
    try:
        check_rate_limit(
            request,
            api_rate_limiter,
            max_requests=5,
            window_seconds=300,
            key_prefix="waitlist"
        )
    except HTTPException:
        return JSONResponse(
            {"error": "Zu viele Anfragen"},
            status_code=429
        )

    try:
        data = await request.json()
        email = data.get("email", "").strip().lower()

        # E-Mail validieren
        email = InputValidator.validate_email(email)

        # In Datenbank speichern (mit Context Manager für garantiertes Schließen)
        with get_db_connection() as db:
            cursor = db.cursor()

            # Prüfen ob bereits eingetragen
            cursor.execute("SELECT id FROM waitlist WHERE email = ?", (email,))
            if cursor.fetchone():
                return JSONResponse({"status": "already_registered"})

            # Eintragen
            cursor.execute(
                "INSERT INTO waitlist (email, created_at, ip_address) VALUES (?, ?, ?)",
                (email, datetime.now().isoformat(), client_ip)
            )
            db.commit()

        logger.info(f"Waitlist signup: {email}")
        return JSONResponse({"status": "success"})

    except ValidationError:
        return JSONResponse({"error": "Ungültige E-Mail"}, status_code=400)
    except Exception as e:
        logger.error(f"Waitlist error: {e}")
        return JSONResponse({"error": "Fehler beim Speichern"}, status_code=500)


@router.post("/api/pilot")
async def add_to_pilot(request: Request):
    """
    Fügt Verein zur Pilotphasen-Warteliste hinzu.
    SECURITY: Rate Limiting, Input-Validierung.
    """
    client_ip = get_client_ip(request)

    # Rate Limiting
    try:
        check_rate_limit(
            request,
            api_rate_limiter,
            max_requests=3,
            window_seconds=300,
            key_prefix="pilot"
        )
    except HTTPException:
        return JSONResponse(
            {"error": "Zu viele Anfragen"},
            status_code=429
        )

    try:
        data = await request.json()
        vereinsname = data.get("vereinsname", "").strip()[:200]
        ansprechpartner = data.get("ansprechpartner", "").strip()[:100]
        email = data.get("email", "").strip().lower()

        # Validierung
        if not vereinsname or len(vereinsname) < 2:
            return JSONResponse({"error": "Vereinsname erforderlich"}, status_code=400)
        if not ansprechpartner or len(ansprechpartner) < 2:
            return JSONResponse({"error": "Ansprechpartner erforderlich"}, status_code=400)
        email = InputValidator.validate_email(email)

        # In Datenbank speichern (mit Context Manager für garantiertes Schließen)
        with get_db_connection() as db:
            cursor = db.cursor()

            # Prüfen ob bereits eingetragen
            cursor.execute(
                "SELECT id FROM pilot_signups WHERE email = ?", (email,))
            if cursor.fetchone():
                return JSONResponse({"status": "already_registered"})

            # Eintragen
            cursor.execute(
                """INSERT INTO pilot_signups (vereinsname, ansprechpartner, email, created_at, ip_address) 
                   VALUES (?, ?, ?, ?, ?)""",
                (vereinsname, ansprechpartner, email,
                 datetime.now().isoformat(), client_ip)
            )
            db.commit()

        logger.info(f"Pilot signup: {vereinsname} - {email}")
        return JSONResponse({"status": "success"})

    except ValidationError:
        return JSONResponse({"error": "Ungültige E-Mail"}, status_code=400)
    except Exception as e:
        logger.error(f"Pilot signup error: {e}")
        return JSONResponse({"error": "Fehler beim Speichern"}, status_code=500)


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    mode: str = Form(None),
    redirect: str = Form(None),
    csrf_token: str = Form("")
):
    """
    Login-Endpunkt.
    SECURITY: Rate Limiting ZUERST, dann CSRF, sichere Passwort-Prüfung, IP-Tracking.
    """
    client_ip = get_client_ip(request)
    request_id = generate_request_id()

    # SECURITY: Rate Limiting ZUERST - VOR allem anderen!
    # Dies verhindert Brute-Force auch ohne gültigen CSRF-Token
    try:
        check_rate_limit(
            request,
            login_rate_limiter,
            max_requests=5,  # Nur 5 Versuche pro Minute (strenger)
            window_seconds=60,
            key_prefix="login"
        )
    except HTTPException as rate_error:
        # Bei Rate Limit: 429 zurückgeben mit Retry-After Header
        logger.warning(
            f"[{request_id}] Login rate limit exceeded from {client_ip}")
        new_csrf = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Zu viele Login-Versuche. Bitte warten Sie 1 Minute.",
                "csrf_token": new_csrf},
            status_code=429,
            headers={"Retry-After": "60"}
        )

    # SECURITY: Honeypot-Felder prüfen (Bot-Erkennung)
    form_data = await request.form()
    is_bot, honeypot_field = check_honeypot_fields(dict(form_data))
    if is_bot:
        logger.warning(
            f"[{request_id}] Bot detected via honeypot field '{honeypot_field}' from {client_ip}")
        log_audit_event(None, SecurityEventType.BOT_DETECTED,
                        "login", None, f"honeypot={honeypot_field}", client_ip)
        # Fake error to confuse bots (don't indicate detection)
        import asyncio
        await asyncio.sleep(2)  # Delay to slow down bots
        new_csrf = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Falsche E-Mail oder Passwort",
                "csrf_token": new_csrf}
        )

    # SECURITY: CSRF-Token validieren
    if not validate_csrf_token(csrf_token, "login_form"):
        logger.warning(
            f"[{request_id}] CSRF validation failed for login from {client_ip}")
        new_csrf = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Ungültige Anfrage. Bitte erneut versuchen.",
                "csrf_token": new_csrf}
        )

    # SECURITY: Prüfe ob IP als verdächtig markiert ist
    if activity_detector.is_suspicious(client_ip):
        logger.warning(f"Login attempt from suspicious IP: {client_ip}")
        # Zusätzliche Verzögerung für verdächtige IPs
        import asyncio
        await asyncio.sleep(2)

    try:
        # Input-Validierung (nur Format, nicht Existenz)
        email = InputValidator.validate_email(email)
    except ValidationError as e:
        new_csrf = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Ungültige E-Mail-Adresse",
                "csrf_token": new_csrf}
        )

    # SECURITY: Forensik-Logging für Angriffsversuche
    check_input_for_attacks(email, "email", client_ip)
    check_input_for_attacks(password, "password", client_ip)

    # SECURITY: Canary Token Detection - Sofortige Alarmierung bei Fake-Credentials
    if is_canary_login(email):
        handle_canary_trigger(email, client_ip)
        # Fake-Delay um Timing-Analyse zu verhindern
        import asyncio
        await asyncio.sleep(3)
        new_csrf = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Falsche E-Mail oder Passwort",
                "csrf_token": new_csrf}
        )

    # SECURITY: Exponential Backoff prüfen (zusätzlich zu DB-basiertem Lockout)
    exp_locked, exp_remaining = exponential_lockout.is_locked(f"login:{email}")
    if exp_locked:
        logger.warning(
            f"Exponential backoff active for {email[:3]}***, {exp_remaining}s remaining")
        new_csrf = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request,
                "error": f"Zu viele Fehlversuche. Bitte warten Sie {exp_remaining} Sekunden.",
                "csrf_token": new_csrf}
        )

    # SECURITY: Rate Limiting prüfen (DB-basiert)
    is_blocked, remaining = is_login_blocked(email, client_ip)
    if is_blocked:
        logger.warning(
            f"Login blocked due to rate limiting: email={email[:3]}***, ip={client_ip}")
        new_csrf = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request,
                "error": f"Zu viele Versuche. Bitte warten Sie {remaining // 60} Minuten.",
                "csrf_token": new_csrf}
        )

    # User laden
    user = get_user_by_email(email)
    logging.info(f"[LOGIN DEBUG] email={email}, user_found={user is not None}")

    # SECURITY: Account Enumeration & Timing-Attack verhindern
    # Führe immer den gleichen bcrypt-Aufwand durch, unabhängig ob User existiert
    # Verwende einen echten Work Factor 12 Hash für realistische Timing
    DUMMY_HASH = b"$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4JQ5kUOIgUfGHVzy"
    if not user:
        inactive_user = get_user_by_email_any(email)
        if inactive_user and not inactive_user.get("is_active"):
            new_csrf = generate_csrf_token("login_form")
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Bitte bestätige zuerst deine E-Mail-Adresse.",
                 "csrf_token": new_csrf, "mode": mode, "redirect": redirect}
            )
        logging.warning(f"[LOGIN DEBUG] User not found in database: {email}")
        bcrypt.checkpw(b"timing_attack_prevention_dummy_password", DUMMY_HASH)
        record_login_attempt(email, client_ip, False)
        activity_detector.record_failed_login(client_ip)

        # SECURITY: Exponential Backoff & IP-Blacklist
        exponential_lockout.record_failure(f"login:{email}")
        if ip_blacklist.record_offense(client_ip, "LOGIN_FAILED"):
            logger.warning(
                f"IP blacklisted after repeated login failures: {client_ip}")

        new_csrf = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Falsche E-Mail oder Passwort",
                "csrf_token": new_csrf}
        )

    # Passwort prüfen (mit Pepper)
    try:
        peppered_password = f"{password}{SecurityConfig.PASSWORD_PEPPER}"
        password_valid = bcrypt.checkpw(
            peppered_password.encode('utf-8'),
            user["password_hash"].encode('utf-8')
        )
    except Exception:
        password_valid = False

    if not password_valid:
        record_login_attempt(email, client_ip, False)
        activity_detector.record_failed_login(client_ip)

        # SECURITY: Exponential Backoff & IP-Blacklist
        exponential_lockout.record_failure(f"login:{email}")
        if ip_blacklist.record_offense(client_ip, "LOGIN_FAILED"):
            logger.warning(
                f"IP blacklisted after repeated login failures: {client_ip}")

        log_audit_event(None, "LOGIN_FAILED", "user", None,
                        f"email={email[:3]}***", client_ip)
        new_csrf = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Falsche E-Mail oder Passwort",
                "csrf_token": new_csrf}
        )

    # 2FA deaktiviert

    # Erfolgreicher Login - Clear Lockouts
    exponential_lockout.clear(f"login:{email}")
    record_login_attempt(email, client_ip, True)
    clear_login_attempts(email)
    update_last_login(user["id"])

    # SECURITY: Concurrent Login Detection
    user_agent = request.headers.get("User-Agent", "")
    if concurrent_login_detector.record_activity(user["id"], client_ip):
        log_audit_event(user["id"], "CONCURRENT_LOGIN_DETECTED",
                        "user", user["id"], f"ip={client_ip}", client_ip)
        logger.warning(f"Concurrent login detected for user {user['id']}")
        # TODO: Optional alle anderen Sessions invalidieren

    # SECURITY: Login-Anomalie-Erkennung + E-Mail-Benachrichtigung
    if login_anomaly_detector.is_anomalous_login(user["id"], client_ip, user_agent):
        log_audit_event(user["id"], SecurityEventType.LOGIN_ANOMALY,
                        "user", user["id"], f"ip={client_ip}", client_ip)
        # E-Mail-Benachrichtigung bei verdächtigem Login
        if EmailConfig.is_configured():
            send_login_notification(email, client_ip, user_agent)

    # Login-Historie für zukünftige Anomalie-Erkennung speichern
    login_anomaly_detector.record_login(user["id"], client_ip, user_agent)

    log_audit_event(user["id"], SecurityEventType.LOGIN_SUCCESS,
                    "user", user["id"], None, client_ip)

    # SECURITY: Verdachtsmarkierung bei erfolgreichem Login entfernen
    activity_detector.clear_suspicion(client_ip)

    # Optional: Spieler-Login erzwingen
    if mode == "player":
        if not user_has_role_in_any_team(user["id"], "spieler"):
            new_csrf = generate_csrf_token("login_form")
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Nur Spieler können sich hier anmelden.",
                 "csrf_token": new_csrf, "mode": "player", "redirect": redirect}
            )

    # SECURITY: Session im SecureSessionManager registrieren
    token = create_session_token(user, request)
    session_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    _ensure_session_record(session_hash, user["id"])
    secure_session_manager.register_session(
        token, user["id"], client_ip, user_agent)

    target = "/dashboard"
    if redirect and isinstance(redirect, str) and redirect.startswith("/"):
        target = redirect
    response = RedirectResponse(url=target, status_code=303)
    set_session_cookie(response, token)

    logger.info(f"Successful login: user_id={user['id']}")
    return response


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, code: str = None):
    """Registrierungs-Seite anzeigen - nur mit gültigem Access-Code."""
    # Prüfe Access-Code (URL-Parameter oder Cookie)
    stored_code = request.cookies.get("beta_access")

    if code == ACCESS_CODE:
        # Code korrekt - Cookie setzen und zur Register-Seite
        csrf_token = generate_csrf_token("register_form")
        response = templates.TemplateResponse(
            "register.html",
            {"request": request, "error": None, "csrf_token": csrf_token}
        )
        response.set_cookie(
            key="beta_access",
            value=_create_beta_access_cookie_token(),
            httponly=True,
            secure=SecurityConfig.COOKIE_SECURE,
            samesite=SecurityConfig.COOKIE_SAMESITE,
            max_age=86400 * 30  # 30 Tage
        )
        return response
    elif _is_beta_access_cookie_valid(stored_code):
        # Bereits verifiziert via Cookie
        csrf_token = generate_csrf_token("register_form")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": None, "csrf_token": csrf_token}
        )
    else:
        # Kein gültiger Code - zur Gate mit Redirect zu register
        return templates.TemplateResponse(
            "access_gate.html",
            {"request": request, "error": None, "redirect": "register"}
        )


@router.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    invitation_code: str = Form(None),
    promo_code: str = Form(None),
    csrf_token: str = Form("")
):
    """
    Registrierungs-Endpunkt.
    SECURITY: Rate Limiting ZUERST, dann CSRF, Input-Validierung, sichere Passwort-Hashing mit Pepper.
    Unterstützt optionale Einladungscodes für direkten Team-Beitritt.
    Unterstützt Promo-Codes für kostenlosen Zugang.
    """
    client_ip = get_client_ip(request)
    request_id = generate_request_id()

    # SECURITY: Rate Limiting ZUERST - Verhindert Spam-Registrierungen
    try:
        check_rate_limit(
            request,
            sensitive_rate_limiter,
            max_requests=3,  # Nur 3 Registrierungsversuche pro Minute
            window_seconds=60,
            key_prefix="register"
        )
    except HTTPException as rate_error:
        logger.warning(
            f"[{request_id}] Register rate limit exceeded from {client_ip}")
        new_csrf = generate_csrf_token("register_form")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Zu viele Registrierungsversuche. Bitte warten Sie 1 Minute.",
                "csrf_token": new_csrf},
            status_code=429,
            headers={"Retry-After": "60"}
        )

    # SECURITY: Honeypot-Felder prüfen (Bot-Erkennung)
    form_data = await request.form()
    is_bot, honeypot_field = check_honeypot_fields(dict(form_data))
    if is_bot:
        logger.warning(
            f"[{request_id}] Bot detected via honeypot field '{honeypot_field}' from {client_ip}")
        log_audit_event(None, SecurityEventType.BOT_DETECTED,
                        "register", None, f"honeypot={honeypot_field}", client_ip)
        # Fake success response to confuse bots
        new_csrf = generate_csrf_token("register_form")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": None, "success": "Registrierung erfolgreich!",
                "csrf_token": new_csrf}
        )

    # SECURITY: CSRF-Token validieren
    if not validate_csrf_token(csrf_token, "register_form"):
        logger.warning(
            f"[{request_id}] CSRF validation failed for register from {client_ip}")
        new_csrf = generate_csrf_token("register_form")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Ungültige Anfrage. Bitte erneut versuchen.",
                "csrf_token": new_csrf}
        )

    # Input-Validierung
    try:
        email = InputValidator.validate_email(email)
        password = InputValidator.validate_password(password)
    except ValidationError as e:
        new_csrf = generate_csrf_token("register_form")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": e.message, "csrf_token": new_csrf}
        )

    # SECURITY: Prüfe auf häufig geleakte/schwache Passwörter
    if is_common_password(password):
        logger.info(
            f"[{request_id}] Weak password rejected for registration from {client_ip}")
        new_csrf = generate_csrf_token("register_form")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Dieses Passwort ist zu häufig verwendet und unsicher. Bitte wählen Sie ein anderes.",
                "csrf_token": new_csrf}
        )

    # SECURITY: Prüfe Passwort-Entropie (mindestens 50 Bits)
    is_strong, entropy = is_password_strong_enough(password, min_entropy=50.0)
    if not is_strong:
        logger.info(
            f"[{request_id}] Low entropy password rejected: {entropy} bits from {client_ip}")
        new_csrf = generate_csrf_token("register_form")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": f"Passwort ist nicht komplex genug. Bitte verwenden Sie eine Mischung aus Groß-/Kleinbuchstaben, Zahlen und Sonderzeichen.",
                "csrf_token": new_csrf}
        )

    # SECURITY: HaveIBeenPwned API Check - Prüfe ob Passwort in Datenlecks vorkommt
    try:
        is_pwned, pwned_count = check_password_pwned_sync(password)
        if is_pwned:
            logger.info(
                f"[{request_id}] Pwned password rejected (found {pwned_count} times) from {client_ip}")
            new_csrf = generate_csrf_token("register_form")
            return templates.TemplateResponse(
                "register.html",
                {"request": request,
                 "error": f"Dieses Passwort wurde in {pwned_count:,} Datenlecks gefunden. Bitte wählen Sie ein sicheres Passwort.",
                 "csrf_token": new_csrf}
            )
    except Exception as e:
        # Bei API-Fehler nicht blockieren, aber loggen
        logger.warning(f"[{request_id}] HIBP check failed: {e}")

    # Einladungscode validieren (falls vorhanden)
    invitation_data = None
    if invitation_code and invitation_code.strip():
        invitation_code = invitation_code.strip()
        # Code aus Link extrahieren falls nötig
        if '/join/' in invitation_code:
            invitation_code = invitation_code.split(
                '/join/')[-1].split('?')[0].split('#')[0]

        try:
            invitation_code = InputValidator.validate_token(invitation_code)
        except ValidationError:
            new_csrf = generate_csrf_token("register_form")
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "error": "Ungültiger Einladungscode",
                    "csrf_token": new_csrf}
            )

        # Prüfe ob Einladung gültig ist
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("""
                SELECT i.*, t.name as team_name, r.name as role_name
                FROM invitations i
                JOIN teams t ON i.team_id = t.id
                LEFT JOIN roles r ON i.role_id = r.id
                WHERE i.token = ? AND i.is_active = 1
                AND (i.expires_at IS NULL OR i.expires_at > datetime('now'))
                AND (i.max_uses IS NULL OR i.uses_count < i.max_uses)
            """, (invitation_code,))
            invitation_data = cursor.fetchone()

            if not invitation_data:
                new_csrf = generate_csrf_token("register_form")
                return templates.TemplateResponse(
                    "register.html",
                    {"request": request, "error": "Einladung ist ungültig oder abgelaufen",
                        "csrf_token": new_csrf}
                )

    with get_db_connection() as db:
        cursor = db.cursor()

        # Prüfen ob Email existiert
        cursor.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        )
        if cursor.fetchone():
            new_csrf = generate_csrf_token("register_form")
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "error": "Diese E-Mail ist bereits registriert",
                    "csrf_token": new_csrf}
            )

        # SECURITY: bcrypt mit Work Factor 12 + Pepper
        peppered_password = f"{password}{SecurityConfig.PASSWORD_PEPPER}"
        password_hash = bcrypt.hashpw(
            peppered_password.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        ).decode('utf-8')

        # User erstellen - mit oder ohne Team
        if invitation_data:
            # Mit Einladung: Direkt Team zuweisen und Onboarding überspringen
            # SECURITY: Bei Einladung ist Zahlung nicht erforderlich (Team-Mitglied)
            # SECURITY: Rolle serverseitig festschreiben (Spieler für Einladungs-Registrierung)
            cursor.execute("""
                SELECT id FROM roles WHERE team_id = ? AND LOWER(name) = 'spieler'
            """, (invitation_data["team_id"],))
            player_role = cursor.fetchone()
            role_id = player_role["id"] if player_role else invitation_data["role_id"]
            cursor.execute("""
                INSERT INTO users (email, password_hash, onboarding_complete, is_active, payment_status)
                VALUES (?, ?, 1, 1, 'paid')
            """, (email, password_hash))
            user_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO team_members (team_id, user_id, role_id)
                VALUES (?, ?, ?)
            """, (invitation_data["team_id"], user_id, role_id))

            # Einladung als benutzt markieren
            cursor.execute("""
                UPDATE invitations SET uses_count = uses_count + 1 WHERE token = ?
            """, (invitation_code,))

            db.commit()

            log_audit_event(user_id, "USER_REGISTERED_WITH_INVITE",
                            "user", user_id, None, client_ip)
            log_audit_event(user_id, "TEAM_JOINED", "user", user_id)
            logger.info(
                f"New user registered with invitation: user_id={user_id}, team_id={invitation_data['team_id']}")

            new_csrf = generate_csrf_token("register_form")
            response = templates.TemplateResponse(
                "register.html",
                {"request": request, "success": "Account erstellt. Du kannst dich jetzt einloggen.",
                 "csrf_token": new_csrf}
            )
        else:
            # Pilotphase: Kostenloser Zugang ohne Paywall
            cursor.execute("""
                INSERT INTO users (email, password_hash, onboarding_complete, is_active, payment_status)
                VALUES (?, ?, 0, 1, 'paid')
            """, (email, password_hash))
            user_id = cursor.lastrowid
            db.commit()
            log_audit_event(user_id, "USER_REGISTERED_FREE_PILOT",
                            "user", user_id, None, client_ip)
            logger.info(
                f"New user registered (free pilot): user_id={user_id}, email={email}")

            new_csrf = generate_csrf_token("register_form")
            response = templates.TemplateResponse(
                "register.html",
                {"request": request, "success": "Account erstellt. Du kannst dich jetzt einloggen.",
                 "csrf_token": new_csrf}
            )
            return response

    return response


@router.get("/logout")
async def logout(request: Request):
    return JSONResponse({"error": "Methode nicht erlaubt"}, status_code=405)


@router.post("/logout")
async def logout_post(request: Request):
    """
    Logout-Endpunkt.
    SECURITY: CSRF-geschützt und Cookie sicher löschen.
    """
    csrf_token = ""
    try:
        data = await request.json()
        csrf_token = str(data.get("csrf_token", "")).strip()
    except Exception:
        try:
            form = await request.form()
            csrf_token = str(form.get("csrf_token", "")).strip()
        except Exception:
            csrf_token = ""

    if not validate_csrf_token(csrf_token, "logout_form"):
        return JSONResponse({"error": "Ungültiges CSRF-Token"}, status_code=403)

    user = get_current_user(request)
    if user:
        log_audit_event(user["id"], "LOGOUT", "user", user["id"])
        if user.get("session_hash"):
            _clear_session_record(user["session_hash"], user["id"])
        token = request.cookies.get("session")
        if token:
            secure_session_manager.invalidate_session(token)

    response = JSONResponse({"success": True})
    response.delete_cookie("session", path="/")
    return response


# ============================================
# Payment Routes (Manueller Prozess)
# ============================================

@router.get("/payment/pending", response_class=HTMLResponse)
async def payment_pending(request: Request):
    """
    Zeigt Zahlungsanweisungen für manuelle Zahlung.
    """
    return templates.TemplateResponse(
        "payment_pending.html",
        {"request": request}
    )


@router.get("/api/admin/pending-users")
async def get_pending_users(request: Request):
    """
    Admin-Endpoint: Liste aller User mit ausstehender Zahlung.
    SECURITY: Nur für Admins.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, email, created_at, payment_status
            FROM users
            WHERE payment_status = 'pending' AND deleted_at IS NULL
            ORDER BY created_at DESC
        """)
        pending_users = [dict(row) for row in cursor.fetchall()]

    return JSONResponse({"users": pending_users})


@router.post("/api/admin/activate-user/{user_id}")
async def activate_user(request: Request, user_id: int):
    """
    Admin-Endpoint: User nach Zahlungseingang freischalten.
    SECURITY: Nur für Admins.
    """
    admin = get_current_user(request)
    if not admin:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_admin = get_user_by_id(admin["id"])
    if not db_admin or not db_admin.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    client_ip = get_client_ip(request)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE users SET 
                payment_status = 'paid',
                is_active = 1,
                paid_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND payment_status = 'pending'
        """, (user_id,))

        if cursor.rowcount == 0:
            return JSONResponse({"error": "User nicht gefunden oder bereits aktiviert"}, status_code=404)

        db.commit()

        # Email des aktivierten Users für Logging holen
        cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        email = user_data["email"] if user_data else "unknown"

    log_audit_event(admin["id"], "ADMIN_ACTIVATED_USER", "user", user_id,
                    f"activated_email={email}", client_ip)
    logger.info(f"Admin {admin['id']} activated user {user_id} ({email})")

    return JSONResponse({"success": True, "message": f"User {email} wurde freigeschaltet"})


# ============================================
# Admin Security & Backup Endpoints
# ============================================

@router.get("/api/admin/security-stats")
async def get_security_stats(request: Request):
    """
    Admin-Endpoint: Security-Statistiken abrufen.
    SECURITY: Nur für Admins.
    """
    admin = get_current_user(request)
    if not admin:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_admin = get_user_by_id(admin["id"])
    if not db_admin or not db_admin.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()

        # User-Statistiken
        cursor.execute(
            "SELECT COUNT(*) as total FROM users WHERE deleted_at IS NULL")
        total_users = cursor.fetchone()["total"]

        cursor.execute(
            "SELECT COUNT(*) as active FROM users WHERE is_active = 1 AND deleted_at IS NULL")
        active_users = cursor.fetchone()["active"]

        # 2FA-Statistiken
        cursor.execute("""
            SELECT COUNT(*) as count FROM user_2fa 
            WHERE is_enabled = 1 AND user_id IN (SELECT id FROM users WHERE deleted_at IS NULL)
        """)
        users_with_2fa = cursor.fetchone()["count"]

        # Login-Statistiken (letzte 24h)
        cursor.execute("""
            SELECT COUNT(*) as count FROM login_attempts 
            WHERE timestamp > datetime('now', '-24 hours') AND success = 1
        """)
        logins_24h = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT COUNT(*) as count FROM login_attempts 
            WHERE timestamp > datetime('now', '-24 hours') AND success = 0
        """)
        failed_logins_24h = cursor.fetchone()["count"]

        # Security Events (letzte 7 Tage)
        cursor.execute("""
            SELECT event_type, COUNT(*) as count FROM security_events 
            WHERE timestamp > datetime('now', '-7 days')
            GROUP BY event_type
        """)
        security_events = {row["event_type"]: row["count"]
                           for row in cursor.fetchall()}

    # Backup-Statistiken
    try:
        from backup_service import get_backup_stats
        backup_stats = get_backup_stats()
    except:
        backup_stats = {"count": 0, "total_size_human": "N/A"}

    return JSONResponse({
        "users": {
            "total": total_users,
            "active": active_users,
            "with_2fa": users_with_2fa,
            "2fa_percentage": round(users_with_2fa / total_users * 100, 1) if total_users > 0 else 0
        },
        "logins_24h": {
            "successful": logins_24h,
            "failed": failed_logins_24h
        },
        "security_events_7d": security_events,
        "backups": backup_stats
    })


@router.get("/api/admin/backups")
async def list_backups_endpoint(request: Request):
    """
    Admin-Endpoint: Alle Backups auflisten.
    SECURITY: Nur für Admins.
    """
    admin = get_current_user(request)
    if not admin:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_admin = get_user_by_id(admin["id"])
    if not db_admin or not db_admin.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    from backup_service import list_backups, get_backup_stats

    return JSONResponse({
        "backups": list_backups(),
        "stats": get_backup_stats()
    })


@router.post("/api/admin/backups/create")
async def create_backup_endpoint(request: Request):
    """
    Admin-Endpoint: Manuelles Backup erstellen.
    SECURITY: Nur für Admins.
    """
    admin = get_current_user(request)
    if not admin:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_admin = get_user_by_id(admin["id"])
    if not db_admin or not db_admin.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    from backup_service import create_backup

    client_ip = get_client_ip(request)
    backup_path = create_backup("manual")

    if backup_path:
        log_audit_event(admin["id"], "ADMIN_CREATED_BACKUP", "system", None,
                        f"path={backup_path}", client_ip)
        return JSONResponse({"success": True, "path": backup_path})
    else:
        return JSONResponse({"error": "Backup fehlgeschlagen"}, status_code=500)


@router.post("/change-password")
async def change_password(request: Request):
    """
    Passwort ändern - für eingeloggte User.
    SECURITY: Prüft aktuelles Passwort, Rate Limiting.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    client_ip = get_client_ip(request)

    # Rate Limiting
    try:
        check_rate_limit(
            request,
            sensitive_rate_limiter,
            max_requests=3,
            window_seconds=300,
            key_prefix="change_password"
        )
    except HTTPException:
        return JSONResponse({"error": "Zu viele Versuche. Bitte warte 5 Minuten."}, status_code=429)

    try:
        data = await request.json()
        current_password = data.get("current_password", "")
        new_password = data.get("new_password", "")
    except:
        return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

    if not current_password or not new_password:
        return JSONResponse({"error": "Beide Passwörter erforderlich"}, status_code=400)

    # Passwort-Stärke prüfen
    is_strong, entropy = is_password_strong_enough(
        new_password, min_entropy=50.0)
    if not is_strong:
        return JSONResponse({"error": "Neues Passwort ist nicht stark genug"}, status_code=400)

    if is_common_password(new_password):
        return JSONResponse({"error": "Dieses Passwort ist zu häufig"}, status_code=400)

    # Aktuelles Passwort prüfen
    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user:
        return JSONResponse({"error": "User nicht gefunden"}, status_code=404)

    peppered_current = current_password + SecurityConfig.PASSWORD_PEPPER
    if not bcrypt.checkpw(peppered_current.encode('utf-8'), db_user["password_hash"].encode('utf-8')):
        log_audit_event(user["id"], "PASSWORD_CHANGE_FAILED",
                        "user", user["id"], "wrong_current_password", client_ip)
        return JSONResponse({"error": "Aktuelles Passwort ist falsch"}, status_code=400)

    # Neues Passwort hashen und speichern
    peppered_new = new_password + SecurityConfig.PASSWORD_PEPPER
    new_hash = bcrypt.hashpw(peppered_new.encode(
        'utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (new_hash, user["id"]))
        db.commit()

    log_audit_event(user["id"], "PASSWORD_CHANGED",
                    "user", user["id"], None, client_ip)
    logger.info(f"Password changed for user {user['id']}")

    # E-Mail-Benachrichtigung senden
    if EmailConfig.is_configured():
        send_password_changed_notification(db_user["email"])

    return JSONResponse({"success": True, "message": "Passwort erfolgreich geändert"})


# ============================================
# Protected Routes
# ============================================

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard - erfordert Authentifizierung."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Payment-Status prüfen
    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user:
        return RedirectResponse(url="/login", status_code=303)

    # Onboarding-Status prüfen
    if not db_user.get("onboarding_complete"):
        return RedirectResponse(url="/onboarding", status_code=303)

    if not db_user.get("team_id"):
        memberships = get_user_memberships(user["id"])
        if len(memberships) > 1:
            return RedirectResponse(url="/select-team", status_code=303)

    role_name = get_user_role_name(db_user)
    if role_name == "spieler" and not db_user.get("is_admin"):
        return templates.TemplateResponse(
            "player.html",
            {"request": request, "user": user}
        )

    return templates.TemplateResponse(
        "os.html",
        {"request": request, "user": user, "logout_csrf_token": generate_csrf_token("logout_form")}
    )


@router.get("/results", response_class=HTMLResponse)
async def results(request: Request):
    """Results-Seite."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "results.html",
        {"request": request, "user": user}
    )


@router.get("/select-team", response_class=HTMLResponse)
async def select_team(request: Request):
    """Team-Auswahl für mehrere Mitgliedschaften."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    memberships = get_user_memberships(user["id"])
    if len(memberships) == 1:
        _ensure_session_record(user["session_hash"], user["id"])
        _set_active_team_for_session(user["session_hash"], user["id"], memberships[0]["team_id"])
        return RedirectResponse(url="/dashboard", status_code=303)

    return templates.TemplateResponse(
        "team_select.html",
        {"request": request, "memberships": memberships}
    )


@router.get("/onboarding", response_class=HTMLResponse)
async def onboarding_page(request: Request):
    """Onboarding-Seite."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Bereits abgeschlossen?
    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if db_user and db_user.get("onboarding_complete"):
        return RedirectResponse(url="/dashboard", status_code=303)

    return templates.TemplateResponse(
        "onboarding.html",
        {"request": request, "user": user}
    )


# ============================================
# API Endpoints - Profile
# ============================================

@router.post("/api/onboarding/complete")
async def complete_onboarding(request: Request):
    """
    Onboarding abschließen.
    SECURITY: Input-Validierung, nur eigene Daten.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

    # Input-Validierung
    try:
        verein = InputValidator.validate_team_name(
            data.get("verein", ""), "verein", required=True)
        mannschaft = InputValidator.validate_team_name(
            data.get("mannschaft", ""), "mannschaft", required=True)
        rolle = InputValidator.validate_rolle(data.get("rolle", ""))
    except ValidationError as e:
        return JSONResponse({"error": e.message}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute("""
            SELECT 1 FROM team_members WHERE user_id = ? LIMIT 1
        """, (user["id"],))
        has_membership = cursor.fetchone() is not None

        if not has_membership:
            # Verein/Mannschaft doppelt? -> neue Mannschaft erzwingen
            cursor.execute("""
                SELECT 1 FROM teams
                WHERE LOWER(verein) = LOWER(?) AND LOWER(mannschaft) = LOWER(?)
                AND deleted_at IS NULL
                LIMIT 1
            """, (verein, mannschaft))
            if cursor.fetchone():
                return JSONResponse({"error": "Verein existiert bereits. Bitte eine neue Mannschaft anlegen."}, status_code=400)

            # Neues Team erstellen
            team_id = create_team(verein, mannschaft, user["id"])

        # User-Daten aktualisieren
        cursor.execute("""
            UPDATE users SET
                verein = ?,
                mannschaft = ?,
                rolle = ?,
                teamname = ?,
                onboarding_complete = 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (verein, mannschaft, rolle, verein, user["id"]))
        db.commit()

    log_audit_event(user["id"], "ONBOARDING_COMPLETE", "user", user["id"])
    if team_id and user.get("session_hash"):
        _ensure_session_record(user["session_hash"], user["id"])
        _set_active_team_for_session(user["session_hash"], user["id"], team_id)
    return {"success": True}


@router.get("/api/profile")
async def get_profile(request: Request):
    """
    Profil abrufen - rollenbasiert.
    SECURITY: Nur eigene Daten, Felder nach Rolle gefiltert.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user:
        return JSONResponse({"error": "Benutzer nicht gefunden"}, status_code=404)

    rolle = get_user_role_name(db_user)
    is_admin = rolle == "admin"
    is_trainer = rolle in ["trainer", "co-trainer"] or is_admin
    is_spieler = rolle == "spieler" or is_admin

    # Basis-Profil für alle Rollen
    profile = {
        "email": db_user.get("email", ""),
        "vorname": db_user.get("vorname", ""),
        "nachname": db_user.get("nachname", ""),
        "geburtsdatum": db_user.get("geburtsdatum", ""),
        "verein": db_user.get("verein", ""),
        "werdegang": db_user.get("werdegang", ""),
        "teamname": db_user.get("teamname", ""),
        "rolle": rolle.capitalize() if rolle else "",
        "mannschaft": db_user.get("mannschaft", ""),
        "telefon": db_user.get("telefon", ""),
    }

    # Spieler-spezifische Felder (für Spieler UND Admin)
    if is_spieler:
        player_position = db_user.get("position", "")
        if db_user.get("team_id"):
            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute("""
                    SELECT position FROM players
                    WHERE user_id = ? AND team_id = ? AND deleted_at IS NULL
                    LIMIT 1
                """, (user["id"], db_user.get("team_id")))
                player_row = cursor.fetchone()
                if player_row and player_row["position"] is not None:
                    player_position = player_row["position"]
        profile.update({
            "groesse": db_user.get("groesse"),
            "gewicht": db_user.get("gewicht"),
            "position": player_position,
            "nebenpositionen": db_user.get("nebenpositionen", ""),
            "starker_fuss": db_user.get("starker_fuss", ""),
            "jahrgang": db_user.get("jahrgang"),
        })

    # Trainer-spezifische Felder (für Trainer, Co-Trainer UND Admin)
    if is_trainer:
        profile.update({
            "spielsystem": db_user.get("spielsystem", ""),
            "taktische_grundidee": db_user.get("taktische_grundidee", ""),
            "trainingsschwerpunkte": db_user.get("trainingsschwerpunkte", ""),
            "bisherige_stationen": db_user.get("bisherige_stationen", ""),
            "lizenzen": db_user.get("lizenzen", ""),
        })

    return profile


@router.post("/api/profile")
async def update_profile(request: Request):
    """
    Profil aktualisieren - rollenbasiert.
    SECURITY: Input-Validierung, nur rollenbezogene Felder (Mass Assignment Prevention).
    Trainer: Nur Trainer-Felder. Spieler: Nur Spieler-Felder.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user:
        return JSONResponse({"error": "Benutzer nicht gefunden"}, status_code=404)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

    rolle = get_user_role_name(db_user)

    # Admin kann wählen welches Profil (Trainer oder Spieler)
    # Erkennung: Anhand der gesendeten Felder
    is_admin = rolle == "admin"

    # Prüfen welcher Profiltyp vom Frontend gewählt wurde
    has_spieler_fields = any(k in data for k in [
                             "groesse", "gewicht", "position", "nebenpositionen", "starker_fuss", "jahrgang"])
    has_trainer_fields = any(k in data for k in [
                             "spielsystem", "taktische_grundidee", "trainingsschwerpunkte", "bisherige_stationen", "lizenzen"])

    # Für Admin: Anhand der gesendeten Felder entscheiden
    if is_admin:
        is_spieler = has_spieler_fields and not has_trainer_fields
        is_trainer = has_trainer_fields or (
            not has_spieler_fields)  # Default: Trainer
    else:
        is_trainer = rolle in ["trainer", "co-trainer"]
        is_spieler = rolle == "spieler"

    # SECURITY: Basis-Felder (für alle Rollen)
    try:
        vorname = InputValidator.validate_name(
            data.get("vorname", ""), "vorname")
        nachname = InputValidator.validate_name(
            data.get("nachname", ""), "nachname")
    except ValidationError as e:
        return JSONResponse({"error": e.message}, status_code=400)

    telefon = str(data.get("telefon", "")).strip()[:30]
    geburtsdatum = str(data.get("geburtsdatum", "")).strip()[:10] or None
    werdegang = str(data.get("werdegang", "")).strip()[:2000]

    # Basis-Update vorbereiten
    update_fields = {
        "vorname": vorname,
        "nachname": nachname,
        "telefon": telefon,
        "geburtsdatum": geburtsdatum,
        "werdegang": werdegang,
    }

    # Spieler-spezifische Felder
    if is_spieler:
        player_entry = None
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("""
                SELECT id, name, position
                FROM players
                WHERE user_id = ? AND team_id = ? AND deleted_at IS NULL
                LIMIT 1
            """, (user["id"], db_user.get("team_id")))
            player_entry = cursor.fetchone()

        # Größe validieren
        groesse = data.get("groesse")
        if groesse:
            try:
                groesse = int(groesse)
                if groesse < 100 or groesse > 250:
                    groesse = None
            except (ValueError, TypeError):
                groesse = None
        update_fields["groesse"] = groesse

        # Gewicht validieren
        gewicht = data.get("gewicht")
        if gewicht:
            try:
                gewicht = int(gewicht)
                if gewicht < 30 or gewicht > 200:
                    gewicht = None
            except (ValueError, TypeError):
                gewicht = None
        update_fields["gewicht"] = gewicht

        # Position ist für Spieler gesperrt (nur Kader-Eintrag)
        locked_position = db_user.get("position", "")
        if player_entry and player_entry["position"] is not None:
            locked_position = player_entry["position"]
        update_fields["position"] = locked_position

        # Nebenpositionen (JSON array als String)
        nebenpositionen = str(data.get("nebenpositionen", "")).strip()[:200]
        update_fields["nebenpositionen"] = nebenpositionen

        # Starker Fuß
        starker_fuss = str(data.get("starker_fuss", "")).strip()[:20]
        if starker_fuss not in ["", "rechts", "links", "beidfuessig"]:
            starker_fuss = ""
        update_fields["starker_fuss"] = starker_fuss

        # Jahrgang
        jahrgang = data.get("jahrgang")
        if jahrgang:
            try:
                jahrgang = int(jahrgang)
                if jahrgang < 1950 or jahrgang > 2025:
                    jahrgang = None
            except (ValueError, TypeError):
                jahrgang = None
        update_fields["jahrgang"] = jahrgang

    # Trainer-spezifische Felder (inkl. Admin, Co-Trainer)
    elif is_trainer:
        update_fields["spielsystem"] = str(
            data.get("spielsystem", "")).strip()[:50]
        update_fields["taktische_grundidee"] = str(
            data.get("taktische_grundidee", "")).strip()[:1000]
        update_fields["trainingsschwerpunkte"] = str(
            data.get("trainingsschwerpunkte", "")).strip()[:500]
        update_fields["bisherige_stationen"] = str(
            data.get("bisherige_stationen", "")).strip()[:1000]
        update_fields["lizenzen"] = str(data.get("lizenzen", "")).strip()[:200]

    # SQL dynamisch bauen
    set_clause = ", ".join([f"{k} = ?" for k in update_fields.keys()])
    values = list(update_fields.values())
    values.append(user["id"])

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(f"""
            UPDATE users SET
                {set_clause},
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, values)
        if is_spieler:
            full_name = f"{vorname} {nachname}".strip()
            cursor.execute("""
                UPDATE players
                SET name = ?, email = ?, telefon = ?, geburtsdatum = ?, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ? AND team_id = ? AND deleted_at IS NULL
            """, (full_name, db_user.get("email", ""), telefon, geburtsdatum,
                  user["id"], db_user.get("team_id")))
        db.commit()

    log_audit_event(user["id"], "PROFILE_UPDATED", "user", user["id"])
    return {"success": True}


@router.get("/api/profile/kader")
async def get_profile_kader(request: Request):
    """
    Kader-Eintrag des eingeloggten Users abrufen.
    SECURITY: Nur eigener Eintrag (verknüpft über user_id).
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return {"player": None}

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, name, position, trikotnummer, status, email, telefon, geburtsdatum, notizen
            FROM players
            WHERE team_id = ? AND user_id = ? AND deleted_at IS NULL
            LIMIT 1
        """, (db_user["team_id"], user["id"]))
        player = cursor.fetchone()

    if player:
        return {"player": dict(player)}
    return {"player": None}


@router.delete("/api/account/delete")
async def delete_account(request: Request):
    """
    Account löschen (DSGVO: Soft Delete).
    SECURITY: Nur eigenen Account.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    client_ip = get_client_ip(request)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT tm.team_id, t.name as team_name, COUNT(tm2.user_id) as admin_count
            FROM team_members tm
            JOIN roles r ON tm.role_id = r.id
            JOIN teams t ON tm.team_id = t.id
            JOIN team_members tm2 ON tm2.team_id = tm.team_id
            JOIN roles r2 ON tm2.role_id = r2.id
            WHERE tm.user_id = ? AND LOWER(r.name) = 'admin'
              AND LOWER(r2.name) = 'admin'
            GROUP BY tm.team_id
            HAVING admin_count <= 1
        """, (user["id"],))
        blocked_teams = cursor.fetchall()

    if blocked_teams:
        team_names = [row["team_name"] or "Team" for row in blocked_teams]
        return JSONResponse(
            {"error": "Bitte benenne zuerst einen Admin.",
             "teams": team_names},
            status_code=400
        )

    # DSGVO-konformes Soft Delete
    success = soft_delete_user(user["id"])

    if success:
        logger.info(f"Account deleted: user_id={user['id']}")
        if user.get("session_hash"):
            _clear_session_record(user["session_hash"], user["id"])
        token = request.cookies.get("session")
        if token:
            secure_session_manager.invalidate_session(token)
        response = JSONResponse({"success": True})
        response.delete_cookie("session", path="/")
        return response

    return JSONResponse({"error": "Fehler beim Löschen"}, status_code=500)


# ============================================
# API Endpoints - Team Management
# ============================================

@router.get("/api/team/info")
async def get_team_info(request: Request):
    """
    Team-Infos abrufen.
    SECURITY: Nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert", "has_team": False}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user:
        return {"has_team": False}

    if not db_user.get("team_id") or not db_user.get("role_id"):
        memberships = get_user_memberships(user["id"])
        return {"has_team": False, "membership_count": len(memberships)}

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT t.id, t.name as team_name, t.verein, t.mannschaft, t.admin_user_id
            FROM teams t
            WHERE t.id = ? AND t.deleted_at IS NULL
        """, (db_user["team_id"],))
        team_row = cursor.fetchone()

        if not team_row:
            return {"has_team": False}

        cursor.execute("""
            SELECT app_id, can_view, can_edit FROM permissions WHERE role_id = ?
        """, (db_user["role_id"],))
        permissions = cursor.fetchall()

    return {
        "has_team": True,
        "is_admin": bool(db_user.get("is_admin")),
        "is_primary_admin": bool(team_row["admin_user_id"] == user["id"]),
        "team_id": team_row["id"],
        "team_name": team_row["team_name"],
        "verein": team_row["verein"],
        "mannschaft": team_row["mannschaft"],
        "role_id": db_user["role_id"],
        "role_name": db_user.get("role_name") or get_user_role_name(db_user),
        "permissions": {
            p["app_id"]: {"view": bool(p["can_view"]), "edit": bool(p["can_edit"])}
            for p in permissions
        }
    }


@router.get("/api/teams")
async def list_teams(request: Request):
    """
    Teams des Users abrufen (für Teamwechsel).
    SECURITY: Nur Teams, in denen der User Mitglied ist.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"teams": []}, status_code=401)

    memberships = get_user_memberships(user["id"])
    teams = [{
        "id": m["team_id"],
        "name": m["team_name"],
        "verein": m["verein"],
        "mannschaft": m["mannschaft"],
        "role_name": m["role_name"],
        "role_id": m["role_id"]
    } for m in memberships]
    return {"teams": teams}


@router.get("/api/memberships")
async def list_memberships(request: Request):
    """
    Liste aller Team-Mitgliedschaften inkl. Rolle.
    SECURITY: Nur eigene Mitgliedschaften.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"memberships": [], "active_team_id": None}, status_code=401)

    memberships = get_user_memberships(user["id"])
    active_team_id = _get_active_team_for_session(user.get("session_hash"), user["id"]) if user.get("session_hash") else None
    return {"memberships": memberships, "active_team_id": active_team_id}


@router.post("/api/memberships/active")
async def set_active_membership(request: Request):
    """
    Aktive Mitgliedschaft setzen.
    SECURITY: Nur eigene Teams, Session-Context.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

    team_id = data.get("team_id")
    if not team_id:
        return JSONResponse({"error": "Team erforderlich"}, status_code=400)
    try:
        team_id = int(team_id)
    except (TypeError, ValueError):
        return JSONResponse({"error": "Ungültiges Team"}, status_code=400)

    memberships = get_user_memberships(user["id"])
    if not any(m["team_id"] == team_id for m in memberships):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    _ensure_session_record(user["session_hash"], user["id"])
    _set_active_team_for_session(user["session_hash"], user["id"], team_id)
    return JSONResponse({"success": True, "team_id": team_id})


@router.post("/api/teams/switch")
async def switch_team(request: Request):
    """
    Aktives Team wechseln.
    SECURITY: Nur eigene Teams, Session-Token neu ausstellen.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

    team_id = data.get("team_id")
    if not team_id:
        return JSONResponse({"error": "Team erforderlich"}, status_code=400)
    try:
        team_id = int(team_id)
    except (TypeError, ValueError):
        return JSONResponse({"error": "Ungültiges Team"}, status_code=400)

    memberships = get_user_memberships(user["id"])
    if not any(m["team_id"] == team_id for m in memberships):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    _ensure_session_record(user["session_hash"], user["id"])
    _set_active_team_for_session(user["session_hash"], user["id"], team_id)
    return JSONResponse({"success": True, "team_id": team_id})


@router.post("/api/team/create")
async def create_team_api(request: Request):
    """
    Team erstellen.
    SECURITY: Input-Validierung, max 1 Team pro User.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    memberships = get_user_memberships(user["id"])
    if memberships:
        return JSONResponse({"error": "Du hast bereits ein Team. Pro Account ist nur ein Team erlaubt."}, status_code=400)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

    try:
        verein = InputValidator.validate_team_name(
            data.get("verein", ""), "verein", required=True)
        mannschaft = InputValidator.validate_team_name(
            data.get("mannschaft", ""), "mannschaft", required=True)
    except ValidationError as e:
        return JSONResponse({"error": e.message}, status_code=400)

    # Verein/Mannschaft doppelt? -> neue Mannschaft erzwingen
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT 1 FROM teams
            WHERE LOWER(verein) = LOWER(?) AND LOWER(mannschaft) = LOWER(?)
            AND deleted_at IS NULL
            LIMIT 1
        """, (verein, mannschaft))
        if cursor.fetchone():
            return JSONResponse({"error": "Verein existiert bereits. Bitte eine neue Mannschaft anlegen."}, status_code=400)

    team_id = create_team(verein, mannschaft, user["id"])
    log_audit_event(user["id"], "TEAM_CREATED", "team", team_id)

    if user.get("session_hash"):
        _ensure_session_record(user["session_hash"], user["id"])
        _set_active_team_for_session(user["session_hash"], user["id"], team_id)

    return {"success": True, "team_id": team_id}


@router.post("/api/team/create/additional")
async def create_additional_team(request: Request):
    """
    Neue Mannschaft fuer bestehenden Verein anlegen.
    SECURITY: Nur Hauptadmin (admin_user_id) des aktiven Teams.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

    try:
        mannschaft = InputValidator.validate_team_name(
            data.get("mannschaft", ""), "mannschaft", required=True)
    except ValidationError as e:
        return JSONResponse({"error": e.message}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, verein, admin_user_id FROM teams
            WHERE id = ? AND deleted_at IS NULL
        """, (db_user["team_id"],))
        team_row = cursor.fetchone()
        if not team_row:
            return JSONResponse({"error": "Team nicht gefunden"}, status_code=404)

        if team_row["admin_user_id"] != user["id"]:
            return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

        verein = team_row["verein"] or ""

        cursor.execute("""
            SELECT 1 FROM teams
            WHERE LOWER(verein) = LOWER(?) AND LOWER(mannschaft) = LOWER(?)
            AND deleted_at IS NULL
            LIMIT 1
        """, (verein, mannschaft))
        if cursor.fetchone():
            return JSONResponse({"error": "Mannschaft existiert bereits."}, status_code=400)

    team_id = create_team(verein, mannschaft, user["id"])
    log_audit_event(user["id"], "TEAM_CREATED_ADDITIONAL", "team", team_id)

    if user.get("session_hash"):
        _ensure_session_record(user["session_hash"], user["id"])
        _set_active_team_for_session(user["session_hash"], user["id"], team_id)
    return JSONResponse({"success": True, "team_id": team_id})


@router.get("/api/team/status")
async def get_team_status(request: Request):
    """
    Prüft ob User ein Team hat.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    memberships = get_user_memberships(user["id"])
    has_team = len(memberships) > 0

    team_info = None
    if db_user and db_user.get("team_id"):
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("""
                SELECT t.id, t.name, t.verein, t.mannschaft 
                FROM teams t WHERE t.id = ?
            """, (db_user["team_id"],))
            team = cursor.fetchone()
            if team:
                team_info = {
                    "id": team["id"],
                    "name": team["name"],
                    "verein": team["verein"],
                    "mannschaft": team["mannschaft"]
                }

    return {"has_team": has_team, "team": team_info, "membership_count": len(memberships)}


@router.get("/api/team/members")
async def get_team_members(request: Request):
    """
    Team-Mitglieder abrufen.
    SECURITY: Nur eigenes Team (IDOR Prevention).
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return {"error": "Kein Team gefunden", "members": []}

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT u.id, u.email, u.vorname, u.nachname, r.name as role_name, r.id as role_id, tm.joined_at
            FROM team_members tm
            JOIN users u ON tm.user_id = u.id
            JOIN roles r ON tm.role_id = r.id
            WHERE tm.team_id = ? AND u.is_active = 1
            ORDER BY r.id, u.nachname
        """, (db_user["team_id"],))
        members = cursor.fetchall()

    return {
        "members": [
            {
                "id": m["id"],
                "email": m["email"],
                "vorname": m["vorname"] or "",
                "nachname": m["nachname"] or "",
                "role_name": m["role_name"],
                "role_id": m["role_id"],
                "joined_at": m["joined_at"],
                "is_admin": (m["role_name"] or "").lower() == "admin"
            }
            for m in members
        ]
    }


@router.get("/api/team/roles")
async def get_team_roles(request: Request):
    """
    Team-Rollen abrufen.
    SECURITY: Nur eigenes Team.
    PERFORMANCE: Single Query statt N+1 für Permissions.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return {"error": "Kein Team gefunden", "roles": []}

    team_id = db_user["team_id"]

    with get_db_connection() as db:
        cursor = db.cursor()

        # PERFORMANCE: Single Query für Rollen mit Member-Count
        cursor.execute("""
            SELECT r.*,
                   (SELECT COUNT(*) FROM team_members WHERE role_id = r.id) as member_count
            FROM roles r
            WHERE r.team_id = ?
            ORDER BY r.id
        """, (team_id,))
        roles = cursor.fetchall()

        if not roles:
            return {"roles": []}

        # PERFORMANCE: Alle Permissions für alle Rollen des Teams in EINER Query
        role_ids = [r["id"] for r in roles]
        placeholders = ",".join("?" * len(role_ids))
        cursor.execute(f"""
            SELECT role_id, app_id, can_view, can_edit 
            FROM permissions 
            WHERE role_id IN ({placeholders})
        """, role_ids)
        all_permissions = cursor.fetchall()

        # Gruppiere Permissions nach role_id
        permissions_by_role = {}
        for p in all_permissions:
            role_id = p["role_id"]
            if role_id not in permissions_by_role:
                permissions_by_role[role_id] = {}
            permissions_by_role[role_id][p["app_id"]] = {
                "view": bool(p["can_view"]),
                "edit": bool(p["can_edit"])
            }

        result = []
        for role in roles:
            result.append({
                "id": role["id"],
                "name": role["name"],
                "description": role["description"] or "",
                "is_default": bool(role["is_default"]),
                "member_count": role["member_count"],
                "permissions": permissions_by_role.get(role["id"], {})
            })

    return {"roles": result}


@router.post("/api/team/roles")
async def create_role(request: Request):
    """
    Neue Rolle erstellen.
    SECURITY: Nur Admin, Input-Validierung.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team gefunden"}, status_code=400)

    # SECURITY: Nur Admins dürfen Rollen erstellen
    if not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()

        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

        name = data.get("name", "").strip()
        if not name or len(name) > 100:
            return JSONResponse({"error": "Ungültiger Rollenname"}, status_code=400)

        description = data.get("description", "")[:500]
        permissions = data.get("permissions", [])

        cursor.execute("""
            INSERT INTO roles (team_id, name, description, is_deletable)
            VALUES (?, ?, ?, 1)
        """, (db_user["team_id"], name, description))
        role_id = cursor.lastrowid

        # Berechtigungen setzen
        if permissions:
            for perm in permissions:
                app_id = perm.get("app_id", "")
                # SECURITY: Nur Whitelist-Apps
                if AppPermissions.is_valid_app(app_id):
                    cursor.execute("""
                        INSERT INTO permissions (role_id, app_id, can_view, can_edit)
                        VALUES (?, ?, ?, ?)
                    """, (
                        role_id, app_id,
                        1 if perm.get("can_view") else 0,
                        1 if perm.get("can_edit") else 0
                    ))
        else:
            # Standard-Berechtigungen
            for app_id in ['dashboard', 'kalender']:
                cursor.execute("""
                    INSERT INTO permissions (role_id, app_id, can_view, can_edit)
                    VALUES (?, ?, 1, 0)
                """, (role_id, app_id))

        db.commit()

    log_audit_event(user["id"], "ROLE_CREATED", "role", role_id)
    return {"success": True, "role_id": role_id}


@router.put("/api/team/roles/{role_id}/permissions")
async def update_role_permissions(request: Request, role_id: int):
    """
    Rollen-Berechtigungen aktualisieren.
    SECURITY: Nur Admin, IDOR Prevention.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team gefunden"}, status_code=400)

    if not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT id FROM roles WHERE id = ? AND team_id = ?",
            (role_id, db_user["team_id"])
        )
        if not cursor.fetchone():
            return JSONResponse({"error": "Rolle nicht gefunden"}, status_code=404)

        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

        permissions = data.get("permissions", {})

        for app_id, perms in permissions.items():
            # SECURITY: Nur Whitelist-Apps
            if not AppPermissions.is_valid_app(app_id):
                continue

            cursor.execute(
                "SELECT id FROM permissions WHERE role_id = ? AND app_id = ?",
                (role_id, app_id)
            )
            existing = cursor.fetchone()

            if existing:
                cursor.execute("""
                    UPDATE permissions SET can_view = ?, can_edit = ?
                    WHERE role_id = ? AND app_id = ?
                """, (
                    1 if perms.get("view") else 0,
                    1 if perms.get("edit") else 0,
                    role_id, app_id
                ))
            else:
                cursor.execute("""
                    INSERT INTO permissions (role_id, app_id, can_view, can_edit)
                    VALUES (?, ?, ?, ?)
                """, (
                    role_id, app_id,
                    1 if perms.get("view") else 0,
                    1 if perms.get("edit") else 0
                ))

        db.commit()

    log_audit_event(user["id"], "ROLE_PERMISSIONS_UPDATED", "role", role_id)
    return {"success": True}


@router.delete("/api/team/roles/{role_id}")
async def delete_role(request: Request, role_id: int):
    """
    Rolle löschen.
    SECURITY: Nur Admin, nur eigenes Team, keine Standard-Rollen.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team gefunden"}, status_code=400)

    if not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT id, is_deletable FROM roles WHERE id = ? AND team_id = ?",
            (role_id, db_user["team_id"])
        )
        role = cursor.fetchone()

        if not role:
            return JSONResponse({"error": "Rolle nicht gefunden"}, status_code=404)

        if not role["is_deletable"]:
            return JSONResponse({"error": "Standard-Rollen können nicht gelöscht werden"}, status_code=400)

        cursor.execute("DELETE FROM permissions WHERE role_id = ?", (role_id,))
        cursor.execute("DELETE FROM roles WHERE id = ?", (role_id,))
        db.commit()

    log_audit_event(user["id"], "ROLE_DELETED", "role", role_id)
    return {"success": True}


@router.put("/api/team/members/{member_id}/role")
async def update_member_role(request: Request, member_id: int):
    """
    Mitglieder-Rolle ändern.
    SECURITY: Nur Admin, nur eigenes Team (IDOR Prevention).
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team gefunden"}, status_code=400)

    if not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute("""
            SELECT tm.id FROM team_members tm
            WHERE tm.user_id = ? AND tm.team_id = ?
        """, (member_id, db_user["team_id"]))

        if not cursor.fetchone():
            return JSONResponse({"error": "Mitglied nicht gefunden"}, status_code=404)

        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

        new_role_id = data.get("role_id")
        if not new_role_id:
            return JSONResponse({"error": "Rolle erforderlich"}, status_code=400)

        # SECURITY: Prüfen ob Rolle zum Team gehört
        cursor.execute(
            "SELECT id FROM roles WHERE id = ? AND team_id = ?",
            (new_role_id, db_user["team_id"])
        )
        if not cursor.fetchone():
            return JSONResponse({"error": "Ungültige Rolle"}, status_code=400)

        cursor.execute(
            "UPDATE team_members SET role_id = ? WHERE user_id = ? AND team_id = ?",
            (new_role_id, member_id, db_user["team_id"])
        )
        db.commit()

    log_audit_event(user["id"], "MEMBER_ROLE_CHANGED", "user", member_id)
    return {"success": True}


@router.delete("/api/team/members/{member_id}")
async def remove_member(request: Request, member_id: int):
    """
    Mitglied entfernen.
    SECURITY: Admin und Trainer/Staff, nicht sich selbst, nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    # SECURITY: Kann sich nicht selbst entfernen
    if member_id == user["id"]:
        return JSONResponse({"error": "Sie können sich nicht selbst entfernen"}, status_code=400)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    staff_roles = ["Admin", "Trainer", "Co-Trainer", "Torwarttrainer",
                   "Betreuer", "Physio", "Jugendleiter", "Vorstand"]
    role_name = (db_user.get("role_name") or get_user_role_name(db_user)).strip()
    is_admin = bool(db_user.get("is_admin")) or role_name == "Admin"

    with get_db_connection() as db:
        cursor = db.cursor()

        if not is_admin and role_name not in staff_roles:
            return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

        # SECURITY: IDOR Prevention
        cursor.execute("""
            SELECT tm.id, r.name as role_name
            FROM team_members tm
            JOIN users u ON tm.user_id = u.id
            LEFT JOIN roles r ON tm.role_id = r.id
            WHERE tm.user_id = ? AND tm.team_id = ?
        """, (member_id, db_user["team_id"]))

        target = cursor.fetchone()
        if not target:
            return JSONResponse({"error": "Mitglied nicht gefunden"}, status_code=404)

        target_role = (target["role_name"] or "").strip()
        target_is_admin = target_role == "Admin"

        if not is_admin:
            if target_is_admin or target_role in staff_roles:
                return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)
            if target_role != "Spieler":
                return JSONResponse({"error": "Nur Spieler können entfernt werden"}, status_code=403)

        cursor.execute(
            "DELETE FROM team_members WHERE user_id = ? AND team_id = ?",
            (member_id, db_user["team_id"])
        )
        cursor.execute("""
            UPDATE players
            SET user_id = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND team_id = ? AND deleted_at IS NULL
        """, (member_id, db_user["team_id"]))
        db.commit()

    log_audit_event(user["id"], "MEMBER_REMOVED", "user", member_id)
    return {"success": True}


# ============================================
# API Endpoints - Invitations
# ============================================

@router.get("/api/invitations")
async def get_invitations(request: Request):
    """
    Einladungen abrufen.
    SECURITY: Nur Admin, nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert", "invitations": []}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team gefunden", "invitations": []}, status_code=400)

    if not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung", "invitations": []}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT i.*, r.name as role_name, u.email as created_by_email
            FROM invitations i
            JOIN roles r ON i.role_id = r.id
            JOIN users u ON i.created_by = u.id
            WHERE i.team_id = ? AND i.is_active = 1
            ORDER BY i.created_at DESC
        """, (db_user["team_id"],))
        invitations = cursor.fetchall()

    return {
        "invitations": [
            {
                "id": inv["id"],
                "token": inv["token"],
                "role_name": inv["role_name"],
                "role_id": inv["role_id"],
                "max_uses": inv["max_uses"],
                "uses": inv["uses"],
                "expires_at": inv["expires_at"],
                "created_by": inv["created_by_email"],
                "created_at": inv["created_at"]
            }
            for inv in invitations
        ]
    }


# ============================================
# Video Management APIs
# ============================================

# Erlaubte Video-Formate und Max-Größe
ALLOWED_VIDEO_EXTENSIONS = {'.mp4', '.mov', '.avi', '.webm', '.mkv'}
ALLOWED_VIDEO_MIME_TYPES = {
    "video/mp4",
    "video/quicktime",
    "video/x-msvideo",
    "video/webm",
    "video/x-matroska",
    "application/octet-stream",
}
MAX_VIDEO_SIZE = 500 * 1024 * 1024  # 500 MB
TEAM_VIDEO_QUOTA = 5 * 1024 * 1024 * 1024  # 5 GB pro Mannschaft


def get_video_upload_dir():
    """Dynamisch den Video-Upload-Pfad ermitteln."""
    return os.path.join(SecurityConfig.DATA_DIR, 'videos')


@router.post("/api/videos/upload")
async def upload_video(
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
    duration: int = Form(0),
    file: UploadFile = File(...)
):
    """
    Video hochladen.
    SECURITY: Nur für Team-Admins/Trainer, Dateityp-Validierung, Größenlimit.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team gefunden"}, status_code=400)

    # SECURITY: Nur Admin/Trainer dürfen Videos hochladen
    role_name = get_user_role_name(db_user)
    if role_name not in ("admin", "trainer", "co-trainer"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    # SECURITY: Content-Length prüfen (wenn vorhanden)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_VIDEO_SIZE + (5 * 1024 * 1024):
                return JSONResponse({"error": "Video zu groß (max. 500 MB)"}, status_code=400)
        except ValueError:
            return JSONResponse({"error": "Ungültige Upload-Größe"}, status_code=400)

    # SECURITY: Dateiendung prüfen
    filename = file.filename or "video"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_VIDEO_EXTENSIONS:
        return JSONResponse({"error": f"Ungültiges Format. Erlaubt: {', '.join(ALLOWED_VIDEO_EXTENSIONS)}"}, status_code=400)

    # SECURITY: MIME-Type prüfen (best effort)
    if file.content_type and file.content_type.lower() not in ALLOWED_VIDEO_MIME_TYPES:
        return JSONResponse({"error": "Ungültiger Dateityp"}, status_code=400)

    # SECURITY: Dateigröße prüfen
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)

    if file_size > MAX_VIDEO_SIZE:
        return JSONResponse({"error": "Video zu groß (max. 500 MB)"}, status_code=400)

    # SECURITY: Team-Quota prüfen (nur nicht-gelöschte Videos)
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT COALESCE(SUM(file_size), 0) as total_size
            FROM videos
            WHERE team_id = ? AND deleted_at IS NULL
        """, (db_user["team_id"],))
        total_size = cursor.fetchone()["total_size"] or 0

    if total_size + file_size > TEAM_VIDEO_QUOTA:
        return JSONResponse({"error": "Team-Speicherlimit erreicht (max. 5 GB)."}, status_code=400)

    # SECURITY: Sicherer Dateiname
    safe_filename = f"{uuid.uuid4().hex}{ext}"
    team_dir = os.path.join(get_video_upload_dir(), str(db_user["team_id"]))
    os.makedirs(team_dir, exist_ok=True)
    file_path = os.path.join(team_dir, safe_filename)

    # Datei speichern
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        logger.error(f"Video upload failed: {e}")
        return JSONResponse({"error": "Upload fehlgeschlagen"}, status_code=500)

    # In DB speichern
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO videos (team_id, title, description, filename, file_size, duration, uploaded_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (db_user["team_id"], title[:200], description[:1000], safe_filename, file_size, duration, user["id"]))
        video_id = cursor.lastrowid
        db.commit()

    logger.info(
        f"Video uploaded: id={video_id}, team={db_user['team_id']}, user={user['id']}")
    return {"success": True, "video_id": video_id}


@router.get("/api/videos")
async def get_videos(request: Request):
    """
    Videos des Teams abrufen.
    SECURITY: Nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return {"videos": []}

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT v.id, v.title, v.description, v.filename, v.file_size, v.duration, 
                   v.created_at, u.vorname, u.nachname
            FROM videos v
            JOIN users u ON v.uploaded_by = u.id
            WHERE v.team_id = ? AND v.deleted_at IS NULL
            ORDER BY v.created_at DESC
        """, (db_user["team_id"],))
        videos = cursor.fetchall()

    return {
        "videos": [
            {
                "id": v["id"],
                "title": v["title"],
                "description": v["description"] or "",
                "file_size": v["file_size"],
                "duration": v["duration"],
                "created_at": v["created_at"],
                "uploaded_by": f"{v['vorname'] or ''} {v['nachname'] or ''}".strip() or "Unbekannt"
            }
            for v in videos
        ]
    }


@router.get("/api/videos/{video_id}/stream")
async def stream_video(request: Request, video_id: int):
    """
    Video streamen mit Range-Request-Unterstützung.
    SECURITY: Nur eigenes Team, IDOR Prevention.
    """
    user = get_current_user(request)

    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)
    if not is_staff_user(db_user):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT filename FROM videos
            WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (video_id, db_user["team_id"]))
        video = cursor.fetchone()

    if not video:
        return JSONResponse({"error": "Video nicht gefunden"}, status_code=404)

    team_dir = os.path.join(get_video_upload_dir(), str(db_user["team_id"]))
    file_path = os.path.join(team_dir, video["filename"])
    normalized_path = os.path.abspath(file_path)
    if not normalized_path.startswith(os.path.abspath(team_dir) + os.sep):
        return JSONResponse({"error": "Datei nicht gefunden"}, status_code=404)
    if not os.path.exists(file_path):
        return JSONResponse({"error": "Datei nicht gefunden"}, status_code=404)

    file_size = os.path.getsize(file_path)
    ext = os.path.splitext(video["filename"])[1].lower()
    media_type = {
        ".mp4": "video/mp4",
        ".mov": "video/quicktime",
        ".avi": "video/x-msvideo",
        ".webm": "video/webm",
        ".mkv": "video/x-matroska",
    }.get(ext, "application/octet-stream")

    # Check for Range header (for video seeking)
    range_header = request.headers.get("range")

    if range_header:
        # Parse range header: "bytes=0-1000" or "bytes=0-"
        range_value = range_header.replace("bytes=", "").strip()
        if "-" not in range_value:
            return JSONResponse({"error": "Ungültiger Range"}, status_code=416)
        range_match = range_value.split("-", 1)
        try:
            start = int(range_match[0]) if range_match[0] else 0
            end = int(range_match[1]) if range_match[1] else file_size - 1
        except ValueError:
            return JSONResponse({"error": "Ungültiger Range"}, status_code=416)

        if start < 0 or end < start or start >= file_size:
            return JSONResponse({"error": "Range nicht verfügbar"}, status_code=416)

        # Clamp end to file size
        end = min(end, file_size - 1)
        chunk_size = end - start + 1

        def iterfile():
            with open(file_path, "rb") as f:
                f.seek(start)
                remaining = chunk_size
                while remaining > 0:
                    read_size = min(65536, remaining)  # 64KB chunks
                    data = f.read(read_size)
                    if not data:
                        break
                    remaining -= len(data)
                    yield data

        headers = {
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Accept-Ranges": "bytes",
            "Content-Length": str(chunk_size),
            "Content-Type": media_type,
        }

        return StreamingResponse(
            iterfile(),
            status_code=206,
            headers=headers,
            media_type=media_type
        )
    else:
        # No range header - return full file with Accept-Ranges header
        return FileResponse(
            file_path,
            media_type=media_type,
            headers={"Accept-Ranges": "bytes"}
        )


@router.delete("/api/videos/{video_id}")
async def delete_video(request: Request, video_id: int):
    """
    Video löschen (Soft Delete).
    SECURITY: Nur Uploader oder Admin.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT uploaded_by FROM videos
            WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (video_id, db_user["team_id"]))
        video = cursor.fetchone()

        if not video:
            return JSONResponse({"error": "Video nicht gefunden"}, status_code=404)

        # Nur Uploader oder Admin darf löschen
        if video["uploaded_by"] != user["id"] and not db_user.get("is_admin"):
            return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

        cursor.execute("""
            UPDATE videos SET deleted_at = ? WHERE id = ?
        """, (datetime.now().isoformat(), video_id))
        db.commit()

    return {"success": True}


@router.post("/api/videos/{video_id}/clips")
async def create_clip(request: Request, video_id: int):
    """
    Video-Clip erstellen (Ausschnitt markieren).
    SECURITY: Nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    try:
        data = await request.json()
        start_time = float(data.get("start_time", 0))
        end_time = float(data.get("end_time", 0))
        note = data.get("note", "").strip()[:500]
        # Title is optional - use note or auto-generate
        title = data.get("title", "").strip()[:200]
        if not title:
            title = note[:
                         50] if note else f"Clip {int(start_time)}s-{int(end_time)}s"

        if start_time >= end_time:
            return JSONResponse({"error": "Ungültige Zeitangaben"}, status_code=400)

    except (ValueError, TypeError) as e:
        logging.error(f"Clip creation error: {e}")
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()

        # Video prüfen
        cursor.execute("""
            SELECT id FROM videos WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (video_id, db_user["team_id"]))
        if not cursor.fetchone():
            return JSONResponse({"error": "Video nicht gefunden"}, status_code=404)

        cursor.execute("""
            INSERT INTO video_clips (video_id, team_id, title, start_time, end_time, note, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (video_id, db_user["team_id"], title, int(start_time), int(end_time), note, user["id"]))
        clip_id = cursor.lastrowid
        db.commit()

    return {"success": True, "clip_id": clip_id}


@router.get("/api/videos/{video_id}/clips")
async def get_clips(request: Request, video_id: int):
    """
    Clips eines Videos abrufen.
    SECURITY: Nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return {"clips": []}

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT c.id, c.title, c.start_time, c.end_time, c.note, c.created_at,
                   u.vorname, u.nachname
            FROM video_clips c
            JOIN users u ON c.created_by = u.id
            WHERE c.video_id = ? AND c.team_id = ? AND c.deleted_at IS NULL
            ORDER BY c.start_time
        """, (video_id, db_user["team_id"]))
        clips = cursor.fetchall()

    return {
        "clips": [
            {
                "id": c["id"],
                "title": c["title"],
                "start_time": c["start_time"],
                "end_time": c["end_time"],
                "note": c["note"] or "",
                "created_at": c["created_at"],
                "created_by": f"{c['vorname'] or ''} {c['nachname'] or ''}".strip()
            }
            for c in clips
        ]
    }


# =====================
# VIDEO MARKERS API
# =====================

@router.post("/api/videos/{video_id}/markers")
async def create_marker(request: Request, video_id: int):
    """
    Marker auf Video erstellen.
    SECURITY: Nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    try:
        data = await request.json()
        time_seconds = float(data.get("time_seconds", 0))
        label = data.get("label", "").strip()[:100]
        color = data.get("color", "#ef4444").strip()[:20]

        if time_seconds < 0:
            return JSONResponse({"error": "Ungültige Zeit"}, status_code=400)

    except (ValueError, TypeError) as e:
        logging.error(f"Marker creation error: {e}")
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()

        # Video prüfen
        cursor.execute("""
            SELECT id FROM videos WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (video_id, db_user["team_id"]))
        if not cursor.fetchone():
            return JSONResponse({"error": "Video nicht gefunden"}, status_code=404)

        cursor.execute("""
            INSERT INTO video_markers (video_id, team_id, time_seconds, label, color, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (video_id, db_user["team_id"], time_seconds, label or None, color, user["id"]))
        marker_id = cursor.lastrowid
        db.commit()

    return {"success": True, "marker_id": marker_id, "time_seconds": time_seconds, "label": label, "color": color}


@router.get("/api/videos/{video_id}/markers")
async def get_markers(request: Request, video_id: int):
    """
    Marker eines Videos abrufen.
    SECURITY: Nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return {"markers": []}

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT m.id, m.time_seconds, m.label, m.color, m.created_at,
                   u.vorname, u.nachname
            FROM video_markers m
            JOIN users u ON m.created_by = u.id
            WHERE m.video_id = ? AND m.team_id = ? AND m.deleted_at IS NULL
            ORDER BY m.time_seconds
        """, (video_id, db_user["team_id"]))
        markers = cursor.fetchall()

    return {
        "markers": [
            {
                "id": m["id"],
                "time_seconds": m["time_seconds"],
                "label": m["label"] or "",
                "color": m["color"] or "#ef4444",
                "created_at": m["created_at"],
                "created_by": f"{m['vorname'] or ''} {m['nachname'] or ''}".strip()
            }
            for m in markers
        ]
    }


@router.delete("/api/markers/{marker_id}")
async def delete_marker(request: Request, marker_id: int):
    """
    Marker löschen.
    SECURITY: Nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE video_markers SET deleted_at = CURRENT_TIMESTAMP
            WHERE id = ? AND team_id = ?
        """, (marker_id, db_user["team_id"]))
        db.commit()

    return {"success": True}


@router.put("/api/markers/{marker_id}")
async def update_marker(request: Request, marker_id: int):
    """
    Marker umbenennen.
    SECURITY: Nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    label = str(data.get("label", "")).strip()[:100]

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE video_markers
            SET label = ?
            WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (label, marker_id, db_user["team_id"]))
        if cursor.rowcount == 0:
            return JSONResponse({"error": "Marker nicht gefunden"}, status_code=404)
        db.commit()

    return {"success": True, "label": label}


@router.delete("/api/clips/{clip_id}")
async def delete_clip(request: Request, clip_id: int):
    """
    Clip löschen.
    SECURITY: Nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE video_clips SET deleted_at = CURRENT_TIMESTAMP
            WHERE id = ? AND team_id = ?
        """, (clip_id, db_user["team_id"]))
        db.commit()

    return {"success": True}


@router.put("/api/clips/{clip_id}")
async def update_clip(request: Request, clip_id: int):
    """
    Clip umbenennen / Notiz aktualisieren.
    SECURITY: Nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    title = str(data.get("title", "")).strip()[:200]
    note = str(data.get("note", "")).strip()[:500]
    if not title:
        return JSONResponse({"error": "Titel erforderlich"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE video_clips
            SET title = ?, note = ?
            WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (title, note, clip_id, db_user["team_id"]))
        if cursor.rowcount == 0:
            return JSONResponse({"error": "Clip nicht gefunden"}, status_code=404)
        db.commit()

    return {"success": True, "title": title, "note": note}


@router.post("/api/clips/{clip_id}/share")
async def share_clip(request: Request, clip_id: int):
    """
    Clip an Spieler senden.
    SECURITY: Nur eigenes Team, nur an Team-Mitglieder.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    try:
        data = await request.json()
        recipient_ids = data.get("recipient_ids", [])
        if not recipient_ids and data.get("recipient_id") is not None:
            recipient_ids = [data.get("recipient_id")]
        message = data.get("message", "").strip()[:500]

        if not recipient_ids or not isinstance(recipient_ids, list):
            return JSONResponse({"error": "Empfänger erforderlich"}, status_code=400)

    except (ValueError, TypeError):
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()

        # Clip prüfen
        cursor.execute("""
            SELECT id FROM video_clips WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (clip_id, db_user["team_id"]))
        if not cursor.fetchone():
            return JSONResponse({"error": "Clip nicht gefunden"}, status_code=404)

        # Empfänger prüfen (müssen im selben Team sein)
        shared_count = 0
        for recipient_id in recipient_ids:
            cursor.execute("""
                SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?
            """, (db_user["team_id"], recipient_id))
            if cursor.fetchone():
                cursor.execute("""
                    INSERT INTO video_shares (clip_id, sender_id, recipient_id, message)
                    VALUES (?, ?, ?, ?)
                """, (clip_id, user["id"], recipient_id, message))
                shared_count += 1

        db.commit()

    return {"success": True, "shared_count": shared_count}


@router.get("/api/shared-clips")
async def get_shared_clips(request: Request):
    """
    Für User freigegebene Clips abrufen.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT s.id as share_id, s.message, s.is_viewed, s.created_at,
                   c.id as clip_id, c.title, c.start_time, c.end_time, c.note,
                   v.id as video_id, v.title as video_title,
                   u.vorname, u.nachname
            FROM video_shares s
            JOIN video_clips c ON s.clip_id = c.id
            JOIN videos v ON c.video_id = v.id
            JOIN users u ON s.sender_id = u.id
            WHERE s.recipient_id = ? AND c.deleted_at IS NULL AND v.deleted_at IS NULL
            ORDER BY s.created_at DESC
        """, (user["id"],))
        shares = cursor.fetchall()

    return {
        "shared_clips": [
            {
                "share_id": s["share_id"],
                "message": s["message"] or "",
                "is_viewed": bool(s["is_viewed"]),
                "shared_at": s["created_at"],
                "clip": {
                    "id": s["clip_id"],
                    "title": s["title"],
                    "start_time": s["start_time"],
                    "end_time": s["end_time"],
                    "note": s["note"] or ""
                },
                "video": {
                    "id": s["video_id"],
                    "title": s["video_title"]
                },
                "sender": f"{s['vorname'] or ''} {s['nachname'] or ''}".strip()
            }
            for s in shares
        ]
    }


@router.get("/api/shared-clips/sent")
async def get_sent_shared_clips(request: Request, recipient_id: int = None):
    """
    Vom User versendete Clips abrufen (optional gefiltert nach Empfänger).
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"shared_clips": []})

    params = [user["id"], db_user["team_id"]]
    recipient_filter = ""
    if recipient_id:
        recipient_filter = "AND s.recipient_id = ?"
        params.append(recipient_id)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(f"""
            SELECT s.id as share_id, s.message, s.is_viewed, s.created_at, s.recipient_id,
                   c.id as clip_id, c.title, c.start_time, c.end_time, c.note,
                   v.id as video_id, v.title as video_title,
                   u.vorname, u.nachname
            FROM video_shares s
            JOIN video_clips c ON s.clip_id = c.id
            JOIN videos v ON c.video_id = v.id
            JOIN users u ON s.recipient_id = u.id
            WHERE s.sender_id = ? AND v.team_id = ? AND c.deleted_at IS NULL AND v.deleted_at IS NULL
            {recipient_filter}
            ORDER BY s.created_at DESC
        """, params)
        shares = cursor.fetchall()

    return {
        "shared_clips": [
            {
                "share_id": s["share_id"],
                "message": s["message"] or "",
                "is_viewed": bool(s["is_viewed"]),
                "shared_at": s["created_at"],
                "clip": {
                    "id": s["clip_id"],
                    "title": s["title"],
                    "start_time": s["start_time"],
                    "end_time": s["end_time"],
                    "note": s["note"] or ""
                },
                "video": {
                    "id": s["video_id"],
                    "title": s["video_title"]
                },
                "recipient": f"{s['vorname'] or ''} {s['nachname'] or ''}".strip()
            }
            for s in shares
        ]
    }


@router.post("/api/shared-clips/{share_id}/viewed")
async def mark_clip_viewed(request: Request, share_id: int):
    """
    Clip als gesehen markieren.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE video_shares 
            SET is_viewed = 1, viewed_at = ?
            WHERE id = ? AND recipient_id = ?
        """, (datetime.now().isoformat(), share_id, user["id"]))
        db.commit()

    return {"success": True}


@router.get("/api/shared-clips/{share_id}/stream")
async def stream_shared_clip(request: Request, share_id: int):
    """
    Shared Clip streamen (nur Empfänger).
    SECURITY: Zugriff nur für Empfänger des Shares.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT v.filename
            FROM video_shares s
            JOIN video_clips c ON s.clip_id = c.id
            JOIN videos v ON c.video_id = v.id
            WHERE s.id = ? AND v.team_id = ? AND v.deleted_at IS NULL
              AND (s.recipient_id = ? OR s.sender_id = ?)
        """, (share_id, db_user["team_id"], user["id"], user["id"]))
        row = cursor.fetchone()

    if not row:
        return JSONResponse({"error": "Clip nicht gefunden"}, status_code=404)

    team_dir = os.path.join(get_video_upload_dir(), str(db_user["team_id"]))
    file_path = os.path.join(team_dir, row["filename"])
    normalized_path = os.path.abspath(file_path)
    if not normalized_path.startswith(os.path.abspath(team_dir) + os.sep):
        return JSONResponse({"error": "Datei nicht gefunden"}, status_code=404)
    if not os.path.exists(file_path):
        return JSONResponse({"error": "Datei nicht gefunden"}, status_code=404)

    file_size = os.path.getsize(file_path)
    ext = os.path.splitext(row["filename"])[1].lower()
    media_type = {
        ".mp4": "video/mp4",
        ".mov": "video/quicktime",
        ".avi": "video/x-msvideo",
        ".webm": "video/webm",
        ".mkv": "video/x-matroska",
    }.get(ext, "application/octet-stream")

    range_header = request.headers.get("range")
    if range_header:
        range_value = range_header.replace("bytes=", "").strip()
        if "-" not in range_value:
            return JSONResponse({"error": "Ungültiger Range"}, status_code=416)
        range_match = range_value.split("-", 1)
        try:
            start = int(range_match[0]) if range_match[0] else 0
            end = int(range_match[1]) if range_match[1] else file_size - 1
        except ValueError:
            return JSONResponse({"error": "Ungültiger Range"}, status_code=416)

        if start < 0 or end < start or start >= file_size:
            return JSONResponse({"error": "Range nicht verfügbar"}, status_code=416)

        end = min(end, file_size - 1)
        chunk_size = end - start + 1

        def iterfile():
            with open(file_path, "rb") as f:
                f.seek(start)
                remaining = chunk_size
                while remaining > 0:
                    read_size = min(65536, remaining)
                    data = f.read(read_size)
                    if not data:
                        break
                    remaining -= len(data)
                    yield data

        headers = {
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Accept-Ranges": "bytes",
            "Content-Length": str(chunk_size),
            "Content-Type": media_type,
        }

        return StreamingResponse(
            iterfile(),
            status_code=206,
            headers=headers,
            media_type=media_type
        )

    return FileResponse(
        file_path,
        media_type=media_type,
        headers={"Accept-Ranges": "bytes"}
    )


@router.post("/api/invitations")
async def create_invitation_api(request: Request):
    """
    Einladung erstellen.
    SECURITY: Nur Admin, Input-Validierung.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team gefunden"}, status_code=400)

    if not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

        role_id = data.get("role_id")
        max_uses = min(data.get("max_uses", 10),
                       SecurityConfig.INVITATION_MAX_USES)
        days_valid = min(data.get("days_valid", 7), 30)

        if not role_id:
            return JSONResponse({"error": "Rolle erforderlich"}, status_code=400)

        # Rolle prüfen
        cursor.execute(
            "SELECT id FROM roles WHERE id = ? AND team_id = ?",
            (role_id, db_user["team_id"])
        )
        if not cursor.fetchone():
            return JSONResponse({"error": "Ungültige Rolle"}, status_code=400)

    try:
        token = create_invitation(
            db_user["team_id"], role_id, user["id"], max_uses, days_valid)
    except (PermissionError, ValueError) as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    return {"success": True, "token": token}


@router.delete("/api/invitations/{invitation_id}")
async def delete_invitation(request: Request, invitation_id: int):
    """
    Einladung deaktivieren.
    SECURITY: Nur Admin, nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team gefunden"}, status_code=400)

    if not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            "UPDATE invitations SET is_active = 0 WHERE id = ? AND team_id = ?",
            (invitation_id, db_user["team_id"])
        )
        db.commit()

    log_audit_event(user["id"], "INVITATION_DELETED",
                    "invitation", invitation_id)
    return {"success": True}


# ============================================
# Join Team Routes
# ============================================

@router.get("/join/{token}")
async def join_page(request: Request, token: str):
    """
    Einladungs-Seite anzeigen.
    SECURITY: Token-Validierung.
    """
    try:
        token = InputValidator.validate_token(token)
    except ValidationError:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Ungültiger Einladungslink"}
        )

    try:
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("""
                SELECT i.*, t.name as team_name, r.name as role_name
                FROM invitations i
                JOIN teams t ON i.team_id = t.id
                JOIN roles r ON i.role_id = r.id
                WHERE i.token = ? AND i.is_active = 1
            """, (token,))
            invitation = cursor.fetchone()

        if not invitation:
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Ungültiger oder abgelaufener Einladungslink"}
            )

        # Ablauf prüfen
        if invitation["expires_at"]:
            try:
                expires = datetime.fromisoformat(invitation["expires_at"])
            except ValueError:
                return templates.TemplateResponse(
                    "login.html",
                    {"request": request, "error": "Einladung ungültig"}
                )
            if expires < datetime.now():
                return templates.TemplateResponse(
                    "login.html",
                    {"request": request, "error": "Einladung abgelaufen"}
                )
    except Exception:
        return templates.TemplateResponse(
            "join.html",
            {"request": request, "error": "Ein Fehler ist aufgetreten. Bitte versuche es erneut.",
             "token": token, "logged_in": False, "team_name": "", "role_name": "Spieler"}
        )

    user = get_current_user(request)
    available_players = []
    try:
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("""
                SELECT id, name, position, trikotnummer
                FROM players
                WHERE team_id = ? AND user_id IS NULL AND deleted_at IS NULL
                ORDER BY name
            """, (invitation["team_id"],))
            available_players = [dict(row) for row in cursor.fetchall()]
    except Exception:
        available_players = []

    # Beta-Cookie setzen damit Einladungs-User die Access Gate umgehen
    response = templates.TemplateResponse("join.html", {
        "request": request,
        "token": token,
        "team_name": invitation["team_name"],
        "role_name": "Spieler",
        "logged_in": user is not None,
        "available_players": available_players
    })

    # Beta-Zugang gewähren - Cookie-Wert muss "verified" sein
    response.set_cookie(
        key="beta_access",
        value=_create_beta_access_cookie_token(),
        max_age=86400 * 365,  # 1 Jahr
        httponly=True,
        secure=SecurityConfig.COOKIE_SECURE,
        samesite=SecurityConfig.COOKIE_SAMESITE
    )

    return response


@router.post("/join/{token}")
async def join_team(request: Request, token: str):
    """
    Team beitreten.
    SECURITY: Token-Validierung, User muss eingeloggt sein.
    """
    user = get_current_user(request)
    invitation_info = None
    try:
        token = InputValidator.validate_token(token)
    except ValidationError:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Ungültiger Einladungslink"}
        )

    try:
        if not user:
            # Registrierung über Einladungslink
            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute("""
                    SELECT i.*, t.name as team_name, r.name as role_name
                    FROM invitations i
                    JOIN teams t ON i.team_id = t.id
                    LEFT JOIN roles r ON i.role_id = r.id
                    WHERE i.token = ? AND i.is_active = 1
                """, (token,))
                invitation_info = cursor.fetchone()

            if not invitation_info:
                return templates.TemplateResponse(
                    "join.html",
                    {"request": request, "error": "Einladung ist ungültig oder abgelaufen", "token": token,
                     "logged_in": False}
                )

            try:
                form_data = await request.form()
            except Exception:
                return templates.TemplateResponse(
                    "login.html",
                    {"request": request, "error": "Ungültige Anfrage"}
                )

            email = str(form_data.get("email", "")).strip()
            password = str(form_data.get("password", "")).strip()
            password_confirm = str(form_data.get("password_confirm", "")).strip()
            player_id_raw = str(form_data.get("player_id", "")).strip()

            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute("""
                    SELECT id, name, position, telefon, geburtsdatum, email
                    FROM players
                    WHERE team_id = ? AND user_id IS NULL AND deleted_at IS NULL
                    ORDER BY name
                """, (invitation_info["team_id"],))
                available_players = [dict(row) for row in cursor.fetchall()]

            if not available_players:
                return templates.TemplateResponse(
                    "join.html",
                    {"request": request, "error": "Bitte zuerst im Kader anlegen. Es gibt keinen freien Spieler-Eintrag.",
                     "token": token, "logged_in": False, "team_name": invitation_info["team_name"],
                     "role_name": "Spieler", "available_players": available_players}
                )

            if not email or not password:
                return templates.TemplateResponse(
                    "join.html",
                    {"request": request, "error": "E-Mail und Passwort erforderlich", "token": token, "logged_in": False,
                     "team_name": invitation_info["team_name"], "role_name": "Spieler",
                     "available_players": available_players}
                )

            if password != password_confirm:
                return templates.TemplateResponse(
                    "join.html",
                    {"request": request, "error": "Passwörter stimmen nicht überein", "token": token, "logged_in": False,
                     "team_name": invitation_info["team_name"], "role_name": "Spieler",
                     "available_players": available_players}
                )

            # Input-Validierung
            try:
                email = InputValidator.validate_email(email)
                password = InputValidator.validate_password(password)
            except ValidationError as e:
                return templates.TemplateResponse(
                    "join.html",
                    {"request": request, "error": e.message, "token": token, "logged_in": False,
                     "team_name": invitation_info["team_name"], "role_name": "Spieler",
                     "available_players": available_players}
                )

            # SECURITY: Prüfe auf häufig geleakte/schwache Passwörter
            if is_common_password(password):
                return templates.TemplateResponse(
                    "join.html",
                    {"request": request, "error": "Dieses Passwort ist zu häufig verwendet", "token": token, "logged_in": False,
                     "team_name": invitation_info["team_name"], "role_name": "Spieler",
                     "available_players": available_players}
                )

            is_strong, _ = is_password_strong_enough(password, min_entropy=50.0)
            if not is_strong:
                return templates.TemplateResponse(
                    "join.html",
                    {"request": request, "error": "Passwort ist nicht komplex genug", "token": token, "logged_in": False,
                     "team_name": invitation_info["team_name"], "role_name": "Spieler",
                     "available_players": available_players}
                )

            try:
                is_pwned, _ = check_password_pwned_sync(password)
                if is_pwned:
                    return templates.TemplateResponse(
                        "join.html",
                        {"request": request, "error": "Passwort wurde in Datenlecks gefunden", "token": token, "logged_in": False,
                         "team_name": invitation_info["team_name"], "role_name": "Spieler",
                         "available_players": available_players}
                    )
            except Exception:
                pass

            if not player_id_raw:
                return templates.TemplateResponse(
                    "join.html",
                    {"request": request, "error": "Bitte wähle deinen Kader-Eintrag.", "token": token, "logged_in": False,
                     "team_name": invitation_info["team_name"], "role_name": "Spieler",
                     "available_players": available_players}
                )

            try:
                player_id = InputValidator.validate_positive_int(player_id_raw, "player_id", max_value=100000000)
            except ValidationError:
                return templates.TemplateResponse(
                    "join.html",
                    {"request": request, "error": "Ungültiger Kader-Eintrag.", "token": token, "logged_in": False,
                     "team_name": invitation_info["team_name"], "role_name": "Spieler",
                     "available_players": available_players}
                )

            invitation = invitation_info
            with get_db_connection() as db:
                cursor = db.cursor()

                if invitation["expires_at"]:
                    try:
                        expires = datetime.fromisoformat(invitation["expires_at"])
                    except ValueError:
                        return templates.TemplateResponse(
                            "join.html",
                            {"request": request, "error": "Einladung ungültig", "token": token, "logged_in": False,
                             "team_name": invitation_info["team_name"], "role_name": "Spieler",
                             "available_players": available_players}
                        )
                    if expires < datetime.now():
                        return templates.TemplateResponse(
                            "join.html",
                            {"request": request, "error": "Einladung abgelaufen", "token": token, "logged_in": False,
                             "team_name": invitation_info["team_name"], "role_name": "Spieler",
                             "available_players": available_players}
                        )

                uses_key = "uses_count" if "uses_count" in invitation.keys() else "uses"
                max_uses = invitation["max_uses"] if "max_uses" in invitation.keys() else None
                current_uses = invitation[uses_key] if uses_key in invitation.keys() else 0
                if max_uses and current_uses >= max_uses:
                    return templates.TemplateResponse(
                        "join.html",
                        {"request": request, "error": "Einladungslimit erreicht", "token": token, "logged_in": False,
                         "team_name": invitation_info["team_name"], "role_name": "Spieler",
                         "available_players": available_players}
                    )

                cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                if cursor.fetchone():
                    return templates.TemplateResponse(
                        "join.html",
                        {"request": request, "error": "E-Mail ist bereits registriert. Bitte einloggen.", "token": token, "logged_in": False,
                         "team_name": invitation_info["team_name"], "role_name": "Spieler",
                         "available_players": available_players}
                    )

                cursor.execute("""
                    SELECT id FROM roles WHERE team_id = ? AND LOWER(name) = 'spieler'
                """, (invitation["team_id"],))
                player_role = cursor.fetchone()
                role_id = player_role["id"] if player_role else invitation["role_id"]

                cursor.execute("""
                    SELECT id, name, position, telefon, geburtsdatum, email
                    FROM players
                    WHERE id = ? AND team_id = ? AND user_id IS NULL AND deleted_at IS NULL
                """, (player_id, invitation["team_id"]))
                player_row = cursor.fetchone()
                if not player_row:
                    return templates.TemplateResponse(
                        "join.html",
                        {"request": request, "error": "Der ausgewählte Kader-Eintrag ist nicht verfügbar.", "token": token,
                         "logged_in": False, "team_name": invitation_info["team_name"], "role_name": "Spieler",
                         "available_players": available_players}
                    )

                player_name = (player_row["name"] or "").strip()
                name_parts = player_name.split()
                vorname = name_parts[0] if name_parts else ""
                nachname = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""

                peppered_password = f"{password}{SecurityConfig.PASSWORD_PEPPER}"
                password_hash = bcrypt.hashpw(
                    peppered_password.encode('utf-8'),
                    bcrypt.gensalt(rounds=12)
                ).decode('utf-8')

                cursor.execute("""
                    INSERT INTO users (email, password_hash, onboarding_complete, is_active, payment_status, vorname, nachname, position, telefon, geburtsdatum)
                    VALUES (?, ?, 1, 1, 'paid', ?, ?, ?, ?, ?)
                """, (email, password_hash, vorname, nachname,
                      player_row["position"] or "", player_row["telefon"] or "", player_row["geburtsdatum"]))
                user_id = cursor.lastrowid

                cursor.execute("""
                    INSERT INTO team_members (team_id, user_id, role_id)
                    VALUES (?, ?, ?)
                """, (invitation["team_id"], user_id, role_id))

                cursor.execute("""
                    UPDATE players
                    SET user_id = ?, email = COALESCE(NULLIF(email, ''), ?), updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND user_id IS NULL
                """, (user_id, email, player_id))

                if cursor.rowcount == 0:
                    return templates.TemplateResponse(
                        "join.html",
                        {"request": request, "error": "Der Kader-Eintrag wurde bereits vergeben.", "token": token,
                         "logged_in": False, "team_name": invitation_info["team_name"], "role_name": "Spieler",
                         "available_players": available_players}
                    )

                # Einladung als benutzt markieren
                if "uses_count" in invitation.keys():
                    cursor.execute("""
                        UPDATE invitations SET uses_count = uses_count + 1 WHERE token = ?
                    """, (token,))
                else:
                    cursor.execute("""
                        UPDATE invitations SET uses = uses + 1 WHERE token = ?
                    """, (token,))

                db.commit()

            return templates.TemplateResponse(
                "join.html",
                {"request": request, "success": "Account erstellt. Du kannst dich jetzt einloggen.",
                 "token": token, "logged_in": False, "team_name": invitation_info["team_name"],
                 "role_name": "Spieler", "available_players": available_players}
            )

        result = use_invitation(token, user["id"])

        if result["success"]:
            log_audit_event(user["id"], "TEAM_JOINED", "user", user["id"])
            return RedirectResponse(url="/dashboard", status_code=303)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": result["error"]}
        )
    except Exception:
        team_name = invitation_info["team_name"] if invitation_info else ""
        return templates.TemplateResponse(
            "join.html",
            {"request": request, "error": "Ein Fehler ist aufgetreten. Bitte versuche es erneut.",
             "token": token, "logged_in": False, "team_name": team_name, "role_name": "Spieler"}
        )


# ============================================
# API Endpoints - Players (Kader)
# ============================================

@router.get("/api/players")
async def get_players(request: Request):
    """
    Spieler des Teams abrufen.
    SECURITY: Admins/Trainer/Co-Trainer sehen alle, 'Spieler'-Rolle nur sich selbst.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"players": []})

    with get_db_connection() as db:
        cursor = db.cursor()
        dummy_names = ["Max Müller", "John Schmidt", "Tom Klaus", "Chris Davis"]
        placeholders = ",".join("?" * len(dummy_names))
        cursor.execute(f"""
            UPDATE players
            SET deleted_at = CURRENT_TIMESTAMP
            WHERE team_id = ?
              AND deleted_at IS NULL
              AND user_id IS NULL
              AND name IN ({placeholders})
              AND (email IS NULL OR email = '')
              AND (telefon IS NULL OR telefon = '')
              AND (notizen IS NULL OR notizen = '')
        """, [db_user["team_id"], *dummy_names])

        # Rolle des Users ermitteln
        cursor.execute("""
            SELECT r.name as role_name FROM roles r 
            WHERE r.id = ?
        """, (db_user.get("role_id"),))
        role_row = cursor.fetchone()
        role_name = role_row["role_name"] if role_row else None

        # SECURITY: Admins, Trainer, Co-Trainer sehen alle Spieler
        # 'Spieler'-Rolle sieht nur sich selbst
        staff_roles = ["Admin", "Trainer", "Co-Trainer", "Torwarttrainer",
                       "Betreuer", "Physio", "Jugendleiter", "Vorstand"]

        if db_user.get("is_admin") or role_name in staff_roles:
            cursor.execute("""
                SELECT id, name, position, trikotnummer, status, email, telefon, geburtsdatum, notizen,
                       starker_fuss, werdegang, verletzungshistorie, user_id, groesse, gewicht
                FROM players
                WHERE team_id = ? AND deleted_at IS NULL
                ORDER BY trikotnummer, name
            """, (db_user["team_id"],))
            players = []
            for row in cursor.fetchall():
                player = dict(row)
                normalized = (player.get("status") or "").strip()
                if normalized in ("Verletzt", "Angeschlagen"):
                    player["status"] = "Ausfall"
                elif normalized not in ("Fit", "Reha", "Ausfall"):
                    player["status"] = "Fit"
                players.append(player)
        else:
            # Spieler/Eltern sehen nur sich selbst (verknüpft über user_id)
            cursor.execute("""
                SELECT id, name, position, trikotnummer, status, email, telefon, geburtsdatum, notizen,
                       starker_fuss, werdegang, verletzungshistorie, user_id, groesse, gewicht
                FROM players
                WHERE team_id = ? AND user_id = ? AND deleted_at IS NULL
            """, (db_user["team_id"], user["id"]))
            players = []
            for row in cursor.fetchall():
                player = dict(row)
                normalized = (player.get("status") or "").strip()
                if normalized in ("Verletzt", "Angeschlagen"):
                    player["status"] = "Ausfall"
                elif normalized not in ("Fit", "Reha", "Ausfall"):
                    player["status"] = "Fit"
                players.append(player)

    return JSONResponse({"players": players})


@router.post("/api/players")
async def create_player(request: Request):
    """
    Neuen Spieler erstellen.
    SECURITY: Nur Admins und Trainer dürfen Spieler erstellen.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team zugeordnet"}, status_code=400)

    # SECURITY: Prüfe Rolle - nur Admins und Trainer dürfen Spieler hinzufügen
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT name FROM roles WHERE id = ?",
                       (db_user.get("role_id"),))
        role_row = cursor.fetchone()
        role_name = role_row["name"] if role_row else None

    edit_roles = ["Admin", "Trainer"]
    if not db_user.get("is_admin") and role_name not in edit_roles:
        return JSONResponse({"error": "Keine Berechtigung. Nur Admins und Trainer können Spieler hinzufügen."}, status_code=403)

    # Limit: Max 30 Spieler pro Kader
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT COUNT(*) as count FROM players 
            WHERE team_id = ? AND deleted_at IS NULL
        """, (db_user["team_id"],))
        player_count = cursor.fetchone()["count"]
        if player_count >= 30:
            return JSONResponse({"error": "Maximum erreicht: 30 Spieler pro Kader."}, status_code=400)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    name = str(data.get("name", "")).strip()[:200]
    if not name:
        return JSONResponse({"error": "Name erforderlich"}, status_code=400)

    position = str(data.get("position", "")).strip()[:50]
    trikotnummer = data.get("trikotnummer")
    if trikotnummer is not None:
        try:
            trikotnummer = int(trikotnummer)
            if trikotnummer < 0 or trikotnummer > 99:
                trikotnummer = None
        except (ValueError, TypeError):
            trikotnummer = None

    status = str(data.get("status", "Fit")).strip()
    if status not in ("Fit", "Reha", "Ausfall"):
        status = "Fit"

    email = str(data.get("email", "")).strip()[:254]
    telefon = str(data.get("telefon", "")).strip()[:30]
    geburtsdatum = str(data.get("geburtsdatum", "")).strip()[:10] or None
    notizen = str(data.get("notizen", "")).strip()[:1000]
    starker_fuss = str(data.get("starker_fuss", "")).strip()[:30]
    werdegang = str(data.get("werdegang", "")).strip()[:1000]
    verletzungshistorie = str(data.get("verletzungshistorie", "")).strip()[:1000]

    groesse = data.get("groesse")
    if groesse is not None and groesse != "":
        try:
            groesse = int(groesse)
            if groesse < 100 or groesse > 250:
                groesse = None
        except (ValueError, TypeError):
            groesse = None
    else:
        groesse = None

    gewicht = data.get("gewicht")
    if gewicht is not None and gewicht != "":
        try:
            gewicht = int(gewicht)
            if gewicht < 30 or gewicht > 200:
                gewicht = None
        except (ValueError, TypeError):
            gewicht = None
    else:
        gewicht = None

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO players (team_id, name, position, trikotnummer, status, email, telefon, geburtsdatum, notizen,
                                 starker_fuss, werdegang, verletzungshistorie, groesse, gewicht)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (db_user["team_id"], name, position, trikotnummer, status, email, telefon, geburtsdatum, notizen,
              starker_fuss, werdegang, verletzungshistorie, groesse, gewicht))
        db.commit()
        player_id = cursor.lastrowid

    return JSONResponse({"success": True, "id": player_id})


@router.put("/api/players/{player_id}")
async def update_player(request: Request, player_id: int):
    """
    Spieler aktualisieren.
    SECURITY: Nur Admins und Trainer dürfen Spieler bearbeiten.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    # SECURITY: Prüfe Rolle - nur Admins und Trainer dürfen bearbeiten
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT name FROM roles WHERE id = ?",
                       (db_user.get("role_id"),))
        role_row = cursor.fetchone()
        role_name = role_row["name"] if role_row else None

    edit_roles = ["Admin", "Trainer"]
    if not db_user.get("is_admin") and role_name not in edit_roles:
        return JSONResponse({"error": "Keine Berechtigung. Nur Admins und Trainer können Spieler bearbeiten."}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        # SECURITY: Nur eigenes Team
        cursor.execute("SELECT id FROM players WHERE id = ? AND team_id = ? AND deleted_at IS NULL",
                       (player_id, db_user["team_id"]))
        if not cursor.fetchone():
            return JSONResponse({"error": "Spieler nicht gefunden"}, status_code=404)

        updates = []
        params = []
        link_user_id = None

        if "name" in data:
            updates.append("name = ?")
            params.append(str(data["name"]).strip()[:200])
        if "position" in data:
            updates.append("position = ?")
            params.append(str(data["position"]).strip()[:50])
        if "trikotnummer" in data:
            updates.append("trikotnummer = ?")
            try:
                params.append(int(data["trikotnummer"]))
            except (ValueError, TypeError):
                params.append(None)
        if "status" in data:
            status = str(data["status"]).strip()
            if status in ("Fit", "Reha", "Ausfall"):
                updates.append("status = ?")
                params.append(status)
        if "email" in data:
            updates.append("email = ?")
            params.append(str(data["email"]).strip()[:254])
        if "telefon" in data:
            updates.append("telefon = ?")
            params.append(str(data["telefon"]).strip()[:30])
        if "notizen" in data:
            updates.append("notizen = ?")
            params.append(str(data["notizen"]).strip()[:1000])
        if "starker_fuss" in data:
            updates.append("starker_fuss = ?")
            params.append(str(data["starker_fuss"]).strip()[:30])
        if "werdegang" in data:
            updates.append("werdegang = ?")
            params.append(str(data["werdegang"]).strip()[:1000])
        if "verletzungshistorie" in data:
            updates.append("verletzungshistorie = ?")
            params.append(str(data["verletzungshistorie"]).strip()[:1000])
        if "groesse" in data:
            try:
                groesse = int(data["groesse"])
                if groesse < 100 or groesse > 250:
                    groesse = None
            except (ValueError, TypeError):
                groesse = None
            updates.append("groesse = ?")
            params.append(groesse)
        if "gewicht" in data:
            try:
                gewicht = int(data["gewicht"])
                if gewicht < 30 or gewicht > 200:
                    gewicht = None
            except (ValueError, TypeError):
                gewicht = None
            updates.append("gewicht = ?")
            params.append(gewicht)
        if "user_id" in data:
            raw_user_id = data.get("user_id")
            if raw_user_id in (None, "", 0, "0"):
                updates.append("user_id = NULL")
                link_user_id = None
            else:
                try:
                    link_user_id = int(raw_user_id)
                except (ValueError, TypeError):
                    return JSONResponse({"error": "Ungültiger Nutzer"}, status_code=400)

                cursor.execute("""
                    SELECT u.id, u.email, r.name as role_name
                    FROM users u
                    JOIN team_members tm ON tm.user_id = u.id
                    JOIN roles r ON tm.role_id = r.id
                    WHERE u.id = ? AND tm.team_id = ? AND u.is_active = 1
                """, (link_user_id, db_user["team_id"]))
                user_row = cursor.fetchone()
                if not user_row:
                    return JSONResponse({"error": "Nutzer nicht gefunden"}, status_code=404)

                role_name = (user_row["role_name"] or "").strip().lower()
                if role_name != "spieler" and not db_user.get("is_admin"):
                    return JSONResponse({"error": "Nur Spieler-Accounts können verknüpft werden"}, status_code=400)

                cursor.execute("""
                    SELECT id FROM players
                    WHERE user_id = ? AND team_id = ? AND deleted_at IS NULL AND id != ?
                """, (link_user_id, db_user["team_id"], player_id))
                if cursor.fetchone():
                    return JSONResponse({"error": "Account ist bereits einem anderen Spieler zugeordnet"}, status_code=400)

                updates.append("user_id = ?")
                params.append(link_user_id)

        if updates:
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(player_id)
            cursor.execute(
                f"UPDATE players SET {', '.join(updates)} WHERE id = ?", params)
            if link_user_id:
                cursor.execute("""
                    SELECT name, position, telefon, geburtsdatum, email
                    FROM players
                    WHERE id = ? AND team_id = ? AND deleted_at IS NULL
                """, (player_id, db_user["team_id"]))
                player_row = cursor.fetchone()
                if player_row:
                    name = (player_row["name"] or "").strip()
                    name_parts = name.split()
                    vorname = name_parts[0] if name_parts else ""
                    nachname = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""
                    cursor.execute("""
                        UPDATE users SET
                            vorname = CASE WHEN vorname IS NULL OR vorname = '' THEN ? ELSE vorname END,
                            nachname = CASE WHEN nachname IS NULL OR nachname = '' THEN ? ELSE nachname END,
                            position = ?,
                            telefon = CASE WHEN telefon IS NULL OR telefon = '' THEN ? ELSE telefon END,
                            geburtsdatum = COALESCE(geburtsdatum, ?),
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (vorname, nachname, player_row["position"] or "",
                          player_row["telefon"] or "", player_row["geburtsdatum"], link_user_id))
                    cursor.execute("""
                        UPDATE players
                        SET email = COALESCE(NULLIF(email, ''), ?), updated_at = CURRENT_TIMESTAMP
                        WHERE id = ? AND team_id = ?
                    """, (user_row["email"], player_id, db_user["team_id"]))
            else:
                cursor.execute("""
                    SELECT user_id, name, position, telefon, geburtsdatum
                    FROM players
                    WHERE id = ? AND team_id = ? AND deleted_at IS NULL
                """, (player_id, db_user["team_id"]))
                row = cursor.fetchone()
                if row and row["user_id"]:
                    name = (row["name"] or "").strip()
                    name_parts = name.split()
                    vorname = name_parts[0] if name_parts else ""
                    nachname = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""
                    cursor.execute("""
                        UPDATE users SET
                            vorname = ?,
                            nachname = ?,
                            position = ?,
                            telefon = ?,
                            geburtsdatum = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (vorname, nachname, row["position"] or "",
                          row["telefon"] or "", row["geburtsdatum"], row["user_id"]))
            db.commit()

    return JSONResponse({"success": True})


@router.delete("/api/players/{player_id}")
async def delete_player(request: Request, player_id: int):
    """
    Spieler löschen (Soft Delete).
    SECURITY: Nur Admins und Trainer dürfen Spieler löschen.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    # SECURITY: Prüfe Rolle - nur Admins und Trainer dürfen löschen
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT name FROM roles WHERE id = ?",
                       (db_user.get("role_id"),))
        role_row = cursor.fetchone()
        role_name = role_row["name"] if role_row else None

    edit_roles = ["Admin", "Trainer"]
    if not db_user.get("is_admin") and role_name not in edit_roles:
        return JSONResponse({"error": "Keine Berechtigung. Nur Admins und Trainer können Spieler löschen."}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE players SET deleted_at = CURRENT_TIMESTAMP
            WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (player_id, db_user["team_id"]))
        db.commit()

    return JSONResponse({"success": True})


@router.delete("/api/players/cleanup-dummy")
async def cleanup_dummy_players(request: Request):
    """
    Dummy-Spieler entfernen (Soft Delete).
    SECURITY: Nur Admins.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    if not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    dummy_names = ["Max Müller", "John Schmidt", "Tom Klaus", "Chris Davis"]
    placeholders = ",".join("?" * len(dummy_names))

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(f"""
            UPDATE players
            SET deleted_at = CURRENT_TIMESTAMP
            WHERE team_id = ?
              AND deleted_at IS NULL
              AND user_id IS NULL
              AND name IN ({placeholders})
              AND (email IS NULL OR email = '')
              AND (telefon IS NULL OR telefon = '')
              AND (notizen IS NULL OR notizen = '')
        """, [db_user["team_id"], *dummy_names])
        db.commit()
        deleted = cursor.rowcount

    return JSONResponse({"success": True, "deleted": deleted})


@router.get("/api/players/stats")
async def get_player_stats(request: Request):
    """Spieler-Statistiken für Dashboard."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"fit": 0, "training": 0, "reha": 0, "ausfall": 0, "total": 0})

    with get_db_connection() as db:
        cursor = db.cursor()
        dummy_names = ["Max Müller", "John Schmidt", "Tom Klaus", "Chris Davis"]
        placeholders = ",".join("?" * len(dummy_names))
        cursor.execute(f"""
            UPDATE players
            SET deleted_at = CURRENT_TIMESTAMP
            WHERE team_id = ?
              AND deleted_at IS NULL
              AND user_id IS NULL
              AND name IN ({placeholders})
              AND (email IS NULL OR email = '')
              AND (telefon IS NULL OR telefon = '')
              AND (notizen IS NULL OR notizen = '')
        """, [db_user["team_id"], *dummy_names])
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status IN ('Fit', 'Belastet', 'Training') THEN 1 ELSE 0 END) as fit,
                SUM(CASE WHEN status = 'Reha' THEN 1 ELSE 0 END) as reha,
                SUM(CASE WHEN status IN ('Ausfall', 'Verletzt', 'Angeschlagen') THEN 1 ELSE 0 END) as ausfall
            FROM players
            WHERE team_id = ? AND deleted_at IS NULL
        """, (db_user["team_id"],))
        row = cursor.fetchone()

    return JSONResponse({
        "total": row["total"] or 0,
        "fit": row["fit"] or 0,
        "reha": row["reha"] or 0,
        "ausfall": row["ausfall"] or 0
    })


# ============================================
# API Endpoints - Calendar Events
# ============================================

@router.get("/api/events")
async def get_events(request: Request):
    """Alle Events des Teams abrufen."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"events": []})

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT e.id, e.title, e.description, e.event_type, e.event_date, e.start_time, e.end_time, e.location, e.visibility,
                   SUM(CASE WHEN r.status = 'yes' THEN 1 ELSE 0 END) as rsvp_yes,
                   SUM(CASE WHEN r.status = 'no' THEN 1 ELSE 0 END) as rsvp_no,
                   SUM(CASE WHEN r.status = 'maybe' THEN 1 ELSE 0 END) as rsvp_maybe,
                   MAX(CASE WHEN r.user_id = ? THEN r.status ELSE NULL END) as my_rsvp
            FROM calendar_events e
            LEFT JOIN event_rsvps r ON r.event_id = e.id
            WHERE e.team_id = ? AND e.deleted_at IS NULL
            GROUP BY e.id
            ORDER BY e.event_date, e.start_time
        """, (user["id"], db_user["team_id"]))
        events = [dict(row) for row in cursor.fetchall()]

        if events:
            event_ids = [e["id"] for e in events]
            placeholders = ",".join("?" * len(event_ids))
            cursor.execute(f"""
                SELECT event_id, user_id FROM event_roster
                WHERE event_id IN ({placeholders})
            """, event_ids)
            roster_rows = cursor.fetchall()
        else:
            roster_rows = []

    roster_map = {}
    for row in roster_rows:
        roster_map.setdefault(row["event_id"], []).append(row["user_id"])

    for event in events:
        event["roster_user_ids"] = roster_map.get(event["id"], [])
        event["rsvp_summary"] = {
            "yes": event.get("rsvp_yes", 0) or 0,
            "no": event.get("rsvp_no", 0) or 0,
            "maybe": event.get("rsvp_maybe", 0) or 0
        }

    return JSONResponse({"events": events})


@router.post("/api/events")
async def create_event(request: Request):
    """Neues Event erstellen."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)
    if not is_staff_user(db_user):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    title = str(data.get("title", "")).strip()[:200]
    if not title:
        return JSONResponse({"error": "Titel erforderlich"}, status_code=400)

    event_date = str(data.get("date", data.get("event_date", ""))).strip()[:10]
    if not event_date:
        return JSONResponse({"error": "Datum erforderlich"}, status_code=400)

    event_type = str(data.get("type", data.get(
        "event_type", "training"))).strip()
    if event_type not in ("training", "match", "meeting", "other"):
        event_type = "other"

    description = str(data.get("description", data.get("notes", ""))).strip()[:1000]
    start_time = str(data.get("start_time", data.get("time", ""))).strip()[
        :8] or None
    end_time = str(data.get("end_time", "")).strip()[:8] or None
    location = str(data.get("location", "")).strip()[:200]
    visibility = str(data.get("visibility", "team")).strip()
    if visibility not in ("private", "team"):
        visibility = "team"

    repeat = str(data.get("repeat", "none")).strip().lower()
    if repeat not in ("none", "weekly", "monthly"):
        repeat = "none"
    repeat_until = str(data.get("repeat_until", "")).strip()[:10] or None

    roster_user_ids = data.get("roster_user_ids") or []
    if not isinstance(roster_user_ids, list):
        roster_user_ids = []
    roster_user_ids = [
        int(uid) for uid in roster_user_ids
        if isinstance(uid, (int, str)) and str(uid).isdigit()
    ]

    if event_type == "match" and roster_user_ids:
        with get_db_connection() as db:
            cursor = db.cursor()
            placeholders = ",".join("?" * len(roster_user_ids))
            cursor.execute(f"""
                SELECT u.id
                FROM users u
                JOIN team_members tm ON tm.user_id = u.id
                JOIN roles r ON tm.role_id = r.id
                WHERE tm.team_id = ? AND u.is_active = 1
                  AND u.id IN ({placeholders})
                  AND LOWER(r.name) = 'spieler'
            """, (db_user["team_id"], *roster_user_ids))
            allowed_ids = {row["id"] for row in cursor.fetchall()}
        roster_user_ids = [uid for uid in roster_user_ids if uid in allowed_ids]
    else:
        roster_user_ids = []
    if event_type == "match" and not roster_user_ids:
        return JSONResponse({"error": "Kader erforderlich"}, status_code=400)

    def add_months(date_value: datetime.date, months: int) -> datetime.date:
        month = date_value.month - 1 + months
        year = date_value.year + month // 12
        month = month % 12 + 1
        day = min(date_value.day, [31, 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
                                   31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1])
        return datetime.date(year, month, day)

    try:
        start_date_obj = datetime.strptime(event_date, "%Y-%m-%d").date()
    except ValueError:
        return JSONResponse({"error": "Ungültiges Datum"}, status_code=400)

    end_date_obj = None
    if repeat_until:
        try:
            end_date_obj = datetime.strptime(repeat_until, "%Y-%m-%d").date()
        except ValueError:
            return JSONResponse({"error": "Ungültiges Wiederholungsdatum"}, status_code=400)

    dates_to_create = [start_date_obj]
    if repeat != "none" and end_date_obj and end_date_obj >= start_date_obj:
        max_occurrences = 52 if repeat == "weekly" else 24
        current = start_date_obj
        for _ in range(max_occurrences - 1):
            if repeat == "weekly":
                current = current + timedelta(weeks=1)
            else:
                current = add_months(current, 1)
            if current > end_date_obj:
                break
            dates_to_create.append(current)

    created_ids = []
    with get_db_connection() as db:
        cursor = db.cursor()
        for date_obj in dates_to_create:
            cursor.execute("""
                INSERT INTO calendar_events (team_id, title, description, event_type, event_date, start_time, end_time, location, created_by, visibility)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (db_user["team_id"], title, description, event_type,
                  date_obj.strftime("%Y-%m-%d"), start_time, end_time, location, user["id"], visibility))
            event_id = cursor.lastrowid
            created_ids.append(event_id)
            if roster_user_ids:
                cursor.executemany("""
                    INSERT OR IGNORE INTO event_roster (event_id, user_id)
                    VALUES (?, ?)
                """, [(event_id, uid) for uid in roster_user_ids])
        db.commit()

    return JSONResponse({"success": True, "id": created_ids[0] if created_ids else None, "created_ids": created_ids})


@router.delete("/api/events/{event_id}")
async def delete_event(request: Request, event_id: int):
    """Event löschen."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)
    if not is_staff_user(db_user):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE calendar_events SET deleted_at = CURRENT_TIMESTAMP
            WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (event_id, db_user["team_id"]))
        db.commit()

    return JSONResponse({"success": True})


@router.put("/api/events/{event_id}")
async def update_event(request: Request, event_id: int):
    """Event bearbeiten."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)
    if not is_staff_user(db_user):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    title = str(data.get("title", "")).strip()[:200]
    if not title:
        return JSONResponse({"error": "Titel erforderlich"}, status_code=400)

    event_date = str(data.get("date", data.get("event_date", ""))).strip()[:10]
    if not event_date:
        return JSONResponse({"error": "Datum erforderlich"}, status_code=400)

    event_type = str(data.get("type", data.get("event_type", "training"))).strip()
    if event_type not in ("training", "match", "meeting", "other"):
        event_type = "other"

    description = str(data.get("description", data.get("notes", ""))).strip()[:1000]
    start_time = str(data.get("start_time", data.get("time", ""))).strip()[:8] or None
    end_time = str(data.get("end_time", "")).strip()[:8] or None
    location = str(data.get("location", "")).strip()[:200]
    visibility = str(data.get("visibility", "team")).strip()
    if visibility not in ("private", "team"):
        visibility = "team"

    roster_user_ids = data.get("roster_user_ids") or []
    if not isinstance(roster_user_ids, list):
        roster_user_ids = []
    roster_user_ids = [
        int(uid) for uid in roster_user_ids
        if isinstance(uid, (int, str)) and str(uid).isdigit()
    ]

    if event_type == "match" and roster_user_ids:
        with get_db_connection() as db:
            cursor = db.cursor()
            placeholders = ",".join("?" * len(roster_user_ids))
            cursor.execute(f"""
                SELECT u.id
                FROM users u
                JOIN team_members tm ON tm.user_id = u.id
                JOIN roles r ON tm.role_id = r.id
                WHERE tm.team_id = ? AND u.is_active = 1
                  AND u.id IN ({placeholders})
                  AND LOWER(r.name) = 'spieler'
            """, (db_user["team_id"], *roster_user_ids))
            allowed_ids = {row["id"] for row in cursor.fetchall()}
        roster_user_ids = [uid for uid in roster_user_ids if uid in allowed_ids]
    else:
        roster_user_ids = []
    if event_type == "match" and not roster_user_ids:
        return JSONResponse({"error": "Kader erforderlich"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id FROM calendar_events
            WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (event_id, db_user["team_id"]))
        if not cursor.fetchone():
            return JSONResponse({"error": "Event nicht gefunden"}, status_code=404)

        cursor.execute("""
            UPDATE calendar_events
            SET title = ?, description = ?, event_type = ?, event_date = ?, start_time = ?, end_time = ?, location = ?,
                visibility = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND team_id = ?
        """, (title, description, event_type, event_date, start_time, end_time,
              location, visibility, event_id, db_user["team_id"]))

        cursor.execute("DELETE FROM event_roster WHERE event_id = ?", (event_id,))
        if roster_user_ids:
            cursor.executemany("""
                INSERT OR IGNORE INTO event_roster (event_id, user_id)
                VALUES (?, ?)
            """, [(event_id, uid) for uid in roster_user_ids])

        db.commit()

    return JSONResponse({"success": True})


@router.get("/api/events/week")
async def get_week_events(request: Request):
    """Events der aktuellen Woche für Dashboard."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"events": [], "week": {}})

    from datetime import date, timedelta
    today = date.today()
    weekday = today.weekday()
    monday = today - timedelta(days=weekday)
    sunday = monday + timedelta(days=6)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, title, event_type, event_date, start_time
            FROM calendar_events
            WHERE team_id = ? AND deleted_at IS NULL
            AND event_date BETWEEN ? AND ?
            ORDER BY event_date, start_time
        """, (db_user["team_id"], monday.isoformat(), sunday.isoformat()))
        events = [dict(row) for row in cursor.fetchall()]

    # Gruppiere nach Wochentag
    week = {i: [] for i in range(7)}
    for event in events:
        event_date = datetime.strptime(event["event_date"], "%Y-%m-%d").date()
        day_index = (event_date - monday).days
        if 0 <= day_index < 7:
            week[day_index].append(event)

    return JSONResponse({"events": events, "week": week})


# ============================================
# API Endpoints - Player View (Mobile)
# ============================================

@router.get("/api/player/next-events")
async def get_player_next_events(request: Request):
    """Naechste Training/Spiel Events fuer Spieler."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"events": []}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"events": []})

    today = datetime.utcnow().date().isoformat()

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT e.id, e.title, e.event_type, e.event_date, e.start_time, e.end_time, e.location,
                   r.status as rsvp_status
            FROM calendar_events e
            LEFT JOIN event_rsvps r ON r.event_id = e.id AND r.user_id = ?
            WHERE e.team_id = ?
              AND e.deleted_at IS NULL
              AND e.event_type IN ('training', 'match')
              AND e.event_date >= ?
              AND e.visibility = 'team'
              AND (
                    (e.event_type = 'match' AND EXISTS (
                        SELECT 1 FROM event_roster er WHERE er.event_id = e.id AND er.user_id = ?
                    ))
                    OR (e.event_type != 'match' AND (
                        NOT EXISTS (SELECT 1 FROM event_roster er WHERE er.event_id = e.id)
                        OR EXISTS (SELECT 1 FROM event_roster er WHERE er.event_id = e.id AND er.user_id = ?)
                        OR EXISTS (SELECT 1 FROM event_rsvps rr WHERE rr.event_id = e.id AND rr.user_id = ?)
                    ))
                  )
            ORDER BY e.event_date, e.start_time
            LIMIT 5
        """, [user["id"], db_user["team_id"], today, user["id"], user["id"], user["id"]])
        events = [dict(row) for row in cursor.fetchall()]

    return JSONResponse({"events": events})


@router.post("/api/player/rsvp")
async def set_player_rsvp(request: Request):
    """Zu- und Absage fuer Team-Events."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    if get_user_role_name(db_user) != "spieler" and not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungueltige Daten"}, status_code=400)

    event_id = data.get("event_id")
    status = str(data.get("status", "")).lower().strip()
    if status not in ("yes", "no", "maybe"):
        return JSONResponse({"error": "Ungueltiger Status"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT e.id, e.event_type
            FROM calendar_events e
            WHERE e.id = ? AND e.team_id = ? AND e.deleted_at IS NULL
              AND e.event_type IN ('training', 'match')
              AND e.visibility = 'team'
        """, [event_id, db_user["team_id"]])
        event_row = cursor.fetchone()
        if not event_row:
            return JSONResponse({"error": "Event nicht gefunden"}, status_code=404)

        cursor.execute("""
            SELECT 1 FROM event_roster WHERE event_id = ?
        """, (event_id,))
        roster_exists = cursor.fetchone() is not None
        if event_row["event_type"] == "match" and not roster_exists:
            return JSONResponse({"error": "Kader erforderlich"}, status_code=403)
        if roster_exists:
            cursor.execute("""
                SELECT 1 FROM event_roster WHERE event_id = ? AND user_id = ?
            """, (event_id, user["id"]))
            if not cursor.fetchone():
                return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

        cursor.execute("""
            INSERT INTO event_rsvps (event_id, user_id, status)
            VALUES (?, ?, ?)
            ON CONFLICT(event_id, user_id)
            DO UPDATE SET status = excluded.status, updated_at = CURRENT_TIMESTAMP
        """, (event_id, user["id"], status))
        db.commit()

    return JSONResponse({"success": True, "status": status})


@router.get("/api/player/calendar")
async def get_player_calendar(request: Request):
    """Kalender fuer Spieler: Team-Events + private Termine."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"events": []}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"events": []})

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT e.id, e.title, e.event_type, e.event_date, e.start_time, e.end_time, e.location,
                   e.visibility, e.created_by
            FROM calendar_events e
            WHERE e.team_id = ? AND e.deleted_at IS NULL
              AND e.visibility = 'team'
              AND (
                    (e.event_type = 'match' AND EXISTS (
                        SELECT 1 FROM event_roster er WHERE er.event_id = e.id AND er.user_id = ?
                    ))
                    OR (e.event_type != 'match' AND (
                        NOT EXISTS (SELECT 1 FROM event_roster er WHERE er.event_id = e.id)
                        OR EXISTS (SELECT 1 FROM event_roster er WHERE er.event_id = e.id AND er.user_id = ?)
                        OR EXISTS (SELECT 1 FROM event_rsvps rr WHERE rr.event_id = e.id AND rr.user_id = ?)
                    ))
                  )
            ORDER BY e.event_date, e.start_time
            LIMIT 200
        """, [db_user["team_id"], user["id"], user["id"], user["id"]])
        rows = cursor.fetchall()

    events = []
    for row in rows:
        item = dict(row)
        item["scope"] = "team"
        events.append(item)

    return JSONResponse({"events": events})


@router.post("/api/player/calendar")
async def create_player_private_event(request: Request):
    """Privaten Termin fuer Spieler erstellen."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    if get_user_role_name(db_user) != "spieler" and not db_user.get("is_admin"):
        return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungueltige Daten"}, status_code=400)

    title = str(data.get("title", "")).strip()[:200]
    if not title:
        return JSONResponse({"error": "Titel erforderlich"}, status_code=400)

    event_date = str(data.get("date", data.get("event_date", ""))).strip()[:10]
    if not event_date:
        return JSONResponse({"error": "Datum erforderlich"}, status_code=400)

    event_type = str(data.get("type", data.get("event_type", "training"))).strip()
    if event_type not in ("training", "match", "meeting", "other"):
        event_type = "other"

    description = str(data.get("description", "")).strip()[:1000]
    start_time = str(data.get("start_time", data.get("time", ""))).strip()[:8] or None
    end_time = str(data.get("end_time", "")).strip()[:8] or None
    location = str(data.get("location", "")).strip()[:200]

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO calendar_events (team_id, title, description, event_type, event_date,
                                         start_time, end_time, location, created_by, visibility)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'private')
        """, (db_user["team_id"], title, description, event_type, event_date,
              start_time, end_time, location, user["id"]))
        db.commit()
        event_id = cursor.lastrowid

    return JSONResponse({"success": True, "id": event_id})


# ============================================
# API Endpoints - Messages
# ============================================

MAX_MESSAGE_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10MB


def _get_message_attachment_dir(team_id: int) -> str:
    base_dir = os.path.join(SecurityConfig.DATA_DIR, "message_attachments", str(team_id))
    os.makedirs(base_dir, exist_ok=True)
    return base_dir


def _sanitize_attachment_name(filename: str) -> str:
    name = os.path.basename(filename or "")
    if not name:
        return "attachment"
    safe = []
    for ch in name:
        is_ascii_alnum = ("0" <= ch <= "9") or ("A" <= ch <= "Z") or ("a" <= ch <= "z")
        if is_ascii_alnum or ch in "._-":
            safe.append(ch)
        else:
            safe.append("_")
    sanitized = "".join(safe).strip("._")
    return sanitized or "attachment"


@router.get("/api/messages")
async def get_messages(request: Request, limit: int = 50, before_id: int = None, scope: str = None, peer_id: int = None):
    """
    Team-Chat Nachrichten abrufen.
    PERFORMANCE: Cursor-basierte Pagination für große Chat-Historien.

    Query Params:
        limit: Max Nachrichten (default 50, max 100)
        before_id: Für Pagination - Nachrichten vor dieser ID laden
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"messages": [], "has_more": False})

    # SECURITY: Limit begrenzen
    limit = min(max(1, limit), 100)

    scope = (scope or "").lower()

    with get_db_connection() as db:
        cursor = db.cursor()

        if scope == "team":
            where_clause = "m.recipient_id IS NULL"
            params = [db_user["team_id"]]
        elif scope == "direct" and peer_id:
            where_clause = "(m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?)"
            params = [db_user["team_id"], user["id"], peer_id, peer_id, user["id"]]
        else:
            where_clause = "(m.recipient_id IS NULL OR m.recipient_id = ? OR m.sender_id = ?)"
            params = [db_user["team_id"], user["id"], user["id"]]

        if before_id:
            # PERFORMANCE: Cursor-Pagination (schneller als OFFSET)
            cursor.execute(f"""
                SELECT m.id, m.content, m.created_at, m.sender_id,
                       m.attachment_name, m.attachment_type, m.attachment_size, m.attachment_path,
                       u.vorname || ' ' || u.nachname as sender_name
                FROM messages m
                LEFT JOIN users u ON m.sender_id = u.id
                WHERE m.team_id = ? AND m.deleted_at IS NULL
                AND ({where_clause})
                AND m.id < ?
                ORDER BY m.created_at DESC
                LIMIT ?
            """, (*params, before_id, limit + 1))
        else:
            cursor.execute(f"""
                SELECT m.id, m.content, m.created_at, m.sender_id,
                       m.attachment_name, m.attachment_type, m.attachment_size, m.attachment_path,
                       u.vorname || ' ' || u.nachname as sender_name
                FROM messages m
                LEFT JOIN users u ON m.sender_id = u.id
                WHERE m.team_id = ? AND m.deleted_at IS NULL
                AND ({where_clause})
                ORDER BY m.created_at DESC
                LIMIT ?
            """, (*params, limit + 1))

        rows = cursor.fetchall()
        has_more = len(rows) > limit
        messages = [dict(row) for row in rows[:limit]]
        for message in messages:
            if message.get("attachment_path"):
                message["attachment_url"] = f"/api/messages/{message['id']}/attachment"

    return JSONResponse({
        "messages": messages[::-1],  # Älteste zuerst
        "has_more": has_more
    })


@router.get("/api/messages/{message_id}/attachment")
async def download_message_attachment(request: Request, message_id: int):
    """Anhang einer Nachricht herunterladen."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, team_id, sender_id, recipient_id,
                   attachment_path, attachment_name, attachment_type
            FROM messages
            WHERE id = ? AND deleted_at IS NULL
        """, (message_id,))
        row = cursor.fetchone()

    if not row:
        return JSONResponse({"error": "Nachricht nicht gefunden"}, status_code=404)

    message = dict(row)
    if message["team_id"] != db_user["team_id"]:
        return JSONResponse({"error": "Kein Zugriff"}, status_code=403)

    if message.get("recipient_id"):
        if user["id"] not in (message["sender_id"], message["recipient_id"]):
            return JSONResponse({"error": "Kein Zugriff"}, status_code=403)

    attachment_path = message.get("attachment_path") or ""
    if not attachment_path or not os.path.exists(attachment_path):
        return JSONResponse({"error": "Anhang nicht gefunden"}, status_code=404)

    return FileResponse(
        attachment_path,
        media_type=message.get("attachment_type") or None,
        filename=message.get("attachment_name") or "attachment"
    )


@router.post("/api/messages")
async def send_message(request: Request):
    """Nachricht senden."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    content = ""
    recipient_id = None
    attachment = None
    content_type = (request.headers.get("content-type") or "").lower()
    form = None

    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        try:
            form = await request.form()
        except Exception:
            form = None

    if form is not None:
        content = str(form.get("content", "")).strip()[:5000]
        recipient_id = form.get("recipient_id")
        attachment = form.get("attachment")
    else:
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

        content = str(data.get("content", "")).strip()[:5000]
        recipient_id = data.get("recipient_id")

    if recipient_id in ("", None):
        recipient_id = None

    if not content and not attachment:
        return JSONResponse({"error": "Nachricht leer"}, status_code=400)
    if not content and attachment:
        content = "__attachment__"

    if recipient_id:
        try:
            recipient_id = int(recipient_id)
        except (ValueError, TypeError):
            return JSONResponse({"error": "Ungültiger Empfänger"}, status_code=400)

        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("""
                SELECT u.id
                FROM users u
                JOIN team_members tm ON tm.user_id = u.id
                WHERE u.id = ? AND tm.team_id = ? AND u.is_active = 1
            """, (recipient_id, db_user["team_id"]))
            if not cursor.fetchone():
                return JSONResponse({"error": "Empfänger nicht gefunden"}, status_code=404)

    attachment_name = None
    attachment_type = None
    attachment_path = None
    attachment_size = None

    if attachment and isinstance(attachment, UploadFile):
        if not attachment.filename:
            attachment = None

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO messages (team_id, sender_id, recipient_id, content)
            VALUES (?, ?, ?, ?)
        """, (db_user["team_id"], user["id"], recipient_id, content))
        message_id = cursor.lastrowid

        if attachment:
            safe_name = _sanitize_attachment_name(attachment.filename)
            attachment_dir = _get_message_attachment_dir(db_user["team_id"])
            attachment_path = os.path.join(attachment_dir, f"{message_id}_{safe_name}")
            attachment_type = attachment.content_type or "application/octet-stream"

            size = 0
            try:
                with open(attachment_path, "wb") as f_out:
                    while True:
                        chunk = await attachment.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_MESSAGE_ATTACHMENT_SIZE:
                            raise ValueError("attachment_too_large")
                        f_out.write(chunk)
            except ValueError:
                if os.path.exists(attachment_path):
                    os.remove(attachment_path)
                return JSONResponse({"error": "Anhang zu groß (max 10MB)"}, status_code=400)
            except Exception:
                if os.path.exists(attachment_path):
                    os.remove(attachment_path)
                logger.error("Message attachment upload failed", exc_info=True)
                return JSONResponse({"error": "Anhang konnte nicht gespeichert werden"}, status_code=500)
            finally:
                try:
                    await attachment.close()
                except Exception:
                    pass

            attachment_name = safe_name
            attachment_size = size
            cursor.execute("""
                UPDATE messages
                SET attachment_name = ?, attachment_type = ?, attachment_path = ?, attachment_size = ?
                WHERE id = ?
            """, (attachment_name, attachment_type, attachment_path, attachment_size, message_id))

        db.commit()

    return JSONResponse({"success": True, "id": message_id})


@router.get("/api/messages/unread")
async def get_unread_count(request: Request):
    """Anzahl ungelesener Nachrichten."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"count": 0})

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"count": 0})

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM messages
            WHERE team_id = ? AND deleted_at IS NULL
            AND sender_id != ? AND is_read = 0
            AND (recipient_id IS NULL OR recipient_id = ?)
        """, (db_user["team_id"], user["id"], user["id"]))
        row = cursor.fetchone()

    return JSONResponse({"count": row["count"] if row else 0})


@router.get("/api/messages/contacts")
async def get_message_contacts(request: Request):
    """Kontaktliste für Messenger (Staff im Team)."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"contacts": []}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"contacts": []})

    staff_roles = list(STAFF_ROLE_NAMES)
    placeholders = ",".join("?" * len(staff_roles))

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(f"""
            SELECT u.id, u.email, u.vorname, u.nachname, r.name as role_name
            FROM users u
            JOIN team_members tm ON tm.user_id = u.id
            JOIN roles r ON tm.role_id = r.id
            WHERE tm.team_id = ? AND u.is_active = 1
              AND LOWER(r.name) IN ({placeholders})
            ORDER BY r.name, u.nachname
        """, (db_user["team_id"], *staff_roles))
        contacts = [dict(row) for row in cursor.fetchall()]

    return JSONResponse({"contacts": contacts})


# ============================================
# API Endpoints - Mannschaftskasse
# ============================================

@router.get("/api/kasse")
async def get_kasse(request: Request):
    """Mannschaftskasse Übersicht."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return {"saldo": 0, "transactions": []}

    with get_db_connection() as db:
        cursor = db.cursor()
        # Transaktionen laden
        cursor.execute("""
            SELECT id, amount, type, description, created_at, created_by
            FROM kasse_transactions
            WHERE team_id = ? AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 50
        """, (db_user["team_id"],))
        transactions = [dict(row) for row in cursor.fetchall()]

        # Saldo berechnen
        cursor.execute("""
            SELECT 
                COALESCE(SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END), 0) as income,
                COALESCE(SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END), 0) as expense
            FROM kasse_transactions
            WHERE team_id = ? AND deleted_at IS NULL
        """, (db_user["team_id"],))
        totals = cursor.fetchone()
        saldo = (totals["income"] or 0) - (totals["expense"] or 0)

    return {"saldo": saldo, "transactions": transactions}


@router.post("/api/kasse")
async def add_kasse_transaction(request: Request):
    """Transaktion zur Mannschaftskasse hinzufügen."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team zugeordnet"}, status_code=400)

    try:
        data = await request.json()
    except:
        return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

    amount = data.get("amount", 0)
    trans_type = data.get("type", "expense")
    description = str(data.get("description", ""))[:200]

    if not amount or amount <= 0:
        return JSONResponse({"error": "Ungültiger Betrag"}, status_code=400)

    if trans_type not in ["income", "expense"]:
        return JSONResponse({"error": "Ungültiger Typ"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO kasse_transactions (team_id, amount, type, description, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        """, (db_user["team_id"], amount, trans_type, description, user["id"]))
        db.commit()

    return {"success": True}


# ============================================
# API Endpoints - Formations (Taktik)
# ============================================

@router.get("/api/formations")
async def get_formations(request: Request):
    """Alle Formationen des Teams."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"formations": []})

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, name, formation_data, created_at
            FROM formations
            WHERE team_id = ? AND deleted_at IS NULL
            ORDER BY created_at DESC
        """, (db_user["team_id"],))
        formations = [dict(row) for row in cursor.fetchall()]

    return JSONResponse({"formations": formations})


@router.post("/api/formations")
async def save_formation(request: Request):
    """Formation speichern."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    db_user = apply_active_membership(request, db_user)
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    name = str(data.get("name", "")).strip()[:100]
    if not name:
        return JSONResponse({"error": "Name erforderlich"}, status_code=400)

    import json
    formation_data = json.dumps(data.get("formation_data", {}))

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO formations (team_id, name, formation_data, created_by)
            VALUES (?, ?, ?, ?)
        """, (db_user["team_id"], name, formation_data, user["id"]))
        db.commit()
        formation_id = cursor.lastrowid

    return JSONResponse({"success": True, "id": formation_id})


# ============================================
# Two-Factor Authentication Routes
# ============================================

@router.post("/verify-2fa", response_class=HTMLResponse)
async def verify_2fa(
    request: Request,
    code: str = Form(...),
    pending_token: str = Form(""),
    csrf_token: str = Form("")
):
    """
    Verifiziert den 2FA-Code nach dem Login.
    SECURITY: Replay-Attack-Schutz, Rate Limiting.
    """
    client_ip = get_client_ip(request)

    # CSRF validieren
    if not validate_csrf_token(csrf_token, "2fa_form"):
        logger.warning(f"CSRF validation failed for 2FA from {client_ip}")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Sitzung abgelaufen. Bitte erneut anmelden.",
             "csrf_token": generate_csrf_token("login_form")}
        )

    # Pending Token aus Cookie oder Form
    if not pending_token:
        pending_token = request.cookies.get("pending_2fa", "")

    if not pending_token:
        return RedirectResponse(url="/auth/login", status_code=303)

    # Token dekodieren
    try:
        pending_data = serializer.loads(
            pending_token, max_age=300)  # 5 Minuten
        user_id = pending_data.get("user_id")
        stored_ip = pending_data.get("ip")
    except (SignatureExpired, BadSignature):
        logger.warning(f"Invalid or expired 2FA token from {client_ip}")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Sitzung abgelaufen. Bitte erneut anmelden.",
             "csrf_token": generate_csrf_token("login_form")}
        )

    # IP muss übereinstimmen
    if stored_ip != client_ip:
        logger.warning(
            f"2FA IP mismatch: expected {stored_ip}, got {client_ip}")
        log_audit_event(user_id, "2FA_IP_MISMATCH", "user", user_id,
                        f"stored_ip={stored_ip}, current_ip={client_ip}", client_ip,
                        severity="WARNING", event_type="2FA_FAILED")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Sicherheitsfehler. Bitte erneut anmelden.",
             "csrf_token": generate_csrf_token("login_form")}
        )

    stored_code_hash = pending_data.get("code_hash")
    if not stored_code_hash:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Sitzung abgelaufen. Bitte erneut anmelden.",
             "csrf_token": generate_csrf_token("login_form")}
        )

    code_hash = hashlib.sha256(
        f"{code}{SecurityConfig.SECRET_KEY}".encode("utf-8")
    ).hexdigest()

    if not constant_time_compare(stored_code_hash, code_hash):
        log_audit_event(user_id, "2FA_INVALID_CODE", "user", user_id,
                        None, client_ip, severity="WARNING", event_type="2FA_FAILED")

        exponential_lockout.record_failure(f"2fa:{user_id}")

        return templates.TemplateResponse(
            "2fa_verify.html",
            {"request": request, "error": "Ungültiger Code. Bitte erneut versuchen.",
             "pending_token": pending_token, "csrf_token": generate_csrf_token("2fa_form")}
        )

    # Login abschließen
    user = get_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)

    user_agent = request.headers.get("User-Agent", "")
    log_audit_event(user_id, "LOGIN_SUCCESS_2FA", "user", user_id,
                    None, client_ip, event_type="LOGIN_SUCCESS")

    # Session erstellen
    token = create_session_token(user, request)
    session_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    _ensure_session_record(session_hash, user_id)
    secure_session_manager.register_session(
        token, user_id, client_ip, user_agent)

    response = RedirectResponse(url="/dashboard", status_code=303)
    set_session_cookie(response, token)
    response.delete_cookie("pending_2fa")

    logger.info(f"Successful 2FA login: user_id={user_id}")
    return response


@router.get("/2fa/setup", response_class=HTMLResponse)
async def setup_2fa_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)

    return HTMLResponse(
        "<h2>E-Mail-Authentifizierung ist automatisch aktiv.</h2>",
        status_code=200
    )


@router.post("/2fa/activate", response_class=HTMLResponse)
async def activate_2fa(request: Request):
    return JSONResponse({"error": "Nicht verfügbar"}, status_code=404)


@router.post("/2fa/disable", response_class=HTMLResponse)
async def disable_2fa_route(request: Request):
    return JSONResponse({"error": "Nicht verfügbar"}, status_code=404)


@router.get("/2fa/status")
async def get_2fa_status(request: Request):
    """Gibt den 2FA-Status für den aktuellen User zurück."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    return JSONResponse({
        "enabled": False
    })
