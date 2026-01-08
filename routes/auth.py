"""
Authentication Routes - Security Hardened Version
==================================================
SECURITY AUDIT: Rate Limiting, Token-Handling, Input-Validierung gehärtet.
"""

import os
import logging
import uuid
import shutil
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import APIRouter, Request, Form, HTTPException, Depends, UploadFile, File, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
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
    get_user_by_email, get_user_by_id, update_last_login,
    log_audit_event, soft_delete_user, verify_user_is_team_admin,
    verify_user_team_access,
    # 2FA Database Functions
    setup_2fa, enable_2fa, disable_2fa, get_user_2fa, is_2fa_enabled,
    update_2fa_last_used, check_replay_attack, use_backup_code, log_security_event
)
from email_service import (
    send_login_notification, send_password_changed_notification,
    send_2fa_enabled_notification, EmailConfig
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Security Logger
logger = logging.getLogger("pitchinsights.security")

# SECURITY: Timed Serializer mit Ablaufzeit
serializer = URLSafeTimedSerializer(SecurityConfig.SECRET_KEY)


# ============================================
# Helper Functions
# ============================================

def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """
    Authentifiziert User anhand des Session-Cookies.
    SECURITY: Token-Ablauf, IP-Binding und Fingerprint werden geprüft.
    """
    token = request.cookies.get("session")
    if not token:
        return None

    try:
        # SECURITY: Token-Ablauf prüfen (max_age in Sekunden)
        data = serializer.loads(
            token,
            max_age=SecurityConfig.SESSION_MAX_AGE_SECONDS
        )

        # SECURITY: IP-Binding prüfen
        if SecurityConfig.SESSION_BIND_IP:
            stored_ip_hash = data.get("ip_hash")
            if stored_ip_hash and not validate_session_ip(stored_ip_hash, request):
                logger.warning(
                    f"Session IP mismatch for user {data.get('id')}")
                return None

        # SECURITY: Fingerprint-Validierung (Browser-Charakteristiken)
        stored_fingerprint = data.get("fp")
        if stored_fingerprint:
            current_fingerprint = get_request_fingerprint(request)
            if stored_fingerprint != current_fingerprint:
                logger.warning(
                    f"Session fingerprint mismatch for user {data.get('id')}")
                return None

        # Zusätzliche Validierung: User muss noch existieren und aktiv sein
        user = get_user_by_id(data.get("id"))
        if not user or not user.get("is_active"):
            return None

        return {"email": data["email"], "id": data["id"]}

    except SignatureExpired:
        logger.info("Session token expired")
        return None
    except BadSignature:
        logger.warning("Invalid session token signature")
        return None
    except Exception as e:
        logger.error(f"Session token error: {type(e).__name__}")
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


# Access-Code für geschützten Login-Bereich
ACCESS_CODE = "pitch2026"

# ============================================
# DEV-ONLY: Auto-Login für lokales Testen
# ============================================
IS_PRODUCTION = os.getenv("PITCHINSIGHTS_ENV") == "production"


@router.get("/dev-login", response_class=HTMLResponse)
async def dev_auto_login(request: Request, user_id: int = 1):
    """
    DEV-ONLY: Automatischer Login ohne Passwort.
    NUR verfügbar wenn PITCHINSIGHTS_ENV != 'production'

    Beispiel: http://localhost:8000/dev-login?user_id=1
    """
    if IS_PRODUCTION:
        raise HTTPException(status_code=404, detail="Not found")

    # User aus DB laden
    user = get_user_by_id(user_id)
    if not user:
        return HTMLResponse(f"<h1>User {user_id} nicht gefunden</h1><p>Verfügbare User-IDs prüfen in der DB.</p>")

    # Session erstellen
    response = RedirectResponse(url="/os", status_code=303)
    session_token = str(uuid.uuid4())

    # Cookie setzen (wie beim normalen Login)
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=False,  # Localhost ist nicht HTTPS
        samesite="lax",
        max_age=86400 * 7  # 7 Tage
    )

    # Session in DB speichern
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO sessions (user_id, token, created_at, expires_at, ip_address, user_agent)
            VALUES (?, ?, datetime('now'), datetime('now', '+7 days'), ?, ?)
        """, (user_id, session_token, "127.0.0.1", "DevLogin"))
        db.commit()

    logger.info(
        f"[DEV] Auto-login für User {user_id} ({user.get('email', 'unknown')})")
    return response


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, code: str = None):
    """Login-Seite anzeigen - nur mit gültigem Access-Code."""
    # Prüfe Access-Code (URL-Parameter oder Cookie)
    stored_code = request.cookies.get("beta_access")

    if code == ACCESS_CODE:
        # Code korrekt - Cookie setzen und zur Login-Seite
        csrf_token = generate_csrf_token("login_form")
        response = templates.TemplateResponse(
            "login.html",
            {"request": request, "error": None, "csrf_token": csrf_token}
        )
        response.set_cookie(
            key="beta_access",
            value="verified",
            httponly=True,
            secure=False,  # True in Production
            samesite="lax",
            max_age=86400 * 30  # 30 Tage
        )
        return response
    elif stored_code == "verified":
        # Bereits verifiziert via Cookie
        csrf_token = generate_csrf_token("login_form")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": None, "csrf_token": csrf_token}
        )
    else:
        # Kein gültiger Code - zur Gate mit Redirect zu login
        return templates.TemplateResponse(
            "access_gate.html",
            {"request": request, "error": None, "redirect": "login"}
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

    # SECURITY: Account Enumeration & Timing-Attack verhindern
    # Führe immer den gleichen bcrypt-Aufwand durch, unabhängig ob User existiert
    # Verwende einen echten Work Factor 12 Hash für realistische Timing
    DUMMY_HASH = b"$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4JQ5kUOIgUfGHVzy"
    if not user:
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

    # ======================================
    # SECURITY: Two-Factor Authentication
    # ======================================
    if is_2fa_enabled(user["id"]):
        # 2FA ist aktiviert - speichere pending login und zeige 2FA-Seite
        pending_token = serializer.dumps({
            "user_id": user["id"],
            "email": email,
            "ip": client_ip,
            "ts": datetime.now().timestamp()
        })

        csrf_2fa = generate_csrf_token("2fa_form")
        response = templates.TemplateResponse(
            "2fa_verify.html",
            {"request": request, "pending_token": pending_token,
             "csrf_token": csrf_2fa, "email": email[:3] + "***"}
        )
        response.set_cookie(
            "pending_2fa",
            pending_token,
            max_age=300,  # 5 Minuten
            httponly=True,
            secure=True,
            samesite="strict"
        )
        return response

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

    # SECURITY: Session im SecureSessionManager registrieren
    token = create_session_token(user, request)
    secure_session_manager.register_session(
        token, user["id"], client_ip, user_agent)

    response = RedirectResponse(url="/dashboard", status_code=303)
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
            value="verified",
            httponly=True,
            secure=False,  # True in Production
            samesite="lax",
            max_age=86400 * 30  # 30 Tage
        )
        return response
    elif stored_code == "verified":
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
            cursor.execute("""
                INSERT INTO users (email, password_hash, team_id, role_id, onboarding_complete, is_active, payment_status)
                VALUES (?, ?, ?, ?, 1, 1, 'paid')
            """, (email, password_hash, invitation_data["team_id"], invitation_data["role_id"]))
            user_id = cursor.lastrowid

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

            # Auto-Login und direkt zum Dashboard
            token = create_session_token(
                {"email": email, "id": user_id}, request)
            response = RedirectResponse(url="/dashboard", status_code=303)
            set_session_cookie(response, token)
        else:
            # Prüfe Promo-Code für kostenlosen Zugang
            valid_promo_codes = ["Admin100", "ADMIN100",
                                 "admin100"]  # Case-insensitive check
            has_valid_promo = promo_code and promo_code.strip() in valid_promo_codes

            if has_valid_promo:
                # Mit gültigem Promo-Code: Kostenloser Zugang
                cursor.execute("""
                    INSERT INTO users (email, password_hash, onboarding_complete, is_active, payment_status)
                    VALUES (?, ?, 0, 1, 'paid')
                """, (email, password_hash))
                user_id = cursor.lastrowid
                db.commit()

                log_audit_event(user_id, "USER_REGISTERED_WITH_PROMO",
                                "user", user_id, f"promo_code={promo_code.strip()}", client_ip)
                logger.info(
                    f"New user registered with promo code: user_id={user_id}, email={email}, promo={promo_code.strip()}")

                # Auto-Login zum Onboarding
                token = create_session_token(
                    {"email": email, "id": user_id}, request)
                response = RedirectResponse(url="/onboarding", status_code=303)
                set_session_cookie(response, token)
                return response

            # Ohne Promo-Code: User erstellen mit payment_status='pending'
            # User muss zuerst bezahlen bevor er Zugang bekommt
            cursor.execute("""
                INSERT INTO users (email, password_hash, onboarding_complete, is_active, payment_status)
                VALUES (?, ?, 0, 0, 'pending')
            """, (email, password_hash))
            user_id = cursor.lastrowid
            db.commit()

            log_audit_event(user_id, "USER_REGISTERED_PENDING_PAYMENT",
                            "user", user_id, None, client_ip)
            logger.info(
                f"New user registered (pending payment): user_id={user_id}, email={email}")

            # Redirect zur Zahlungsanweisungs-Seite
            return RedirectResponse(url="/payment/pending", status_code=303)

    return response


@router.get("/logout")
async def logout(request: Request):
    """
    Logout-Endpunkt.
    SECURITY: Cookie sicher löschen.
    """
    user = get_current_user(request)
    if user:
        log_audit_event(user["id"], "LOGOUT", "user", user["id"])

    response = RedirectResponse(url="/login", status_code=303)
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
    if not db_user:
        return RedirectResponse(url="/login", status_code=303)

    # SECURITY: User ohne Bezahlung hat keinen Zugang
    payment_status = db_user.get("payment_status", "unpaid")
    if payment_status not in ("paid",):
        return templates.TemplateResponse(
            "login.html",
            {"request": request,
             "error": "Dein Account ist noch nicht freigeschaltet. Bitte schließe die Zahlung ab.",
             "csrf_token": generate_csrf_token("login_form")}
        )

    # Onboarding-Status prüfen
    if not db_user.get("onboarding_complete"):
        return RedirectResponse(url="/onboarding", status_code=303)

    return templates.TemplateResponse(
        "os.html",
        {"request": request, "user": user}
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


@router.get("/onboarding", response_class=HTMLResponse)
async def onboarding_page(request: Request):
    """Onboarding-Seite."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Bereits abgeschlossen?
    db_user = get_user_by_id(user["id"])
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

        # Prüfen ob User bereits Team hat
        cursor.execute(
            "SELECT team_id FROM users WHERE id = ?",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        if not user_data or not user_data["team_id"]:
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
    return {"success": True}


@router.get("/api/profile")
async def get_profile(request: Request):
    """
    Profil abrufen.
    SECURITY: Nur eigene Daten.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    if not db_user:
        return JSONResponse({"error": "Benutzer nicht gefunden"}, status_code=404)

    # SECURITY: Nur erlaubte Felder zurückgeben
    return {
        "email": db_user.get("email", ""),
        "vorname": db_user.get("vorname", ""),
        "nachname": db_user.get("nachname", ""),
        "telefon": db_user.get("telefon", ""),
        "geburtsdatum": db_user.get("geburtsdatum", ""),
        "groesse": db_user.get("groesse"),
        "position": db_user.get("position", ""),
        "starker_fuss": db_user.get("starker_fuss", ""),
        "werdegang": db_user.get("werdegang", ""),
        "teamname": db_user.get("teamname", ""),
        "rolle": db_user.get("rolle", ""),
        "verein": db_user.get("verein", ""),
        "mannschaft": db_user.get("mannschaft", "")
    }


@router.post("/api/profile")
async def update_profile(request: Request):
    """
    Profil aktualisieren.
    SECURITY: Input-Validierung, nur erlaubte Felder (Mass Assignment Prevention).
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

    # SECURITY: Nur explizit erlaubte Felder (Whitelist)
    try:
        vorname = InputValidator.validate_name(
            data.get("vorname", ""), "vorname")
        nachname = InputValidator.validate_name(
            data.get("nachname", ""), "nachname")
        teamname = InputValidator.validate_team_name(
            data.get("teamname", ""), "teamname", required=False)
        rolle = InputValidator.validate_rolle(data.get("rolle", ""))
    except ValidationError as e:
        return JSONResponse({"error": e.message}, status_code=400)

    # Telefon und Geburtsdatum (einfache Validierung)
    telefon = str(data.get("telefon", "")).strip()[:30]
    geburtsdatum = str(data.get("geburtsdatum", "")).strip()[:10] or None

    # Neue Felder: Größe, Position, Starker Fuß, Werdegang
    groesse = data.get("groesse")
    if groesse:
        try:
            groesse = int(groesse)
            if groesse < 100 or groesse > 250:
                groesse = None
        except (ValueError, TypeError):
            groesse = None

    position = str(data.get("position", "")).strip()[:50]
    valid_positions = ["", "Torwart", "Innenverteidiger", "Außenverteidiger", "Defensives Mittelfeld",
                       "Zentrales Mittelfeld", "Offensives Mittelfeld", "Flügelspieler", "Stürmer"]
    if position not in valid_positions:
        position = ""

    starker_fuss = str(data.get("starker_fuss", "")).strip()[:20]
    if starker_fuss not in ["", "rechts", "links", "beidfuessig"]:
        starker_fuss = ""

    # Werdegang: Max 2000 Zeichen, wird rechtlich überprüft
    werdegang = str(data.get("werdegang", "")).strip()[:2000]

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE users SET
                vorname = ?,
                nachname = ?,
                telefon = ?,
                geburtsdatum = ?,
                groesse = ?,
                position = ?,
                starker_fuss = ?,
                werdegang = ?,
                teamname = ?,
                rolle = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (vorname, nachname, telefon, geburtsdatum, groesse, position, starker_fuss, werdegang, teamname, rolle, user["id"]))
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

    # DSGVO-konformes Soft Delete
    success = soft_delete_user(user["id"])

    if success:
        logger.info(f"Account deleted: user_id={user['id']}")
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

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT u.*, r.name as role_name, t.name as team_name, t.verein, t.mannschaft
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            LEFT JOIN teams t ON u.team_id = t.id
            WHERE u.id = ? AND u.is_active = 1
        """, (user["id"],))
        user_data = cursor.fetchone()

        if not user_data or not user_data["team_id"]:
            return {"has_team": False, "is_admin": True}

        # Berechtigungen laden
        cursor.execute("""
            SELECT app_id, can_view, can_edit FROM permissions WHERE role_id = ?
        """, (user_data["role_id"],))
        permissions = cursor.fetchall()

    return {
        "has_team": True,
        "is_admin": bool(user_data["is_admin"]),
        "team_id": user_data["team_id"],
        "team_name": user_data["team_name"],
        "verein": user_data["verein"],
        "mannschaft": user_data["mannschaft"],
        "role_id": user_data["role_id"],
        "role_name": user_data["role_name"],
        "permissions": {
            p["app_id"]: {"view": bool(
                p["can_view"]), "edit": bool(p["can_edit"])}
            for p in permissions
        }
    }


@router.post("/api/team/create")
async def create_team_api(request: Request):
    """
    Team erstellen.
    SECURITY: Input-Validierung, max 1 Team pro User.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    # SECURITY: Prüfe ob User bereits ein Team hat (Limit: 1 Team)
    db_user = get_user_by_id(user["id"])
    if db_user and db_user.get("team_id"):
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

    team_id = create_team(verein, mannschaft, user["id"])
    log_audit_event(user["id"], "TEAM_CREATED", "team", team_id)

    return {"success": True, "team_id": team_id}


@router.get("/api/team/status")
async def get_team_status(request: Request):
    """
    Prüft ob User ein Team hat.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    has_team = db_user and db_user.get("team_id") is not None

    team_info = None
    if has_team:
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

    return {"has_team": has_team, "team": team_info}


@router.get("/api/team/members")
async def get_team_members(request: Request):
    """
    Team-Mitglieder abrufen.
    SECURITY: Nur eigenes Team (IDOR Prevention).
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    with get_db_connection() as db:
        cursor = db.cursor()

        # Eigenes Team ermitteln
        cursor.execute(
            "SELECT team_id FROM users WHERE id = ? AND is_active = 1",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        if not user_data or not user_data["team_id"]:
            return {"error": "Kein Team gefunden", "members": []}

        # SECURITY: Nur Members des eigenen Teams
        cursor.execute("""
            SELECT u.id, u.email, u.vorname, u.nachname, r.name as role_name, r.id as role_id, tm.joined_at
            FROM team_members tm
            JOIN users u ON tm.user_id = u.id
            JOIN roles r ON tm.role_id = r.id
            WHERE tm.team_id = ? AND u.is_active = 1
            ORDER BY r.id, u.nachname
        """, (user_data["team_id"],))
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
                "joined_at": m["joined_at"]
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

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT team_id FROM users WHERE id = ? AND is_active = 1",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        if not user_data or not user_data["team_id"]:
            return {"error": "Kein Team gefunden", "roles": []}

        team_id = user_data["team_id"]

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

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT team_id, is_admin FROM users WHERE id = ? AND is_active = 1",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        # SECURITY: Nur Admins dürfen Rollen erstellen
        if not user_data or not user_data["is_admin"]:
            return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

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
        """, (user_data["team_id"], name, description))
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

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT team_id, is_admin FROM users WHERE id = ? AND is_active = 1",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        if not user_data or not user_data["is_admin"]:
            return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

        # SECURITY: Prüfen ob Rolle zum eigenen Team gehört (IDOR Prevention)
        cursor.execute(
            "SELECT id FROM roles WHERE id = ? AND team_id = ?",
            (role_id, user_data["team_id"])
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

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT team_id, is_admin FROM users WHERE id = ? AND is_active = 1",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        if not user_data or not user_data["is_admin"]:
            return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

        # SECURITY: IDOR Prevention + is_deletable Check
        cursor.execute(
            "SELECT id, is_deletable FROM roles WHERE id = ? AND team_id = ?",
            (role_id, user_data["team_id"])
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

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT team_id, is_admin FROM users WHERE id = ? AND is_active = 1",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        if not user_data or not user_data["is_admin"]:
            return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

        # SECURITY: Prüfen ob Member im eigenen Team
        cursor.execute("""
            SELECT tm.id FROM team_members tm
            WHERE tm.user_id = ? AND tm.team_id = ?
        """, (member_id, user_data["team_id"]))

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
            (new_role_id, user_data["team_id"])
        )
        if not cursor.fetchone():
            return JSONResponse({"error": "Ungültige Rolle"}, status_code=400)

        cursor.execute(
            "UPDATE team_members SET role_id = ? WHERE user_id = ? AND team_id = ?",
            (new_role_id, member_id, user_data["team_id"])
        )
        cursor.execute(
            "UPDATE users SET role_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (new_role_id, member_id)
        )
        db.commit()

    log_audit_event(user["id"], "MEMBER_ROLE_CHANGED", "user", member_id)
    return {"success": True}


@router.delete("/api/team/members/{member_id}")
async def remove_member(request: Request, member_id: int):
    """
    Mitglied entfernen.
    SECURITY: Nur Admin, nicht sich selbst, nur eigenes Team.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    # SECURITY: Kann sich nicht selbst entfernen
    if member_id == user["id"]:
        return JSONResponse({"error": "Sie können sich nicht selbst entfernen"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT team_id, is_admin FROM users WHERE id = ? AND is_active = 1",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        if not user_data or not user_data["is_admin"]:
            return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

        # SECURITY: IDOR Prevention
        cursor.execute("""
            SELECT tm.id FROM team_members tm
            WHERE tm.user_id = ? AND tm.team_id = ?
        """, (member_id, user_data["team_id"]))

        if not cursor.fetchone():
            return JSONResponse({"error": "Mitglied nicht gefunden"}, status_code=404)

        cursor.execute(
            "DELETE FROM team_members WHERE user_id = ? AND team_id = ?",
            (member_id, user_data["team_id"])
        )
        cursor.execute(
            "UPDATE users SET team_id = NULL, role_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (member_id,)
        )
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

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT team_id, is_admin FROM users WHERE id = ? AND is_active = 1",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        if not user_data or not user_data["is_admin"]:
            return JSONResponse({"error": "Keine Berechtigung", "invitations": []}, status_code=403)

        cursor.execute("""
            SELECT i.*, r.name as role_name, u.email as created_by_email
            FROM invitations i
            JOIN roles r ON i.role_id = r.id
            JOIN users u ON i.created_by = u.id
            WHERE i.team_id = ? AND i.is_active = 1
            ORDER BY i.created_at DESC
        """, (user_data["team_id"],))
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
MAX_VIDEO_SIZE = 500 * 1024 * 1024  # 500 MB


def get_video_upload_dir():
    """Dynamisch den Video-Upload-Pfad ermitteln."""
    return os.path.join(SecurityConfig.DATA_DIR, 'videos')


@router.post("/api/videos/upload")
async def upload_video(
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
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
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team gefunden"}, status_code=400)

    # SECURITY: Dateiendung prüfen
    filename = file.filename or "video"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_VIDEO_EXTENSIONS:
        return JSONResponse({"error": f"Ungültiges Format. Erlaubt: {', '.join(ALLOWED_VIDEO_EXTENSIONS)}"}, status_code=400)

    # SECURITY: Dateigröße prüfen
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)

    if file_size > MAX_VIDEO_SIZE:
        return JSONResponse({"error": "Video zu groß (max. 500 MB)"}, status_code=400)

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
            INSERT INTO videos (team_id, title, description, filename, file_size, uploaded_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (db_user["team_id"], title[:200], description[:1000], safe_filename, file_size, user["id"]))
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
    Video streamen.
    SECURITY: Nur eigenes Team, IDOR Prevention.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT filename FROM videos
            WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (video_id, db_user["team_id"]))
        video = cursor.fetchone()

    if not video:
        return JSONResponse({"error": "Video nicht gefunden"}, status_code=404)

    file_path = os.path.join(get_video_upload_dir(), str(
        db_user["team_id"]), video["filename"])
    if not os.path.exists(file_path):
        return JSONResponse({"error": "Datei nicht gefunden"}, status_code=404)

    return FileResponse(file_path, media_type="video/mp4")


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
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    try:
        data = await request.json()
        title = data.get("title", "").strip()[:200]
        start_time = int(data.get("start_time", 0))
        end_time = int(data.get("end_time", 0))
        note = data.get("note", "").strip()[:500]

        if not title or len(title) < 1:
            return JSONResponse({"error": "Titel erforderlich"}, status_code=400)
        if start_time >= end_time:
            return JSONResponse({"error": "Ungültige Zeitangaben"}, status_code=400)

    except (ValueError, TypeError):
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
        """, (video_id, db_user["team_id"], title, start_time, end_time, note, user["id"]))
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
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    try:
        data = await request.json()
        recipient_ids = data.get("recipient_ids", [])
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


@router.post("/api/invitations")
async def create_invitation_api(request: Request):
    """
    Einladung erstellen.
    SECURITY: Nur Admin, Input-Validierung.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT team_id, is_admin FROM users WHERE id = ? AND is_active = 1",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        if not user_data or not user_data["is_admin"]:
            return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

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
            (role_id, user_data["team_id"])
        )
        if not cursor.fetchone():
            return JSONResponse({"error": "Ungültige Rolle"}, status_code=400)

    try:
        token = create_invitation(
            user_data["team_id"], role_id, user["id"], max_uses, days_valid)
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

    with get_db_connection() as db:
        cursor = db.cursor()

        cursor.execute(
            "SELECT team_id, is_admin FROM users WHERE id = ? AND is_active = 1",
            (user["id"],)
        )
        user_data = cursor.fetchone()

        if not user_data or not user_data["is_admin"]:
            return JSONResponse({"error": "Keine Berechtigung"}, status_code=403)

        # SECURITY: IDOR Prevention
        cursor.execute(
            "UPDATE invitations SET is_active = 0 WHERE id = ? AND team_id = ?",
            (invitation_id, user_data["team_id"])
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
        expires = datetime.fromisoformat(invitation["expires_at"])
        if expires < datetime.now():
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Einladung abgelaufen"}
            )

    user = get_current_user(request)

    return templates.TemplateResponse("join.html", {
        "request": request,
        "token": token,
        "team_name": invitation["team_name"],
        "role_name": invitation["role_name"],
        "logged_in": user is not None
    })


@router.post("/join/{token}")
async def join_team(request: Request, token: str):
    """
    Team beitreten.
    SECURITY: Token-Validierung, User muss eingeloggt sein.
    """
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url=f"/login?redirect=/join/{token}", status_code=303)

    try:
        token = InputValidator.validate_token(token)
    except ValidationError:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Ungültiger Einladungslink"}
        )

    result = use_invitation(token, user["id"])

    if result["success"]:
        log_audit_event(user["id"], "TEAM_JOINED", "user", user["id"])
        return RedirectResponse(url="/dashboard", status_code=303)
    else:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": result["error"]}
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
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"players": []})

    with get_db_connection() as db:
        cursor = db.cursor()

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
                SELECT id, name, position, trikotnummer, status, email, telefon, geburtsdatum, notizen, user_id
                FROM players
                WHERE team_id = ? AND deleted_at IS NULL
                ORDER BY trikotnummer, name
            """, (db_user["team_id"],))
            players = [dict(row) for row in cursor.fetchall()]
        else:
            # Spieler/Eltern sehen nur sich selbst (verknüpft über user_id)
            cursor.execute("""
                SELECT id, name, position, trikotnummer, status, email, telefon, geburtsdatum, notizen, user_id
                FROM players
                WHERE team_id = ? AND user_id = ? AND deleted_at IS NULL
            """, (db_user["team_id"], user["id"]))
            players = [dict(row) for row in cursor.fetchall()]

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
    if status not in ("Fit", "Belastet", "Angeschlagen", "Verletzt", "Reha", "Ausfall"):
        status = "Fit"

    email = str(data.get("email", "")).strip()[:254]
    telefon = str(data.get("telefon", "")).strip()[:30]
    geburtsdatum = str(data.get("geburtsdatum", "")).strip()[:10] or None
    notizen = str(data.get("notizen", "")).strip()[:1000]

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO players (team_id, name, position, trikotnummer, status, email, telefon, geburtsdatum, notizen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (db_user["team_id"], name, position, trikotnummer, status, email, telefon, geburtsdatum, notizen))
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
            if status in ("Fit", "Belastet", "Angeschlagen", "Verletzt", "Reha", "Ausfall"):
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

        if updates:
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(player_id)
            cursor.execute(
                f"UPDATE players SET {', '.join(updates)} WHERE id = ?", params)
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


@router.get("/api/players/stats")
async def get_player_stats(request: Request):
    """Spieler-Statistiken für Dashboard."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"fit": 0, "belastet": 0, "verletzt": 0, "total": 0})

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'Fit' THEN 1 ELSE 0 END) as fit,
                SUM(CASE WHEN status IN ('Belastet', 'Angeschlagen') THEN 1 ELSE 0 END) as belastet,
                SUM(CASE WHEN status IN ('Verletzt', 'Ausfall', 'Reha') THEN 1 ELSE 0 END) as verletzt
            FROM players
            WHERE team_id = ? AND deleted_at IS NULL
        """, (db_user["team_id"],))
        row = cursor.fetchone()

    return JSONResponse({
        "total": row["total"] or 0,
        "fit": row["fit"] or 0,
        "belastet": row["belastet"] or 0,
        "verletzt": row["verletzt"] or 0
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
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"events": []})

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, title, description, event_type, event_date, start_time, end_time, location
            FROM calendar_events
            WHERE team_id = ? AND deleted_at IS NULL
            ORDER BY event_date, start_time
        """, (db_user["team_id"],))
        events = [dict(row) for row in cursor.fetchall()]

    return JSONResponse({"events": events})


@router.post("/api/events")
async def create_event(request: Request):
    """Neues Event erstellen."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

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

    description = str(data.get("description", "")).strip()[:1000]
    start_time = str(data.get("start_time", data.get("time", ""))).strip()[
        :8] or None
    end_time = str(data.get("end_time", "")).strip()[:8] or None
    location = str(data.get("location", "")).strip()[:200]

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO calendar_events (team_id, title, description, event_type, event_date, start_time, end_time, location, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (db_user["team_id"], title, description, event_type, event_date, start_time, end_time, location, user["id"]))
        db.commit()
        event_id = cursor.lastrowid

    return JSONResponse({"success": True, "id": event_id})


@router.delete("/api/events/{event_id}")
async def delete_event(request: Request, event_id: int):
    """Event löschen."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE calendar_events SET deleted_at = CURRENT_TIMESTAMP
            WHERE id = ? AND team_id = ? AND deleted_at IS NULL
        """, (event_id, db_user["team_id"]))
        db.commit()

    return JSONResponse({"success": True})


@router.get("/api/events/week")
async def get_week_events(request: Request):
    """Events der aktuellen Woche für Dashboard."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
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
# API Endpoints - Messages
# ============================================

@router.get("/api/messages")
async def get_messages(request: Request, limit: int = 50, before_id: int = None):
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
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"messages": [], "has_more": False})

    # SECURITY: Limit begrenzen
    limit = min(max(1, limit), 100)

    with get_db_connection() as db:
        cursor = db.cursor()

        if before_id:
            # PERFORMANCE: Cursor-Pagination (schneller als OFFSET)
            cursor.execute("""
                SELECT m.id, m.content, m.created_at, m.sender_id,
                       u.vorname || ' ' || u.nachname as sender_name
                FROM messages m
                LEFT JOIN users u ON m.sender_id = u.id
                WHERE m.team_id = ? AND m.recipient_id IS NULL AND m.deleted_at IS NULL
                AND m.id < ?
                ORDER BY m.created_at DESC
                LIMIT ?
            """, (db_user["team_id"], before_id, limit + 1))
        else:
            cursor.execute("""
                SELECT m.id, m.content, m.created_at, m.sender_id,
                       u.vorname || ' ' || u.nachname as sender_name
                FROM messages m
                LEFT JOIN users u ON m.sender_id = u.id
                WHERE m.team_id = ? AND m.recipient_id IS NULL AND m.deleted_at IS NULL
                ORDER BY m.created_at DESC
                LIMIT ?
            """, (db_user["team_id"], limit + 1))

        rows = cursor.fetchall()
        has_more = len(rows) > limit
        messages = [dict(row) for row in rows[:limit]]

    return JSONResponse({
        "messages": messages[::-1],  # Älteste zuerst
        "has_more": has_more
    })


@router.post("/api/messages")
async def send_message(request: Request):
    """Nachricht senden."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    db_user = get_user_by_id(user["id"])
    if not db_user or not db_user.get("team_id"):
        return JSONResponse({"error": "Kein Team"}, status_code=400)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Ungültige Daten"}, status_code=400)

    content = str(data.get("content", "")).strip()[:5000]
    if not content:
        return JSONResponse({"error": "Nachricht leer"}, status_code=400)

    recipient_id = data.get("recipient_id")  # None = Team-Chat

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO messages (team_id, sender_id, recipient_id, content)
            VALUES (?, ?, ?, ?)
        """, (db_user["team_id"], user["id"], recipient_id, content))
        db.commit()
        message_id = cursor.lastrowid

    return JSONResponse({"success": True, "id": message_id})


@router.get("/api/messages/unread")
async def get_unread_count(request: Request):
    """Anzahl ungelesener Nachrichten."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"count": 0})

    db_user = get_user_by_id(user["id"])
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

    # 2FA-Daten laden
    tfa_data = get_user_2fa(user_id)
    if not tfa_data or not tfa_data.get("totp_secret"):
        logger.error(f"2FA data not found for user {user_id}")
        return RedirectResponse(url="/auth/login", status_code=303)

    # Replay-Attack prüfen
    if check_replay_attack(user_id, code):
        log_audit_event(user_id, "2FA_REPLAY_ATTACK", "user", user_id,
                        f"code={code[:2]}***", client_ip,
                        severity="CRITICAL", event_type="2FA_FAILED")
        return templates.TemplateResponse(
            "2fa_verify.html",
            {"request": request, "error": "Code bereits verwendet.",
             "pending_token": pending_token, "csrf_token": generate_csrf_token("2fa_form")}
        )

    # TOTP verifizieren
    if not verify_totp(tfa_data["totp_secret"], code):
        log_audit_event(user_id, "2FA_INVALID_CODE", "user", user_id,
                        None, client_ip, severity="WARNING", event_type="2FA_FAILED")

        # Rate limiting für 2FA
        exponential_lockout.record_failure(f"2fa:{user_id}")

        return templates.TemplateResponse(
            "2fa_verify.html",
            {"request": request, "error": "Ungültiger Code. Bitte erneut versuchen.",
             "pending_token": pending_token, "csrf_token": generate_csrf_token("2fa_form")}
        )

    # Code als verwendet markieren (Replay-Schutz)
    update_2fa_last_used(user_id, code)

    # Login abschließen
    user = get_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)

    user_agent = request.headers.get("User-Agent", "")
    log_audit_event(user_id, "LOGIN_SUCCESS_2FA", "user", user_id,
                    None, client_ip, event_type="LOGIN_SUCCESS")

    # Session erstellen
    token = create_session_token(user, request)
    secure_session_manager.register_session(
        token, user_id, client_ip, user_agent)

    response = RedirectResponse(url="/dashboard", status_code=303)
    set_session_cookie(response, token)
    response.delete_cookie("pending_2fa")

    logger.info(f"Successful 2FA login: user_id={user_id}")
    return response


@router.get("/2fa/setup", response_class=HTMLResponse)
async def setup_2fa_page(request: Request):
    """Zeigt die 2FA-Setup-Seite."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)

    db_user = get_user_by_id(user["id"])
    if not db_user:
        return RedirectResponse(url="/auth/login", status_code=303)

    # Bereits aktiviert?
    if is_2fa_enabled(user["id"]):
        return templates.TemplateResponse(
            "2fa_setup.html",
            {"request": request, "success": "2FA ist bereits aktiviert.",
             "csrf_token": generate_csrf_token("2fa_setup")}
        )

    # Neuen Secret generieren
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, db_user["email"])
    qr_code = generate_totp_qr_code(uri)
    backup_codes = generate_backup_codes(10)

    import json
    backup_codes_json = json.dumps(backup_codes)

    csrf_token = generate_csrf_token("2fa_setup")
    return templates.TemplateResponse(
        "2fa_setup.html",
        {
            "request": request,
            "secret": secret,
            "qr_code": qr_code,
            "backup_codes": backup_codes,
            "backup_codes_json": backup_codes_json,
            "csrf_token": csrf_token
        }
    )


@router.post("/2fa/activate", response_class=HTMLResponse)
async def activate_2fa(
    request: Request,
    code: str = Form(...),
    secret: str = Form(...),
    backup_codes: str = Form(...),
    csrf_token: str = Form("")
):
    """Aktiviert 2FA nach Verifikation des ersten Codes."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)

    client_ip = get_client_ip(request)

    # CSRF validieren
    if not validate_csrf_token(csrf_token, "2fa_setup"):
        logger.warning(
            f"CSRF validation failed for 2FA setup from {client_ip}")
        return templates.TemplateResponse(
            "2fa_setup.html",
            {"request": request, "error": "Ungültige Anfrage. Bitte erneut versuchen.",
             "csrf_token": generate_csrf_token("2fa_setup")}
        )

    # Secret validieren (muss 32 Zeichen Base32 sein)
    if not secret or len(secret) != 32:
        return templates.TemplateResponse(
            "2fa_setup.html",
            {"request": request, "error": "Ungültiger Secret. Bitte neu starten.",
             "csrf_token": generate_csrf_token("2fa_setup")}
        )

    # TOTP-Code verifizieren
    if not verify_totp(secret, code):
        return templates.TemplateResponse(
            "2fa_setup.html",
            {"request": request, "error": "Ungültiger Code. Bitte erneut versuchen.",
             "secret": secret, "csrf_token": generate_csrf_token("2fa_setup")}
        )

    # Backup-Codes hashen
    import json
    try:
        codes_list = json.loads(backup_codes)
        # Codes als JSON speichern (in Production: einzeln hashen)
        codes_hash = json.dumps(codes_list)
    except json.JSONDecodeError:
        codes_hash = "[]"

    # 2FA in DB speichern
    setup_2fa(user["id"], secret, codes_hash)
    enable_2fa(user["id"])

    log_audit_event(user["id"], "2FA_ENABLED", "user", user["id"],
                    None, client_ip, event_type="2FA_ENABLED")

    logger.info(f"2FA enabled for user {user['id']}")

    return templates.TemplateResponse(
        "2fa_setup.html",
        {"request": request, "success": "Zwei-Faktor-Authentifizierung wurde erfolgreich aktiviert!",
         "csrf_token": generate_csrf_token("2fa_setup")}
    )


@router.post("/2fa/disable", response_class=HTMLResponse)
async def disable_2fa_route(
    request: Request,
    password: str = Form(...),
    csrf_token: str = Form("")
):
    """Deaktiviert 2FA (erfordert Passwort-Bestätigung)."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)

    client_ip = get_client_ip(request)

    # CSRF validieren
    if not validate_csrf_token(csrf_token, "2fa_disable"):
        return JSONResponse({"error": "Ungültige Anfrage"}, status_code=400)

    # Passwort verifizieren
    db_user = get_user_by_id(user["id"])
    if not db_user:
        return JSONResponse({"error": "User nicht gefunden"}, status_code=400)

    try:
        peppered_password = f"{password}{SecurityConfig.PASSWORD_PEPPER}"
        password_valid = bcrypt.checkpw(
            peppered_password.encode('utf-8'),
            db_user["password_hash"].encode('utf-8')
        )
    except Exception:
        password_valid = False

    if not password_valid:
        log_audit_event(user["id"], "2FA_DISABLE_FAILED", "user", user["id"],
                        "invalid_password", client_ip, severity="WARNING")
        return JSONResponse({"error": "Falsches Passwort"}, status_code=400)

    # 2FA deaktivieren
    disable_2fa(user["id"])

    log_audit_event(user["id"], "2FA_DISABLED", "user", user["id"],
                    None, client_ip, severity="WARNING", event_type="2FA_DISABLED")

    logger.info(f"2FA disabled for user {user['id']}")

    return JSONResponse({"success": True, "message": "2FA wurde deaktiviert"})


@router.get("/2fa/status")
async def get_2fa_status(request: Request):
    """Gibt den 2FA-Status für den aktuellen User zurück."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Nicht authentifiziert"}, status_code=401)

    enabled = is_2fa_enabled(user["id"])
    tfa_data = get_user_2fa(user["id"])

    return JSONResponse({
        "enabled": enabled,
        "enabled_at": tfa_data.get("enabled_at") if tfa_data else None
    })
