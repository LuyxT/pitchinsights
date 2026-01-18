"""
PitchInsights Main Application - Security Hardened Version
===========================================================
SECURITY AUDIT: CORS, Middleware und Error-Handling gehärtet.
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import uvicorn

from config import SecurityConfig
from database import init_db, init_team_tables
from routes.auth import router as auth_router
from security import (
    get_secure_headers, check_rate_limit, api_rate_limiter,
    get_client_ip, validate_json_request_origin,
    ip_blacklist, validate_request_integrity, generate_request_id,
    generate_csp_nonce, get_secure_headers_with_nonce
)


# ============================================
# Security Logging Setup
# ============================================

def setup_logging(enable_file_logging: bool = False):
    """
    Konfiguriert sicheres Logging.
    SECURITY: Keine sensiblen Daten in Logs.
    """
    # Security Logger
    security_logger = logging.getLogger("pitchinsights.security")

    # Verhindere doppelte Handler
    if security_logger.handlers:
        return security_logger

    security_logger.setLevel(getattr(logging, SecurityConfig.LOG_LEVEL))

    # Console Handler (immer aktiv)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(levelname)s: %(message)s'
    ))
    security_logger.addHandler(console_handler)

    # File Handler nur wenn explizit angefordert und möglich
    if enable_file_logging:
        try:
            os.makedirs("data", exist_ok=True)
            file_handler = RotatingFileHandler(
                SecurityConfig.LOG_FILE,
                maxBytes=10_000_000,  # 10MB
                backupCount=5
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            security_logger.addHandler(file_handler)
            security_logger.info("File logging enabled")
        except (PermissionError, OSError) as e:
            security_logger.warning(f"File logging disabled: {e}")

    return security_logger


# Initial nur Console-Logging
logger = setup_logging(enable_file_logging=False)


# ============================================
# Application Lifecycle
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application Lifecycle Handler.
    SECURITY: Sichere Initialisierung.
    """
    import time

    # Startup
    logger.info("PitchInsights starting up...")

    # Data-Verzeichnis aus Config
    data_dir = SecurityConfig.DATA_DIR
    logger.info(f"Configured data directory: {data_dir}")

    # Debug: Check if /app/data exists and its permissions
    if os.path.exists("/app/data"):
        logger.info(f"/app/data EXISTS - Volume is mounted!")
        try:
            stat_info = os.stat("/app/data")
            logger.info(
                f"/app/data permissions: {oct(stat_info.st_mode)}, uid={stat_info.st_uid}, gid={stat_info.st_gid}")
        except Exception as e:
            logger.warning(f"Could not stat /app/data: {e}")
    else:
        logger.warning("/app/data does NOT exist - Volume not mounted!")

    # Warte auf Volume-Mount (Railway braucht manchmal etwas Zeit)
    max_retries = 5
    use_fallback = False

    for attempt in range(max_retries):
        try:
            os.makedirs(f"{data_dir}/uploads", exist_ok=True)
            os.makedirs(f"{data_dir}/videos", exist_ok=True)
            os.makedirs(f"{data_dir}/backups", exist_ok=True)
            # Test write
            test_file = f"{data_dir}/.write_test"
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            logger.info(f"Data directories created and writable at {data_dir}")
            break
        except PermissionError as e:
            if attempt < max_retries - 1:
                logger.warning(
                    f"Permission denied for {data_dir}, retrying in 2s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(2)
            else:
                logger.warning(
                    f"Volume {data_dir} not accessible after {max_retries} attempts, using /tmp fallback")
                use_fallback = True
        except Exception as e:
            logger.error(
                f"Unexpected error creating directories in {data_dir}: {e}")
            use_fallback = True
            break

    # Fallback zu /tmp wenn Volume nicht verfügbar
    if use_fallback:
        data_dir = "/tmp/pitchinsights_data"
        # WICHTIG: SecurityConfig aktualisieren damit database.py den richtigen Pfad nutzt
        SecurityConfig.DATA_DIR = data_dir
        SecurityConfig.DATABASE_PATH = f"{data_dir}/pitchinsights.db"
        SecurityConfig.LOG_FILE = f"{data_dir}/security.log"
        logger.info(f"Switched to fallback directory: {data_dir}")
        os.makedirs(f"{data_dir}/uploads", exist_ok=True)
        os.makedirs(f"{data_dir}/videos", exist_ok=True)
        os.makedirs(f"{data_dir}/backups", exist_ok=True)

    logger.info(f"Final data directory: {SecurityConfig.DATA_DIR}")
    logger.info(f"Final database path: {SecurityConfig.DATABASE_PATH}")

    # File-Logging aktivieren
    setup_logging(enable_file_logging=True)

    # Database initialisieren
    try:
        init_db()
        init_team_tables()
        logger.info("Database initialized")

        # DEBUG: Log user count to detect data loss
        from database import get_db_connection
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
            user_count = cursor.fetchone()[0]
            cursor.execute(
                "SELECT COUNT(*) FROM videos WHERE deleted_at IS NULL")
            video_count = cursor.fetchone()[0]
            logger.info(
                f"DATABASE CHECK: {user_count} users, {video_count} videos found")
            if user_count == 0:
                logger.warning(
                    "WARNING: No users in database! Data may have been lost.")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        logger.error(f"Attempted DB path: {SecurityConfig.DATABASE_PATH}")
        raise

    yield

    # Shutdown
    logger.info("PitchInsights shutting down...")


# ============================================
# Templates Setup
# ============================================
templates = Jinja2Templates(directory="templates")


# ============================================
# FastAPI Application
# ============================================

app = FastAPI(
    title="PitchInsights Beta",
    # SECURITY: Keine detaillierten API-Docs in Production
    docs_url="/docs" if os.environ.get(
        "PITCHINSIGHTS_ENV") != "production" else None,
    redoc_url="/redoc" if os.environ.get(
        "PITCHINSIGHTS_ENV") != "production" else None,
    openapi_url="/openapi.json" if os.environ.get(
        "PITCHINSIGHTS_ENV") != "production" else None,
    lifespan=lifespan
)

# ============================================
# Security Middleware
# ============================================

# SECURITY: Nur explizit erlaubte Origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=SecurityConfig.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    expose_headers=["X-Request-ID"],
    max_age=600,  # 10 Minuten Cache für Preflight
)

# SECURITY: Trusted Hosts (custom middleware for healthcheck allowlist)
allowed_hosts = os.environ.get(
    "PITCHINSIGHTS_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
allowed_hosts = [host.strip().lower() for host in allowed_hosts if host.strip()]
if os.path.exists("/app"):
    allowed_hosts.append("*.up.railway.app")


# ============================================
# HTTPS Redirect Middleware (Production)
# ============================================

def _is_allowed_host(host: str, allowed: list[str]) -> bool:
    if not host:
        return False
    host = host.split(":", 1)[0].strip().lower()
    for entry in allowed:
        if entry == "*":
            return True
        if entry.startswith("*.") and host.endswith(entry[1:]):
            return True
        if host == entry:
            return True
    return False


@app.middleware("http")
async def trusted_host_middleware(request: Request, call_next):
    """
    Prüft erlaubte Hosts.
    SECURITY: Blockt unzulässige Host-Header.
    """
    if request.url.path in ["/health", "/_health"]:
        return await call_next(request)

    host = request.headers.get("host", "")
    if not _is_allowed_host(host, allowed_hosts):
        return JSONResponse(status_code=400, content={"error": "Ungültiger Host"})

    return await call_next(request)

@app.middleware("http")
async def https_redirect_middleware(request: Request, call_next):
    """
    Erzwingt HTTPS in Produktion.
    SECURITY: Verhindert unverschlüsselte Verbindungen.
    """
    # Skip für Healthcheck Endpoints (Railway macht HTTP intern)
    if request.url.path in ["/health", "/_health"]:
        return await call_next(request)

    if SecurityConfig.IS_PRODUCTION:
        # Prüfe ob Request über HTTPS kam (via Proxy-Header)
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "http")
        if forwarded_proto != "https" and request.url.scheme != "https":
            # Redirect zu HTTPS
            url = str(request.url).replace("http://", "https://", 1)
            return JSONResponse(
                status_code=301,
                content={"redirect": url},
                headers={"Location": url}
            )

    return await call_next(request)


# ============================================
# IP Blacklist Middleware (FIRST LINE OF DEFENSE)
# ============================================

@app.middleware("http")
async def ip_blacklist_middleware(request: Request, call_next):
    """
    Blockiert geblacklistete IPs sofort.
    SECURITY: Erste Verteidigungslinie gegen bekannte Angreifer.
    """
    client_ip = get_client_ip(request)
    is_blocked, remaining = ip_blacklist.is_blacklisted(client_ip)

    if is_blocked:
        logger.warning(f"Blocked request from blacklisted IP: {client_ip}")
        return JSONResponse(
            status_code=403,
            content={"error": "Zugriff verweigert"},
            headers={"Retry-After": str(remaining)}
        )

    return await call_next(request)


# ============================================
# Request Integrity Middleware
# ============================================

@app.middleware("http")
async def request_integrity_middleware(request: Request, call_next):
    """
    Validiert Request-Integrität und erkennt Scanner/Bots.
    SECURITY: Blockiert bösartige Tools automatisch.
    """
    client_ip = get_client_ip(request)

    if request.url.path in ["/health", "/_health"]:
        return await call_next(request)

    # Validiere Request
    is_valid, error_reason = validate_request_integrity(request)

    if not is_valid:
        logger.warning(
            f"Invalid request blocked: {error_reason} from {client_ip}")
        # Bei Scanner-Detection -> Blacklist
        if "Scanner detected" in (error_reason or ""):
            ip_blacklist.record_offense(client_ip, error_reason)

        return JSONResponse(
            status_code=400,
            content={"error": "Ungültige Anfrage"}
        )

    return await call_next(request)


# ============================================
# Request ID Tracking Middleware
# ============================================

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """
    Fügt Request-ID für Audit-Trail hinzu.
    SECURITY: Ermöglicht Korrelation bei Incident Response.
    """
    request_id = generate_request_id()
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id

    return response


# ============================================
# CSRF / Origin Validation Middleware
# ============================================

@app.middleware("http")
async def origin_validation_middleware(request: Request, call_next):
    """
    Prüft Origin für JSON-API-Anfragen.
    SECURITY: Zusätzlicher CSRF-Schutz für mutating requests.
    """
    # Nur für API POST/PUT/DELETE
    if request.url.path.startswith("/api/") and request.method in ("POST", "PUT", "DELETE"):
        if not validate_json_request_origin(request):
            return JSONResponse(
                status_code=403,
                content={"error": "Ungültige Anfrage-Quelle"}
            )

    return await call_next(request)


# ============================================
# Global Rate Limiting Middleware
# ============================================

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """
    Globales Rate Limiting für alle API-Anfragen.
    SECURITY: Verhindert DoS-Angriffe.
    """
    # Nur für API-Endpoints
    if request.url.path.startswith("/api/"):
        try:
            check_rate_limit(
                request,
                api_rate_limiter,
                max_requests=SecurityConfig.API_RATE_LIMIT_PER_MINUTE,
                window_seconds=60,
                key_prefix="api"
            )
        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.detail},
                headers=e.headers or {}
            )

    return await call_next(request)


# ============================================
# Security Headers Middleware (mit CSP Nonce)
# ============================================

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    Fügt Security-Headers zu allen Responses hinzu.
    SECURITY AUDIT: CSP mit Nonce statt unsafe-inline.
    """
    # Generiere Nonce für diese Request
    csp_nonce = generate_csp_nonce()
    request.state.csp_nonce = csp_nonce

    response = await call_next(request)

    # Hole alle Security Headers mit Nonce
    secure_headers = get_secure_headers_with_nonce(
        csp_nonce, SecurityConfig.IS_PRODUCTION)
    for header, value in secure_headers.items():
        response.headers[header] = value

    # Cache-Control für sensible Seiten
    if "/api/" in request.url.path or "/login" in request.url.path:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


# ============================================
# Healthcheck Bypass (must run first)
# ============================================

@app.middleware("http")
async def healthcheck_bypass(request: Request, call_next):
    if request.url.path in ["/health", "/_health"]:
        return JSONResponse({"status": "healthy"})
    return await call_next(request)


# ============================================
# Global Error Handler
# ============================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Globaler Error Handler.
    SECURITY: Keine internen Fehlerdetails an Clients.
    """
    # Logge den vollen Error serverseitig
    logger.error(f"Unhandled exception: {type(exc).__name__}", exc_info=True)

    # SECURITY: Generische Fehlermeldung an Client
    return JSONResponse(
        status_code=500,
        content={
            "error": "Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut."}
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """404 Handler ohne Details."""
    return JSONResponse(
        status_code=404,
        content={"error": "Nicht gefunden"}
    )


# ============================================
# Static Files
# ============================================

app.mount("/static", StaticFiles(directory="static"), name="static")


# ============================================
# Routes
# ============================================

app.include_router(auth_router)


@app.get("/os", response_class=HTMLResponse)
async def serve_os(request: Request):
    """
    Serve the PitchInsights OS.
    SECURITY: Cache-Control Header verhindert Caching.
    """
    from routes.auth import get_current_user, get_user_by_id

    # User aus Session holen
    user = get_current_user(request)
    user_data = None
    if user:
        user_data = get_user_by_id(user.get("id"))

    response = templates.TemplateResponse(
        "os.html",
        {
            "request": request,
            "user": user_data
        }
    )
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response


@app.get("/taktik")
async def serve_taktik():
    """Serve the Taktik-Tafel page."""
    template_path = os.path.join(
        os.path.dirname(__file__), "templates", "taktik.html"
    )
    return FileResponse(
        template_path,
        media_type="text/html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate"
        }
    )


# ============================================
# Health Check (für Monitoring)
# ============================================

@app.get("/health")
@app.get("/_health")
async def health_check():
    """
    Health Check Endpoint.
    SECURITY: Keine sensitiven Infos.
    """
    return {"status": "healthy"}


# ============================================
# Main Entry Point
# ============================================

if __name__ == "__main__":
    # SECURITY: In Production sollte ein Reverse Proxy (nginx) verwendet werden
    uvicorn.run(
        "main:app",
        host="127.0.0.1",  # Nur localhost, nicht 0.0.0.0
        port=8000,
        reload=os.environ.get("PITCHINSIGHTS_ENV") != "production",
        # SECURITY: Access Log für Audit
        access_log=True,
        # SECURITY: Keine Server Header
        server_header=False,
    )
