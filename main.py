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
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
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

def setup_logging():
    """
    Konfiguriert sicheres Logging.
    SECURITY: Keine sensiblen Daten in Logs.
    """
    os.makedirs("data", exist_ok=True)

    # Security Logger
    security_logger = logging.getLogger("pitchinsights.security")
    security_logger.setLevel(getattr(logging, SecurityConfig.LOG_LEVEL))

    # File Handler mit Rotation
    file_handler = RotatingFileHandler(
        SecurityConfig.LOG_FILE,
        maxBytes=10_000_000,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    security_logger.addHandler(file_handler)

    # Console Handler für Development
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(levelname)s: %(message)s'
    ))
    security_logger.addHandler(console_handler)

    return security_logger


logger = setup_logging()


# ============================================
# Application Lifecycle
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application Lifecycle Handler.
    SECURITY: Sichere Initialisierung.
    """
    # Startup
    logger.info("PitchInsights starting up...")
    os.makedirs("data/uploads", exist_ok=True)
    init_db()
    init_team_tables()
    logger.info("Database initialized")

    yield

    # Shutdown
    logger.info("PitchInsights shutting down...")


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

# SECURITY: Trusted Host Middleware
# Erlaubt auch Railway interne Health Checks
allowed_hosts = os.environ.get(
    "PITCHINSIGHTS_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
# Füge Wildcard für Railway Health Checks hinzu
allowed_hosts.append("*")  # Railway Health Checks kommen von internen IPs
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=allowed_hosts
)


# ============================================
# HTTPS Redirect Middleware (Production)
# ============================================

@app.middleware("http")
async def https_redirect_middleware(request: Request, call_next):
    """
    Erzwingt HTTPS in Produktion.
    SECURITY: Verhindert unverschlüsselte Verbindungen.
    """
    # Skip für Healthcheck Endpoints (Railway macht HTTP intern)
    if request.url.path in ["/", "/health"]:
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


@app.get("/os")
async def serve_os():
    """
    Serve the PitchInsights OS.
    SECURITY: Cache-Control Header verhindert Caching.
    """
    template_path = os.path.join(
        os.path.dirname(__file__), "templates", "os.html"
    )
    return FileResponse(
        template_path,
        media_type="text/html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache"
        }
    )


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

@app.get("/")
@app.get("/health")
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
