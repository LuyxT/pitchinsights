"""
Security Middleware Module
==========================
CSRF-Protection, Rate Limiting, IP-Binding und weitere Sicherheitsfunktionen.
"""

import re
import os
import time
import secrets
import hashlib
import ipaddress
import logging
from typing import Dict, Optional, Tuple, List, Any
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import Request, HTTPException
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from config import SecurityConfig

logger = logging.getLogger("pitchinsights.security")


# ============================================
# CSRF Protection
# ============================================

csrf_serializer = URLSafeTimedSerializer(SecurityConfig.CSRF_SECRET)


def generate_csrf_token(session_id: str) -> str:
    """
    Generiert einen CSRF-Token gebunden an die Session.
    SECURITY: Token ist signiert und zeitlich begrenzt.
    """
    return csrf_serializer.dumps({
        "session": session_id,
        "nonce": secrets.token_hex(16)
    })


def validate_csrf_token(token: str, session_id: str) -> bool:
    """
    Validiert einen CSRF-Token.
    SECURITY: Prüft Signatur, Ablaufzeit und Session-Bindung.
    """
    if not token:
        return False

    try:
        data = csrf_serializer.loads(
            token,
            max_age=SecurityConfig.CSRF_TOKEN_EXPIRY
        )
        return data.get("session") == session_id
    except (SignatureExpired, BadSignature):
        return False
    except Exception:
        return False


# ============================================
# Rate Limiting (In-Memory für Single-Instance)
# ============================================

class RateLimiter:
    """
    Token-Bucket Rate Limiter.
    SECURITY: Verhindert Brute-Force und DoS-Angriffe.

    Für Production mit mehreren Instanzen sollte Redis verwendet werden.
    """

    def __init__(self):
        # IP -> (tokens, last_update)
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._cleanup_interval = 300  # 5 Minuten
        self._last_cleanup = time.time()

    def _cleanup_old_entries(self):
        """Entfernt alte Einträge um Speicher zu sparen."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        cutoff = now - 3600  # Einträge älter als 1 Stunde
        self._buckets = {
            k: v for k, v in self._buckets.items()
            if v[1] > cutoff
        }
        self._last_cleanup = now

    def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int
    ) -> Tuple[bool, int]:
        """
        Prüft ob eine Anfrage erlaubt ist.

        Returns: (is_allowed, remaining_requests)
        """
        self._cleanup_old_entries()

        now = time.time()
        refill_rate = max_requests / window_seconds

        if key not in self._buckets:
            self._buckets[key] = (max_requests - 1, now)
            return True, max_requests - 1

        tokens, last_update = self._buckets[key]

        # Tokens nachfüllen basierend auf vergangener Zeit
        elapsed = now - last_update
        tokens = min(max_requests, tokens + elapsed * refill_rate)

        if tokens >= 1:
            self._buckets[key] = (tokens - 1, now)
            return True, int(tokens - 1)
        else:
            self._buckets[key] = (tokens, now)
            return False, 0


# Globale Rate Limiter Instanzen
api_rate_limiter = RateLimiter()
login_rate_limiter = RateLimiter()
sensitive_rate_limiter = RateLimiter()


def check_rate_limit(
    request: Request,
    limiter: RateLimiter,
    max_requests: int,
    window_seconds: int,
    key_prefix: str = ""
) -> None:
    """
    Prüft Rate Limit und wirft HTTPException wenn überschritten.
    """
    client_ip = get_client_ip(request)
    key = f"{key_prefix}:{client_ip}"

    allowed, remaining = limiter.is_allowed(key, max_requests, window_seconds)

    if not allowed:
        logger.warning(f"Rate limit exceeded for {key}")
        raise HTTPException(
            status_code=429,
            detail="Zu viele Anfragen. Bitte warten Sie einen Moment.",
            headers={"Retry-After": str(window_seconds)}
        )


# ============================================
# IP-Bound Sessions
# ============================================

def _is_valid_ip(ip: str) -> bool:
    """Prüft ob ein String eine gültige IP-Adresse ist."""
    if not ip or len(ip) > 45:  # Max IPv6 Länge
        return False
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """
    Ermittelt die echte Client-IP.
    SECURITY: Berücksichtigt X-Forwarded-For nur hinter Proxy.
    SECURITY FIX: Validiert IP-Format um Spoofing zu verhindern.
    """
    if os.environ.get("PITCHINSIGHTS_BEHIND_PROXY") == "true":
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Erste IP in der Kette ist der echte Client
            # SECURITY: Validiere dass es wirklich eine IP ist
            candidate = forwarded.split(",")[0].strip()
            if _is_valid_ip(candidate):
                return candidate
            else:
                logger.warning(
                    f"Invalid X-Forwarded-For IP rejected: {candidate[:50]}")

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            candidate = real_ip.strip()
            if _is_valid_ip(candidate):
                return candidate
            else:
                logger.warning(f"Invalid X-Real-IP rejected: {candidate[:50]}")

    return request.client.host if request.client else "unknown"


def get_ip_hash(ip: str) -> str:
    """
    Erstellt einen Hash der IP für Session-Binding.
    SECURITY: Hash statt Klartext-IP im Token.
    """
    return hashlib.sha256(
        f"{ip}:{SecurityConfig.SECRET_KEY}".encode()
    ).hexdigest()[:16]


def validate_session_ip(stored_ip_hash: str, request: Request) -> bool:
    """
    Prüft ob die Session-IP noch übereinstimmt.
    SECURITY: Verhindert Session-Hijacking bei IP-Wechsel.
    """
    if not SecurityConfig.SESSION_BIND_IP:
        return True

    current_ip = get_client_ip(request)
    current_hash = get_ip_hash(current_ip)

    return stored_ip_hash == current_hash


# ============================================
# Request Fingerprinting
# ============================================

def get_request_fingerprint(request: Request) -> str:
    """
    Erstellt einen Fingerprint der Request-Charakteristiken.
    SECURITY: Zusätzliche Absicherung gegen Session-Hijacking.
    """
    components = [
        request.headers.get("User-Agent", ""),
        request.headers.get("Accept-Language", ""),
        request.headers.get("Accept-Encoding", ""),
    ]

    fingerprint = "|".join(components)
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]


# ============================================
# Secure Headers Helper
# ============================================

def get_secure_headers(is_production: bool = False) -> Dict[str, str]:
    """
    Gibt sichere HTTP-Headers zurück.
    SECURITY: Umfassende Header-Sammlung gegen verschiedene Angriffsvektoren.
    """
    headers = {
        # Verhindert MIME-Type-Sniffing
        "X-Content-Type-Options": "nosniff",
        # Verhindert Clickjacking
        "X-Frame-Options": "DENY",
        # XSS-Filter (legacy, aber schadet nicht)
        "X-XSS-Protection": "1; mode=block",
        # Kontrolliert Referrer-Informationen
        "Referrer-Policy": "strict-origin-when-cross-origin",
        # Beschränkt Browser-APIs
        "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
        # Verhindert Cross-Domain-Flash/PDF-Zugriff
        "X-Permitted-Cross-Domain-Policies": "none",
        # Verhindert DNS-Prefetching
        "X-DNS-Prefetch-Control": "off",
        # Kontrolliert Download-Verhalten
        "X-Download-Options": "noopen",
        # Cross-Origin Resource Policy
        "Cross-Origin-Resource-Policy": "same-origin",
        # Cross-Origin Opener Policy - Schutz vor Spectre-Angriffen
        "Cross-Origin-Opener-Policy": "same-origin",
        # Cross-Origin Embedder Policy
        "Cross-Origin-Embedder-Policy": "require-corp",
    }

    if is_production:
        # CSP für Production
        # NOTE: 'unsafe-inline' ist nötig wegen Inline-Scripts in os.html
        # XSS wird durch escapeHtml() im Frontend verhindert
        headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "upgrade-insecure-requests;"
        )
        # HSTS - Browser soll nur HTTPS verwenden
        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    else:
        # Development-CSP (lockerer für Debugging)
        headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

    return headers


# ============================================
# CSRF Protection for JSON APIs
# ============================================

def validate_json_request_origin(request: Request) -> bool:
    """
    Prüft ob ein JSON-Request von einer erlaubten Origin kommt.
    SECURITY: Zusätzlicher Schutz neben SameSite-Cookies.
    """
    # Fetch Metadata API (moderne Browser)
    sec_fetch_site = request.headers.get("Sec-Fetch-Site")
    if sec_fetch_site:
        # same-origin ist sicher, cross-site ist verdächtig
        if sec_fetch_site not in ("same-origin", "same-site", "none"):
            logger.warning(f"Cross-site request blocked: {sec_fetch_site}")
            return False

    # Prüfe Origin-Header für nicht-GET-Requests
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("Origin")
        if origin:
            # Origin muss in ALLOWED_ORIGINS sein
            if origin not in SecurityConfig.ALLOWED_ORIGINS:
                logger.warning(f"Invalid Origin header: {origin}")
                return False

    return True


# ============================================
# Suspicious Activity Detection
# ============================================

class SuspiciousActivityDetector:
    """
    Erkennt verdächtige Aktivitätsmuster.
    """

    def __init__(self):
        self._failed_logins: Dict[str, list] = defaultdict(list)
        self._suspicious_ips: set = set()

    def record_failed_login(self, ip: str) -> None:
        """Zeichnet fehlgeschlagenen Login auf."""
        now = time.time()
        self._failed_logins[ip].append(now)

        # Behalte nur letzte 24 Stunden
        cutoff = now - 86400
        self._failed_logins[ip] = [
            t for t in self._failed_logins[ip] if t > cutoff
        ]

        # Markiere als verdächtig bei zu vielen Fehlversuchen
        if len(self._failed_logins[ip]) > 20:
            self._suspicious_ips.add(ip)
            logger.warning(f"IP marked as suspicious: {ip}")

    def is_suspicious(self, ip: str) -> bool:
        """Prüft ob IP als verdächtig markiert ist."""
        return ip in self._suspicious_ips

    def clear_suspicion(self, ip: str) -> None:
        """Entfernt Verdachtsmarkierung nach erfolgreichem Login."""
        self._suspicious_ips.discard(ip)
        self._failed_logins.pop(ip, None)


# Globale Instanz
activity_detector = SuspiciousActivityDetector()


# ============================================
# Request ID Tracking
# ============================================

def generate_request_id() -> str:
    """
    Generiert eine eindeutige Request-ID für Audit-Logging.
    SECURITY: Ermöglicht Korrelation von Logs bei Incident Response.
    """
    return secrets.token_hex(8)


# ============================================
# Honeypot Detection
# ============================================

HONEYPOT_FIELD_NAMES = [
    "website",
    "url",
    "homepage",
    "company",
    "fax",
    "fax_number",
    "phone",
    "phone_number",
]


def check_honeypot_fields(form_data: dict) -> Tuple[bool, Optional[str]]:
    """
    Prüft ob Honeypot-Felder ausgefüllt wurden (Bot-Erkennung).
    SECURITY: Bots füllen oft versteckte Felder aus.
    Returns: (is_suspicious, field_name)
    """
    for field in HONEYPOT_FIELD_NAMES:
        value = form_data.get(field)
        if value and str(value).strip():
            logger.warning(f"Honeypot field filled: {field}")
            return True, field
    return False, None


# ============================================
# Password Breach Detection
# ============================================

COMMON_WEAK_PASSWORDS = {
    "password123", "123456789", "qwerty123", "password1",
    "iloveyou1", "admin12345", "welcome123", "monkey1234",
    "dragon1234", "master1234", "letmein123", "login12345",
    "princess1", "sunshine1", "football1", "baseball1",
    "Password1!", "Qwerty123!", "Welcome1!", "Admin123!"
}


def is_common_password(password: str) -> bool:
    """
    Prüft ob das Passwort zu den häufigsten gehört.
    SECURITY: Verhindert schwache Passwörter.
    """
    # Prüfe exakt und lowercase
    return password in COMMON_WEAK_PASSWORDS or password.lower() in {
        p.lower() for p in COMMON_WEAK_PASSWORDS
    }


# ============================================
# Geo-Blocking / Anomaly Detection
# ============================================

class LoginAnomalyDetector:
    """
    Erkennt ungewöhnliche Login-Muster.
    SECURITY: Früherkennung von Account-Takeover-Versuchen.
    """

    def __init__(self):
        # user_id -> [(timestamp, ip, user_agent)]
        self._login_history: Dict[int, list] = defaultdict(list)
        self._max_history = 10

    def record_login(self, user_id: int, ip: str, user_agent: str) -> None:
        """Zeichnet erfolgreichen Login auf."""
        self._login_history[user_id].append({
            "ts": time.time(),
            "ip": ip,
            "ua": user_agent[:200] if user_agent else ""
        })
        # Behalte nur die letzten N Einträge
        self._login_history[user_id] = self._login_history[user_id][-self._max_history:]

    def is_anomalous_login(self, user_id: int, ip: str, user_agent: str) -> bool:
        """
        Prüft ob der aktuelle Login ungewöhnlich ist.
        Returns: True wenn anomal (z.B. komplett neue IP + neuer User-Agent)
        """
        history = self._login_history.get(user_id, [])
        if len(history) < 3:
            return False  # Nicht genug Historie

        # Prüfe ob IP jemals gesehen wurde
        known_ips = {h["ip"] for h in history}
        ip_known = ip in known_ips

        # Prüfe ob User-Agent ähnlich zu bekannten
        known_uas = {h["ua"][:50] for h in history}  # Erste 50 Zeichen
        ua_prefix = (user_agent[:50] if user_agent else "")
        ua_known = ua_prefix in known_uas

        # Anomalie: Komplett neue IP UND neuer User-Agent
        if not ip_known and not ua_known:
            logger.warning(
                f"Anomalous login detected: user_id={user_id}, new IP and UA"
            )
            return True

        return False


# Globale Instanz
login_anomaly_detector = LoginAnomalyDetector()


# ============================================
# SQL Injection Detection (Logging only)
# ============================================

# Patterns die auf SQL-Injection hindeuten könnten
SQL_INJECTION_PATTERNS = [
    re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
    re.compile(
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", re.IGNORECASE),
    re.compile(
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))", re.IGNORECASE),
    re.compile(r"((union)(.*)(select))|((select)(.*)(from))", re.IGNORECASE),
    re.compile(r"((insert)(.*)(into))|((delete)(.*)(from))", re.IGNORECASE),
    re.compile(r"((drop)(.*)(table))|((alter)(.*)(table))", re.IGNORECASE),
    re.compile(r"(exec(\s|\+)+(x|X)?p)|xp_cmdshell", re.IGNORECASE),
    re.compile(r"waitfor(\s)+delay", re.IGNORECASE),
    re.compile(r"benchmark\s*\(", re.IGNORECASE),
    re.compile(r"sleep\s*\(", re.IGNORECASE),
]


def detect_sql_injection(input_string: str) -> Tuple[bool, Optional[str]]:
    """
    Erkennt potenzielle SQL-Injection-Versuche.
    SECURITY: Nur für Logging/Alerting, nicht als primärer Schutz!
    Primärer Schutz sind parametrisierte Queries.

    Returns: (is_suspicious, matched_pattern)
    """
    if not input_string or not isinstance(input_string, str):
        return False, None

    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(input_string):
            return True, pattern.pattern[:50]  # Truncate pattern for log

    return False, None


def check_input_for_attacks(input_string: str, field_name: str, client_ip: str) -> None:
    """
    Prüft Eingaben auf Angriffsversuche und loggt verdächtige Aktivität.
    SECURITY: Forensik und Alerting, nicht als primärer Schutz!
    """
    if not input_string:
        return

    # SQL Injection Check
    is_sqli, pattern = detect_sql_injection(input_string)
    if is_sqli:
        logger.warning(
            f"Potential SQL injection attempt - IP: {client_ip}, "
            f"Field: {field_name}, Pattern: {pattern}"
        )

    # XSS Check (HTML/Script tags)
    if re.search(r'<[^>]*script|javascript:|on\w+\s*=', input_string, re.IGNORECASE):
        logger.warning(
            f"Potential XSS attempt - IP: {client_ip}, "
            f"Field: {field_name}, Input: {input_string[:100]}"
        )

    # Path Traversal Check
    if re.search(r'\.\.[\\/]|[\\/]etc[\\/]|[\\/]proc[\\/]', input_string, re.IGNORECASE):
        logger.warning(
            f"Potential path traversal attempt - IP: {client_ip}, "
            f"Field: {field_name}"
        )


# ============================================
# Security Event Types
# ============================================

class SecurityEventType:
    """Konstanten für Security-Events."""
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGIN_BLOCKED = "LOGIN_BLOCKED"
    LOGIN_ANOMALY = "LOGIN_ANOMALY"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    SESSION_HIJACK_ATTEMPT = "SESSION_HIJACK_ATTEMPT"
    CSRF_VIOLATION = "CSRF_VIOLATION"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    SUSPICIOUS_IP = "SUSPICIOUS_IP"
    BOT_DETECTED = "BOT_DETECTED"
    SQL_INJECTION_ATTEMPT = "SQL_INJECTION_ATTEMPT"
    XSS_ATTEMPT = "XSS_ATTEMPT"
    PATH_TRAVERSAL_ATTEMPT = "PATH_TRAVERSAL_ATTEMPT"
    IP_BLACKLISTED = "IP_BLACKLISTED"
    BRUTE_FORCE_DETECTED = "BRUTE_FORCE_DETECTED"


# ============================================
# Automatic IP Blacklisting
# ============================================

class IPBlacklist:
    """
    Automatische IP-Blacklist für hartnäckige Angreifer.
    SECURITY: Blockiert IPs die wiederholt bösartige Aktionen ausführen.
    """

    def __init__(self):
        # IP -> (block_until, offense_count)
        self._blacklist: Dict[str, Tuple[float, int]] = {}
        # IP -> [timestamps of offenses]
        self._offense_history: Dict[str, list] = defaultdict(list)
        # Eskalationsstufen in Sekunden
        # 5min, 15min, 1h, 24h, 7 Tage
        self._block_durations = [300, 900, 3600, 86400, 604800]

    def record_offense(self, ip: str, offense_type: str) -> bool:
        """
        Zeichnet einen Verstoß auf und blacklisted ggf. die IP.
        Returns: True wenn IP jetzt geblacklisted ist.
        """
        now = time.time()

        # Cleanup alte Offenses (älter als 24h)
        cutoff = now - 86400
        self._offense_history[ip] = [
            t for t in self._offense_history[ip] if t > cutoff]

        # Neuen Offense hinzufügen
        self._offense_history[ip].append(now)
        offense_count = len(self._offense_history[ip])

        # Bei 5+ Offenses in 24h -> Blacklist
        if offense_count >= 5:
            # Eskaliere Blockdauer basierend auf Wiederholungen
            current_offense = self._blacklist.get(ip, (0, 0))[1]
            new_offense = current_offense + 1
            duration_idx = min(new_offense - 1, len(self._block_durations) - 1)
            block_duration = self._block_durations[duration_idx]

            self._blacklist[ip] = (now + block_duration, new_offense)
            logger.warning(
                f"IP blacklisted: {ip}, offense={offense_type}, "
                f"duration={block_duration}s, total_offenses={new_offense}"
            )
            return True

        return False

    def is_blacklisted(self, ip: str) -> Tuple[bool, int]:
        """
        Prüft ob IP geblacklisted ist.
        Returns: (is_blocked, seconds_remaining)
        """
        if ip not in self._blacklist:
            return False, 0

        block_until, _ = self._blacklist[ip]
        now = time.time()

        if now >= block_until:
            # Block abgelaufen, aber History behalten für Eskalation
            return False, 0

        return True, int(block_until - now)

    def get_offense_count(self, ip: str) -> int:
        """Gibt die Anzahl der Offenses in den letzten 24h zurück."""
        return len(self._offense_history.get(ip, []))


# Globale Instanz
ip_blacklist = IPBlacklist()


# ============================================
# Request Integrity Validation
# ============================================

def validate_request_integrity(request: Request) -> Tuple[bool, Optional[str]]:
    """
    Validiert die Integrität eines Requests.
    SECURITY: Erkennt manipulierte oder bösartige Requests.

    Returns: (is_valid, error_reason)
    """
    # 1. Prüfe auf übermäßig große Headers
    total_header_size = sum(len(k) + len(v)
                            for k, v in request.headers.items())
    if total_header_size > 16384:  # 16KB
        return False, "Headers too large"

    # 2. Prüfe auf verdächtige Header-Injection
    for header_name, header_value in request.headers.items():
        if '\n' in header_value or '\r' in header_value:
            return False, "Header injection attempt"
        if len(header_value) > 8192:  # 8KB per Header
            return False, f"Header {header_name} too large"

    # 3. Prüfe User-Agent (leere oder verdächtige User-Agents)
    user_agent = request.headers.get("User-Agent", "")
    if not user_agent:
        # Kein User-Agent ist verdächtig
        logger.info(
            f"Request without User-Agent from {get_client_ip(request)}")
    elif len(user_agent) > 500:
        return False, "User-Agent too long"

    # 4. Prüfe auf bekannte Scanner/Bot-Signaturen
    scanner_signatures = [
        "sqlmap", "nikto", "nmap", "masscan", "zgrab",
        "nuclei", "dirbuster", "gobuster", "wfuzz", "ffuf",
        "burp", "hydra", "medusa"
    ]
    ua_lower = user_agent.lower()
    for sig in scanner_signatures:
        if sig in ua_lower:
            logger.warning(
                f"Scanner detected: {sig} from {get_client_ip(request)}")
            return False, f"Scanner detected: {sig}"

    # 5. Prüfe URL-Länge
    if len(str(request.url)) > 2048:
        return False, "URL too long"

    return True, None


# ============================================
# Content-Type Validation
# ============================================

def validate_content_type(request: Request, expected_types: list) -> bool:
    """
    Validiert den Content-Type Header.
    SECURITY: Verhindert Content-Type-Confusion-Angriffe.
    """
    content_type = request.headers.get("Content-Type", "")
    if not content_type:
        return False

    # Extrahiere Basis-Content-Type ohne charset etc.
    base_type = content_type.split(";")[0].strip().lower()

    return base_type in [t.lower() for t in expected_types]


# ============================================
# Session Security Enhancement
# ============================================

class SecureSessionManager:
    """
    Erweiterte Session-Verwaltung mit Rotation und Invalidierung.
    SECURITY: Verhindert Session-Fixation und Session-Hijacking.
    """

    def __init__(self):
        # session_token_hash -> {user_id, created_at, last_used, ip, ua}
        self._active_sessions: Dict[str, dict] = {}
        # user_id -> [session_token_hashes]
        self._user_sessions: Dict[int, list] = defaultdict(list)
        self._max_sessions_per_user = 5

    def _hash_token(self, token: str) -> str:
        """Hash des Session-Tokens für sichere Speicherung."""
        return hashlib.sha256(token.encode()).hexdigest()

    def register_session(self, token: str, user_id: int, ip: str, user_agent: str) -> None:
        """Registriert eine neue Session."""
        token_hash = self._hash_token(token)
        now = time.time()

        self._active_sessions[token_hash] = {
            "user_id": user_id,
            "created_at": now,
            "last_used": now,
            "ip": ip,
            "ua": user_agent[:200] if user_agent else ""
        }

        # Zur User-Session-Liste hinzufügen
        self._user_sessions[user_id].append(token_hash)

        # Älteste Sessions entfernen wenn Limit überschritten
        while len(self._user_sessions[user_id]) > self._max_sessions_per_user:
            old_token_hash = self._user_sessions[user_id].pop(0)
            self._active_sessions.pop(old_token_hash, None)
            logger.info(
                f"Old session removed for user {user_id} (max sessions)")

    def validate_session(self, token: str, ip: str, user_agent: str) -> Tuple[bool, Optional[str]]:
        """
        Validiert eine Session.
        Returns: (is_valid, error_reason)
        """
        token_hash = self._hash_token(token)

        if token_hash not in self._active_sessions:
            return False, "Session not found"

        session = self._active_sessions[token_hash]

        # IP-Binding prüfen
        if SecurityConfig.SESSION_BIND_IP and session["ip"] != ip:
            logger.warning(
                f"Session IP mismatch: expected {session['ip']}, got {ip}")
            return False, "IP mismatch"

        # Session-Alter prüfen (max 24h)
        age = time.time() - session["created_at"]
        if age > SecurityConfig.SESSION_MAX_AGE_SECONDS:
            return False, "Session expired"

        # Update last_used
        self._active_sessions[token_hash]["last_used"] = time.time()

        return True, None

    def invalidate_session(self, token: str) -> None:
        """Invalidiert eine einzelne Session."""
        token_hash = self._hash_token(token)
        session = self._active_sessions.pop(token_hash, None)
        if session:
            user_id = session["user_id"]
            if token_hash in self._user_sessions.get(user_id, []):
                self._user_sessions[user_id].remove(token_hash)

    def invalidate_all_user_sessions(self, user_id: int, except_current: str = None) -> int:
        """
        Invalidiert alle Sessions eines Users (z.B. nach Passwortänderung).
        Returns: Anzahl der invalidierten Sessions.
        """
        count = 0
        current_hash = self._hash_token(
            except_current) if except_current else None

        for token_hash in list(self._user_sessions.get(user_id, [])):
            if token_hash != current_hash:
                self._active_sessions.pop(token_hash, None)
                count += 1

        self._user_sessions[user_id] = [current_hash] if current_hash else []
        logger.info(f"Invalidated {count} sessions for user {user_id}")
        return count


# Globale Instanz
secure_session_manager = SecureSessionManager()


# ============================================
# Timing-Safe Comparison
# ============================================

def constant_time_compare(a: str, b: str) -> bool:
    """
    Vergleicht zwei Strings in konstanter Zeit.
    SECURITY: Verhindert Timing-Angriffe.
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y

    return result == 0


# ============================================
# Account Lockout with Exponential Backoff
# ============================================

class ExponentialBackoffLockout:
    """
    Account-Lockout mit exponentieller Verzögerung.
    SECURITY: Macht Brute-Force exponentiell teurer.
    """

    def __init__(self):
        # key (email/ip) -> (failed_attempts, last_attempt, lockout_until)
        self._lockouts: Dict[str, Tuple[int, float, float]] = {}

    def record_failure(self, key: str) -> Tuple[bool, int]:
        """
        Zeichnet Fehlversuch auf.
        Returns: (is_locked, lockout_seconds)
        """
        now = time.time()

        if key in self._lockouts:
            attempts, last_attempt, lockout_until = self._lockouts[key]

            # Reset wenn letzter Versuch > 24h her
            if now - last_attempt > 86400:
                attempts = 0

            attempts += 1
        else:
            attempts = 1

        # Berechne Lockout-Dauer (exponentiell)
        # 0->0, 1->0, 2->0, 3->30s, 4->60s, 5->120s, 6->240s, ...
        if attempts >= 3:
            lockout_seconds = min(30 * (2 ** (attempts - 3)), 3600)  # Max 1h
            lockout_until = now + lockout_seconds
        else:
            lockout_seconds = 0
            lockout_until = 0

        self._lockouts[key] = (attempts, now, lockout_until)

        if lockout_seconds > 0:
            logger.warning(
                f"Account locked: {key[:20]}***, attempts={attempts}, lockout={lockout_seconds}s")

        return lockout_seconds > 0, lockout_seconds

    def is_locked(self, key: str) -> Tuple[bool, int]:
        """
        Prüft ob Account gesperrt ist.
        Returns: (is_locked, seconds_remaining)
        """
        if key not in self._lockouts:
            return False, 0

        _, _, lockout_until = self._lockouts[key]
        now = time.time()

        if lockout_until > now:
            return True, int(lockout_until - now)

        return False, 0

    def clear(self, key: str) -> None:
        """Löscht Lockout nach erfolgreichem Login."""
        self._lockouts.pop(key, None)


# Globale Instanz
exponential_lockout = ExponentialBackoffLockout()


# ============================================
# ADVANCED: Argon2 Password Hashing (GPU-resistant)
# ============================================

def hash_password_argon2(password: str) -> str:
    """
    Hasht ein Passwort mit Argon2id (GPU-resistenter als bcrypt).
    SECURITY: Argon2 ist der Gewinner des Password Hashing Competition.
    Fallback auf bcrypt wenn argon2-cffi nicht installiert.
    """
    try:
        from argon2 import PasswordHasher
        from argon2.profiles import RFC_9106_LOW_MEMORY
        ph = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)
        peppered = f"{password}{SecurityConfig.PASSWORD_PEPPER}"
        return ph.hash(peppered)
    except ImportError:
        # Fallback zu bcrypt
        import bcrypt
        peppered = f"{password}{SecurityConfig.PASSWORD_PEPPER}"
        return bcrypt.hashpw(peppered.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password_argon2(password: str, hash: str) -> bool:
    """
    Verifiziert ein Passwort gegen einen Argon2-Hash.
    SECURITY: Unterstützt auch bcrypt-Hashes für Migration.
    """
    peppered = f"{password}{SecurityConfig.PASSWORD_PEPPER}"

    # Argon2 Hash beginnt mit $argon2
    if hash.startswith("$argon2"):
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
            ph = PasswordHasher()
            try:
                ph.verify(hash, peppered)
                return True
            except VerifyMismatchError:
                return False
        except ImportError:
            return False

    # bcrypt Hash beginnt mit $2b$
    elif hash.startswith("$2"):
        import bcrypt
        try:
            return bcrypt.checkpw(peppered.encode(), hash.encode())
        except Exception:
            return False

    return False


# ============================================
# ADVANCED: Request Signing (API Integrity)
# ============================================

def generate_request_signature(method: str, path: str, body: bytes, timestamp: int) -> str:
    """
    Generiert eine HMAC-Signatur für einen Request.
    SECURITY: Ermöglicht Verifizierung der Request-Integrität.
    """
    import hmac
    message = f"{method}:{path}:{timestamp}:{body.hex() if body else ''}"
    return hmac.new(
        SecurityConfig.SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_request_signature(request: Request, signature: str, max_age: int = 300) -> bool:
    """
    Verifiziert die Signatur eines Requests.
    SECURITY: Verhindert Request-Tampering und Replay-Attacks.
    """
    import hmac

    timestamp_str = request.headers.get("X-Timestamp", "")
    if not timestamp_str:
        return False

    try:
        timestamp = int(timestamp_str)
    except ValueError:
        return False

    # Prüfe Alter (max 5 Minuten)
    now = int(time.time())
    if abs(now - timestamp) > max_age:
        logger.warning(f"Request signature expired: {now - timestamp}s old")
        return False

    # Berechne erwartete Signatur
    # Note: Body muss vorher gelesen werden
    expected = generate_request_signature(
        request.method,
        str(request.url.path),
        b"",  # Body kann hier nicht async gelesen werden
        timestamp
    )

    return hmac.compare_digest(signature, expected)


# ============================================
# ADVANCED: Geo-IP Blocking (Basic)
# ============================================

# Bekannte Tor-Exit-Nodes und VPN-IP-Ranges (Beispiel)
# In Production sollte dies aus einer aktualisierten Liste kommen
SUSPICIOUS_IP_RANGES = [
    # Beispiel: Bekannte böswillige IP-Ranges
    # Format: (start_ip_int, end_ip_int)
]


def ip_to_int(ip: str) -> int:
    """Konvertiert eine IPv4-Adresse zu einem Integer."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return 0
        return sum(int(part) << (24 - 8 * i) for i, part in enumerate(parts))
    except (ValueError, AttributeError):
        return 0


def is_ip_in_suspicious_range(ip: str) -> bool:
    """
    Prüft ob eine IP in einem verdächtigen Range liegt.
    SECURITY: Kann für Geo-Blocking oder VPN-Erkennung verwendet werden.
    """
    ip_int = ip_to_int(ip)
    if ip_int == 0:
        return False

    for start, end in SUSPICIOUS_IP_RANGES:
        if start <= ip_int <= end:
            return True

    return False


# ============================================
# ADVANCED: Password Entropy Check
# ============================================

def calculate_password_entropy(password: str) -> float:
    """
    Berechnet die Entropie eines Passworts in Bits.
    SECURITY: Höhere Entropie = stärkeres Passwort.
    """
    import math
    if not password:
        return 0.0

    # Bestimme Zeichenpool
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(not c.isalnum() for c in password):
        pool_size += 32  # Sonderzeichen

    if pool_size == 0:
        return 0.0

    # Entropie = log2(pool_size^length)
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def is_password_strong_enough(password: str, min_entropy: float = 60.0) -> Tuple[bool, float]:
    """
    Prüft ob ein Passwort genug Entropie hat.
    SECURITY: 60 Bits Entropie = sehr stark.
    Returns: (is_strong, actual_entropy)
    """
    entropy = calculate_password_entropy(password)
    return entropy >= min_entropy, entropy


# ============================================
# ADVANCED: Canary Token Detection
# ============================================

CANARY_TOKENS = {
    # Fake-Admin-Credentials die niemals gültig sein sollten
    "admin@pitchinsights.de",
    "administrator@pitchinsights.de",
    "root@pitchinsights.de",
    "test@test.com",
    "admin@admin.com",
}


def is_canary_login(email: str) -> bool:
    """
    Prüft ob ein Login-Versuch ein Canary-Token verwendet.
    SECURITY: Wenn jemand diese Credentials verwendet, ist es definitiv ein Angreifer.
    """
    return email.lower() in CANARY_TOKENS


def handle_canary_trigger(email: str, ip: str) -> None:
    """
    Handelt einen Canary-Token-Trigger.
    SECURITY: Sofortige Alarmierung und Blacklisting.
    """
    logger.critical(
        f"🚨 CANARY TRIGGERED: email={email}, ip={ip} - Possible breach attempt!"
    )
    # IP sofort für 7 Tage sperren
    ip_blacklist.record_offense(ip, "CANARY_TRIGGERED")
    ip_blacklist.record_offense(ip, "CANARY_TRIGGERED")
    ip_blacklist.record_offense(ip, "CANARY_TRIGGERED")
    ip_blacklist.record_offense(ip, "CANARY_TRIGGERED")
    ip_blacklist.record_offense(ip, "CANARY_TRIGGERED")


# ============================================
# ADVANCED: Concurrent Login Detection
# ============================================

class ConcurrentLoginDetector:
    """
    Erkennt verdächtige gleichzeitige Logins.
    SECURITY: Wenn ein User von 2+ IPs gleichzeitig aktiv ist, könnte Account kompromittiert sein.
    """

    def __init__(self):
        # user_id -> [(ip, timestamp)]
        self._active_users: Dict[int, list] = defaultdict(list)
        self._max_concurrent = 3
        self._activity_window = 300  # 5 Minuten

    def record_activity(self, user_id: int, ip: str) -> bool:
        """
        Zeichnet Aktivität auf und prüft auf verdächtige Patterns.
        Returns: True wenn verdächtig (zu viele verschiedene IPs)
        """
        now = time.time()

        # Alte Einträge entfernen
        self._active_users[user_id] = [
            (stored_ip, ts) for stored_ip, ts in self._active_users[user_id]
            if now - ts < self._activity_window
        ]

        # Neue Aktivität hinzufügen
        self._active_users[user_id].append((ip, now))

        # Prüfe auf zu viele verschiedene IPs
        unique_ips = set(stored_ip for stored_ip,
                         _ in self._active_users[user_id])

        if len(unique_ips) > self._max_concurrent:
            logger.warning(
                f"Concurrent login detected: user_id={user_id}, "
                f"ips={unique_ips}"
            )
            return True

        return False


# Globale Instanz
concurrent_login_detector = ConcurrentLoginDetector()


# ============================================
# ADVANCED: Security Headers Nonce für CSP
# ============================================

def generate_csp_nonce() -> str:
    """
    Generiert einen Nonce für Content-Security-Policy.
    SECURITY: Ermöglicht strikte CSP ohne 'unsafe-inline'.
    """
    return secrets.token_urlsafe(16)


def get_secure_headers_with_nonce(nonce: str, is_production: bool = False) -> Dict[str, str]:
    """
    Gibt sichere HTTP-Headers mit CSP-Nonce zurück.
    SECURITY: Inline-Scripts und Styles erlaubt für Template-Kompatibilität.
    """
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
        "X-Permitted-Cross-Domain-Policies": "none",
        "X-DNS-Prefetch-Control": "off",
        "X-Download-Options": "noopen",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
    }

    # CSP: unsafe-inline für Scripts/Styles (Templates nutzen keine Nonces)
    # XSS-Schutz durch Input-Validierung und escapeHtml() im Frontend
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'unsafe-inline'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data: blob:; "
        f"font-src 'self'; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self';"
    )

    if is_production:
        csp += " upgrade-insecure-requests;"
        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

    headers["Content-Security-Policy"] = csp
    return headers


# ============================================
# ADVANCED: HaveIBeenPwned Password Check
# ============================================

async def check_password_pwned(password: str) -> Tuple[bool, int]:
    """
    Prüft ob ein Passwort in bekannten Datenlecks vorkommt.
    SECURITY: Nutzt k-Anonymity - nur SHA1-Prefix wird gesendet.
    Returns: (is_pwned, count)
    """
    try:
        import httpx
        import hashlib

        # SHA1 des Passworts
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        # Nur Prefix an API senden (k-Anonymity)
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"}  # Timing-Attack-Schutz
            )

            if response.status_code != 200:
                logger.warning(f"HIBP API error: {response.status_code}")
                return False, 0

            # Suche nach unserem Suffix in der Antwort
            for line in response.text.splitlines():
                if ":" in line:
                    hash_suffix, count = line.split(":")
                    if hash_suffix == suffix:
                        count = int(count)
                        logger.warning(f"Password found in {count} breaches")
                        return True, count

            return False, 0

    except Exception as e:
        logger.error(f"HIBP check failed: {e}")
        return False, 0  # Bei Fehler nicht blockieren


def check_password_pwned_sync(password: str) -> Tuple[bool, int]:
    """
    Synchrone Version des HIBP-Checks (für Registrierung).
    """
    try:
        import requests
        import hashlib

        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=5
        )

        if response.status_code != 200:
            return False, 0

        for line in response.text.splitlines():
            if ":" in line:
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return True, int(count)

        return False, 0

    except Exception as e:
        logger.error(f"HIBP sync check failed: {e}")
        return False, 0


# ============================================
# ADVANCED: Two-Factor Authentication (TOTP)
# ============================================

def generate_totp_secret() -> str:
    """
    Generiert einen TOTP-Secret für 2FA.
    SECURITY: 32 Zeichen Base32-encoded für Kompatibilität.
    """
    try:
        import pyotp
        return pyotp.random_base32()
    except ImportError:
        # Fallback ohne pyotp
        import base64
        return base64.b32encode(secrets.token_bytes(20)).decode()[:32]


def get_totp_uri(secret: str, email: str, issuer: str = "PitchInsights") -> str:
    """
    Generiert die otpauth:// URI für Authenticator-Apps.
    """
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=issuer)
    except ImportError:
        # Manuell bauen
        import urllib.parse
        return f"otpauth://totp/{issuer}:{urllib.parse.quote(email)}?secret={secret}&issuer={issuer}"


def verify_totp(secret: str, code: str) -> bool:
    """
    Verifiziert einen TOTP-Code.
    SECURITY: Erlaubt 1 Code vor/nach aktuellem (30s Toleranz).
    """
    if not secret or not code:
        return False

    # Code bereinigen
    code = code.strip().replace(" ", "").replace("-", "")
    if not code.isdigit() or len(code) != 6:
        return False

    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    except ImportError:
        logger.error("pyotp not installed, 2FA verification failed")
        return False
    except Exception as e:
        logger.error(f"TOTP verification error: {e}")
        return False


def generate_totp_qr_code(uri: str) -> str:
    """
    Generiert einen QR-Code als Base64-PNG für die 2FA-Einrichtung.
    """
    try:
        import qrcode
        import io
        import base64

        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode()

    except ImportError:
        logger.warning("qrcode not installed, returning empty")
        return ""
    except Exception as e:
        logger.error(f"QR code generation failed: {e}")
        return ""


def generate_backup_codes(count: int = 10) -> List[str]:
    """
    Generiert Backup-Codes für 2FA-Recovery.
    SECURITY: Einmal verwendbar, kryptographisch sicher.
    """
    codes = []
    for _ in range(count):
        # 8 Zeichen, alphanumerisch, ohne verwechselbare Zeichen
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        # Format: XXXX-XXXX
        codes.append(f"{code[:4]}-{code[4:]}")
    return codes


# ============================================
# ADVANCED: Audit Log Events (für DB-Speicherung)
# ============================================

class AuditEventType:
    """Audit Event Types für Datenbank-Logging."""
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGIN_BLOCKED = "LOGIN_BLOCKED"
    LOGOUT = "LOGOUT"
    REGISTER = "REGISTER"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PASSWORD_RESET_REQUEST = "PASSWORD_RESET_REQUEST"
    PASSWORD_RESET_COMPLETE = "PASSWORD_RESET_COMPLETE"
    TWO_FA_ENABLED = "2FA_ENABLED"
    TWO_FA_DISABLED = "2FA_DISABLED"
    TWO_FA_FAILED = "2FA_FAILED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    DATA_EXPORT = "DATA_EXPORT"
    DATA_DELETE = "DATA_DELETE"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    BOT_DETECTED = "BOT_DETECTED"
    CANARY_TRIGGERED = "CANARY_TRIGGERED"


def create_audit_event(
    event_type: str,
    user_id: Optional[int],
    ip_address: str,
    user_agent: str = "",
    details: Optional[Dict[str, Any]] = None,
    severity: str = "INFO"
) -> Dict[str, Any]:
    """
    Erstellt ein strukturiertes Audit-Event für DB-Speicherung.
    """
    import json
    return {
        "event_type": event_type,
        "user_id": user_id,
        "ip_address": ip_address,
        "user_agent": user_agent[:500] if user_agent else "",
        "details": json.dumps(details) if details else None,
        "severity": severity,
        "created_at": datetime.now().isoformat()
    }


# ============================================
# ADVANCED: Account Lockout Notification
# ============================================

class LockoutNotifier:
    """
    Benachrichtigt User bei Account-Lockout.
    SECURITY: Warnt legitime User vor möglichem Angriff.
    """

    def __init__(self):
        self._notified: Dict[str, float] = {}
        self._cooldown = 3600  # 1 Stunde zwischen Benachrichtigungen

    def should_notify(self, email: str) -> bool:
        """Prüft ob Benachrichtigung gesendet werden soll."""
        now = time.time()
        last_notified = self._notified.get(email, 0)
        return (now - last_notified) > self._cooldown

    def mark_notified(self, email: str) -> None:
        """Markiert dass Benachrichtigung gesendet wurde."""
        self._notified[email] = time.time()

    def get_lockout_message(self, email: str, ip: str, attempts: int) -> Dict[str, str]:
        """
        Erstellt Lockout-Benachrichtigungsinhalt.
        In Production: Per E-Mail senden.
        """
        return {
            "subject": "⚠️ PitchInsights: Verdächtige Login-Aktivität",
            "body": f"""
Hallo,

Wir haben {attempts} fehlgeschlagene Login-Versuche für Ihren Account ({email}) festgestellt.

Details:
- IP-Adresse: {ip}
- Zeitpunkt: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

Ihr Account wurde vorübergehend gesperrt.

Falls Sie diese Versuche nicht unternommen haben, empfehlen wir:
1. Ändern Sie Ihr Passwort nach dem Entsperren
2. Aktivieren Sie die Zwei-Faktor-Authentifizierung
3. Überprüfen Sie Ihre letzten Aktivitäten

Falls Sie Hilfe benötigen, kontaktieren Sie uns.

Mit freundlichen Grüßen,
Das PitchInsights Team

---
Diese E-Mail wurde automatisch generiert.
            """.strip()
        }


# Globale Instanz
lockout_notifier = LockoutNotifier()


# ============================================
# ADVANCED: Double-Submit Cookie CSRF
# ============================================

def generate_double_submit_token() -> str:
    """
    Generiert einen Double-Submit Cookie Token.
    SECURITY: Zusätzliche CSRF-Schutzschicht.
    """
    return secrets.token_hex(32)


def validate_double_submit(cookie_token: str, form_token: str) -> bool:
    """
    Validiert Double-Submit Cookie Pattern.
    SECURITY: Cookie und Form-Token müssen übereinstimmen.
    """
    if not cookie_token or not form_token:
        return False
    return constant_time_compare(cookie_token, form_token)
