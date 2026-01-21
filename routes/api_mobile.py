"""
Mobile API Routes for iOS/Android Apps
=======================================
REST API with JSON responses and Bearer token authentication.
"""

import logging
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Request, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ConfigDict
import bcrypt

from config import SecurityConfig
from validators import InputValidator, ValidationError
from security import (
    get_client_ip, check_rate_limit, api_rate_limiter,
    generate_request_id
)
from database import (
    get_db_connection, get_user_by_email, get_user_by_id,
    record_login_attempt, is_login_blocked, clear_login_attempts,
    update_last_login, verify_user_team_access, use_invitation
)

router = APIRouter(prefix="/api/v1", tags=["Mobile API"])

# Security Logger
logger = logging.getLogger("pitchinsights.security")

# Token Storage (In production, use Redis or database)
# Format: {token: {user_id, expires_at, refresh_token}}
active_tokens: Dict[str, Dict] = {}


# ============================================
# Pydantic Models
# ============================================

class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=6, max_length=128)


class RegisterRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)
    first_name: str = Field(min_length=1, max_length=100, alias="firstName")
    last_name: str = Field(min_length=1, max_length=100, alias="lastName")
    invitation_code: Optional[str] = Field(default=None, alias="invitationCode")

    model_config = ConfigDict(populate_by_name=True)


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(alias="refreshToken")

    model_config = ConfigDict(populate_by_name=True)


class JoinTeamRequest(BaseModel):
    invitation_code: str = Field(alias="invitationCode")

    model_config = ConfigDict(populate_by_name=True)


class UpdateStatusRequest(BaseModel):
    status: str = Field(pattern="^(FIT|SLIGHTLY_INJURED|INJURED|UNAVAILABLE)$")
    note: Optional[str] = Field(default=None, max_length=500)
    valid_until: Optional[str] = Field(default=None, alias="validUntil")
    available_from: Optional[str] = Field(default=None, alias="availableFrom")

    model_config = ConfigDict(populate_by_name=True)


class UpdateProfileRequest(BaseModel):
    first_name: Optional[str] = Field(default=None, max_length=100, alias="firstName")
    last_name: Optional[str] = Field(default=None, max_length=100, alias="lastName")
    position: Optional[str] = None
    jersey_number: Optional[int] = Field(default=None, ge=1, le=99, alias="jerseyNumber")
    preferred_foot: Optional[str] = Field(default=None, alias="preferredFoot")
    phone: Optional[str] = Field(default=None, alias="phone")

    model_config = ConfigDict(populate_by_name=True)


class AttendanceUpdateRequest(BaseModel):
    event_id: Optional[str] = Field(default=None, alias="eventId")
    status: str
    note: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


# ============================================
# Auth Helper Functions
# ============================================

def _to_iso8601(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat() + "Z"


def _combine_date_time(date_value: Optional[str], time_value: Optional[str]) -> Optional[datetime]:
    if not date_value:
        return None
    try:
        base_date = datetime.strptime(date_value, "%Y-%m-%d").date()
    except ValueError:
        return None
    if not time_value:
        return datetime.combine(base_date, datetime.min.time())
    for fmt in ("%H:%M:%S", "%H:%M"):
        try:
            base_time = datetime.strptime(time_value, fmt).time()
            return datetime.combine(base_date, base_time)
        except ValueError:
            continue
    return datetime.combine(base_date, datetime.min.time())


def _parse_iso_date(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    trimmed = value.replace("Z", "")
    try:
        parsed = datetime.fromisoformat(trimmed)
        return parsed.date().isoformat()
    except ValueError:
        return None


def _map_player_status_to_api(db_value: Optional[str]) -> str:
    mapping = {
        "Fit": "FIT",
        "Belastet": "SLIGHTLY_INJURED",
        "Angeschlagen": "SLIGHTLY_INJURED",
        "Verletzt": "INJURED",
        "Reha": "UNAVAILABLE",
        "Ausfall": "UNAVAILABLE",
    }
    return mapping.get((db_value or "").strip(), "FIT")


def _map_player_status_from_api(api_value: Optional[str]) -> str:
    value = (api_value or "").strip().upper()
    mapping = {
        "FIT": "Fit",
        "SLIGHTLY_INJURED": "Angeschlagen",
        "INJURED": "Verletzt",
        "UNAVAILABLE": "Ausfall",
    }
    return mapping.get(value, "Fit")


def _map_preferred_foot_to_api(db_value: Optional[str]) -> Optional[str]:
    value = (db_value or "").strip().lower()
    if value == "rechts":
        return "RIGHT"
    if value == "links":
        return "LEFT"
    if value in ("beidfuessig", "beidfüssig", "beidfüßig", "beidfuessig"):
        return "BOTH"
    return None


def _map_preferred_foot_from_api(api_value: Optional[str]) -> Optional[str]:
    value = (api_value or "").strip().upper()
    if value == "RIGHT":
        return "rechts"
    if value == "LEFT":
        return "links"
    if value == "BOTH":
        return "beidfuessig"
    return None


def _map_position_to_api(db_value: Optional[str]) -> Optional[str]:
    value = (db_value or "").strip().upper()
    if value in ("TORWART", "GOALKEEPER", "GK", "TW"):
        return "GOALKEEPER"
    if value in ("VERTEIDIGER", "DEFENDER", "DF", "DEFENCE", "DEFENSE"):
        return "DEFENDER"
    if value in ("MITTELFELD", "MIDFIELDER", "MF", "MIDFIELD"):
        return "MIDFIELDER"
    if value in ("STUERMER", "STÜRMER", "FORWARD", "FW", "STRIKER"):
        return "FORWARD"
    return None


def _map_position_from_api(api_value: Optional[str]) -> Optional[str]:
    value = (api_value or "").strip().upper()
    if value == "GOALKEEPER":
        return "Torwart"
    if value == "DEFENDER":
        return "Verteidiger"
    if value == "MIDFIELDER":
        return "Mittelfeld"
    if value == "FORWARD":
        return "Stürmer"
    return None


def _map_event_type_to_api(db_value: Optional[str]) -> str:
    value = (db_value or "").strip().lower()
    mapping = {
        "training": "TRAINING",
        "match": "MATCH",
        "meeting": "MEETING",
        "other": "OTHER",
    }
    return mapping.get(value, "OTHER")


def _map_rsvp_to_attendance(db_value: Optional[str]) -> str:
    value = (db_value or "").strip().lower()
    mapping = {
        "yes": "CONFIRMED",
        "no": "DECLINED",
        "maybe": "MAYBE",
    }
    return mapping.get(value, "PENDING")


def _map_attendance_to_rsvp(api_value: Optional[str]) -> Optional[str]:
    value = (api_value or "").strip().upper()
    mapping = {
        "CONFIRMED": "yes",
        "DECLINED": "no",
        "MAYBE": "maybe",
    }
    return mapping.get(value)


def _get_primary_team_id(user_id: int) -> Optional[int]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT team_id
            FROM team_members
            WHERE user_id = ?
            ORDER BY joined_at ASC
            LIMIT 1
        """, (user_id,))
        row = cursor.fetchone()
    return row["team_id"] if row else None


def _get_player_row(user_id: int, team_id: Optional[int]) -> Optional[Dict[str, Any]]:
    if not team_id:
        return None
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, position, trikotnummer, status, telefon, geburtsdatum, updated_at
            FROM players
            WHERE user_id = ? AND team_id = ? AND deleted_at IS NULL
            LIMIT 1
        """, (user_id, team_id))
        row = cursor.fetchone()
    return dict(row) if row else None


def _event_row_to_api(row: Dict[str, Any]) -> Dict[str, Any]:
    start_dt = _combine_date_time(row.get("event_date"), row.get("start_time"))
    end_dt = _combine_date_time(row.get("event_date"), row.get("end_time")) if row.get("end_time") else None
    created_at = _parse_db_datetime(row.get("created_at"))
    updated_at = _parse_db_datetime(row.get("updated_at")) if row.get("updated_at") else created_at

    return {
        "id": str(row["id"]),
        "teamId": str(row["team_id"]),
        "teamName": row.get("team_name"),
        "type": _map_event_type_to_api(row.get("event_type")),
        "title": row.get("title") or "",
        "description": row.get("description") or "",
        "startDate": _to_iso8601(start_dt) if start_dt else None,
        "endDate": _to_iso8601(end_dt) if end_dt else None,
        "location": {
            "name": row.get("location") or "",
            "address": None
        } if row.get("location") else None,
        "meetingPoint": None,
        "meetingTime": None,
        "attendanceStatus": _map_rsvp_to_attendance(row.get("rsvp_status")),
        "attendanceNote": None,
        "isRequired": True,
        "createdAt": _to_iso8601(created_at),
        "updatedAt": _to_iso8601(updated_at)
    }

def generate_tokens(user_id: int) -> Dict[str, Any]:
    """Generate access and refresh tokens."""
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(48)

    expires_at = datetime.utcnow() + timedelta(hours=24)
    refresh_expires_at = datetime.utcnow() + timedelta(days=30)

    active_tokens[access_token] = {
        "user_id": user_id,
        "expires_at": expires_at,
        "refresh_token": refresh_token,
        "refresh_expires_at": refresh_expires_at
    }

    return {
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresIn": 86400,  # 24 hours in seconds
        "tokenType": "Bearer"
    }


def verify_token(authorization: Optional[str]) -> int:
    """Verify Bearer token and return user_id."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="Missing or invalid authorization header")

    token = authorization[7:]  # Remove "Bearer " prefix

    token_data = active_tokens.get(token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if datetime.utcnow() > token_data["expires_at"]:
        del active_tokens[token]
        raise HTTPException(status_code=401, detail="Token expired")

    return token_data["user_id"]


def get_current_user(authorization: str = Header(None)) -> Dict[str, Any]:
    """Dependency to get current authenticated user."""
    user_id = verify_token(authorization)

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return dict(user)


def user_to_json(
    user: Dict,
    include_private: bool = False,
    player_row: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Convert database user to JSON response."""
    preferred_foot = _map_preferred_foot_to_api(user.get("starker_fuss"))
    position = None
    jersey_number = None

    if player_row:
        position = _map_position_to_api(player_row.get("position"))
        jersey_number = player_row.get("trikotnummer")

    if not position:
        position = _map_position_to_api(user.get("position"))

    data = {
        "id": str(user["id"]),
        "email": user["email"],
        "firstName": user.get("vorname", ""),
        "lastName": user.get("nachname", ""),
        "displayName": f"{user.get('vorname', '')} {user.get('nachname', '')}".strip(),
        "avatarURL": None,  # TODO: Implement avatar support
        "createdAt": user.get("created_at", ""),
        "updatedAt": user.get("updated_at", ""),
        "phoneNumber": user.get("telefon"),
        "birthDate": user.get("geburtsdatum"),
        "position": position,
        "jerseyNumber": jersey_number,
        "preferredFoot": preferred_foot,
    }

    if include_private:
        # TODO: Implement email verification check
        data["emailVerified"] = True

    return data


def get_user_teams(user_id: int) -> List[Dict[str, Any]]:
    """Get all teams for a user."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, t.name, t.verein, t.mannschaft,
                   r.name as role_name, tm.joined_at
            FROM team_members tm
            JOIN teams t ON tm.team_id = t.id
            JOIN roles r ON tm.role_id = r.id
            WHERE tm.user_id = ? AND t.deleted_at IS NULL AND t.is_active = 1
            ORDER BY tm.joined_at ASC
        """, (user_id,))

        teams = []
        for row in cursor.fetchall():
            teams.append({
                "id": str(row["id"]),
                "name": row["name"],
                "clubName": row["verein"] or row["name"],
                "teamName": row["mannschaft"] or "",
                "logoURL": None,
                "memberCount": get_team_member_count(row["id"]),
                "myRole": row["role_name"],
                "joinedAt": row["joined_at"]
            })

        return teams


def get_team_member_count(team_id: int) -> int:
    """Get number of members in a team."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) as count FROM team_members WHERE team_id = ?
        """, (team_id,))
        return cursor.fetchone()["count"]


# ============================================
# Auth Endpoints
# ============================================

@router.post("/auth/register")
async def register(request: Request, data: RegisterRequest):
    """Register a new user account."""
    try:
        client_ip = get_client_ip(request)

        # Rate limiting (10 requests per minute)
        allowed, _ = api_rate_limiter.is_allowed(
            f"register:{client_ip}", max_requests=10, window_seconds=60)
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many requests")

        # Validate input
        try:
            InputValidator.validate_email(data.email)
            InputValidator.validate_name(
                data.first_name, field_name="Vorname", required=True)
            InputValidator.validate_name(
                data.last_name, field_name="Nachname", required=True)
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Check if email exists
        existing_user = get_user_by_email(data.email)
        if existing_user:
            raise HTTPException(
                status_code=409, detail="Email already registered")

        # Hash password
        password_hash = bcrypt.hashpw(
            data.password.encode(), bcrypt.gensalt()).decode()

        # Create user
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (email, password_hash, vorname, nachname, is_active)
                VALUES (?, ?, ?, ?, 1)
            """, (data.email.lower(), password_hash, data.first_name, data.last_name))
            conn.commit()
            user_id = cursor.lastrowid

        # Handle invitation code if provided
        if data.invitation_code:
            result = use_invitation(data.invitation_code, user_id)
            if not result.get("success"):
                logger.warning(
                    f"Invitation code failed for new user: {result.get('error')}")

        # Generate tokens
        tokens = generate_tokens(user_id)
        user = get_user_by_id(user_id)

        logger.info(f"New user registered via mobile API: user_id={user_id}")

        team_id = user.get("team_id") or _get_primary_team_id(user_id)
        player_row = _get_player_row(user_id, team_id)

        return JSONResponse({
            "user": user_to_json(dict(user), include_private=True, player_row=player_row),
            "tokens": tokens,
            "teams": get_user_teams(user_id)
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Registration failed: {str(e)}")


@router.post("/auth/login")
async def login(request: Request, data: LoginRequest):
    """Authenticate user and return tokens."""
    client_ip = get_client_ip(request)

    # Rate limiting (20 requests per minute)
    allowed, _ = api_rate_limiter.is_allowed(
        f"login:{client_ip}", max_requests=20, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many requests")

    # Check if blocked - is_login_blocked returns (is_blocked, remaining_seconds)
    is_blocked, remaining_seconds = is_login_blocked(data.email, client_ip)
    if is_blocked:
        raise HTTPException(
            status_code=429, detail=f"Too many failed attempts. Please try again in {remaining_seconds // 60} minutes.")

    # Find user
    user = get_user_by_email(data.email)
    if not user:
        record_login_attempt(data.email, client_ip, success=False)
        raise HTTPException(
            status_code=401, detail="Invalid email or password")

    # Verify password
    if not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
        record_login_attempt(data.email, client_ip, success=False)
        raise HTTPException(
            status_code=401, detail="Invalid email or password")

    # Check if user is active
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is deactivated")

    # Clear failed attempts and record success
    clear_login_attempts(data.email)
    record_login_attempt(data.email, client_ip, success=True)
    update_last_login(user["id"])

    # Generate tokens
    tokens = generate_tokens(user["id"])

    logger.info(f"User logged in via mobile API: user_id={user['id']}")

    team_id = user.get("team_id") or _get_primary_team_id(user["id"])
    player_row = _get_player_row(user["id"], team_id)

    return JSONResponse({
        "user": user_to_json(dict(user), include_private=True, player_row=player_row),
        "tokens": tokens,
        "teams": get_user_teams(user["id"])
    })


@router.post("/auth/refresh")
async def refresh_token(data: RefreshTokenRequest):
    """Refresh access token using refresh token."""
    # Find token by refresh token
    for access_token, token_data in list(active_tokens.items()):
        if token_data.get("refresh_token") == data.refresh_token:
            if datetime.utcnow() > token_data.get("refresh_expires_at", datetime.min):
                del active_tokens[access_token]
                raise HTTPException(
                    status_code=401, detail="Refresh token expired")

            # Generate new tokens
            user_id = token_data["user_id"]
            del active_tokens[access_token]

            new_tokens = generate_tokens(user_id)
            user = get_user_by_id(user_id)

            return JSONResponse({
                "user": user_to_json(dict(user), include_private=True),
                "tokens": new_tokens
            })

    raise HTTPException(status_code=401, detail="Invalid refresh token")


@router.post("/auth/logout")
async def logout(authorization: str = Header(None)):
    """Logout and invalidate tokens."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        if token in active_tokens:
            del active_tokens[token]

    return JSONResponse({"success": True})


@router.get("/auth/me")
async def get_me(user: Dict = Depends(get_current_user)):
    """Get current user info."""
    team_id = user.get("team_id") or _get_primary_team_id(user["id"])
    player_row = _get_player_row(user["id"], team_id)

    return JSONResponse({
        "user": user_to_json(user, include_private=True, player_row=player_row),
        "teams": get_user_teams(user["id"])
    })


# ============================================
# Teams Endpoints
# ============================================

@router.get("/teams")
async def get_teams(user: Dict = Depends(get_current_user)):
    """Get all teams for current user."""
    return JSONResponse(get_user_teams(user["id"]))


@router.post("/teams/join")
async def join_team(data: JoinTeamRequest, user: Dict = Depends(get_current_user)):
    """Join a team using invitation code."""
    result = use_invitation(data.invitation_code, user["id"])

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get(
            "error", "Invalid invitation code"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, t.name, t.verein, t.mannschaft, tm.joined_at
            FROM team_members tm
            JOIN teams t ON tm.team_id = t.id
            WHERE tm.user_id = ?
            ORDER BY tm.joined_at DESC
            LIMIT 1
        """, (user["id"],))
        team_row = cursor.fetchone()

    team = None
    if team_row:
        team = {
            "id": str(team_row["id"]),
            "name": team_row["name"],
            "clubName": team_row["verein"] or team_row["name"],
            "shortName": team_row["mannschaft"] or None,
            "memberCount": get_team_member_count(team_row["id"]),
            "role": "PLAYER"
        }

    return JSONResponse({
        "success": True,
        "team": team,
        "membership": None,
        "message": None
    })


@router.get("/teams/{team_id}")
async def get_team(team_id: str, user: Dict = Depends(get_current_user)):
    """Get team details."""
    if not verify_user_team_access(user["id"], int(team_id)):
        raise HTTPException(status_code=403, detail="Access denied")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, verein, mannschaft, created_at
            FROM teams WHERE id = ? AND deleted_at IS NULL
        """, (int(team_id),))
        team = cursor.fetchone()

        if not team:
            raise HTTPException(status_code=404, detail="Team not found")

        return JSONResponse({
            "id": str(team["id"]),
            "name": team["name"],
            "clubName": team["verein"] or team["name"],
            "shortName": team["mannschaft"] or None,
            "memberCount": get_team_member_count(team["id"]),
            "createdAt": team["created_at"]
        })


# ============================================
# Events/Calendar Endpoints
# ============================================

@router.get("/teams/{team_id}/events")
async def get_team_events(
    team_id: str,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    user: Dict = Depends(get_current_user)
):
    """Get calendar events for a team."""
    if not verify_user_team_access(user["id"], int(team_id)):
        raise HTTPException(status_code=403, detail="Access denied")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        conditions = ["e.team_id = ?", "e.deleted_at IS NULL"]
        params: List[Any] = [user["id"], int(team_id)]

        if from_date:
            conditions.append("e.event_date >= ?")
            params.append(from_date[:10])
        if to_date:
            conditions.append("e.event_date <= ?")
            params.append(to_date[:10])

        where_clause = " AND ".join(conditions)
        cursor.execute(f"""
            SELECT e.id, e.title, e.description, e.event_type, e.event_date,
                   e.start_time, e.end_time, e.location, e.created_at, e.updated_at,
                   e.team_id, t.name as team_name, r.status as rsvp_status
            FROM calendar_events e
            JOIN teams t ON e.team_id = t.id
            LEFT JOIN event_rsvps r ON r.event_id = e.id AND r.user_id = ?
            WHERE {where_clause}
            ORDER BY e.event_date ASC, e.start_time ASC
            LIMIT 200
        """, params)

        events = [_event_row_to_api(dict(row)) for row in cursor.fetchall()]

        return JSONResponse(events)


@router.get("/events/upcoming")
async def get_upcoming_events(user: Dict = Depends(get_current_user)):
    """Get upcoming events across all user's teams."""
    teams = get_user_teams(user["id"])
    team_ids = [int(t["id"]) for t in teams]

    if not team_ids:
        return JSONResponse([])

    with get_db_connection() as conn:
        cursor = conn.cursor()
        placeholders = ",".join("?" * len(team_ids))
        cursor.execute(f"""
            SELECT e.id, e.title, e.description, e.event_type, e.event_date,
                   e.start_time, e.end_time, e.location, e.created_at, e.updated_at,
                   e.team_id, t.name as team_name, r.status as rsvp_status
            FROM calendar_events e
            JOIN teams t ON e.team_id = t.id
            LEFT JOIN event_rsvps r ON r.event_id = e.id AND r.user_id = ?
            WHERE e.team_id IN ({placeholders})
              AND e.deleted_at IS NULL
              AND e.event_date >= date('now')
            ORDER BY e.event_date ASC, e.start_time ASC
            LIMIT 50
        """, [user["id"], *team_ids])

        events = [_event_row_to_api(dict(row)) for row in cursor.fetchall()]

        return JSONResponse(events)


@router.put("/events/{event_id}/attendance")
async def update_event_attendance(
    event_id: str,
    data: AttendanceUpdateRequest,
    user: Dict = Depends(get_current_user)
):
    """Update attendance for an event."""
    if data.event_id and str(data.event_id) != str(event_id):
        raise HTTPException(status_code=400, detail="Event ID mismatch")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, team_id, visibility
            FROM calendar_events
            WHERE id = ? AND deleted_at IS NULL
        """, (int(event_id),))
        event_row = cursor.fetchone()

        if not event_row:
            raise HTTPException(status_code=404, detail="Event not found")

        if not verify_user_team_access(user["id"], int(event_row["team_id"])):
            raise HTTPException(status_code=403, detail="Access denied")

        rsvp_status = _map_attendance_to_rsvp(data.status)
        if rsvp_status is None:
            cursor.execute("""
                DELETE FROM event_rsvps WHERE event_id = ? AND user_id = ?
            """, (int(event_id), user["id"]))
        else:
            cursor.execute("""
                INSERT INTO event_rsvps (event_id, user_id, status)
                VALUES (?, ?, ?)
                ON CONFLICT(event_id, user_id)
                DO UPDATE SET status = excluded.status, updated_at = CURRENT_TIMESTAMP
            """, (int(event_id), user["id"], rsvp_status))
        conn.commit()

    return JSONResponse({})


@router.get("/teams/{team_id}/statistics")
async def get_team_statistics(
    team_id: str,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    user: Dict = Depends(get_current_user)
):
    """Get player statistics for a team."""
    if not verify_user_team_access(user["id"], int(team_id)):
        raise HTTPException(status_code=403, detail="Access denied")

    start_date = _parse_iso_date(from_date) or (datetime.utcnow() - timedelta(days=28)).date().isoformat()
    end_date = _parse_iso_date(to_date) or datetime.utcnow().date().isoformat()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                SUM(CASE WHEN e.event_type = 'training' THEN 1 ELSE 0 END) as trainings_total,
                SUM(CASE WHEN e.event_type = 'match' THEN 1 ELSE 0 END) as matches_total,
                SUM(CASE WHEN e.event_type = 'training' AND r.status = 'yes' THEN 1 ELSE 0 END) as trainings_attended,
                SUM(CASE WHEN e.event_type = 'training' AND r.status = 'maybe' THEN 1 ELSE 0 END) as trainings_excused,
                SUM(CASE WHEN e.event_type = 'training' AND r.status = 'no' THEN 1 ELSE 0 END) as trainings_unexcused,
                SUM(CASE WHEN e.event_type = 'match' AND r.status = 'yes' THEN 1 ELSE 0 END) as matches_played
            FROM calendar_events e
            LEFT JOIN event_rsvps r ON r.event_id = e.id AND r.user_id = ?
            WHERE e.team_id = ?
              AND e.deleted_at IS NULL
              AND e.visibility = 'team'
              AND e.event_date BETWEEN ? AND ?
        """, (user["id"], int(team_id), start_date, end_date))
        row = cursor.fetchone()

    stats = {
        "playerId": str(user["id"]),
        "teamId": str(team_id),
        "period": {
            "startDate": _to_iso8601(datetime.fromisoformat(start_date)),
            "endDate": _to_iso8601(datetime.fromisoformat(end_date)),
            "label": "Custom"
        },
        "trainingsTotal": row["trainings_total"] or 0,
        "trainingsAttended": row["trainings_attended"] or 0,
        "trainingsExcused": row["trainings_excused"] or 0,
        "trainingsUnexcused": row["trainings_unexcused"] or 0,
        "matchesTotal": row["matches_total"] or 0,
        "matchesPlayed": row["matches_played"] or 0,
        "matchesStarted": 0,
        "matchesBench": 0,
        "daysInjured": 0,
        "daysUnavailable": 0
    }

    return JSONResponse(stats)


# ============================================
# Player Profile Endpoints
# ============================================

def _parse_db_datetime(value: Optional[str]) -> datetime:
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return datetime.utcnow()


def _apply_profile_update(user_id: int, data: UpdateProfileRequest) -> Dict[str, Any]:
    db_user = get_user_by_id(user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    team_id = db_user.get("team_id") or _get_primary_team_id(user_id)
    user_updates = []
    user_params = []
    player_updates = []
    player_params = []

    if data.first_name:
        user_updates.append("vorname = ?")
        user_params.append(data.first_name)
    if data.last_name:
        user_updates.append("nachname = ?")
        user_params.append(data.last_name)
    if data.phone is not None:
        user_updates.append("telefon = ?")
        user_params.append(data.phone.strip()[:30])

    if data.preferred_foot:
        mapped = _map_preferred_foot_from_api(data.preferred_foot)
        if mapped:
            user_updates.append("starker_fuss = ?")
            user_params.append(mapped)

    if data.position:
        mapped = _map_position_from_api(data.position)
        if mapped:
            user_updates.append("position = ?")
            user_params.append(mapped)
            player_updates.append("position = ?")
            player_params.append(mapped)

    if data.jersey_number is not None:
        player_updates.append("trikotnummer = ?")
        player_params.append(data.jersey_number)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        if user_updates:
            user_params.append(user_id)
            cursor.execute(f"""
                UPDATE users SET {", ".join(user_updates)}, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, user_params)
        if team_id and player_updates:
            cursor.execute("""
                SELECT id FROM players
                WHERE user_id = ? AND team_id = ? AND deleted_at IS NULL
                LIMIT 1
            """, (user_id, team_id))
            player_row = cursor.fetchone()
            if player_row:
                player_params.extend([user_id, team_id])
                cursor.execute(f"""
                    UPDATE players SET {", ".join(player_updates)}, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ? AND team_id = ? AND deleted_at IS NULL
                """, player_params)
        conn.commit()

    updated_user = get_user_by_id(user_id)
    player_row = _get_player_row(user_id, team_id)
    return user_to_json(dict(updated_user), include_private=True, player_row=player_row)


@router.get("/user/me")
async def get_user_me(user: Dict = Depends(get_current_user)):
    """Get current user profile."""
    db_user = get_user_by_id(user["id"])
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    team_id = db_user.get("team_id") or _get_primary_team_id(user["id"])
    player_row = _get_player_row(user["id"], team_id)
    return JSONResponse(user_to_json(dict(db_user), include_private=True, player_row=player_row))


@router.patch("/user/me")
async def update_user_me(data: UpdateProfileRequest, user: Dict = Depends(get_current_user)):
    """Update current user profile."""
    updated_user = _apply_profile_update(user["id"], data)
    return JSONResponse(updated_user)


@router.get("/user/status")
async def get_user_status(user: Dict = Depends(get_current_user)):
    """Get current player's status."""
    db_user = get_user_by_id(user["id"])
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    team_id = db_user.get("team_id") or _get_primary_team_id(user["id"])
    player_row = _get_player_row(user["id"], team_id)
    status_value = _map_player_status_to_api(player_row.get("status") if player_row else None)
    updated_at = _parse_db_datetime(player_row.get("updated_at") if player_row else None)

    return JSONResponse({
        "status": status_value,
        "note": None,
        "updatedAt": _to_iso8601(updated_at),
        "validUntil": None
    })


@router.put("/user/status")
async def update_user_status(data: UpdateStatusRequest, user: Dict = Depends(get_current_user)):
    """Update current player's status."""
    db_user = get_user_by_id(user["id"])
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    team_id = db_user.get("team_id") or _get_primary_team_id(user["id"])
    if not team_id:
        raise HTTPException(status_code=400, detail="No team assigned")

    new_status = _map_player_status_from_api(data.status)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE players
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND team_id = ? AND deleted_at IS NULL
        """, (new_status, user["id"], team_id))
        conn.commit()

    updated_at = datetime.utcnow()
    valid_until = data.valid_until or data.available_from

    return JSONResponse({
        "status": data.status,
        "note": data.note,
        "updatedAt": _to_iso8601(updated_at),
        "validUntil": valid_until
    })


@router.get("/player/profile")
async def get_player_profile(user: Dict = Depends(get_current_user)):
    """Get current player's profile."""
    db_user = get_user_by_id(user["id"])
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    team_id = db_user.get("team_id") or _get_primary_team_id(user["id"])
    player_row = _get_player_row(user["id"], team_id)
    status_value = _map_player_status_to_api(player_row.get("status") if player_row else None)
    updated_at = _parse_db_datetime(player_row.get("updated_at") if player_row else None)

    return JSONResponse({
        "user": user_to_json(dict(db_user), include_private=True, player_row=player_row),
        "status": {
            "status": status_value,
            "note": None,
            "updatedAt": _to_iso8601(updated_at),
            "validUntil": None
        },
        "statistics": {
            "gamesPlayed": 0,
            "goalsScored": 0,
            "assists": 0,
            "yellowCards": 0,
            "redCards": 0,
            "minutesPlayed": 0
        }
    })


@router.put("/player/status")
async def update_player_status(data: UpdateStatusRequest, user: Dict = Depends(get_current_user)):
    """Update player availability status."""
    response = await update_user_status(data, user)
    return response


@router.put("/player/profile")
async def update_player_profile(data: UpdateProfileRequest, user: Dict = Depends(get_current_user)):
    """Update player profile."""
    updated_user = _apply_profile_update(user["id"], data)
    return JSONResponse({"user": updated_user})


# ============================================
# Announcements Endpoints
# ============================================

@router.get("/announcements")
async def get_announcements(user: Dict = Depends(get_current_user)):
    """Get announcements for user's teams."""
    teams = get_user_teams(user["id"])
    team_ids = [int(t["id"]) for t in teams]

    if not team_ids:
        return JSONResponse([])

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check if announcements table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='announcements'
        """)

        if not cursor.fetchone():
            return JSONResponse([])

        placeholders = ",".join("?" * len(team_ids))
        cursor.execute(f"""
            SELECT a.id, a.title, a.content, a.priority, a.team_id,
                   a.created_at, a.expires_at, t.name as team_name
            FROM announcements a
            JOIN teams t ON a.team_id = t.id
            WHERE a.team_id IN ({placeholders})
              AND (a.expires_at IS NULL OR a.expires_at > datetime('now'))
            ORDER BY a.created_at DESC
            LIMIT 50
        """, team_ids)

        announcements = []
        for row in cursor.fetchall():
            priority_value = (row["priority"] or "normal").upper()
            created_at = _to_iso8601(_parse_db_datetime(row["created_at"]))
            expires_at = _to_iso8601(_parse_db_datetime(row["expires_at"])) if row["expires_at"] else None
            announcements.append({
                "id": str(row["id"]),
                "teamId": str(row["team_id"]),
                "teamName": row["team_name"],
                "title": row["title"],
                "content": row["content"],
                "priority": priority_value,
                "category": "GENERAL",
                "authorName": None,
                "isRead": False,
                "createdAt": created_at,
                "expiresAt": expires_at
            })

        return JSONResponse(announcements)


@router.post("/announcements/{announcement_id}/read")
async def mark_announcement_read(announcement_id: str, user: Dict = Depends(get_current_user)):
    """Mark announcement as read (no-op for now)."""
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return JSONResponse({})


# ============================================
# Invitation Link Validation
# ============================================

@router.get("/invitations/{code}/validate")
async def validate_invitation(code: str):
    """Validate an invitation code without using it."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT i.id, i.team_id, i.expires_at, i.max_uses, i.uses, i.is_active,
                   t.name as team_name, t.verein, t.mannschaft
            FROM invitations i
            JOIN teams t ON i.team_id = t.id
            WHERE i.token = ? AND t.deleted_at IS NULL
        """, (code,))

        invitation = cursor.fetchone()

        if not invitation:
            raise HTTPException(
                status_code=404, detail="Invalid invitation code")

        if not invitation["is_active"]:
            raise HTTPException(
                status_code=410, detail="Invitation has been deactivated")

        if invitation["uses"] >= invitation["max_uses"]:
            raise HTTPException(
                status_code=410, detail="Invitation has reached maximum uses")

        if datetime.fromisoformat(invitation["expires_at"]) < datetime.utcnow():
            raise HTTPException(
                status_code=410, detail="Invitation has expired")

        return JSONResponse({
            "valid": True,
            "teamId": str(invitation["team_id"]),
            "teamName": invitation["team_name"],
            "clubName": invitation["verein"] or invitation["team_name"]
        })


# ============================================
# Health Check
# ============================================

@router.get("/health")
async def health_check():
    """API health check endpoint."""
    return JSONResponse({
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    })
