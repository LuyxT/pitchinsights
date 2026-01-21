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
    status: str = Field(pattern="^(available|limited|injured|sick|absent)$")
    note: Optional[str] = Field(default=None, max_length=500)
    available_from: Optional[str] = Field(default=None, alias="availableFrom")

    model_config = ConfigDict(populate_by_name=True)


class UpdateProfileRequest(BaseModel):
    first_name: Optional[str] = Field(default=None, max_length=100, alias="firstName")
    last_name: Optional[str] = Field(default=None, max_length=100, alias="lastName")
    position: Optional[str] = None
    jersey_number: Optional[int] = Field(default=None, ge=1, le=99, alias="jerseyNumber")

    model_config = ConfigDict(populate_by_name=True)


# ============================================
# Auth Helper Functions
# ============================================

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


def user_to_json(user: Dict, include_private: bool = False) -> Dict[str, Any]:
    """Convert database user to JSON response."""
    data = {
        "id": str(user["id"]),
        "email": user["email"],
        "firstName": user.get("vorname", ""),
        "lastName": user.get("nachname", ""),
        "displayName": f"{user.get('vorname', '')} {user.get('nachname', '')}".strip(),
        "avatarURL": None,  # TODO: Implement avatar support
        "createdAt": user.get("created_at", ""),
    }

    if include_private:
        # TODO: Implement email verification check
        data["emailVerified"] = True
        data["phoneNumber"] = None

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

        return JSONResponse({
            "user": user_to_json(dict(user), include_private=True),
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

    return JSONResponse({
        "user": user_to_json(dict(user), include_private=True),
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
    return JSONResponse({
        "user": user_to_json(user, include_private=True),
        "teams": get_user_teams(user["id"])
    })


# ============================================
# Teams Endpoints
# ============================================

@router.get("/teams")
async def get_teams(user: Dict = Depends(get_current_user)):
    """Get all teams for current user."""
    return JSONResponse({
        "teams": get_user_teams(user["id"])
    })


@router.post("/teams/join")
async def join_team(data: JoinTeamRequest, user: Dict = Depends(get_current_user)):
    """Join a team using invitation code."""
    result = use_invitation(data.invitation_code, user["id"])

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get(
            "error", "Invalid invitation code"))

    return JSONResponse({
        "success": True,
        "teams": get_user_teams(user["id"])
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
            "teamName": team["mannschaft"] or "",
            "memberCount": get_team_member_count(team["id"]),
            "createdAt": team["created_at"]
        })


# ============================================
# Events/Calendar Endpoints
# ============================================

@router.get("/teams/{team_id}/events")
async def get_team_events(team_id: str, user: Dict = Depends(get_current_user)):
    """Get calendar events for a team."""
    if not verify_user_team_access(user["id"], int(team_id)):
        raise HTTPException(status_code=403, detail="Access denied")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, title, description, event_type, event_date, 
                   start_time, end_time, location, created_at
            FROM calendar_events 
            WHERE team_id = ? AND event_date >= date('now', '-7 days')
            ORDER BY event_date ASC, start_time ASC
            LIMIT 50
        """, (int(team_id),))

        events = []
        for row in cursor.fetchall():
            events.append({
                "id": str(row["id"]),
                "title": row["title"],
                "description": row["description"] or "",
                "type": row["event_type"],
                "date": row["event_date"],
                "startTime": row["start_time"],
                "endTime": row["end_time"],
                "location": {
                    "name": row["location"] or "",
                    "address": None
                } if row["location"] else None,
                "teamId": team_id
            })

        return JSONResponse({"events": events})


@router.get("/events/upcoming")
async def get_upcoming_events(user: Dict = Depends(get_current_user)):
    """Get upcoming events across all user's teams."""
    teams = get_user_teams(user["id"])
    team_ids = [int(t["id"]) for t in teams]

    if not team_ids:
        return JSONResponse({"events": []})

    with get_db_connection() as conn:
        cursor = conn.cursor()
        placeholders = ",".join("?" * len(team_ids))
        cursor.execute(f"""
            SELECT e.id, e.title, e.description, e.event_type, e.event_date,
                   e.start_time, e.end_time, e.location, e.team_id, t.name as team_name
            FROM calendar_events e
            JOIN teams t ON e.team_id = t.id
            WHERE e.team_id IN ({placeholders}) AND e.event_date >= date('now')
            ORDER BY e.event_date ASC, e.start_time ASC
            LIMIT 20
        """, team_ids)

        events = []
        for row in cursor.fetchall():
            events.append({
                "id": str(row["id"]),
                "title": row["title"],
                "description": row["description"] or "",
                "type": row["event_type"],
                "date": row["event_date"],
                "startTime": row["start_time"],
                "endTime": row["end_time"],
                "location": {
                    "name": row["location"] or "",
                    "address": None
                } if row["location"] else None,
                "teamId": str(row["team_id"]),
                "teamName": row["team_name"]
            })

        return JSONResponse({"events": events})


# ============================================
# Player Profile Endpoints
# ============================================

@router.get("/player/profile")
async def get_player_profile(user: Dict = Depends(get_current_user)):
    """Get current player's profile."""
    return JSONResponse({
        "user": user_to_json(user, include_private=True),
        "status": {
            "current": "available",
            "note": None,
            "updatedAt": None
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
    # TODO: Store status in database
    logger.info(
        f"Player status updated: user_id={user['id']}, status={data.status}")

    return JSONResponse({
        "status": {
            "current": data.status,
            "note": data.note,
            "availableFrom": data.available_from,
            "updatedAt": datetime.utcnow().isoformat()
        }
    })


@router.put("/player/profile")
async def update_player_profile(data: UpdateProfileRequest, user: Dict = Depends(get_current_user)):
    """Update player profile."""
    updates = []
    params = []

    if data.first_name:
        updates.append("vorname = ?")
        params.append(data.first_name)
    if data.last_name:
        updates.append("nachname = ?")
        params.append(data.last_name)

    if updates:
        params.append(user["id"])
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE users SET {", ".join(updates)}, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, params)
            conn.commit()

    updated_user = get_user_by_id(user["id"])
    return JSONResponse({
        "user": user_to_json(dict(updated_user), include_private=True)
    })


# ============================================
# Announcements Endpoints
# ============================================

@router.get("/announcements")
async def get_announcements(user: Dict = Depends(get_current_user)):
    """Get announcements for user's teams."""
    teams = get_user_teams(user["id"])
    team_ids = [int(t["id"]) for t in teams]

    if not team_ids:
        return JSONResponse({"announcements": []})

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check if announcements table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='announcements'
        """)

        if not cursor.fetchone():
            return JSONResponse({"announcements": []})

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
            announcements.append({
                "id": str(row["id"]),
                "title": row["title"],
                "content": row["content"],
                "priority": row["priority"] or "normal",
                "teamId": str(row["team_id"]),
                "teamName": row["team_name"],
                "createdAt": row["created_at"],
                "expiresAt": row["expires_at"],
                "isRead": False  # TODO: Track read status
            })

        return JSONResponse({"announcements": announcements})


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
