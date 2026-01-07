"""
Input Validation Module
=======================
Zentrale Validierung für alle Benutzereingaben.
SECURITY AUDIT: Alle Eingaben MÜSSEN hier validiert werden.
"""

import re
from typing import Optional, Tuple
from config import SecurityConfig


class ValidationError(Exception):
    """Custom Exception für Validierungsfehler."""

    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


class InputValidator:
    """
    Zentrale Input-Validierung mit Whitelist-Ansatz.
    SECURITY AUDIT: Niemals Benutzereingaben ohne Validierung verarbeiten.
    """

    # Regex-Patterns (Whitelists)
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    # Nur alphanumerisch, Leerzeichen, Bindestrich, Umlaute
    NAME_PATTERN = re.compile(r'^[a-zA-ZäöüÄÖÜß\s\-]{1,100}$')
    # Team/Verein: alphanumerisch, Leerzeichen, Bindestrich, Zahlen
    TEAM_PATTERN = re.compile(r'^[a-zA-Z0-9äöüÄÖÜß\s\-\.]{1,200}$')
    # Token: nur URL-safe Zeichen
    TOKEN_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{20,64}$')

    @classmethod
    def validate_email(cls, email: str) -> str:
        """
        Validiert und normalisiert eine E-Mail-Adresse.
        Gibt die normalisierte E-Mail zurück oder wirft ValidationError.
        """
        if not email or not isinstance(email, str):
            raise ValidationError("email", "E-Mail ist erforderlich")

        email = email.strip().lower()

        if len(email) > 254:
            raise ValidationError("email", "E-Mail ist zu lang")

        if not cls.EMAIL_PATTERN.match(email):
            raise ValidationError("email", "Ungültiges E-Mail-Format")

        return email

    @classmethod
    def validate_password(cls, password: str) -> str:
        """
        Validiert ein Passwort gegen die Sicherheitsrichtlinien.
        Gibt das Passwort zurück oder wirft ValidationError.
        """
        if not password or not isinstance(password, str):
            raise ValidationError("password", "Passwort ist erforderlich")

        if len(password) < SecurityConfig.PASSWORD_MIN_LENGTH:
            raise ValidationError(
                "password",
                f"Passwort muss mindestens {SecurityConfig.PASSWORD_MIN_LENGTH} Zeichen lang sein"
            )

        if len(password) > 128:
            raise ValidationError(
                "password", "Passwort ist zu lang (max. 128 Zeichen)")

        if SecurityConfig.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            raise ValidationError(
                "password", "Passwort muss mindestens einen Großbuchstaben enthalten")

        if SecurityConfig.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            raise ValidationError(
                "password", "Passwort muss mindestens einen Kleinbuchstaben enthalten")

        if SecurityConfig.PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
            raise ValidationError(
                "password", "Passwort muss mindestens eine Ziffer enthalten")

        if SecurityConfig.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError(
                "password", "Passwort muss mindestens ein Sonderzeichen enthalten")

        return password

    @classmethod
    def validate_name(cls, name: str, field_name: str = "name", required: bool = False) -> str:
        """
        Validiert einen Namen (Vorname, Nachname).
        """
        if not name or not isinstance(name, str):
            if required:
                raise ValidationError(
                    field_name, f"{field_name} ist erforderlich")
            return ""

        name = name.strip()

        if len(name) > 100:
            raise ValidationError(
                field_name, f"{field_name} ist zu lang (max. 100 Zeichen)")

        if name and not cls.NAME_PATTERN.match(name):
            raise ValidationError(
                field_name, f"Ungültiges Format für {field_name}")

        return name

    @classmethod
    def validate_team_name(cls, name: str, field_name: str = "team", required: bool = True) -> str:
        """
        Validiert Team-/Vereinsnamen.
        """
        if not name or not isinstance(name, str):
            if required:
                raise ValidationError(
                    field_name, f"{field_name} ist erforderlich")
            return ""

        name = name.strip()

        if len(name) > 200:
            raise ValidationError(
                field_name, f"{field_name} ist zu lang (max. 200 Zeichen)")

        if name and not cls.TEAM_PATTERN.match(name):
            raise ValidationError(
                field_name, f"Ungültiges Format für {field_name}")

        return name

    @classmethod
    def validate_rolle(cls, rolle: str, required: bool = False) -> str:
        """
        Validiert eine Rollen-Angabe.
        SECURITY: Whitelist-Check gegen erlaubte Rollen.
        """
        if not rolle or not isinstance(rolle, str):
            if required:
                raise ValidationError("rolle", "Rolle ist erforderlich")
            return ""

        rolle = rolle.strip()

        # Whitelist-Check
        allowed_roles = [
            "Trainer", "Co-Trainer", "Spieler", "Eltern", "Betreuer",
            "Physio", "Torwarttrainer", "Jugendleiter", "Vorstand", "Admin"
        ]

        if rolle and rolle not in allowed_roles:
            raise ValidationError("rolle", "Ungültige Rolle")

        return rolle

    @classmethod
    def validate_token(cls, token: str) -> str:
        """
        Validiert ein Token (Einladungs-Token etc.).
        """
        if not token or not isinstance(token, str):
            raise ValidationError("token", "Token ist erforderlich")

        token = token.strip()

        if not cls.TOKEN_PATTERN.match(token):
            raise ValidationError("token", "Ungültiges Token-Format")

        return token

    @classmethod
    def validate_positive_int(cls, value, field_name: str, max_value: int = 1000000) -> int:
        """
        Validiert einen positiven Integer.
        """
        try:
            int_value = int(value)
        except (TypeError, ValueError):
            raise ValidationError(
                field_name, f"{field_name} muss eine Zahl sein")

        if int_value < 0:
            raise ValidationError(
                field_name, f"{field_name} muss positiv sein")

        if int_value > max_value:
            raise ValidationError(field_name, f"{field_name} ist zu groß")

        return int_value

    @classmethod
    def sanitize_for_log(cls, value: str, max_length: int = 50) -> str:
        """
        Bereinigt einen Wert für Logging (entfernt sensible Daten).
        SECURITY AUDIT: Niemals Passwörter oder Tokens loggen.
        """
        if not value:
            return "[leer]"
        # Kürzen und nur sichere Zeichen behalten
        safe = re.sub(r'[^\w\s@.\-]', '', str(value))
        if len(safe) > max_length:
            return safe[:max_length] + "..."
        return safe
