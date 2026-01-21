"""
Email Service Module
====================
Sicherer E-Mail-Versand für Login-Benachrichtigungen und 2FA-Codes.
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

logger = logging.getLogger("pitchinsights.email")


class EmailConfig:
    """E-Mail-Konfiguration aus Umgebungsvariablen."""
    SMTP_HOST: str = os.environ.get("PITCHINSIGHTS_SMTP_HOST", "")
    SMTP_PORT: int = int(os.environ.get("PITCHINSIGHTS_SMTP_PORT", "587"))
    SMTP_USER: str = os.environ.get("PITCHINSIGHTS_SMTP_USER", "")
    SMTP_PASSWORD: str = os.environ.get("PITCHINSIGHTS_SMTP_PASSWORD", "")
    FROM_EMAIL: str = os.environ.get(
        "PITCHINSIGHTS_FROM_EMAIL", "noreply@pitchinsights.de")
    FROM_NAME: str = "PitchInsights"

    @classmethod
    def is_configured(cls) -> bool:
        return bool(cls.SMTP_HOST and cls.SMTP_USER and cls.SMTP_PASSWORD)


def send_email(to_email: str, subject: str, html_body: str, text_body: Optional[str] = None) -> bool:
    """
    Sendet eine E-Mail sicher.
    SECURITY: TLS/SSL wird erzwungen.
    """
    if not EmailConfig.is_configured():
        logger.warning(
            "E-Mail nicht konfiguriert - E-Mail wird nicht gesendet")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{EmailConfig.FROM_NAME} <{EmailConfig.FROM_EMAIL}>"
        msg["To"] = to_email

        # Text-Version als Fallback
        if text_body:
            msg.attach(MIMEText(text_body, "plain", "utf-8"))

        # HTML-Version
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        # SMTP-Verbindung mit TLS
        with smtplib.SMTP(EmailConfig.SMTP_HOST, EmailConfig.SMTP_PORT) as server:
            server.starttls()
            server.login(EmailConfig.SMTP_USER, EmailConfig.SMTP_PASSWORD)
            server.send_message(msg)

        logger.info(f"E-Mail gesendet an {to_email[:3]}***")
        return True

    except Exception as e:
        logger.error(f"E-Mail-Fehler: {type(e).__name__}")
        return False


def send_login_notification(email: str, ip_address: str, user_agent: str, location: str = "Unbekannt") -> bool:
    """
    Sendet eine Benachrichtigung bei neuem Login.
    SECURITY: Warnt User bei verdächtigen Logins.
    """
    now = datetime.now().strftime("%d.%m.%Y um %H:%M Uhr")

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 12px 12px 0 0; }}
            .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 12px 12px; }}
            .info-box {{ background: white; padding: 15px; border-radius: 8px; margin: 15px 0; }}
            .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
            .footer {{ text-align: center; color: #6c757d; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Neuer Login bei PitchInsights</h1>
            </div>
            <div class="content">
                <p>Hallo,</p>
                <p>Es gab soeben einen erfolgreichen Login in deinem PitchInsights-Konto:</p>
                
                <div class="info-box">
                    <p><strong>📅 Zeitpunkt:</strong> {now}</p>
                    <p><strong>🌍 IP-Adresse:</strong> {ip_address}</p>
                    <p><strong>💻 Gerät:</strong> {user_agent[:50]}...</p>
                </div>
                
                <div class="warning">
                    <strong>⚠️ Das warst nicht du?</strong><br>
                    Wenn du diesen Login nicht selbst durchgeführt hast, ändere sofort dein Passwort 
                    und aktiviere die Zwei-Faktor-Authentifizierung in deinen Kontoeinstellungen.
                </div>
                
                <div class="footer">
                    <p>Diese E-Mail wurde automatisch von PitchInsights gesendet.</p>
                    <p>© 2026 PitchInsights - Teammanagement für Fußballvereine</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

    text_body = f"""
    Neuer Login bei PitchInsights
    
    Zeitpunkt: {now}
    IP-Adresse: {ip_address}
    Gerät: {user_agent[:50]}
    
    Das warst nicht du? Ändere sofort dein Passwort!
    """

    return send_email(email, "🔐 Neuer Login bei PitchInsights", html_body, text_body)


def send_2fa_code(email: str, code: str) -> bool:
    """
    Sendet einen 2FA-Code per E-Mail.
    SECURITY: Code ist nur 5 Minuten gültig.
    """
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 12px 12px 0 0; text-align: center; }}
            .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 12px 12px; text-align: center; }}
            .code-box {{ background: white; padding: 30px; border-radius: 12px; margin: 20px 0; }}
            .code {{ font-size: 48px; font-weight: bold; color: #667eea; letter-spacing: 8px; font-family: monospace; }}
            .expire {{ color: #dc3545; font-size: 14px; margin-top: 10px; }}
            .footer {{ color: #6c757d; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔑 Dein Bestätigungscode</h1>
            </div>
            <div class="content">
                <p>Verwende diesen Code, um dich bei PitchInsights anzumelden:</p>
                
                <div class="code-box">
                    <div class="code">{code}</div>
                    <div class="expire">⏱️ Gültig für 5 Minuten</div>
                </div>
                
                <p>Wenn du diesen Code nicht angefordert hast, ignoriere diese E-Mail.</p>
                
                <div class="footer">
                    <p>Diese E-Mail wurde automatisch von PitchInsights gesendet.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

    text_body = f"""
    Dein PitchInsights Bestätigungscode: {code}
    
    Gültig für 5 Minuten.
    
    Wenn du diesen Code nicht angefordert hast, ignoriere diese E-Mail.
    """

    return send_email(email, f"🔑 Dein Code: {code}", html_body, text_body)


def send_password_changed_notification(email: str) -> bool:
    """
    Benachrichtigt User über Passwortänderung.
    SECURITY: Frühzeitige Warnung bei Account-Kompromittierung.
    """
    now = datetime.now().strftime("%d.%m.%Y um %H:%M Uhr")

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 30px; border-radius: 12px 12px 0 0; }}
            .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 12px 12px; }}
            .warning {{ background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 20px 0; }}
            .footer {{ text-align: center; color: #6c757d; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>✅ Passwort geändert</h1>
            </div>
            <div class="content">
                <p>Hallo,</p>
                <p>Dein PitchInsights-Passwort wurde am <strong>{now}</strong> erfolgreich geändert.</p>
                
                <div class="warning">
                    <strong>⚠️ Das warst nicht du?</strong><br>
                    Kontaktiere uns sofort unter info@pitchinsights.de
                </div>
                
                <div class="footer">
                    <p>© 2026 PitchInsights</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

    return send_email(email, "✅ Dein Passwort wurde geändert", html_body)


def send_2fa_enabled_notification(email: str) -> bool:
    """
    Bestätigt 2FA-Aktivierung per E-Mail.
    """
    html_body = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 30px; border-radius: 12px 12px 0 0; text-align: center; }
            .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 12px 12px; }
            .success { background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ 2FA aktiviert</h1>
            </div>
            <div class="content">
                <div class="success">
                    <strong>✅ Zwei-Faktor-Authentifizierung wurde erfolgreich aktiviert!</strong><br><br>
                    Dein Konto ist jetzt besser geschützt. Bei jedem Login benötigst du zusätzlich 
                    zum Passwort einen Code aus deiner Authenticator-App.
                </div>
                <p><strong>Wichtig:</strong> Bewahre deine Backup-Codes sicher auf!</p>
            </div>
        </div>
    </body>
    </html>
    """

    return send_email(email, "🛡️ 2FA wurde aktiviert", html_body)

