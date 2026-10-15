"""Envío de correos electrónicos con ``smtplib`` (librería estándar)."""

import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.config import settings

logger = logging.getLogger(__name__)


def mask_email(email: str) -> str:
    """Oculta parte del correo para mostrarlo en respuestas: ``ana@x.com`` -> ``a**@x.com``."""
    local, _, domain = email.partition("@")
    visible = local[0] if local else ""
    return f"{visible}{'*' * max(len(local) - 1, 2)}@{domain}"


def build_otp_message(to_email: str, full_name: str, code: str) -> EmailMessage:
    """Construye el correo (texto plano + HTML) con el código OTP."""
    minutes = settings.otp_expire_minutes
    msg = EmailMessage()
    msg["Subject"] = f"Tu código de verificación: {code}"
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = to_email
    msg.set_content(
        f"Hola {full_name},\n\n"
        f"Tu código de verificación es: {code}\n\n"
        f"Es válido durante {minutes} minutos y solo puede usarse una vez.\n"
        "Si no intentaste iniciar sesión, ignora este mensaje.\n"
    )
    msg.add_alternative(
        f"""\
<html>
  <body style="font-family: Arial, sans-serif;">
    <p>Hola {full_name},</p>
    <p>Tu código de verificación es:</p>
    <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px;">{code}</p>
    <p>Es válido durante {minutes} minutos y solo puede usarse una vez.</p>
    <p style="color: #777;">Si no intentaste iniciar sesión, ignora este mensaje.</p>
  </body>
</html>
""",
        subtype="html",
    )
    return msg


def send_email(msg: EmailMessage) -> None:
    """Envía un mensaje por SMTP según la configuración.

    * Puerto 465: conexión SSL directa.
    * Otro puerto con ``SMTP_USE_TLS=true`` (p. ej. 587): se cifra con STARTTLS.
    """
    context = ssl.create_default_context()
    if settings.smtp_port == 465:
        with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, context=context, timeout=15) as server:
            server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
            if settings.smtp_use_tls:
                server.starttls(context=context)
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)


def send_otp_email(to_email: str, full_name: str, code: str) -> None:
    """Envía el código OTP al usuario.

    Con ``EMAIL_BACKEND=console`` (solo desarrollo) el código se escribe en el
    log en lugar de enviarse. En producción debe usarse ``smtp``.

    Se ejecuta en segundo plano (BackgroundTasks), por lo que los errores se
    registran en el log sin datos sensibles en vez de propagarse al cliente.
    """
    if settings.email_backend == "console":
        logger.warning("[DEV] OTP para %s: %s (EMAIL_BACKEND=console)", mask_email(to_email), code)
        return

    try:
        send_email(build_otp_message(to_email, full_name, code))
        logger.info("Correo OTP enviado a %s", mask_email(to_email))
    except (smtplib.SMTPException, OSError) as exc:
        # No se registra el código ni las credenciales, solo el tipo de error.
        logger.error("No se pudo enviar el correo OTP a %s: %s", mask_email(to_email), type(exc).__name__)
