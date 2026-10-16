"""Envío de correos electrónicos.

Hay tres modos (variable ``EMAIL_BACKEND``):

* ``smtp``: envío con ``smtplib`` (librería estándar) a cualquier servidor SMTP.
* ``brevo``: envío por la API HTTPS de Brevo. Se usa en Render gratis, que
  bloquea los puertos SMTP (25, 465 y 587) desde septiembre de 2025.
* ``console``: solo desarrollo; el código se escribe en el log.
"""

import html
import json
import logging
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage

from app.config import settings

logger = logging.getLogger(__name__)

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


class EmailSendError(Exception):
    """Error al enviar un correo (sin incluir datos sensibles en el mensaje)."""


def mask_email(email: str) -> str:
    """Oculta parte del correo para mostrarlo en respuestas: ``ana@x.com`` -> ``a**@x.com``."""
    local, _, domain = email.partition("@")
    visible = local[0] if local else ""
    return f"{visible}{'*' * max(len(local) - 1, 2)}@{domain}"


def sender_email() -> str:
    """Correo remitente: ``SMTP_FROM`` o, si no se definió, ``SMTP_USER``."""
    return settings.smtp_from or settings.smtp_user


def build_otp_content(full_name: str, code: str) -> tuple[str, str, str]:
    """Genera asunto, texto plano y HTML del correo con el código OTP.

    El nombre se escapa en la versión HTML para que un nombre malicioso
    (p. ej. con etiquetas ``<script>``) no se interprete como HTML.
    """
    minutes = settings.otp_expire_minutes
    subject = f"Tu código de verificación: {code}"
    text = (
        f"Hola {full_name},\n\n"
        f"Tu código de verificación es: {code}\n\n"
        f"Es válido durante {minutes} minutos y solo puede usarse una vez.\n"
        "Si no intentaste iniciar sesión, ignora este mensaje.\n"
    )
    html_body = f"""\
<html>
  <body style="font-family: Arial, sans-serif;">
    <p>Hola {html.escape(full_name)},</p>
    <p>Tu código de verificación es:</p>
    <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px;">{code}</p>
    <p>Es válido durante {minutes} minutos y solo puede usarse una vez.</p>
    <p style="color: #777;">Si no intentaste iniciar sesión, ignora este mensaje.</p>
  </body>
</html>
"""
    return subject, text, html_body


def build_otp_message(to_email: str, full_name: str, code: str) -> EmailMessage:
    """Construye el correo MIME (texto plano + HTML) para enviarlo por SMTP."""
    subject, text, html_body = build_otp_content(full_name, code)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender_email()
    msg["To"] = to_email
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")
    return msg


def send_via_smtp(msg: EmailMessage) -> None:
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


def brevo_error_reason(exc: urllib.error.HTTPError) -> str:
    """Extrae el mensaje de error de la respuesta de Brevo (máx. 300 caracteres)."""
    try:
        body = json.loads(exc.read().decode("utf-8"))
        reason = str(body.get("message") or body.get("code") or "sin detalle")
    except (ValueError, AttributeError, OSError):
        reason = "sin detalle"
    return reason[:300]


def send_via_brevo(to_email: str, full_name: str, code: str) -> None:
    """Envía el correo con la API transaccional de Brevo (HTTPS, puerto 443).

    Raises:
        EmailSendError: si Brevo responde con error o no se puede conectar.
    """
    subject, text, html_body = build_otp_content(full_name, code)
    payload = {
        "sender": {"name": settings.app_name, "email": sender_email()},
        "to": [{"email": to_email, "name": full_name}],
        "subject": subject,
        "textContent": text,
        "htmlContent": html_body,
    }
    request = urllib.request.Request(
        BREVO_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": settings.brevo_api_key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status >= 300:
                raise EmailSendError(f"Brevo respondió {response.status}")
    except urllib.error.HTTPError as exc:
        # Se registra el código HTTP y el motivo que da Brevo (p. ej. "Key not
        # found" o "unrecognised IP address"), nunca la API key ni el OTP.
        raise EmailSendError(f"Brevo respondió {exc.code}: {brevo_error_reason(exc)}") from exc
    except urllib.error.URLError as exc:
        raise EmailSendError("No se pudo conectar con Brevo") from exc


def send_otp_email(to_email: str, full_name: str, code: str) -> None:
    """Envía el código OTP al usuario con el backend configurado.

    Se ejecuta en segundo plano (BackgroundTasks), por lo que los errores se
    registran en el log sin datos sensibles en vez de propagarse al cliente.
    """
    if settings.email_backend == "console":
        logger.warning("[DEV] OTP para %s: %s (EMAIL_BACKEND=console)", mask_email(to_email), code)
        return

    try:
        if settings.email_backend == "brevo":
            send_via_brevo(to_email, full_name, code)
        else:
            send_via_smtp(build_otp_message(to_email, full_name, code))
        logger.info("Correo OTP enviado a %s", mask_email(to_email))
    except EmailSendError as exc:
        logger.error("No se pudo enviar el correo OTP a %s: %s", mask_email(to_email), exc)
    except (smtplib.SMTPException, OSError) as exc:
        # No se registra el código ni las credenciales, solo el tipo de error.
        logger.error("No se pudo enviar el correo OTP a %s: %s", mask_email(to_email), type(exc).__name__)
