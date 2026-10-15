"""Utilidades de seguridad: hashing de contraseñas y manejo de tokens JWT."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import settings


def as_utc(value: datetime) -> datetime:
    """Asegura que una fecha tenga zona horaria UTC.

    SQLite no guarda la zona horaria, así que las fechas leídas de la BD llegan
    "naive". Se les asigna UTC para poder compararlas con ``datetime.now(UTC)``.
    """
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


# ---------- Contraseñas ----------


def hash_password(password: str) -> str:
    """Genera el hash bcrypt de una contraseña (incluye una sal aleatoria)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Comprueba si ``password`` corresponde a ``password_hash``.

    Devuelve ``False`` en lugar de lanzar excepción si la contraseña es
    inválida para bcrypt (por ejemplo, más de 72 bytes).
    """
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


# ---------- JWT ----------


def create_access_token(user_id: int, expires_minutes: int | None = None) -> tuple[str, datetime]:
    """Crea un JWT firmado para ``user_id``.

    El token incluye los claims:
      * ``sub``: id del usuario
      * ``iat``: fecha de emisión
      * ``exp``: fecha de expiración (la librería la valida al decodificar)
      * ``jti``: identificador único, para que dos tokens nunca sean iguales

    Returns:
        Tupla ``(token, fecha_de_expiracion)``.
    """
    minutes = expires_minutes if expires_minutes is not None else settings.access_token_expire_minutes
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=minutes)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": expires_at,
        "jti": secrets.token_hex(16),
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, expires_at


def decode_access_token(token: str) -> dict:
    """Decodifica y valida un JWT (firma y expiración).

    Raises:
        jwt.ExpiredSignatureError: si el token expiró.
        jwt.InvalidTokenError: si el token es inválido o fue manipulado.
    """
    return jwt.decode(
        token,
        settings.secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"require": ["exp", "sub", "iat"]},
    )


def hash_token(token: str) -> str:
    """Hash SHA-256 del JWT; es lo que se guarda en ``login_sessions.token``."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
