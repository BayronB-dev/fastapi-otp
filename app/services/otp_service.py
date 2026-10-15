"""Generación, almacenamiento y validación de códigos OTP."""

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import pyotp
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import settings
from app.models import OTPCode, User
from app.security import as_utc


def generate_otp_code() -> str:
    """Genera un código numérico aleatorio de 6 dígitos con PyOTP.

    Se crea un secreto base32 aleatorio en cada llamada y se toma el código
    TOTP actual; como el secreto es nuevo cada vez, el código es impredecible.
    PyOTP usa el módulo ``secrets`` (criptográficamente seguro) para el secreto.
    """
    secret = pyotp.random_base32()
    return pyotp.TOTP(secret, digits=settings.otp_digits).now()


def hash_otp(code: str) -> str:
    """Calcula el HMAC-SHA256 del código usando ``SECRET_KEY`` como clave.

    Así en la base de datos nunca queda el código en texto plano.
    """
    return hmac.new(settings.secret_key.encode(), code.encode(), hashlib.sha256).hexdigest()


def create_otp(db: Session, user: User) -> str:
    """Invalida los OTP pendientes del usuario y crea uno nuevo.

    Solo puede haber un código válido a la vez: al pedir uno nuevo (login o
    reenvío) los anteriores se marcan como usados.

    Returns:
        El código en texto plano, para enviarlo por correo. No se guarda así.
    """
    db.execute(
        update(OTPCode).where(OTPCode.user_id == user.id, OTPCode.used.is_(False)).values(used=True)
    )
    code = generate_otp_code()
    otp = OTPCode(
        user_id=user.id,
        code=hash_otp(code),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.otp_expire_minutes),
        used=False,
    )
    db.add(otp)
    db.commit()
    return code


def verify_otp(db: Session, user: User, code: str) -> bool:
    """Valida el código del usuario y lo marca como usado si es correcto.

    Un código es válido si: pertenece al usuario, no se ha usado, no ha
    expirado y su hash coincide. La comparación usa ``hmac.compare_digest``
    para evitar ataques de tiempo.
    """
    otp = db.scalars(
        select(OTPCode)
        .where(OTPCode.user_id == user.id, OTPCode.used.is_(False))
        .order_by(OTPCode.created_at.desc(), OTPCode.id.desc())
        .limit(1)
    ).first()
    if otp is None:
        return False
    if as_utc(otp.expires_at) < datetime.now(timezone.utc):
        return False
    if not hmac.compare_digest(otp.code, hash_otp(code)):
        return False

    otp.used = True
    db.commit()
    return True
