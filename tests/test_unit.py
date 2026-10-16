"""Tests unitarios: funciones de seguridad, OTP, correo, validaciones y rate limiting."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import jwt
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.middleware import is_protected
from app.models import OTPCode, User
from app.rate_limit import RateLimiter
from app.schemas import UserRegister
from app.security import (
    as_utc,
    create_access_token,
    decode_access_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.services.email_service import build_otp_message, mask_email
from app.services.otp_service import create_otp, generate_otp_code, hash_otp, verify_otp


def make_user(db) -> User:
    """Crea un usuario directamente en la BD."""
    user = User(email="test@example.com", password_hash=hash_password("Secreta123"), full_name="Test")
    db.add(user)
    db.commit()
    return user


# ---------- Contraseñas ----------


def test_password_hash_and_verify():
    """El hash no es la contraseña y solo valida con la contraseña correcta."""
    hashed = hash_password("Secreta123")
    assert hashed != "Secreta123"
    assert hashed.startswith("$2")  # formato bcrypt
    assert verify_password("Secreta123", hashed)
    assert not verify_password("otra-clave1", hashed)


def test_password_hash_uses_random_salt():
    """Dos hashes de la misma contraseña son distintos (sal aleatoria)."""
    assert hash_password("Secreta123") != hash_password("Secreta123")


def test_verify_password_too_long_returns_false():
    """Una contraseña de más de 72 bytes no rompe la verificación."""
    assert verify_password("a" * 100, hash_password("Secreta123")) is False


# ---------- JWT ----------


def test_access_token_contains_expected_claims():
    """El token incluye sub, exp, iat y jti, y expira en el tiempo configurado."""
    token, expires_at = create_access_token(42, expires_minutes=10)
    payload = decode_access_token(token)
    assert payload["sub"] == "42"
    assert {"exp", "iat", "jti"} <= payload.keys()
    expected = datetime.now(timezone.utc) + timedelta(minutes=10)
    assert abs((expires_at - expected).total_seconds()) < 5


def test_expired_token_is_rejected():
    """Un token expirado lanza ExpiredSignatureError."""
    token, _ = create_access_token(1, expires_minutes=-1)
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_tampered_token_is_rejected():
    """Un token con la firma alterada es inválido."""
    token, _ = create_access_token(1)
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(tampered)


def test_tokens_are_unique_and_hash_is_stable():
    """Dos tokens del mismo usuario son distintos; el hash del token es determinista."""
    t1, _ = create_access_token(1)
    t2, _ = create_access_token(1)
    assert t1 != t2
    assert hash_token(t1) == hash_token(t1)
    assert len(hash_token(t1)) == 64


def test_as_utc_adds_timezone_to_naive_dates():
    """Las fechas sin zona horaria se interpretan como UTC."""
    naive = datetime(2026, 1, 1, 12, 0)
    assert as_utc(naive).tzinfo == timezone.utc


# ---------- OTP ----------


def test_generate_otp_code_has_six_digits():
    """El código OTP tiene exactamente 6 dígitos numéricos."""
    for _ in range(20):
        code = generate_otp_code()
        assert len(code) == 6 and code.isdigit()


def test_create_otp_stores_hash_and_expiration(db):
    """Se guarda el hash (no el código) con validez de 15 minutos."""
    user = make_user(db)
    code = create_otp(db, user)
    otp = db.query(OTPCode).filter_by(user_id=user.id).one()
    assert otp.code != code
    assert otp.code == hash_otp(code)
    assert otp.used is False
    remaining = as_utc(otp.expires_at) - datetime.now(timezone.utc)
    assert timedelta(minutes=14) < remaining <= timedelta(minutes=15)


def test_verify_otp_only_works_once(db):
    """El código correcto valida una sola vez."""
    user = make_user(db)
    code = create_otp(db, user)
    assert verify_otp(db, user, code) is True
    assert verify_otp(db, user, code) is False


def test_verify_otp_rejects_wrong_code(db):
    """Un código incorrecto no valida y no consume el código correcto."""
    user = make_user(db)
    code = create_otp(db, user)
    wrong = "000000" if code != "000000" else "111111"
    assert verify_otp(db, user, wrong) is False
    assert verify_otp(db, user, code) is True


def test_verify_otp_rejects_expired_code(db):
    """Un código expirado no valida."""
    user = make_user(db)
    code = create_otp(db, user)
    otp = db.query(OTPCode).filter_by(user_id=user.id).one()
    otp.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert verify_otp(db, user, code) is False


def test_new_otp_invalidates_previous(db):
    """Al generar un nuevo OTP el anterior deja de servir."""
    user = make_user(db)
    old_code = create_otp(db, user)
    new_code = create_otp(db, user)
    if old_code != new_code:
        assert verify_otp(db, user, old_code) is False
    assert verify_otp(db, user, new_code) is True


# ---------- Correo ----------


def test_mask_email():
    """El correo se enmascara dejando solo la primera letra y el dominio."""
    assert mask_email("ana@example.com") == "a**@example.com"
    assert mask_email("juanperez@mail.com") == "j********@mail.com"


def test_build_otp_message_contains_code():
    """El correo generado incluye el destinatario y el código."""
    msg = build_otp_message("ana@example.com", "Ana", "123456")
    assert msg["To"] == "ana@example.com"
    assert "123456" in msg["Subject"]
    assert "123456" in msg.get_body(preferencelist=("plain",)).get_content()


# ---------- Validaciones ----------


@pytest.mark.parametrize("password", ["corta1", "solo-letras", "12345678"])
def test_register_schema_rejects_weak_passwords(password):
    """Se exige mínimo 8 caracteres con letras y números."""
    with pytest.raises(ValidationError):
        UserRegister(email="ana@example.com", password=password, full_name="Ana")


def test_register_schema_rejects_invalid_email():
    """El correo debe tener un formato válido."""
    with pytest.raises(ValidationError):
        UserRegister(email="no-es-un-correo", password="Secreta123", full_name="Ana")


# ---------- Configuración de producción ----------


def test_production_requires_smtp_settings(monkeypatch):
    """En producción la app no arranca si faltan los datos SMTP."""
    from app.config import settings
    from app.main import check_production_settings

    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "email_backend", "smtp")
    monkeypatch.setattr(settings, "smtp_user", "")
    monkeypatch.setattr(settings, "smtp_password", "")
    with pytest.raises(RuntimeError, match="SMTP_USER, SMTP_PASSWORD"):
        check_production_settings()

    monkeypatch.setattr(settings, "smtp_user", "app@example.com")
    monkeypatch.setattr(settings, "smtp_password", "clave-de-aplicacion")
    check_production_settings()  # configuración completa: no lanza error


# ---------- Middleware y rate limiting ----------


def test_is_protected_paths():
    """Solo las rutas privadas exigen token."""
    assert is_protected("/users/profile")
    assert is_protected("/auth/logout")
    assert is_protected("/auth/refresh")
    assert not is_protected("/auth/login")
    assert not is_protected("/auth/register")
    assert not is_protected("/docs")


def test_rate_limiter_blocks_after_limit():
    """Tras superar el límite se responde 429 con cabecera Retry-After."""
    limiter = RateLimiter(times=2, seconds=60)
    request = MagicMock()
    request.client.host = "1.2.3.4"
    request.url.path = "/auth/login"

    limiter(request)
    limiter(request)
    with pytest.raises(HTTPException) as exc:
        limiter(request)
    assert exc.value.status_code == 429
    assert "Retry-After" in exc.value.headers

    # Otra IP tiene su propio contador.
    other = MagicMock()
    other.client.host = "5.6.7.8"
    other.url.path = "/auth/login"
    limiter(other)
