"""Esquemas Pydantic: validan los datos de entrada y dan forma a las respuestas."""

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


def validate_password_strength(value: str) -> str:
    """Exige al menos 8 caracteres, una letra y un número."""
    if len(value) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres")
    # bcrypt solo procesa los primeros 72 bytes; se rechaza lo que exceda.
    if len(value.encode("utf-8")) > 72:
        raise ValueError("La contraseña no puede superar 72 bytes")
    if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
        raise ValueError("La contraseña debe contener letras y números")
    return value


# ---------- Entradas ----------


class UserRegister(BaseModel):
    """Datos para registrar un usuario. ``EmailStr`` valida el formato del correo."""

    email: EmailStr = Field(examples=["ana@example.com"])
    password: str = Field(min_length=8, max_length=72, examples=["Secreta123"])
    full_name: str = Field(min_length=2, max_length=150, examples=["Ana Pérez"])

    _check_password = field_validator("password")(validate_password_strength)

    @field_validator("full_name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        """Elimina espacios sobrantes del nombre."""
        value = value.strip()
        if len(value) < 2:
            raise ValueError("El nombre es demasiado corto")
        return value


class UserLogin(BaseModel):
    """Credenciales para iniciar sesión (primer factor)."""

    email: EmailStr = Field(examples=["ana@example.com"])
    password: str = Field(min_length=1, max_length=72, examples=["Secreta123"])


class OTPVerify(BaseModel):
    """Código OTP recibido por correo (segundo factor)."""

    email: EmailStr = Field(examples=["ana@example.com"])
    code: str = Field(pattern=r"^\d{6}$", examples=["482913"], description="Código de 6 dígitos")


class OTPResend(BaseModel):
    """Solicitud para reenviar el código OTP."""

    email: EmailStr = Field(examples=["ana@example.com"])


class UserUpdate(BaseModel):
    """Campos editables del perfil. Para cambiar la contraseña se exige la actual."""

    full_name: str | None = Field(default=None, min_length=2, max_length=150, examples=["Ana María Pérez"])
    current_password: str | None = Field(default=None, max_length=72, examples=["Secreta123"])
    new_password: str | None = Field(default=None, min_length=8, max_length=72, examples=["NuevaClave456"])

    @field_validator("new_password")
    @classmethod
    def check_new_password(cls, value: str | None) -> str | None:
        """Aplica la misma política de contraseñas que el registro."""
        return validate_password_strength(value) if value is not None else value


# ---------- Respuestas ----------


class UserOut(BaseModel):
    """Datos públicos de un usuario (nunca incluye el hash de la contraseña)."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "email": "ana@example.com",
                "full_name": "Ana Pérez",
                "created_at": "2026-10-15T14:00:00Z",
                "updated_at": "2026-10-15T14:00:00Z",
            }
        },
    )

    id: int
    email: EmailStr
    full_name: str
    created_at: datetime
    updated_at: datetime


class MessageOut(BaseModel):
    """Respuesta genérica con un mensaje."""

    message: str = Field(examples=["Operación realizada correctamente"])


class LoginOut(MessageOut):
    """Respuesta del login: confirma el envío del OTP sin revelar el código."""

    email: str = Field(examples=["a***@example.com"], description="Correo enmascarado al que se envió el código")
    otp_expires_in: int = Field(examples=[900], description="Segundos de validez del código")


class TokenOut(BaseModel):
    """Token JWT entregado tras verificar el OTP o refrescar la sesión."""

    access_token: str = Field(examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."])
    token_type: str = Field(default="bearer", examples=["bearer"])
    expires_in: int = Field(examples=[1800], description="Segundos hasta que expira el token")
