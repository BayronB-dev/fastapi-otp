"""Esquemas Pydantic: validan los datos de entrada y dan forma a las respuestas."""

import re
from datetime import date, datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

Priority = Literal["baja", "media", "alta"]


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
                "email_verified": True,
                "created_at": "2026-10-15T14:00:00Z",
                "updated_at": "2026-10-15T14:00:00Z",
            }
        },
    )

    id: int
    email: EmailStr
    full_name: str
    email_verified: bool
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", "updated_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        """SQLite devuelve fechas sin zona horaria; se marcan como UTC."""
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class MessageOut(BaseModel):
    """Respuesta genérica con un mensaje."""

    message: str = Field(examples=["Operación realizada correctamente"])


class OTPSentOut(MessageOut):
    """Respuesta del registro y del login: confirma el envío del OTP sin revelar el código."""

    email: str = Field(examples=["a***@example.com"], description="Correo enmascarado al que se envió el código")
    otp_expires_in: int = Field(examples=[900], description="Segundos de validez del código")


# ---------- Tareas ----------


class TaskCreate(BaseModel):
    """Datos para crear una tarea."""

    title: str = Field(min_length=1, max_length=200, examples=["Estudiar para el parcial"])
    description: str = Field(default="", max_length=2000, examples=["Repasar JWT, OTP y middleware"])
    priority: Priority = Field(default="media", examples=["alta"])
    due_date: date | None = Field(default=None, examples=["2026-10-16"])

    @field_validator("title")
    @classmethod
    def strip_title(cls, value: str) -> str:
        """El título no puede quedar vacío tras quitar espacios."""
        value = value.strip()
        if not value:
            raise ValueError("El título no puede estar vacío")
        return value


class TaskUpdate(BaseModel):
    """Campos editables de una tarea; solo se modifican los que se envían."""

    title: str | None = Field(default=None, min_length=1, max_length=200, examples=["Estudiar para el parcial"])
    description: str | None = Field(default=None, max_length=2000)
    priority: Priority | None = Field(default=None, examples=["baja"])
    due_date: date | None = Field(default=None, examples=["2026-10-20"])
    completed: bool | None = Field(default=None, examples=[True])

    @field_validator("title")
    @classmethod
    def strip_title(cls, value: str | None) -> str | None:
        """El título no puede quedar vacío tras quitar espacios."""
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("El título no puede estar vacío")
        return value


class TaskOut(BaseModel):
    """Tarea devuelta por la API."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "title": "Estudiar para el parcial",
                "description": "Repasar JWT, OTP y middleware",
                "priority": "alta",
                "due_date": "2026-10-16",
                "completed": False,
                "created_at": "2026-10-15T14:00:00Z",
                "updated_at": "2026-10-15T14:00:00Z",
            }
        },
    )

    id: int
    title: str
    description: str
    priority: Priority
    due_date: date | None
    completed: bool
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", "updated_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        """SQLite devuelve fechas sin zona horaria; se marcan como UTC."""
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class TaskSummary(BaseModel):
    """Resumen de las tareas del usuario para el panel."""

    total: int = Field(examples=[8])
    completed: int = Field(examples=[3])
    pending: int = Field(examples=[5])
    overdue: int = Field(examples=[1], description="Pendientes con fecha límite ya pasada")


class TokenOut(BaseModel):
    """Token JWT entregado tras verificar el OTP o refrescar la sesión."""

    access_token: str = Field(examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."])
    token_type: str = Field(default="bearer", examples=["bearer"])
    expires_in: int = Field(examples=[1800], description="Segundos hasta que expira el token")
