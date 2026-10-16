"""Modelos SQLAlchemy que representan las tablas de la base de datos."""

from datetime import date, datetime, timezone

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    """Fecha y hora actual en UTC (se usa como valor por defecto de las columnas)."""
    return datetime.now(timezone.utc)


class User(Base):
    """Usuario registrado en el sistema.

    Ejemplo::

        User(email="ana@example.com", password_hash="$2b$12$...", full_name="Ana Pérez")
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(150), nullable=False)
    # Pasa a True cuando el usuario confirma el primer OTP enviado a su correo.
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    otp_codes: Mapped[list["OTPCode"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    sessions: Mapped[list["LoginSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    tasks: Mapped[list["Task"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class OTPCode(Base):
    """Código OTP generado para un usuario durante el login.

    Por seguridad, en la columna ``code`` no se guarda el código en texto plano
    sino su hash HMAC-SHA256 (ver ``otp_service``). Si alguien obtiene la base de
    datos no puede usar los códigos pendientes.
    """

    __tablename__ = "otp_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    code: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    user: Mapped[User] = relationship(back_populates="otp_codes")


class LoginSession(Base):
    """Sesión activa asociada a un token JWT.

    Mientras exista la fila, el token es válido (además de su propia
    expiración). Cerrar sesión elimina la fila, lo que revoca el token aunque
    todavía no haya expirado. En ``token`` se guarda el hash SHA-256 del JWT,
    no el JWT completo.
    """

    __tablename__ = "login_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    user: Mapped[User] = relationship(back_populates="sessions")


class Task(Base):
    """Tarea del gestor de tareas. Cada tarea pertenece a un único usuario.

    Ejemplo::

        Task(user_id=1, title="Entregar parcial", priority="alta", due_date=date(2026, 10, 16))
    """

    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    priority: Mapped[str] = mapped_column(String(10), default="media", nullable=False)  # baja | media | alta
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    completed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    user: Mapped[User] = relationship(back_populates="tasks")
