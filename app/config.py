"""Configuración de la aplicación leída desde variables de entorno / archivo .env."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Parámetros configurables de la aplicación.

    Cada atributo puede sobrescribirse con una variable de entorno del mismo
    nombre (sin distinguir mayúsculas) o desde el archivo ``.env``.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Auth OTP API"
    environment: str = "development"

    # JWT
    # Solo para desarrollo; en producción se exige definir SECRET_KEY (ver main.py).
    secret_key: str = "dev-only-secret-key-change-me-in-production-0123456789"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Base de datos
    database_url: str = "sqlite:///./app.db"

    # OTP
    otp_expire_minutes: int = 15
    otp_digits: int = 6

    # Correo
    email_backend: str = "console"  # "console" | "smtp" | "brevo"
    brevo_api_key: str = ""
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True

    # Rate limiting
    rate_limit_enabled: bool = True


@lru_cache
def get_settings() -> Settings:
    """Devuelve una única instancia de ``Settings`` (se lee una sola vez)."""
    return Settings()


settings = get_settings()
