"""Punto de entrada de la aplicación FastAPI."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import Settings, settings
from app.database import init_db
from app.middleware import AuthMiddleware, SecurityHeadersMiddleware
from app.routes import auth, tasks, users

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("app")


def check_production_settings() -> None:
    """Impide arrancar en producción con una configuración incompleta.

    Exige una ``SECRET_KEY`` propia y el envío real de correos (SMTP o Brevo)
    con sus datos completos; si falta algo, el servicio no arranca y el log
    indica qué variable revisar (sin mostrar sus valores).
    """
    if settings.environment != "production":
        return
    if settings.secret_key == Settings.model_fields["secret_key"].default:
        raise RuntimeError("Define SECRET_KEY en las variables de entorno antes de desplegar")
    if settings.email_backend == "smtp":
        required = (
            ("SMTP_HOST", settings.smtp_host),
            ("SMTP_USER", settings.smtp_user),
            ("SMTP_PASSWORD", settings.smtp_password),
        )
    elif settings.email_backend == "brevo":
        required = (
            ("BREVO_API_KEY", settings.brevo_api_key),
            ("SMTP_FROM", settings.smtp_from),
        )
    else:
        raise RuntimeError("En producción EMAIL_BACKEND debe ser 'smtp' o 'brevo'")
    missing = [name for name, value in required if not value]
    if missing:
        raise RuntimeError(f"Faltan variables de correo: {', '.join(missing)}")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Valida la configuración y crea las tablas al arrancar."""
    check_production_settings()
    init_db()
    logger.info("Aplicación iniciada (entorno=%s)", settings.environment)
    yield


app = FastAPI(
    title=settings.app_name,
    description=(
        "API de autenticación con dos factores: contraseña + código OTP enviado por correo.\n\n"
        "**Flujo:** `/auth/register` → `/auth/login` (envía OTP) → `/auth/verify-otp` (devuelve JWT) → "
        "usar el token en el botón *Authorize* para las rutas protegidas."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# El último middleware añadido es el más externo: SecurityHeaders envuelve a
# AuthMiddleware, así que también las respuestas 401 llevan las cabeceras.
app.add_middleware(AuthMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(tasks.router)

# Archivos de la interfaz web (HTML, CSS, JS).
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    """Devuelve 422 con los campos inválidos, sin repetir los valores enviados.

    El manejador por defecto incluye el valor recibido ("input"), lo que podría
    exponer contraseñas en la respuesta; aquí solo se devuelve campo y mensaje.
    """
    errors = [
        {"field": ".".join(str(part) for part in err["loc"] if part != "body"), "message": err["msg"]}
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": "Datos de entrada inválidos", "errors": errors},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Captura errores no controlados: se registran en el log y el cliente recibe un 500 genérico."""
    logger.error("Error no controlado en %s %s: %s", request.method, request.url.path, type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor"},
    )


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    """Sirve la interfaz web (aplicación de una sola página)."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api", tags=["General"])
def api_info() -> dict:
    """Información básica de la API."""
    return {"name": settings.app_name, "docs": "/docs", "status": "ok"}


@app.get("/health", tags=["General"])
def health() -> dict:
    """Endpoint de salud para el servicio de despliegue."""
    return {"status": "ok"}
