"""Middlewares: autenticación JWT en rutas protegidas y cabeceras de seguridad HTTP."""

from datetime import datetime, timezone

import jwt
from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app import database
from app.config import settings
from app.models import LoginSession, User
from app.security import as_utc, decode_access_token, hash_token

# Rutas que exigen un token válido. Se comparan por prefijo.
PROTECTED_PREFIXES: tuple[str, ...] = ("/users", "/tasks", "/auth/refresh", "/auth/logout")


def is_protected(path: str) -> bool:
    """Indica si la ruta requiere autenticación."""
    return any(path == p or path.startswith(p + "/") for p in PROTECTED_PREFIXES)


def unauthorized(detail: str) -> JSONResponse:
    """Respuesta 401 estándar con la cabecera ``WWW-Authenticate`` que exige el protocolo."""
    return JSONResponse(status_code=401, content={"detail": detail}, headers={"WWW-Authenticate": "Bearer"})


class AuthMiddleware(BaseHTTPMiddleware):
    """Valida el JWT de las rutas protegidas antes de llegar al endpoint.

    Pasos:
      1. Leer la cabecera ``Authorization: Bearer <token>``.
      2. Verificar firma y expiración del JWT.
      3. Comprobar que la sesión existe en ``login_sessions`` (si se cerró
         sesión, la fila ya no existe y el token queda revocado).
      4. Cargar el usuario y guardarlo en ``request.state`` para los endpoints.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Intercepta cada petición y aplica la validación si la ruta es protegida."""
        if request.method == "OPTIONS" or not is_protected(request.url.path):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return unauthorized("No se proporcionó un token de autenticación")

        try:
            payload = decode_access_token(token)
            user_id = int(payload["sub"])
        except jwt.ExpiredSignatureError:
            return unauthorized("El token ha expirado")
        except (jwt.InvalidTokenError, ValueError, KeyError):
            return unauthorized("Token inválido")

        # La consulta a la BD es síncrona: se ejecuta en un hilo aparte para no
        # bloquear el event loop de asyncio.
        error, session_id = await run_in_threadpool(check_session, token, user_id)
        if error:
            return unauthorized(error)

        request.state.user_id = user_id
        request.state.session_id = session_id
        request.state.token = token
        return await call_next(request)


#: Política de seguridad de contenido para la interfaz web: solo se permite
#: cargar scripts, estilos e imágenes del propio dominio (sin scripts en línea),
#: lo que bloquea la mayoría de ataques XSS aunque se colara HTML malicioso.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)

#: Swagger y ReDoc cargan recursos de un CDN y usan scripts en línea, así que
#: no se les aplica la CSP estricta.
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Añade cabeceras de seguridad HTTP a todas las respuestas.

    * ``X-Content-Type-Options: nosniff``: el navegador no "adivina" tipos de archivo.
    * ``X-Frame-Options: DENY``: la página no puede incrustarse en un iframe (clickjacking).
    * ``Referrer-Policy: no-referrer``: no se filtra la URL a otros sitios.
    * ``Content-Security-Policy``: limita de dónde se cargan scripts y estilos (XSS).
    * ``Cache-Control: no-store`` en la API: datos personales y tokens no se guardan en caché.
    * ``Strict-Transport-Security`` en producción: fuerza HTTPS.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Ejecuta la petición y añade las cabeceras a la respuesta."""
        response = await call_next(request)
        path = request.url.path
        headers = response.headers
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "no-referrer"
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not path.startswith(DOCS_PATHS):
            headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        if path.startswith(("/auth", "/users", "/tasks")):
            headers["Cache-Control"] = "no-store"
        if settings.environment == "production":
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


def check_session(token: str, user_id: int) -> tuple[str | None, int | None]:
    """Verifica en la BD que la sesión del token exista, no haya expirado y su usuario exista.

    Returns:
        ``(mensaje_de_error, None)`` si no es válida o ``(None, id_de_sesion)`` si lo es.
    """
    db = database.SessionLocal()
    try:
        session = db.scalars(select(LoginSession).where(LoginSession.token == hash_token(token))).first()
        if session is None or session.user_id != user_id:
            return "La sesión no existe o fue cerrada", None
        if as_utc(session.expires_at) < datetime.now(timezone.utc):
            return "La sesión ha expirado", None
        if db.get(User, user_id) is None:
            return "Usuario no encontrado", None
        return None, session.id
    finally:
        db.close()
