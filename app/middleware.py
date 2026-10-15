"""Middleware de autenticación: valida el token JWT en las rutas protegidas."""

from datetime import datetime, timezone

import jwt
from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app import database
from app.models import LoginSession, User
from app.security import as_utc, decode_access_token, hash_token

# Rutas que exigen un token válido. Se comparan por prefijo.
PROTECTED_PREFIXES: tuple[str, ...] = ("/users", "/auth/refresh", "/auth/logout")


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
