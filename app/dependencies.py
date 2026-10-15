"""Dependencias compartidas por los routers."""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User

# Solo sirve para que Swagger (/docs) muestre el botón "Authorize".
# La validación real del token la hace AuthMiddleware.
bearer_scheme = HTTPBearer(auto_error=False, description="Token JWT obtenido en /auth/verify-otp")


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    _credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> User:
    """Devuelve el usuario autenticado que dejó el middleware en ``request.state``."""
    user_id = getattr(request.state, "user_id", None)
    user = db.get(User, user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
