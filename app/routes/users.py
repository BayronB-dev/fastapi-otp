"""Endpoints del perfil del usuario autenticado."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.schemas import UserOut, UserUpdate
from app.security import hash_password, verify_password

router = APIRouter(prefix="/users", tags=["Usuarios"])


@router.get("/profile", response_model=UserOut)
def get_profile(user: User = Depends(get_current_user)) -> User:
    """Devuelve los datos del usuario autenticado."""
    return user


@router.put(
    "/profile",
    response_model=UserOut,
    responses={400: {"description": "Datos de actualización inválidos"}},
)
def update_profile(data: UserUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
    """Actualiza el nombre y/o la contraseña del usuario autenticado.

    Para cambiar la contraseña hay que enviar también la contraseña actual.
    """
    if data.full_name is None and data.new_password is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No se envió ningún campo para actualizar")

    if data.full_name is not None:
        user.full_name = data.full_name.strip()

    if data.new_password is not None:
        if not data.current_password or not verify_password(data.current_password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña actual no es correcta")
        user.password_hash = hash_password(data.new_password)

    db.commit()
    db.refresh(user)
    return user
