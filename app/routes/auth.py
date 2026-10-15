"""Endpoints de autenticación: registro, login con OTP, tokens y cierre de sesión."""

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models import LoginSession, OTPCode, User
from app.rate_limit import login_limiter, register_limiter, resend_otp_limiter, verify_otp_limiter
from app.schemas import LoginOut, MessageOut, OTPResend, OTPVerify, TokenOut, UserLogin, UserOut, UserRegister
from app.security import create_access_token, hash_password, hash_token, verify_password
from app.services.email_service import mask_email, send_otp_email
from app.services.otp_service import create_otp, verify_otp

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Autenticación"])

INVALID_OTP = "Código OTP inválido o expirado"


def normalize_email(email: str) -> str:
    """Pasa el correo a minúsculas para evitar duplicados como Ana@x.com / ana@x.com."""
    return email.strip().lower()


def get_user_by_email(db: Session, email: str) -> User | None:
    """Busca un usuario por correo (ya normalizado)."""
    return db.scalars(select(User).where(User.email == email)).first()


def issue_token(db: Session, user: User) -> TokenOut:
    """Crea un JWT para el usuario y registra la sesión en ``login_sessions``."""
    token, expires_at = create_access_token(user.id)
    db.add(LoginSession(user_id=user.id, token=hash_token(token), expires_at=expires_at))
    db.commit()
    return TokenOut(access_token=token, expires_in=settings.access_token_expire_minutes * 60)


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(register_limiter)],
    responses={409: {"description": "El correo ya está registrado"}},
)
def register(data: UserRegister, db: Session = Depends(get_db)) -> User:
    """Registra un nuevo usuario.

    Valida el formato del correo y la fortaleza de la contraseña (en el
    esquema), comprueba que el correo no exista y guarda la contraseña
    hasheada con bcrypt.
    """
    email = normalize_email(data.email)
    if get_user_by_email(db, email) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="El correo ya está registrado")

    user = User(email=email, password_hash=hash_password(data.password), full_name=data.full_name)
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("Usuario registrado id=%s", user.id)
    return user


@router.post(
    "/login",
    response_model=LoginOut,
    dependencies=[Depends(login_limiter)],
    responses={401: {"description": "Credenciales inválidas"}},
)
def login(data: UserLogin, background_tasks: BackgroundTasks, db: Session = Depends(get_db)) -> LoginOut:
    """Primer factor: valida correo y contraseña y envía un OTP al correo.

    No devuelve ningún token; para obtenerlo hay que verificar el OTP en
    ``/auth/verify-otp``. El mensaje de error es el mismo si el correo no
    existe o si la contraseña es incorrecta, para no revelar qué cuentas existen.
    """
    user = get_user_by_email(db, normalize_email(data.email))
    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Correo o contraseña incorrectos")

    code = create_otp(db, user)
    # El correo se envía después de responder para no hacer esperar al cliente.
    background_tasks.add_task(send_otp_email, user.email, user.full_name, code)

    return LoginOut(
        message="Se envió un código de verificación a tu correo",
        email=mask_email(user.email),
        otp_expires_in=settings.otp_expire_minutes * 60,
    )


@router.post(
    "/verify-otp",
    response_model=TokenOut,
    dependencies=[Depends(verify_otp_limiter)],
    responses={401: {"description": INVALID_OTP}},
)
def verify_otp_endpoint(data: OTPVerify, db: Session = Depends(get_db)) -> TokenOut:
    """Segundo factor: valida el OTP y entrega el token JWT.

    El código solo sirve una vez y durante su tiempo de validez.
    """
    user = get_user_by_email(db, normalize_email(data.email))
    if user is None or not verify_otp(db, user, data.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_OTP)

    logger.info("Inicio de sesión completado id=%s", user.id)
    return issue_token(db, user)


@router.post("/resend-otp", response_model=MessageOut, dependencies=[Depends(resend_otp_limiter)])
def resend_otp(data: OTPResend, background_tasks: BackgroundTasks, db: Session = Depends(get_db)) -> MessageOut:
    """Reenvía un nuevo código OTP e invalida el anterior.

    Solo se envía si el usuario tiene un login pendiente de verificar (su
    último OTP no se ha usado). La respuesta es siempre la misma para no
    revelar si el correo está registrado.
    """
    user = get_user_by_email(db, normalize_email(data.email))
    if user is not None:
        last_otp = db.scalars(
            select(OTPCode)
            .where(OTPCode.user_id == user.id)
            .order_by(OTPCode.created_at.desc(), OTPCode.id.desc())
            .limit(1)
        ).first()
        if last_otp is not None and not last_otp.used:
            code = create_otp(db, user)
            background_tasks.add_task(send_otp_email, user.email, user.full_name, code)

    return MessageOut(message="Si hay un inicio de sesión pendiente, se envió un nuevo código al correo")


@router.post("/refresh", response_model=TokenOut)
def refresh(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> TokenOut:
    """Entrega un token nuevo y revoca el actual (requiere un token válido)."""
    db.execute(delete(LoginSession).where(LoginSession.id == request.state.session_id))
    return issue_token(db, user)


@router.post("/logout", response_model=MessageOut)
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> MessageOut:
    """Cierra la sesión: elimina la sesión de la BD y el token deja de ser válido."""
    db.execute(delete(LoginSession).where(LoginSession.id == request.state.session_id))
    db.commit()
    logger.info("Sesión cerrada id=%s", user.id)
    return MessageOut(message="Sesión cerrada correctamente")
