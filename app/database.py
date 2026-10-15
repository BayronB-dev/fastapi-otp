"""Configuración de SQLAlchemy: motor, sesiones y clase base de los modelos."""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

# SQLite no permite por defecto usar la misma conexión desde varios hilos;
# FastAPI atiende peticiones en un pool de hilos, así que se desactiva esa
# comprobación (cada petición usa su propia sesión de todas formas).
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(settings.database_url, connect_args=connect_args)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    """Clase base de la que heredan todos los modelos ORM."""


def get_db() -> Generator[Session, None, None]:
    """Dependencia de FastAPI que abre una sesión de BD por petición y la cierra al final."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Crea las tablas definidas en los modelos si todavía no existen."""
    from app import models  # noqa: F401  (registra los modelos en Base.metadata)

    Base.metadata.create_all(bind=engine)
