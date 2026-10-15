"""Fixtures compartidas por los tests.

Las variables de entorno se definen ANTES de importar la app para que use una
base de datos temporal y no envíe correos reales.
"""

import os
import tempfile
from pathlib import Path

TEST_DB = Path(tempfile.gettempdir()) / "auth_otp_test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["EMAIL_BACKEND"] = "console"
os.environ["ENVIRONMENT"] = "testing"
os.environ["SECRET_KEY"] = "test-secret-key-with-at-least-32-bytes-1234567890"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.rate_limit import ALL_LIMITERS  # noqa: E402
from app.routes import auth as auth_routes  # noqa: E402

PASSWORD = "Secreta123"


@pytest.fixture(autouse=True)
def clean_state():
    """Antes de cada test: BD vacía y contadores de rate limiting en cero."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    for limiter in ALL_LIMITERS:
        limiter.reset()
    yield


@pytest.fixture
def db():
    """Sesión de base de datos para los tests unitarios."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def outbox(monkeypatch):
    """Reemplaza el envío de correo y guarda los códigos OTP "enviados"."""
    sent: list[dict] = []

    def fake_send(to_email: str, full_name: str, code: str) -> None:
        sent.append({"to": to_email, "name": full_name, "code": code})

    monkeypatch.setattr(auth_routes, "send_otp_email", fake_send)
    return sent


@pytest.fixture
def client():
    """Cliente HTTP de pruebas contra la app."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def registered_user(client):
    """Registra un usuario de prueba y devuelve sus datos."""
    data = {"email": "ana@example.com", "password": PASSWORD, "full_name": "Ana Pérez"}
    response = client.post("/auth/register", json=data)
    assert response.status_code == 201
    return data


@pytest.fixture
def auth_headers(client, registered_user, outbox):
    """Hace login + verificación OTP y devuelve la cabecera Authorization."""
    client.post("/auth/login", json={"email": registered_user["email"], "password": PASSWORD})
    response = client.post("/auth/verify-otp", json={"email": registered_user["email"], "code": outbox[-1]["code"]})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
