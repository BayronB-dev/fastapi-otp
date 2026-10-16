"""Tests de integración: prueban los endpoints de punta a punta con la BD real de pruebas."""

from datetime import datetime, timedelta, timezone

from app.models import OTPCode
from tests.conftest import PASSWORD


def login(client, email: str, password: str = PASSWORD):
    """Hace POST /auth/login."""
    return client.post("/auth/login", json={"email": email, "password": password})


def test_full_authentication_flow(client, outbox):
    """Registro -> login -> OTP -> perfil -> refresh -> logout."""
    # 1. Registro
    response = client.post(
        "/auth/register", json={"email": "Ana@Example.com", "password": PASSWORD, "full_name": "Ana Pérez"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "ana@example.com"  # se normaliza a minúsculas
    assert "password" not in body and "password_hash" not in body

    # 2. Login: no entrega token, envía el OTP por correo
    response = login(client, "ana@example.com")
    assert response.status_code == 200
    assert "access_token" not in response.json()
    assert response.json()["otp_expires_in"] == 15 * 60
    assert len(outbox) == 1 and outbox[0]["to"] == "ana@example.com"

    # 3. Verificación del OTP -> JWT
    response = client.post("/auth/verify-otp", json={"email": "ana@example.com", "code": outbox[0]["code"]})
    assert response.status_code == 200
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 4. Ruta protegida
    response = client.get("/users/profile", headers=headers)
    assert response.status_code == 200
    assert response.json()["full_name"] == "Ana Pérez"

    # 5. Refresh: el token nuevo funciona y el anterior queda revocado
    response = client.post("/auth/refresh", headers=headers)
    assert response.status_code == 200
    new_headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.get("/users/profile", headers=headers).status_code == 401
    assert client.get("/users/profile", headers=new_headers).status_code == 200

    # 6. Logout: el token deja de funcionar
    assert client.post("/auth/logout", headers=new_headers).status_code == 200
    assert client.get("/users/profile", headers=new_headers).status_code == 401


def test_register_duplicate_and_invalid_data(client, registered_user):
    """Correo duplicado -> 409; datos inválidos -> 422 sin devolver la contraseña."""
    response = client.post("/auth/register", json=registered_user)
    assert response.status_code == 409

    response = client.post("/auth/register", json={"email": "malo", "password": "abc", "full_name": "X"})
    assert response.status_code == 422
    fields = {err["field"] for err in response.json()["errors"]}
    assert {"email", "password", "full_name"} <= fields
    assert "abc" not in response.text  # no se expone el valor enviado


def test_login_with_wrong_credentials(client, registered_user, outbox):
    """Contraseña incorrecta o correo inexistente -> 401 con el mismo mensaje."""
    wrong_password = login(client, registered_user["email"], "OtraClave999")
    unknown_user = login(client, "nadie@example.com")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()
    assert outbox == []


def test_verify_otp_wrong_reused_and_expired(client, registered_user, outbox, db):
    """OTP incorrecto, reutilizado o expirado -> 401."""
    email = registered_user["email"]
    login(client, email)
    code = outbox[-1]["code"]
    wrong = "000000" if code != "000000" else "111111"

    assert client.post("/auth/verify-otp", json={"email": email, "code": wrong}).status_code == 401
    assert client.post("/auth/verify-otp", json={"email": email, "code": code}).status_code == 200
    # Reutilizar el mismo código
    assert client.post("/auth/verify-otp", json={"email": email, "code": code}).status_code == 401

    # Código expirado
    login(client, email)
    db.query(OTPCode).filter_by(used=False).update(
        {"expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)}
    )
    db.commit()
    response = client.post("/auth/verify-otp", json={"email": email, "code": outbox[-1]["code"]})
    assert response.status_code == 401


def test_verify_otp_rejects_bad_format(client):
    """El código debe ser de 6 dígitos."""
    response = client.post("/auth/verify-otp", json={"email": "ana@example.com", "code": "12ab"})
    assert response.status_code == 422


def test_protected_routes_require_valid_token(client):
    """Sin token, con formato incorrecto o con token falso -> 401."""
    assert client.get("/users/profile").status_code == 401
    assert client.get("/users/profile", headers={"Authorization": "Basic abc"}).status_code == 401
    response = client.get("/users/profile", headers={"Authorization": "Bearer token.falso.123"})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert client.post("/auth/logout").status_code == 401
    assert client.post("/auth/refresh").status_code == 401


def test_resend_otp_invalidates_previous_code(client, registered_user, outbox):
    """El reenvío genera un código nuevo y el anterior deja de servir."""
    email = registered_user["email"]
    login(client, email)
    first_code = outbox[-1]["code"]

    response = client.post("/auth/resend-otp", json={"email": email})
    assert response.status_code == 200
    assert len(outbox) == 2
    second_code = outbox[-1]["code"]

    if first_code != second_code:
        assert client.post("/auth/verify-otp", json={"email": email, "code": first_code}).status_code == 401
    assert client.post("/auth/verify-otp", json={"email": email, "code": second_code}).status_code == 200


def test_resend_otp_does_not_reveal_users(client, registered_user, outbox):
    """Sin login pendiente o con correo inexistente no se envía nada, pero la respuesta es igual."""
    no_pending = client.post("/auth/resend-otp", json={"email": registered_user["email"]})
    unknown = client.post("/auth/resend-otp", json={"email": "nadie@example.com"})
    assert no_pending.status_code == unknown.status_code == 200
    assert no_pending.json() == unknown.json()
    assert outbox == []


def test_update_profile(client, auth_headers, registered_user):
    """Actualizar nombre y contraseña (esta última exige la contraseña actual)."""
    response = client.put("/users/profile", headers=auth_headers, json={"full_name": "Ana María"})
    assert response.status_code == 200
    assert response.json()["full_name"] == "Ana María"

    response = client.put(
        "/users/profile", headers=auth_headers, json={"current_password": "Incorrecta1", "new_password": "NuevaClave456"}
    )
    assert response.status_code == 400

    response = client.put(
        "/users/profile", headers=auth_headers, json={"current_password": PASSWORD, "new_password": "NuevaClave456"}
    )
    assert response.status_code == 200
    assert login(client, registered_user["email"], "NuevaClave456").status_code == 200

    assert client.put("/users/profile", headers=auth_headers, json={}).status_code == 400


def test_login_rate_limit(client, registered_user):
    """Más de 5 intentos de login por minuto desde la misma IP -> 429."""
    codes = [login(client, registered_user["email"], "Incorrecta1").status_code for _ in range(6)]
    assert codes[:5] == [401] * 5
    assert codes[5] == 429


def test_security_headers(client):
    """Todas las respuestas llevan cabeceras de seguridad; la API no se cachea."""
    response = client.get("/users/profile")  # incluso en un 401 del middleware
    assert response.status_code == 401
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"

    # Swagger necesita su CDN, así que no lleva la CSP estricta.
    assert "Content-Security-Policy" not in client.get("/docs").headers


def test_health_endpoint(client):
    """El endpoint de salud responde sin autenticación."""
    assert client.get("/health").json() == {"status": "ok"}
