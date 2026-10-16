"""Tests de integración: prueban los endpoints de punta a punta con la BD real de pruebas."""

from datetime import datetime, timedelta, timezone

from app.models import OTPCode, User
from tests.conftest import PASSWORD


def login(client, email: str, password: str = PASSWORD):
    """Hace POST /auth/login."""
    return client.post("/auth/login", json={"email": email, "password": password})


def test_full_authentication_flow(client, outbox):
    """Registro + verificación de correo -> login -> OTP -> perfil -> refresh -> logout."""
    # 1. Registro: no entrega token, envía un OTP para verificar el correo
    response = client.post(
        "/auth/register", json={"email": "Ana@Example.com", "password": PASSWORD, "full_name": "Ana Pérez"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "a**@example.com"  # correo normalizado y enmascarado
    assert "access_token" not in body and "password" not in response.text
    assert len(outbox) == 1 and outbox[0]["to"] == "ana@example.com"

    # 2. Verificar el correo con el OTP del registro -> JWT y cuenta verificada
    response = client.post("/auth/verify-otp", json={"email": "ana@example.com", "code": outbox[0]["code"]})
    assert response.status_code == 200
    first_headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.get("/users/profile", headers=first_headers).json()["email_verified"] is True

    # 3. Login: no entrega token, envía otro OTP (segundo factor)
    response = login(client, "ana@example.com")
    assert response.status_code == 200
    assert "access_token" not in response.json()
    assert response.json()["otp_expires_in"] == 15 * 60
    assert len(outbox) == 2

    # 4. Verificación del OTP del login -> JWT
    response = client.post("/auth/verify-otp", json={"email": "ana@example.com", "code": outbox[1]["code"]})
    assert response.status_code == 200
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 5. Ruta protegida
    response = client.get("/users/profile", headers=headers)
    assert response.status_code == 200
    assert response.json()["full_name"] == "Ana Pérez"

    # 6. Refresh: el token nuevo funciona y el anterior queda revocado
    response = client.post("/auth/refresh", headers=headers)
    assert response.status_code == 200
    new_headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.get("/users/profile", headers=headers).status_code == 401
    assert client.get("/users/profile", headers=new_headers).status_code == 200

    # 7. Logout: el token deja de funcionar
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


def test_unverified_registration_can_be_reclaimed_after_expiry(client, outbox, db):
    """Un registro sin verificar bloquea el correo 15 min; después, el dueño real puede registrarse."""
    intruder = {"email": "victima@example.com", "password": "Intruso123", "full_name": "Intruso"}
    owner = {"email": "victima@example.com", "password": "Duenio1234", "full_name": "Dueño Real"}
    assert client.post("/auth/register", json=intruder).status_code == 201

    # Dentro de la ventana de verificación el correo está ocupado.
    assert client.post("/auth/register", json=owner).status_code == 409

    # Pasada la ventana sin verificar, el registro se reemplaza.
    db.query(User).filter_by(email="victima@example.com").update(
        {"updated_at": datetime.now(timezone.utc) - timedelta(minutes=16)}
    )
    db.commit()
    assert client.post("/auth/register", json=owner).status_code == 201
    response = client.post("/auth/verify-otp", json={"email": owner["email"], "code": outbox[-1]["code"]})
    assert response.status_code == 200

    # La contraseña del intruso ya no sirve; la del dueño sí.
    assert login(client, owner["email"], intruder["password"]).status_code == 401
    assert login(client, owner["email"], owner["password"]).status_code == 200


def test_registration_otp_invalidated_by_login(client, outbox):
    """Un usuario sin verificar puede verificarse con el OTP del login (el del registro deja de valer)."""
    data = {"email": "luis@example.com", "password": PASSWORD, "full_name": "Luis"}
    client.post("/auth/register", json=data)
    register_code = outbox[-1]["code"]
    login(client, data["email"])
    login_code = outbox[-1]["code"]

    if register_code != login_code:
        assert client.post("/auth/verify-otp", json={"email": data["email"], "code": register_code}).status_code == 401
    response = client.post("/auth/verify-otp", json={"email": data["email"], "code": login_code})
    assert response.status_code == 200
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.get("/users/profile", headers=headers).json()["email_verified"] is True


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


def test_web_interface_is_served(client):
    """La raíz sirve la interfaz web con CSP estricta y sus archivos estáticos."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "TaskGuard" in response.text
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/styles.css").status_code == 200


def test_health_endpoint(client):
    """El endpoint de salud responde sin autenticación."""
    assert client.get("/health").json() == {"status": "ok"}
