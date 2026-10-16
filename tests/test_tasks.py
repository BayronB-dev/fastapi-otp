"""Tests de integración del gestor de tareas."""

from datetime import date, timedelta

from tests.conftest import PASSWORD


def login_as(client, outbox, email: str, name: str = "Otro Usuario") -> dict:
    """Registra un usuario, completa login + OTP y devuelve su cabecera Authorization."""
    client.post("/auth/register", json={"email": email, "password": PASSWORD, "full_name": name})
    client.post("/auth/login", json={"email": email, "password": PASSWORD})
    token = client.post("/auth/verify-otp", json={"email": email, "code": outbox[-1]["code"]}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_tasks_require_authentication(client):
    """Sin token no se puede acceder a ninguna ruta de tareas."""
    assert client.get("/tasks").status_code == 401
    assert client.post("/tasks", json={"title": "x"}).status_code == 401
    assert client.get("/tasks/summary").status_code == 401
    assert client.delete("/tasks/1").status_code == 401


def test_task_crud(client, auth_headers):
    """Crear, leer, actualizar y eliminar una tarea."""
    response = client.post(
        "/tasks",
        headers=auth_headers,
        json={"title": "  Estudiar  ", "description": "JWT y OTP", "priority": "alta", "due_date": "2026-10-16"},
    )
    assert response.status_code == 201
    task = response.json()
    assert task["title"] == "Estudiar"  # se recortan los espacios
    assert task["completed"] is False

    assert client.get(f"/tasks/{task['id']}", headers=auth_headers).json()["priority"] == "alta"

    response = client.put(f"/tasks/{task['id']}", headers=auth_headers, json={"completed": True, "due_date": None})
    assert response.status_code == 200
    assert response.json()["completed"] is True
    assert response.json()["due_date"] is None
    assert response.json()["title"] == "Estudiar"  # lo no enviado no cambia

    assert client.put(f"/tasks/{task['id']}", headers=auth_headers, json={}).status_code == 400

    assert client.delete(f"/tasks/{task['id']}", headers=auth_headers).status_code == 204
    assert client.get(f"/tasks/{task['id']}", headers=auth_headers).status_code == 404


def test_task_validation(client, auth_headers):
    """Título vacío, prioridad inválida o fecha mal formada -> 422."""
    assert client.post("/tasks", headers=auth_headers, json={"title": "   "}).status_code == 422
    assert client.post("/tasks", headers=auth_headers, json={"title": "x", "priority": "urgente"}).status_code == 422
    assert client.post("/tasks", headers=auth_headers, json={"title": "x", "due_date": "mañana"}).status_code == 422


def test_users_cannot_access_each_others_tasks(client, auth_headers, outbox):
    """Un usuario no puede ver, editar ni borrar tareas de otro (recibe 404)."""
    task_id = client.post("/tasks", headers=auth_headers, json={"title": "Privada"}).json()["id"]
    other = login_as(client, outbox, "otro@example.com")

    assert client.get("/tasks", headers=other).json() == []
    assert client.get(f"/tasks/{task_id}", headers=other).status_code == 404
    assert client.put(f"/tasks/{task_id}", headers=other, json={"title": "Hackeada"}).status_code == 404
    assert client.delete(f"/tasks/{task_id}", headers=other).status_code == 404

    # La tarea sigue intacta para su dueño.
    assert client.get(f"/tasks/{task_id}", headers=auth_headers).json()["title"] == "Privada"


def test_list_filters_order_and_summary(client, auth_headers):
    """Filtros por estado, prioridad y búsqueda; orden y resumen del panel."""
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    tasks = [
        {"title": "Sin fecha", "priority": "baja"},
        {"title": "Vencida", "priority": "alta", "due_date": yesterday},
        {"title": "Mañana", "priority": "media", "due_date": tomorrow, "description": "repasar OTP"},
        {"title": "Hecha", "priority": "alta"},
    ]
    ids = {t["title"]: client.post("/tasks", headers=auth_headers, json=t).json()["id"] for t in tasks}
    client.put(f"/tasks/{ids['Hecha']}", headers=auth_headers, json={"completed": True})

    titles = [t["title"] for t in client.get("/tasks", headers=auth_headers).json()]
    assert titles == ["Vencida", "Mañana", "Sin fecha", "Hecha"]

    pending = client.get("/tasks", headers=auth_headers, params={"completed": False}).json()
    assert {t["title"] for t in pending} == {"Vencida", "Mañana", "Sin fecha"}

    high = client.get("/tasks", headers=auth_headers, params={"priority": "alta"}).json()
    assert {t["title"] for t in high} == {"Vencida", "Hecha"}

    found = client.get("/tasks", headers=auth_headers, params={"search": "otp"}).json()
    assert [t["title"] for t in found] == ["Mañana"]

    summary = client.get("/tasks/summary", headers=auth_headers).json()
    assert summary == {"total": 4, "completed": 1, "pending": 3, "overdue": 1}


def test_search_is_safe_against_sql_injection(client, auth_headers):
    """Un texto con SQL en la búsqueda se trata como texto normal."""
    client.post("/tasks", headers=auth_headers, json={"title": "Normal"})
    response = client.get("/tasks", headers=auth_headers, params={"search": "' OR '1'='1"})
    assert response.status_code == 200
    assert response.json() == []
