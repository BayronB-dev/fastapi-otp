"""Endpoints del gestor de tareas. Todos requieren autenticación.

Cada usuario solo puede ver y modificar sus propias tareas: todas las
consultas filtran por ``user_id``. Si se pide una tarea de otro usuario se
responde 404 (no 403) para no revelar que esa tarea existe.
"""

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import Task, User
from app.schemas import Priority, TaskCreate, TaskOut, TaskSummary, TaskUpdate

router = APIRouter(prefix="/tasks", tags=["Tareas"])


def get_user_task(db: Session, user: User, task_id: int) -> Task:
    """Obtiene una tarea del usuario o lanza 404 si no existe o es de otro usuario."""
    task = db.scalars(select(Task).where(Task.id == task_id, Task.user_id == user.id)).first()
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tarea no encontrada")
    return task


@router.get("", response_model=list[TaskOut])
def list_tasks(
    completed: bool | None = Query(default=None, description="Filtrar por estado"),
    priority: Priority | None = Query(default=None, description="Filtrar por prioridad"),
    search: str | None = Query(default=None, max_length=100, description="Buscar en título o descripción"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Task]:
    """Lista las tareas del usuario con filtros opcionales.

    Orden: primero las pendientes; dentro de cada grupo, por fecha límite
    (las que no tienen fecha al final) y luego las más recientes.
    """
    query = select(Task).where(Task.user_id == user.id)
    if completed is not None:
        query = query.where(Task.completed.is_(completed))
    if priority is not None:
        query = query.where(Task.priority == priority)
    if search:
        # SQLAlchemy usa parámetros enlazados, así que el texto no puede inyectar SQL.
        pattern = f"%{search.strip()}%"
        query = query.where(or_(Task.title.ilike(pattern), Task.description.ilike(pattern)))

    query = query.order_by(Task.completed, Task.due_date.is_(None), Task.due_date, Task.created_at.desc())
    return list(db.scalars(query))


@router.get("/summary", response_model=TaskSummary)
def task_summary(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> TaskSummary:
    """Cuenta las tareas totales, completadas, pendientes y vencidas del usuario."""
    base = select(func.count()).select_from(Task).where(Task.user_id == user.id)
    total = db.scalar(base) or 0
    completed = db.scalar(base.where(Task.completed.is_(True))) or 0
    overdue = db.scalar(base.where(Task.completed.is_(False), Task.due_date < date.today())) or 0
    return TaskSummary(total=total, completed=completed, pending=total - completed, overdue=overdue)


@router.post("", response_model=TaskOut, status_code=status.HTTP_201_CREATED)
def create_task(data: TaskCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Task:
    """Crea una tarea para el usuario autenticado."""
    task = Task(user_id=user.id, **data.model_dump())
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


@router.get("/{task_id}", response_model=TaskOut, responses={404: {"description": "Tarea no encontrada"}})
def get_task(task_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Task:
    """Devuelve una tarea del usuario."""
    return get_user_task(db, user, task_id)


@router.put("/{task_id}", response_model=TaskOut, responses={404: {"description": "Tarea no encontrada"}})
def update_task(
    task_id: int, data: TaskUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Task:
    """Actualiza los campos enviados de una tarea (los demás no cambian).

    Solo ``due_date`` acepta ``null`` (para quitar la fecha límite); en el resto
    de campos un ``null`` se ignora.
    """
    task = get_user_task(db, user, task_id)
    changes = {
        field: value
        for field, value in data.model_dump(exclude_unset=True).items()
        if value is not None or field == "due_date"
    }
    if not changes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No se envió ningún campo para actualizar")
    for field, value in changes.items():
        setattr(task, field, value)
    db.commit()
    db.refresh(task)
    return task


@router.delete(
    "/{task_id}", status_code=status.HTTP_204_NO_CONTENT, responses={404: {"description": "Tarea no encontrada"}}
)
def delete_task(task_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Response:
    """Elimina una tarea del usuario."""
    task = get_user_task(db, user, task_id)
    db.delete(task)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
