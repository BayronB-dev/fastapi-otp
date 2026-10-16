# TaskGuard — Gestor de tareas con autenticación OTP (FastAPI)

Aplicación web de gestión de tareas protegida por un sistema de autenticación en dos pasos: el usuario inicia sesión con correo y contraseña, recibe un **código OTP de 6 dígitos por correo** (válido 15 minutos) y, al verificarlo, obtiene un **token JWT** con el que accede a sus tareas.

**Stack:** FastAPI · SQLAlchemy · SQLite · PyOTP · bcrypt · PyJWT · smtplib / Brevo · pytest · HTML + CSS + JavaScript

---

## Contenido

- [Funcionalidades](#funcionalidades)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Instalación local](#instalación-local)
- [Variables de entorno](#variables-de-entorno)
- [Endpoints](#endpoints)
- [Ejemplo de uso con la API](#ejemplo-de-uso-con-la-api)
- [Seguridad](#seguridad)
- [Base de datos](#base-de-datos)
- [Tests](#tests)
- [Despliegue en Render](#despliegue-en-render)

---

## Funcionalidades

### Autenticación (requisitos del parcial)

1. Registro de usuarios con validación de email: se comprueba el formato y, además, que el correo **existe y es del usuario**: el registro envía un OTP y la cuenta queda sin verificar hasta confirmarlo. Un registro abandonado sin verificar puede reclamarlo el dueño real del correo pasados 15 minutos.
2. Login con correo y contraseña (primer factor).
3. Generación de código OTP de 6 dígitos con validez de 15 minutos.
4. Envío del OTP por correo electrónico (SMTP con `smtplib`, o API HTTPS de Brevo en producción).
5. Verificación del OTP (segundo factor). Cada código sirve una sola vez.
6. Tokens JWT con expiración (`exp`).
7. Rutas protegidas que requieren autenticación.
8. Middleware que valida el token en cada petición protegida.
9. Cierre de sesión con revocación del token.
10. Manejo de errores con códigos HTTP adecuados (201, 204, 400, 401, 404, 409, 422, 429, 500).

Extras: refresco de token con rotación, reenvío de OTP, rate limiting, cabeceras de seguridad HTTP y documentación interactiva en `/docs`.

### Gestor de tareas (sistema protegido)

- Crear, listar, editar, completar y eliminar tareas (título, descripción, prioridad y fecha límite).
- Filtros por estado y prioridad, y búsqueda por texto.
- Resumen con tareas totales, pendientes, completadas y vencidas.
- Cada usuario solo ve y modifica **sus propias** tareas.

### Interfaz web

Servida por el mismo FastAPI en `/`: registro, login, pantalla del código OTP (con cuenta atrás y reenvío), panel de tareas y edición de perfil. Funciona en móvil y respeta el modo oscuro del sistema.

## Estructura del proyecto

```
parcial-fastapi-otp/
├── app/
│   ├── main.py              # Aplicación, middlewares, routers, errores e interfaz web
│   ├── config.py            # Configuración desde variables de entorno (.env)
│   ├── database.py          # Motor SQLAlchemy, sesiones y creación de tablas
│   ├── models.py            # Modelos: users, otp_codes, login_sessions, tasks
│   ├── schemas.py           # Esquemas Pydantic (validación y respuestas)
│   ├── security.py          # bcrypt, creación/validación de JWT
│   ├── middleware.py        # Middleware de autenticación JWT y cabeceras de seguridad
│   ├── dependencies.py      # Dependencia get_current_user
│   ├── rate_limit.py        # Rate limiting por IP y endpoint
│   ├── routes/
│   │   ├── auth.py          # /auth/*
│   │   ├── users.py         # /users/*
│   │   └── tasks.py         # /tasks/*
│   ├── services/
│   │   ├── email_service.py # Envío de correos (smtplib / Brevo)
│   │   └── otp_service.py   # Generación y validación de OTP
│   └── static/              # Interfaz web (index.html, styles.css, app.js)
├── tests/
│   ├── conftest.py          # Fixtures (BD temporal, cliente, correo simulado)
│   ├── test_unit.py         # Tests unitarios
│   ├── test_integration.py  # Tests de integración de autenticación
│   └── test_tasks.py        # Tests de integración del gestor de tareas
├── .env.example
├── requirements.txt
├── Procfile                 # Comando de arranque (Railway / Heroku)
├── render.yaml              # Blueprint de despliegue en Render
└── pytest.ini
```

## Instalación local

Requisitos: Python 3.9 o superior (probado con 3.11).

```bash
git clone https://github.com/BayronB-dev/fastapi-otp.git
cd fastapi-otp

python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env      # en Windows: copy .env.example .env
# Edita .env y define SECRET_KEY

uvicorn app.main:app --reload
```

- Interfaz web: `http://127.0.0.1:8000`
- Documentación de la API: `http://127.0.0.1:8000/docs`

> Con `EMAIL_BACKEND=console` (valor por defecto) el código OTP **no se envía**: aparece en la consola del servidor. Es útil para desarrollar sin configurar correo. En producción debe usarse `smtp` o `brevo`.

## Variables de entorno

| Variable | Descripción | Valor por defecto |
|---|---|---|
| `ENVIRONMENT` | `development` / `production`. En producción la app no arranca si falta `SECRET_KEY` o la configuración de correo | `development` |
| `SECRET_KEY` | Clave para firmar los JWT y los hashes de OTP | clave de desarrollo |
| `JWT_ALGORITHM` | Algoritmo de firma del JWT | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Minutos de validez del JWT | `30` |
| `DATABASE_URL` | Cadena de conexión de SQLAlchemy | `sqlite:///./app.db` |
| `OTP_EXPIRE_MINUTES` | Minutos de validez del OTP | `15` |
| `EMAIL_BACKEND` | `console` (log), `smtp` (smtplib) o `brevo` (API HTTPS) | `console` |
| `BREVO_API_KEY` | API key de Brevo (solo con `EMAIL_BACKEND=brevo`) | — |
| `SMTP_FROM` | Remitente de los correos (con Brevo debe estar verificado) | `SMTP_USER` |
| `SMTP_HOST` / `SMTP_PORT` | Servidor SMTP | `smtp.gmail.com` / `587` |
| `SMTP_USER` / `SMTP_PASSWORD` | Credenciales SMTP | — |
| `SMTP_USE_TLS` | Usar STARTTLS (puerto 587). Con el puerto 465 se usa SSL directo | `true` |
| `RATE_LIMIT_ENABLED` | Activa el rate limiting | `true` |

Generar una `SECRET_KEY` segura:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### ¿Por qué hay dos formas de enviar correo?

El envío está implementado con `smtplib` (librería estándar), como pide el enunciado. Sin embargo, el plan gratuito de Render **bloquea los puertos SMTP (25, 465 y 587)** desde septiembre de 2025, igual que los planes gratuitos de Railway. Por eso en el servidor se usa la API HTTPS de Brevo (puerto 443), que entrega el correo a cualquier destinatario. Las dos opciones generan el mismo correo (`build_otp_content`) y se eligen con `EMAIL_BACKEND`.

## Endpoints

| Método | Ruta | Descripción | Auth | Rate limit |
|---|---|---|---|---|
| POST | `/auth/register` | Registrar nuevo usuario y enviar OTP de verificación del correo | No | 5/min |
| POST | `/auth/login` | Login y envío de OTP | No | 5/min |
| POST | `/auth/verify-otp` | Verificar OTP y obtener JWT | No | 5/min |
| POST | `/auth/resend-otp` | Reenviar código OTP | No | 3/min |
| POST | `/auth/refresh` | Refrescar token JWT | Sí | — |
| POST | `/auth/logout` | Cerrar sesión y revocar token | Sí | — |
| GET | `/users/profile` | Ver perfil | Sí | — |
| PUT | `/users/profile` | Actualizar nombre y/o contraseña | Sí | — |
| GET | `/tasks` | Listar tareas (`completed`, `priority`, `search`) | Sí | — |
| POST | `/tasks` | Crear tarea | Sí | — |
| GET | `/tasks/summary` | Resumen (total, pendientes, completadas, vencidas) | Sí | — |
| GET | `/tasks/{id}` | Ver una tarea | Sí | — |
| PUT | `/tasks/{id}` | Editar una tarea (solo los campos enviados) | Sí | — |
| DELETE | `/tasks/{id}` | Eliminar una tarea | Sí | — |
| GET | `/` | Interfaz web | No | — |
| GET | `/health` | Estado del servicio | No | — |

Las rutas con autenticación requieren la cabecera `Authorization: Bearer <token>`.

### Códigos de respuesta

| Código | Cuándo |
|---|---|
| `200` | Operación correcta |
| `201` | Usuario o tarea creados |
| `204` | Tarea eliminada |
| `400` | Actualización sin datos o contraseña actual incorrecta |
| `401` | Credenciales, OTP o token inválidos/expirados/revocados |
| `404` | La tarea no existe o pertenece a otro usuario |
| `409` | El correo ya está registrado |
| `422` | Datos de entrada con formato inválido |
| `429` | Se superó el límite de peticiones (incluye cabecera `Retry-After`) |
| `500` | Error interno (mensaje genérico, sin detalles) |

## Ejemplo de uso con la API

```bash
# 1. Registro -> se envía un OTP para verificar el correo
curl -X POST http://127.0.0.1:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "ana@example.com", "password": "Secreta123", "full_name": "Ana Pérez"}'
# {"message": "Cuenta creada. Te enviamos un código...", "email": "a**@example.com", "otp_expires_in": 900}

# 2. En los siguientes inicios de sesión: login -> se envía un nuevo OTP
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "ana@example.com", "password": "Secreta123"}'

# 3. Verificar el OTP recibido (del registro o del login) -> JWT
curl -X POST http://127.0.0.1:8000/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "ana@example.com", "code": "482913"}'

# 4. Crear y listar tareas
curl -X POST http://127.0.0.1:8000/tasks -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"title": "Estudiar", "priority": "alta", "due_date": "2026-10-16"}'
curl http://127.0.0.1:8000/tasks -H "Authorization: Bearer <token>"

# 5. Cerrar sesión
curl -X POST http://127.0.0.1:8000/auth/logout -H "Authorization: Bearer <token>"
```

También se puede probar desde `/docs`: después de verificar el OTP, pulsa **Authorize** y pega el `access_token`.

## Seguridad

| Medida | Implementación |
|---|---|
| Contraseñas | Hash **bcrypt** con sal aleatoria (`security.py`). Nunca se guardan ni se devuelven en texto plano. Política: mínimo 8 caracteres con letras y números |
| OTP | 6 dígitos generados con PyOTP a partir de un secreto aleatorio nuevo; válido 15 minutos; **un solo uso**; al pedir uno nuevo se invalidan los anteriores. En la BD se guarda su **HMAC-SHA256**, no el código |
| JWT | Firmado con HS256 e incluye `sub`, `iat`, `exp` y `jti`. La expiración se valida al decodificar |
| Revocación | Cada token se registra en `login_sessions` (se guarda su hash SHA-256). El middleware exige que la sesión exista, así que `logout` y `refresh` invalidan el token aunque no haya expirado |
| Middleware | `AuthMiddleware` valida cabecera, firma, expiración y sesión antes de llegar a las rutas protegidas; responde `401` con `WWW-Authenticate: Bearer` |
| Autorización | Todas las consultas de tareas filtran por el usuario autenticado; pedir una tarea ajena devuelve `404` (no revela que existe) |
| Rate limiting | Ventana deslizante por IP y endpoint en registro, login, verificación y reenvío de OTP; responde `429` |
| Enumeración de usuarios | Login devuelve el mismo error si el correo no existe o la contraseña es incorrecta; `resend-otp` responde siempre igual |
| XSS | La interfaz inserta el contenido de los usuarios con `textContent` (nunca `innerHTML`); el nombre se escapa en el correo HTML; la cabecera **CSP** solo permite scripts y estilos del propio dominio |
| Cabeceras HTTP | `Content-Security-Policy`, `X-Frame-Options: DENY` (clickjacking), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Cache-Control: no-store` en la API y `Strict-Transport-Security` en producción |
| Inyección SQL | Todas las consultas usan SQLAlchemy con parámetros enlazados (incluida la búsqueda) |
| Token en el navegador | Se guarda en `sessionStorage` (se borra al cerrar la pestaña) y se renueva automáticamente antes de expirar |
| Errores y logs | Los errores 422 no repiten los valores enviados (evita exponer contraseñas); los 500 devuelven un mensaje genérico; los logs muestran el correo enmascarado y nunca contraseñas, tokens, códigos ni credenciales |
| Configuración | Los secretos se leen de variables de entorno; `.env` está en `.gitignore`; en producción la app no arranca con la clave de desarrollo ni sin la configuración de correo |
| Comparaciones | `hmac.compare_digest` para comparar los OTP (evita ataques de tiempo) |

## Base de datos

SQLite gestionada con SQLAlchemy. Las tablas se crean automáticamente al arrancar.

| Tabla | Campos | Descripción |
|---|---|---|
| `users` | `id`, `email`, `password_hash`, `full_name`, `email_verified`, `created_at`, `updated_at` | Usuarios registrados (`email_verified` se añadió para confirmar el correo) |
| `otp_codes` | `id`, `user_id`, `code`, `expires_at`, `used`, `created_at` | Códigos OTP (hash) con su expiración |
| `login_sessions` | `id`, `user_id`, `token`, `expires_at`, `created_at` | Sesiones activas (hash del token) |
| `tasks` | `id`, `user_id`, `title`, `description`, `priority`, `due_date`, `completed`, `created_at`, `updated_at` | Tareas de cada usuario |

## Tests

```bash
pytest
```

Los tests usan una base de datos temporal y un envío de correo simulado, así que no necesitan conexión ni credenciales.

- **Unitarios** (`tests/test_unit.py`): hashing de contraseñas, creación/expiración/manipulación de JWT, generación y validación de OTP (uso único, expiración, invalidación), envío por Brevo (simulado) sin filtrar secretos, enmascarado de correo, validaciones de esquemas, configuración de producción, rutas protegidas y rate limiter.
- **Integración de autenticación** (`tests/test_integration.py`): flujo completo registro → verificación del correo → login → OTP → perfil → refresh → logout, registro duplicado e inválido, reclamación de registros sin verificar, credenciales incorrectas, OTP incorrecto/reutilizado/expirado, rutas protegidas sin token, reenvío de OTP, actualización de perfil, rate limiting, cabeceras de seguridad e interfaz web.
- **Integración de tareas** (`tests/test_tasks.py`): CRUD, validaciones, aislamiento entre usuarios, filtros, orden, resumen e intento de inyección SQL.

## Despliegue en Render

1. **Brevo** (envío de correos):
   - Crea una cuenta gratuita en [brevo.com](https://www.brevo.com).
   - En **Senders, Domains & Dedicated IPs → Senders**, añade y verifica el correo remitente.
   - En **SMTP & API → API Keys**, genera una API key.
2. En [Render](https://render.com) elige **New → Blueprint** y selecciona el repositorio. Render lee `render.yaml` y crea el servicio con:
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn app.main:app -k uvicorn_worker.UvicornWorker -w 1 --bind 0.0.0.0:$PORT`
   - `SECRET_KEY` generada automáticamente, `ENVIRONMENT=production` y `EMAIL_BACKEND=brevo`.
3. Completa las variables `BREVO_API_KEY` y `SMTP_FROM` (el correo verificado en Brevo).
4. Al terminar el despliegue, abre `https://<tu-servicio>.onrender.com`.

Para **Railway** o **Heroku** se usa el `Procfile` con el mismo comando y las variables de entorno de la tabla anterior.

**Notas:**
- En el plan gratuito de Render el disco es efímero: la base SQLite se reinicia en cada despliegue o reinicio. Para conservar datos se puede añadir un disco persistente y apuntar `DATABASE_URL` a él.
- El servicio gratuito se suspende tras ~15 minutos sin uso; la primera petición posterior tarda unos 50 segundos.
- Se usa un solo worker porque SQLite y el rate limiter en memoria no se comparten entre procesos.
