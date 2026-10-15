# Sistema de Autenticación con OTP — FastAPI

API REST de autenticación en dos pasos: el usuario inicia sesión con correo y contraseña, recibe un **código OTP de 6 dígitos por correo** (válido 15 minutos) y, al verificarlo, obtiene un **token JWT** para acceder a las rutas protegidas.

**Stack:** FastAPI · SQLAlchemy · SQLite · PyOTP · bcrypt · PyJWT · smtplib · pytest

---

## Contenido

- [Funcionalidades](#funcionalidades)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Instalación local](#instalación-local)
- [Variables de entorno](#variables-de-entorno)
- [Endpoints](#endpoints)
- [Ejemplo de uso](#ejemplo-de-uso)
- [Seguridad](#seguridad)
- [Base de datos](#base-de-datos)
- [Tests](#tests)
- [Despliegue en Render](#despliegue-en-render)

---

## Funcionalidades

1. Registro de usuarios con validación de formato de correo y fortaleza de contraseña.
2. Login con correo y contraseña (primer factor).
3. Generación de código OTP de 6 dígitos con validez de 15 minutos.
4. Envío del OTP por correo electrónico (SMTP con `smtplib`).
5. Verificación del OTP (segundo factor). Cada código sirve una sola vez.
6. Tokens JWT con expiración (`exp`).
7. Rutas protegidas que requieren autenticación.
8. Middleware que valida el token en cada petición protegida.
9. Cierre de sesión con revocación del token.
10. Manejo de errores con códigos HTTP adecuados (201, 400, 401, 409, 422, 429, 500).

Extras: refresco de token con rotación, reenvío de OTP, rate limiting y documentación interactiva en `/docs`.

## Estructura del proyecto

```
parcial-fastapi-otp/
├── app/
│   ├── __init__.py
│   ├── main.py              # Aplicación, middleware, routers y manejadores de errores
│   ├── config.py            # Configuración desde variables de entorno (.env)
│   ├── database.py          # Motor SQLAlchemy, sesiones y creación de tablas
│   ├── models.py            # Modelos: users, otp_codes, login_sessions
│   ├── schemas.py           # Esquemas Pydantic (validación y respuestas)
│   ├── security.py          # bcrypt, creación/validación de JWT
│   ├── middleware.py        # Middleware de autenticación JWT
│   ├── dependencies.py      # Dependencia get_current_user
│   ├── rate_limit.py        # Rate limiting por IP y endpoint
│   ├── routes/
│   │   ├── auth.py          # /auth/*
│   │   └── users.py         # /users/*
│   └── services/
│       ├── email_service.py # Envío de correos (smtplib)
│       └── otp_service.py   # Generación y validación de OTP
├── tests/
│   ├── conftest.py          # Fixtures (BD temporal, cliente, correo simulado)
│   ├── test_unit.py         # Tests unitarios
│   └── test_integration.py  # Tests de integración
├── .env.example
├── requirements.txt
├── Procfile                 # Comando de arranque (Railway / Heroku)
├── render.yaml              # Blueprint de despliegue en Render
└── pytest.ini
```

## Instalación local

Requisitos: Python 3.9 o superior (probado con 3.11).

```bash
git clone <url-del-repositorio>
cd parcial-fastapi-otp

python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env      # en Windows: copy .env.example .env
# Edita .env y define SECRET_KEY (y los datos SMTP si quieres enviar correos reales)

uvicorn app.main:app --reload
```

La API queda en `http://127.0.0.1:8000` y la documentación interactiva en `http://127.0.0.1:8000/docs`.

> Con `EMAIL_BACKEND=console` (valor por defecto) el código OTP **no se envía**: aparece en la consola del servidor. Es útil para desarrollar sin configurar SMTP. En producción debe usarse `smtp`.

## Variables de entorno

| Variable | Descripción | Valor por defecto |
|---|---|---|
| `ENVIRONMENT` | `development` / `production`. En producción se exige `SECRET_KEY` propia y `EMAIL_BACKEND=smtp` | `development` |
| `SECRET_KEY` | Clave para firmar los JWT y los hashes de OTP | clave de desarrollo |
| `JWT_ALGORITHM` | Algoritmo de firma del JWT | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Minutos de validez del JWT | `30` |
| `DATABASE_URL` | Cadena de conexión de SQLAlchemy | `sqlite:///./app.db` |
| `OTP_EXPIRE_MINUTES` | Minutos de validez del OTP | `15` |
| `EMAIL_BACKEND` | `console` (log) o `smtp` (envío real) | `console` |
| `SMTP_HOST` / `SMTP_PORT` | Servidor SMTP | `smtp.gmail.com` / `587` |
| `SMTP_USER` / `SMTP_PASSWORD` | Credenciales SMTP | — |
| `SMTP_FROM` | Remitente de los correos | `SMTP_USER` |
| `SMTP_USE_TLS` | Usar STARTTLS (puerto 587). Con el puerto 465 se usa SSL directo | `true` |
| `RATE_LIMIT_ENABLED` | Activa el rate limiting | `true` |

Generar una `SECRET_KEY` segura:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

**Gmail:** activa la verificación en dos pasos en tu cuenta y crea una [contraseña de aplicación](https://myaccount.google.com/apppasswords); úsala en `SMTP_PASSWORD`.

## Endpoints

| Método | Ruta | Descripción | Auth | Rate limit |
|---|---|---|---|---|
| POST | `/auth/register` | Registrar nuevo usuario | No | 5/min |
| POST | `/auth/login` | Login y envío de OTP | No | 5/min |
| POST | `/auth/verify-otp` | Verificar OTP y obtener JWT | No | 5/min |
| POST | `/auth/resend-otp` | Reenviar código OTP | No | 3/min |
| POST | `/auth/refresh` | Refrescar token JWT | Sí | — |
| POST | `/auth/logout` | Cerrar sesión y revocar token | Sí | — |
| GET | `/users/profile` | Ver perfil | Sí | — |
| PUT | `/users/profile` | Actualizar nombre y/o contraseña | Sí | — |
| GET | `/health` | Estado del servicio | No | — |

Las rutas con autenticación requieren la cabecera `Authorization: Bearer <token>`.

### Códigos de respuesta

| Código | Cuándo |
|---|---|
| `200` | Operación correcta |
| `201` | Usuario registrado |
| `400` | Actualización de perfil inválida (p. ej. contraseña actual incorrecta) |
| `401` | Credenciales, OTP o token inválidos/expirados/revocados |
| `409` | El correo ya está registrado |
| `422` | Datos de entrada con formato inválido |
| `429` | Se superó el límite de peticiones (incluye cabecera `Retry-After`) |
| `500` | Error interno (mensaje genérico, sin detalles) |

## Ejemplo de uso

```bash
# 1. Registro
curl -X POST http://127.0.0.1:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "ana@example.com", "password": "Secreta123", "full_name": "Ana Pérez"}'

# 2. Login -> se envía el OTP al correo
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "ana@example.com", "password": "Secreta123"}'
# {"message": "Se envió un código de verificación a tu correo", "email": "a**@example.com", "otp_expires_in": 900}

# 3. Verificar el OTP recibido -> JWT
curl -X POST http://127.0.0.1:8000/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "ana@example.com", "code": "482913"}'
# {"access_token": "eyJhbGciOi...", "token_type": "bearer", "expires_in": 1800}

# 4. Ruta protegida
curl http://127.0.0.1:8000/users/profile -H "Authorization: Bearer <token>"

# 5. Refrescar token (el anterior queda revocado)
curl -X POST http://127.0.0.1:8000/auth/refresh -H "Authorization: Bearer <token>"

# 6. Cerrar sesión
curl -X POST http://127.0.0.1:8000/auth/logout -H "Authorization: Bearer <token>"
```

También se puede probar todo desde `/docs`: después de verificar el OTP, pulsa **Authorize** y pega el `access_token`.

## Seguridad

| Medida | Implementación |
|---|---|
| Contraseñas | Hash **bcrypt** con sal aleatoria (`security.py`). Nunca se guardan ni se devuelven en texto plano. Política: mínimo 8 caracteres con letras y números |
| OTP | 6 dígitos generados con PyOTP a partir de un secreto aleatorio nuevo; válido 15 minutos; **un solo uso**; al pedir uno nuevo se invalidan los anteriores. En la BD se guarda su **HMAC-SHA256**, no el código |
| JWT | Firmado con HS256 e incluye `sub`, `iat`, `exp` y `jti`. La expiración se valida al decodificar |
| Revocación | Cada token se registra en `login_sessions` (se guarda su hash SHA-256). El middleware exige que la sesión exista, así que `logout` y `refresh` invalidan el token aunque no haya expirado |
| Middleware | `AuthMiddleware` valida cabecera, firma, expiración y sesión antes de llegar a las rutas protegidas; responde `401` con `WWW-Authenticate: Bearer` |
| Rate limiting | Ventana deslizante por IP y endpoint en registro, login, verificación y reenvío de OTP; responde `429` |
| Enumeración de usuarios | Login devuelve el mismo error si el correo no existe o la contraseña es incorrecta; `resend-otp` responde siempre igual |
| Errores y logs | Los errores 422 no repiten los valores enviados (evita exponer contraseñas); los 500 devuelven un mensaje genérico; los logs muestran el correo enmascarado y nunca contraseñas, tokens ni credenciales SMTP |
| Configuración | Los secretos se leen de variables de entorno; `.env` está en `.gitignore`; en producción la app no arranca con la clave de desarrollo |
| Comparaciones | `hmac.compare_digest` para comparar los OTP (evita ataques de tiempo) |

## Base de datos

SQLite gestionada con SQLAlchemy. Las tablas se crean automáticamente al arrancar.

| Tabla | Campos | Descripción |
|---|---|---|
| `users` | `id`, `email`, `password_hash`, `full_name`, `created_at`, `updated_at` | Usuarios registrados |
| `otp_codes` | `id`, `user_id`, `code`, `expires_at`, `used`, `created_at` | Códigos OTP (hash) con su expiración |
| `login_sessions` | `id`, `user_id`, `token`, `expires_at`, `created_at` | Sesiones activas (hash del token) |

## Tests

```bash
pytest
```

Los tests usan una base de datos temporal y un envío de correo simulado, así que no necesitan SMTP.

- **Unitarios** (`tests/test_unit.py`): hashing de contraseñas, creación/expiración/manipulación de JWT, generación y validación de OTP (uso único, expiración, invalidación), enmascarado de correo, validaciones de esquemas, rutas protegidas y rate limiter.
- **Integración** (`tests/test_integration.py`): flujo completo registro → login → OTP → perfil → refresh → logout, registro duplicado e inválido, credenciales incorrectas, OTP incorrecto/reutilizado/expirado, rutas protegidas sin token, reenvío de OTP, actualización de perfil y rate limiting.

## Despliegue en Render

1. Sube el repositorio a GitHub.
2. En [Render](https://render.com) elige **New → Blueprint** y selecciona el repositorio. Render lee `render.yaml` y crea el servicio con:
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn app.main:app -k uvicorn_worker.UvicornWorker -w 1 --bind 0.0.0.0:$PORT`
   - `SECRET_KEY` generada automáticamente y `ENVIRONMENT=production`.
3. Completa en el panel las variables `SMTP_USER`, `SMTP_PASSWORD` y `SMTP_FROM`.
4. Al terminar el despliegue, abre `https://<tu-servicio>.onrender.com/docs`.

Para **Railway** o **Heroku** se usa el `Procfile` con el mismo comando y las variables de entorno de la tabla anterior.

**Notas:**
- En el plan gratuito de Render el disco es efímero: la base SQLite se reinicia en cada despliegue o reinicio. Para conservar datos se puede añadir un disco persistente y apuntar `DATABASE_URL` a él.
- Se usa un solo worker porque SQLite y el rate limiter en memoria no se comparten entre procesos.
- Si el proveedor bloquea el puerto SMTP 587, prueba con el 465 (SSL) o con un servicio SMTP como Brevo o SendGrid.
