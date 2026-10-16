# TaskGuard

Gestor de tareas con autenticación en dos pasos hecho con FastAPI. Para entrar se usa correo y contraseña, y después un código OTP de 6 dígitos que llega al correo y vale 15 minutos. Al verificarlo se obtiene un token JWT para acceder a las tareas.

- Aplicación: https://auth-otp-api.onrender.com
- Documentación de la API: https://auth-otp-api.onrender.com/docs

## Tecnologías

FastAPI, SQLAlchemy, SQLite, PyOTP, bcrypt, PyJWT, smtplib / Brevo, pytest. La interfaz está hecha con HTML, CSS y JavaScript sin frameworks.

## Funcionamiento

1. **Registro:** se crea la cuenta y se envía un código al correo. La cuenta queda sin verificar hasta confirmar ese código, así se comprueba que el correo existe y es del usuario.
2. **Login:** se validan correo y contraseña y se envía un código nuevo.
3. **Verificación:** con el código correcto se entrega un JWT que expira a los 30 minutos.
4. **Rutas protegidas:** un middleware revisa el token en `/users` y `/tasks`.
5. **Logout:** elimina la sesión de la base de datos, así que el token deja de funcionar aunque no haya expirado.

## Estructura

```
app/
├── main.py            # app, middlewares y manejo de errores
├── config.py          # variables de entorno
├── database.py        # conexión a SQLite
├── models.py          # tablas: users, otp_codes, login_sessions, tasks
├── schemas.py         # validación de datos (Pydantic)
├── security.py        # bcrypt y JWT
├── middleware.py      # validación del token y cabeceras de seguridad
├── rate_limit.py      # límite de peticiones por IP
├── routes/            # endpoints de auth, users y tasks
├── services/          # generación de OTP y envío de correos
└── static/            # interfaz web
tests/                 # tests unitarios y de integración
```

## Instalación local

```bash
git clone https://github.com/BayronB-dev/fastapi-otp.git
cd fastapi-otp
python -m venv .venv
.venv\Scripts\activate          # en Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env          # en Linux/macOS: cp .env.example .env
uvicorn app.main:app --reload
```

La aplicación queda en http://127.0.0.1:8000. En local el correo está en modo `console`: el código OTP se muestra en la terminal en vez de enviarse.

## Variables de entorno

Están todas en `.env.example`. Las principales:

| Variable | Uso |
|---|---|
| `SECRET_KEY` | Firma de los JWT |
| `ENVIRONMENT` | `development` o `production` |
| `EMAIL_BACKEND` | `console`, `smtp` o `brevo` |
| `BREVO_API_KEY`, `SMTP_FROM` | Envío de correos con Brevo |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD` | Envío de correos por SMTP |

## Endpoints

| Método | Ruta | Descripción | Auth |
|---|---|---|---|
| POST | `/auth/register` | Registro y envío del código de verificación | No |
| POST | `/auth/login` | Login y envío del OTP | No |
| POST | `/auth/verify-otp` | Verifica el OTP y devuelve el JWT | No |
| POST | `/auth/resend-otp` | Reenvía el OTP | No |
| POST | `/auth/refresh` | Renueva el token | Sí |
| POST | `/auth/logout` | Cierra la sesión y revoca el token | Sí |
| GET / PUT | `/users/profile` | Ver y editar el perfil | Sí |
| GET / POST | `/tasks` | Listar y crear tareas | Sí |
| GET | `/tasks/summary` | Resumen de tareas | Sí |
| GET / PUT / DELETE | `/tasks/{id}` | Ver, editar y eliminar una tarea | Sí |

## Seguridad

- Contraseñas guardadas con bcrypt.
- Los códigos OTP se guardan como hash, sirven una sola vez y vencen a los 15 minutos.
- JWT con expiración. Las sesiones se guardan en la base de datos para poder revocarlas.
- Rate limiting en registro, login y verificación del OTP.
- Cada usuario solo puede ver y modificar sus propias tareas.
- Cabeceras de seguridad (CSP, X-Frame-Options, entre otras) y protección contra XSS en la interfaz.
- Los errores y logs no muestran contraseñas, tokens ni códigos.

## Tests

```bash
pytest
```

Incluye tests unitarios (contraseñas, JWT, OTP, envío de correo) y de integración (flujo completo de autenticación y tareas). Usan una base de datos temporal y no envían correos reales.

## Despliegue

La aplicación está desplegada en Render con la configuración de `render.yaml` (Gunicorn con workers de Uvicorn). En Render hay que definir `BREVO_API_KEY` y `SMTP_FROM`.

El plan gratuito de Render bloquea los puertos SMTP, por eso en producción los correos se envían con la API de Brevo. El envío con `smtplib` sigue disponible con `EMAIL_BACKEND=smtp`.

En el plan gratuito la base de datos se reinicia con cada despliegue y el servicio se suspende tras unos minutos sin uso.
