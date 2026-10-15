"""Rate limiting sencillo en memoria para proteger endpoints críticos."""

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from app.config import settings


class RateLimiter:
    """Limita a ``times`` peticiones cada ``seconds`` segundos por IP y endpoint.

    Usa una ventana deslizante: por cada clave se guardan las marcas de tiempo
    de las peticiones recientes y se descartan las que salen de la ventana.

    Se usa como dependencia de FastAPI::

        @router.post("/login", dependencies=[Depends(RateLimiter(times=5, seconds=60))])

    Nota: el estado vive en memoria del proceso. Con varios workers cada uno
    lleva su propia cuenta; para algo distribuido habría que usar Redis.
    """

    def __init__(self, times: int, seconds: int) -> None:
        """Configura el límite de peticiones permitidas en la ventana de tiempo."""
        self.times = times
        self.seconds = seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def reset(self) -> None:
        """Borra todos los contadores (útil en los tests)."""
        with self._lock:
            self._hits.clear()

    def __call__(self, request: Request) -> None:
        """Registra la petición y lanza 429 si se superó el límite."""
        if not settings.rate_limit_enabled:
            return

        client_ip = request.client.host if request.client else "unknown"
        key = f"{client_ip}:{request.url.path}"
        now = time.monotonic()

        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.seconds:
                hits.popleft()
            if len(hits) >= self.times:
                retry_after = int(self.seconds - (now - hits[0])) + 1
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Demasiadas solicitudes. Inténtalo de nuevo más tarde.",
                    headers={"Retry-After": str(retry_after)},
                )
            hits.append(now)


# Límites por endpoint (peticiones / segundos).
register_limiter = RateLimiter(times=5, seconds=60)
login_limiter = RateLimiter(times=5, seconds=60)
verify_otp_limiter = RateLimiter(times=5, seconds=60)
resend_otp_limiter = RateLimiter(times=3, seconds=60)

ALL_LIMITERS = (register_limiter, login_limiter, verify_otp_limiter, resend_otp_limiter)
