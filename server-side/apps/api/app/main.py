import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.db import database_ready
from app.errors import register_exception_handlers
from app.logging_config import configure_logging
from app.routes.all_results import router as all_results_router
from app.routes.latest_results import router as latest_results_router
from app.routes.results import router as results_router
from app.routes.scans import router as scans_router
from app.routes.servers import router as servers_router
from app.routes.collisions_latest import router as collisions_router
from app.routes.collision_keys import router as collision_keys_router
from app.routes.map import router as map_router
from app.routes.takeout import router as takeout_router
from fastapi.middleware.cors import CORSMiddleware

settings = get_settings()

configure_logging(
    settings.log_level, "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("backend_api.request")

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url="/redoc" if settings.enable_docs else None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)

_UNTHROTTLED_PATHS = {"/health", "/ready"}
_WINDOW_SECONDS = 60.0
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)
_blocked_until: dict[str, float] = {}
_rate_limit_lock = asyncio.Lock()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# Returns seconds until the client is not rate limited anymore, or None if not rate limited.
async def _rate_limit_retry_after(client_ip: str) -> float | None:
    now = time.monotonic()
    async with _rate_limit_lock:
        blocked_until = _blocked_until.get(client_ip)
        if blocked_until is not None:
            if now < blocked_until:
                return blocked_until - now
            del _blocked_until[client_ip]

        bucket = _rate_buckets[client_ip]
        while bucket and now - bucket[0] > _WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= settings.rate_limit_requests_per_minute:
            _blocked_until[client_ip] = now + settings.rate_limit_timeout_seconds
            bucket.clear()
            return settings.rate_limit_timeout_seconds
        bucket.append(now)
        return None


def _add_response_headers(response, request_id: str) -> None:
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"


def _log_request(
    request: Request, request_id: str, status_code: int, duration_ms: float
) -> None:
    logger.info(
        json.dumps(
            {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_ms": round(duration_ms, 2),
                "client_ip": _client_ip(request),
            }
        )
    )


@app.middleware("http")
async def request_context_and_security(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    request.state.request_id = request_id

    if settings.enable_rate_limit and request.url.path not in _UNTHROTTLED_PATHS:
        retry_after = await _rate_limit_retry_after(_client_ip(request))
        if retry_after is not None:
            response = JSONResponse(
                status_code=429, content={"detail": "Too many requests"}
            )
            response.headers["Retry-After"] = str(max(1, round(retry_after)))
            _add_response_headers(response, request_id)
            return response

    started = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - started) * 1000

    _add_response_headers(response, request_id)
    _log_request(request, request_id, response.status_code, duration_ms)
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8081",
        "https://vowifi-watchdog.sec.univie.ac.at",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready", tags=["system"])
async def ready() -> dict[str, str]:
    if not await database_ready():
        raise HTTPException(status_code=503, detail="Database temporarily unavailable")
    return {"status": "ready"}


register_exception_handlers(app)

for router in (
    servers_router,
    scans_router,
    results_router,
    latest_results_router,
    all_results_router,
    map_router,
    collisions_router,
    collision_keys_router,
    takeout_router,
):
    app.include_router(router, prefix=settings.api_v1_prefix)
