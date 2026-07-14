from collections.abc import AsyncGenerator
import logging
import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings
from app.errors import DatabaseUnavailableError

settings = get_settings()
logger = logging.getLogger("backend_api.db")

engine = create_async_engine(
    settings.resolved_database_url,
    pool_pre_ping=True,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_timeout=settings.db_pool_timeout_seconds,
    pool_recycle=settings.db_pool_recycle_seconds,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def _execute(session: AsyncSession, query: str, params: dict[str, Any] | None = None):
    started = time.perf_counter()
    try:
        result = await session.execute(text(query), params or {})
        duration_ms = (time.perf_counter() - started) * 1000
        if duration_ms >= settings.db_slow_query_ms:
            logger.warning(
                "slow_query duration_ms=%.2f threshold_ms=%d",
                duration_ms,
                settings.db_slow_query_ms,
            )
        return result
    except SQLAlchemyError as exc:
        raise DatabaseUnavailableError() from exc


async def fetch_all(session: AsyncSession, query: str, params: dict[str, Any] | None = None):
    result = await _execute(session, query, params)
    return list(result.mappings().all())


async def fetch_one(session: AsyncSession, query: str, params: dict[str, Any] | None = None):
    result = await _execute(session, query, params)
    return result.mappings().first()


async def database_ready() -> bool:
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text('SELECT 1'))
        return True
    except SQLAlchemyError:
        return False
