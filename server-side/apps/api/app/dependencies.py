from collections.abc import AsyncGenerator

from fastapi import Header, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_db_session


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_db_session():
        yield session


async def require_api_key(
    x_api_key: str | None = Header(default=None),
    api_key: str | None = Query(default=None),
) -> None:
    settings = get_settings()
    expected_key = settings.resolved_api_key
    if not expected_key:
        return

    provided_key = x_api_key or api_key
    if provided_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key"
        )


def pagination_params(
    offset: int = Query(default=0, ge=0),
    limit: int | None = Query(default=None, ge=1),
) -> tuple[int, int]:
    settings = get_settings()
    resolved_limit = settings.default_limit if limit is None else limit

    if resolved_limit > settings.max_limit:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"limit must be <= {settings.max_limit}",
        )

    return offset, resolved_limit
