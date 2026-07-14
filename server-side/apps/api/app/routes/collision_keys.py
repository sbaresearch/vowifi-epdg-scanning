from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all
from app.dependencies import get_db, pagination_params, require_api_key
from app.schemas import CollisionKeyOut

router = APIRouter(
    prefix="/collision-keys",
    tags=["collision_keys"],
    dependencies=[Depends(require_api_key)],
)


@router.get("", response_model=list[CollisionKeyOut])
async def list_collision_keys(
    pagination: tuple[int, int] = Depends(pagination_params),
    db: AsyncSession = Depends(get_db),
):
    offset, limit = pagination
    query = """
        SELECT key, usage_count, dh_variant, operators, server_ids, inserted_at, updated_at
        FROM collision_keys
        ORDER BY usage_count DESC
        OFFSET :offset LIMIT :limit
        """
    rows = await fetch_all(db, query, {"offset": offset, "limit": limit})
    return [CollisionKeyOut.model_validate(row) for row in rows]
