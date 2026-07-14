from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all
from app.dependencies import get_db, pagination_params, require_api_key
from app.schemas import CollisionOut

router = APIRouter(
    prefix="/collisions-latest", tags=["collisions"], dependencies=[Depends(require_api_key)]
)


@router.get("", response_model=list[CollisionOut])
async def list_scans(
    pagination: tuple[int, int] = Depends(pagination_params),
    db: AsyncSession = Depends(get_db),
):
    offset, limit = pagination
    query = """
        SELECT
            r.key_hex,
            COUNT(DISTINCT r.server_id) AS server_count,
            COUNT(DISTINCT s.target_ip) AS ip_count,
            jsonb_agg(
                jsonb_build_object(
                    'server_id',  r.server_id,
                    'target_ip',  s.target_ip,
                    'operator',   s.operator,
                    'country',    s.country,
                    'dh_variant', r.dh_variant
                )
                ORDER BY s.country, s.operator
            ) AS servers
        FROM latest_epdg_result r
        JOIN epdg_server s ON s.id = r.server_id
        WHERE r.key_hex IS NOT NULL
        AND r.dh_variant NOT IN ('DOWNGRADE_DH2048', 'TOLERATE_DH1024')
        GROUP BY r.key_hex
        HAVING COUNT(DISTINCT r.server_id) > 1
        AND COUNT(DISTINCT s.target_ip) > 1
        ORDER BY server_count DESC
        OFFSET :offset LIMIT :limit
        """
    rows = await fetch_all(db, query, {"offset": offset, "limit": limit})
    return [CollisionOut.model_validate(row) for row in rows]
