from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all, fetch_one
from app.dependencies import get_db, pagination_params, require_api_key
from app.schemas import ServerOut

router = APIRouter(prefix='/servers', tags=['servers'], dependencies=[Depends(require_api_key)])

SERVER_COLUMNS = (
    'id, inserted_at, epdg_domain, target_ip, mcc, mnc, country, iso3, network, operator, itu_region'
)


@router.get('', response_model=list[ServerOut])
async def list_servers(
    pagination: tuple[int, int] = Depends(pagination_params),
    db: AsyncSession = Depends(get_db),
):
    offset, limit = pagination
    query = f'SELECT {SERVER_COLUMNS} FROM epdg_server ORDER BY inserted_at DESC OFFSET :offset LIMIT :limit'
    rows = await fetch_all(db, query, {'offset': offset, 'limit': limit})
    return [ServerOut.model_validate(row) for row in rows]


@router.get('/{server_id}', response_model=ServerOut)
async def get_server(server_id: UUID, db: AsyncSession = Depends(get_db)):
    query = f'SELECT {SERVER_COLUMNS} FROM epdg_server WHERE id = :id'
    row = await fetch_one(db, query, {'id': str(server_id)})
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Server not found')
    return ServerOut.model_validate(row)
