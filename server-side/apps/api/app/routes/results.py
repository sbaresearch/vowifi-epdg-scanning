from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all, fetch_one
from app.dependencies import get_db, pagination_params, require_api_key
from app.schemas import IKEResult, ResultOut

router = APIRouter(prefix='/results', tags=['results'], dependencies=[Depends(require_api_key)])

RESULT_COLUMNS = (
    'id, inserted_at, scan_id, server_id, observed_at, raw_state, result, '
    'dh_group, encr_id, encr_key_len, integ_id, prf_id, key_hex, nonce_hex'
)


@router.get('', response_model=list[ResultOut])
async def list_results(
    scan_id: UUID | None = None,
    server_id: UUID | None = None,
    key_hex: str | None = None,
    result: IKEResult | None = Query(default=None),
    pagination: tuple[int, int] = Depends(pagination_params),
    db: AsyncSession = Depends(get_db),
):
    offset, limit = pagination

    conditions: list[str] = []
    params: dict[str, object] = {'offset': offset, 'limit': limit}

    if scan_id is not None:
        conditions.append('scan_id = :scan_id')
        params['scan_id'] = str(scan_id)
    if server_id is not None:
        conditions.append('server_id = :server_id')
        params['server_id'] = str(server_id)
    if key_hex is not None:
        conditions.append('key_hex = :key_hex')
        params['key_hex'] = key_hex
    if result is not None:
        conditions.append('result = :result')
        params['result'] = result.value

    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ''
    query = (
        f'SELECT {RESULT_COLUMNS} FROM epdg_result{where_clause} '
        'ORDER BY inserted_at DESC OFFSET :offset LIMIT :limit'
    )
    rows = await fetch_all(db, query, params)
    return [ResultOut.model_validate(row) for row in rows]


@router.get('/{result_id}', response_model=ResultOut)
async def get_result(result_id: UUID, db: AsyncSession = Depends(get_db)):
    query = f'SELECT {RESULT_COLUMNS} FROM epdg_result WHERE id = :id'
    row = await fetch_one(db, query, {'id': str(result_id)})
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Result not found')
    return ResultOut.model_validate(row)
