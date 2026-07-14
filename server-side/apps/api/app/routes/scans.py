from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all, fetch_one
from app.dependencies import get_db, pagination_params, require_api_key
from app.schemas import ScanOut

router = APIRouter(prefix='/scans', tags=['scans'], dependencies=[Depends(require_api_key)])

SCAN_COLUMNS = 'id, inserted_at, dh_variant, header_text, source_file'


@router.get('', response_model=list[ScanOut])
async def list_scans(
    pagination: tuple[int, int] = Depends(pagination_params),
    db: AsyncSession = Depends(get_db),
):
    offset, limit = pagination
    query = f'SELECT {SCAN_COLUMNS} FROM scan ORDER BY inserted_at DESC OFFSET :offset LIMIT :limit'
    rows = await fetch_all(db, query, {'offset': offset, 'limit': limit})
    return [ScanOut.model_validate(row) for row in rows]


@router.get('/{scan_id}', response_model=ScanOut)
async def get_scan(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    query = f'SELECT {SCAN_COLUMNS} FROM scan WHERE id = :id'
    row = await fetch_one(db, query, {'id': str(scan_id)})
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Scan not found')
    return ScanOut.model_validate(row)
