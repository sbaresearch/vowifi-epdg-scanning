from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all, fetch_one
from app.dependencies import get_db, pagination_params, require_api_key
from app.schemas import ScanOut
from app.vantage import resolve_mode, resolve_vantage_label

router = APIRouter(prefix='/scans', tags=['scans'], dependencies=[Depends(require_api_key)])

SCAN_COLUMNS = (
    'sc.id, sc.inserted_at, sc.dh_variant, sc.header_text, sc.source_file, '
    'sc.vantage_id, v.label AS vantage_label, sc.mode, '
    'sc.exit_ip, sc.exit_country, sc.warp_ip, sc.warp_country'
)

SCAN_FROM = 'FROM scan sc JOIN vantage_point v ON v.id = sc.vantage_id'


@router.get('', response_model=list[ScanOut])
async def list_scans(
    vantage: str | None = Query(
        default=None,
        description="Only scans run from this vantage point (uuid or label). "
                    "Omit to list scans from every vantage point.",
    ),
    mode: str | None = Query(
        default=None,
        description="Only scans measured this way (full, full_warp, "
                    "dh2048_warp, local). Omit to list every mode.",
    ),
    pagination: tuple[int, int] = Depends(pagination_params),
    db: AsyncSession = Depends(get_db),
):
    offset, limit = pagination
    params: dict[str, object] = {'offset': offset, 'limit': limit}
    conditions = []
    if vantage is not None:
        # by label: each exit has its own id, so one id would miss earlier exits.
        params['vantage_label'] = await resolve_vantage_label(db, vantage)
        conditions.append('v.label = :vantage_label')
    if mode is not None:
        params['mode'] = resolve_mode(mode)
        conditions.append('sc.mode = :mode')
    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ''

    query = (
        f'SELECT {SCAN_COLUMNS} {SCAN_FROM}{where_clause} '
        'ORDER BY sc.inserted_at DESC OFFSET :offset LIMIT :limit'
    )
    rows = await fetch_all(db, query, params)
    return [ScanOut.model_validate(row) for row in rows]


@router.get('/{scan_id}', response_model=ScanOut)
async def get_scan(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    query = f'SELECT {SCAN_COLUMNS} {SCAN_FROM} WHERE sc.id = :id'
    row = await fetch_one(db, query, {'id': str(scan_id)})
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Scan not found')
    return ScanOut.model_validate(row)
