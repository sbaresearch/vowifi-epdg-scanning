from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all, fetch_one
from app.dependencies import get_db, pagination_params, require_api_key
from app.schemas import IKEResult, LatestResultOut

router = APIRouter(prefix='/latest-results', tags=['latest-results'], dependencies=[Depends(require_api_key)])

LATEST_RESULT_COLUMNS = (
    'r.server_id, s.country, s.iso3, s.mcc, s.mnc, s.operator, s.network, '
    'r.dh_variant, r.scan_id, r.observed_at, r.inserted_at, r.result, r.raw_state, '
    'r.dh_group, r.encr_id, r.encr_key_len, r.integ_id, r.prf_id, r.key_hex, r.nonce_hex'
)

SORT_ALLOWLIST = {
    'inserted_at': 'r.inserted_at',
    'observed_at': 'r.observed_at',
    'country': 's.country',
    'iso3': 's.iso3',
    'mcc': 's.mcc',
    'mnc': 's.mnc',
    'operator': 's.operator',
    'network': 's.network',
    'dh_variant': 'r.dh_variant',
    'result': 'r.result',
    'dh_group': 'r.dh_group',
    'encr_key_len': 'r.encr_key_len',
    'key_hex': 'r.key_hex',
}


@router.get('', response_model=list[LatestResultOut])
async def list_latest_results(
    server_id: UUID | None = None,
    country: str | None = None,
    iso3: str | None = None,
    mcc: str | None = None,
    mnc: str | None = None,
    operator: str | None = None,
    network: str | None = None,
    dh_variant: str | None = None,
    key_hex: str | None = None,
    result: IKEResult | None = Query(default=None),
    dh_group: int | None = Query(default=None),
    observed_from: datetime | None = Query(default=None),
    observed_to: datetime | None = Query(default=None),
    sort_by: str = Query(default='inserted_at'),
    sort_dir: str = Query(default='desc'),
    pagination: tuple[int, int] = Depends(pagination_params),
    db: AsyncSession = Depends(get_db),
):
    offset, limit = pagination

    conditions: list[str] = []
    params: dict[str, object] = {'offset': offset, 'limit': limit}

    if server_id is not None:
        conditions.append('r.server_id = :server_id')
        params['server_id'] = str(server_id)
    if country is not None:
        conditions.append('s.country ILIKE :country')
        params['country'] = f'%{country.strip()}%'
    if iso3 is not None:
        conditions.append('s.iso3 = :iso3')
        params['iso3'] = iso3.strip().upper()
    if mcc is not None:
        conditions.append('s.mcc = :mcc')
        params['mcc'] = mcc.strip()
    if mnc is not None:
        conditions.append('s.mnc = :mnc')
        params['mnc'] = mnc.strip()
    if operator is not None:
        conditions.append('s.operator ILIKE :operator')
        params['operator'] = f'%{operator.strip()}%'
    if network is not None:
        conditions.append('s.network ILIKE :network')
        params['network'] = f'%{network.strip()}%'
    if dh_variant is not None:
        conditions.append('r.dh_variant ILIKE :dh_variant')
        params['dh_variant'] = f'%{dh_variant.strip()}%'
    if key_hex is not None:
        conditions.append('r.key_hex ILIKE :key_hex')
        params['key_hex'] = f'%{key_hex.strip()}%'
    if result is not None:
        conditions.append('r.result = :result')
        params['result'] = result.value
    if dh_group is not None:
        conditions.append('r.dh_group = :dh_group')
        params['dh_group'] = dh_group
    if observed_from is not None:
        conditions.append('r.observed_at >= :observed_from')
        params['observed_from'] = observed_from
    if observed_to is not None:
        conditions.append('r.observed_at <= :observed_to')
        params['observed_to'] = observed_to

    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ''
    sort_column = SORT_ALLOWLIST.get(sort_by, SORT_ALLOWLIST['inserted_at'])
    sort_direction = 'ASC' if sort_dir.lower() == 'asc' else 'DESC'
    query = (
        f'SELECT {LATEST_RESULT_COLUMNS} '
        'FROM latest_epdg_result r '
        'JOIN epdg_server s ON s.id = r.server_id '
        f'{where_clause} '
        f'ORDER BY {sort_column} {sort_direction}, r.server_id ASC, r.dh_variant ASC '
        'OFFSET :offset LIMIT :limit'
    )
    rows = await fetch_all(db, query, params)
    return [LatestResultOut.model_validate(row) for row in rows]


@router.get('/{server_id}/{dh_variant}', response_model=LatestResultOut)
async def get_latest_result(server_id: UUID, dh_variant: str, db: AsyncSession = Depends(get_db)):
    query = (
        f'SELECT {LATEST_RESULT_COLUMNS} '
        'FROM latest_epdg_result r '
        'JOIN epdg_server s ON s.id = r.server_id '
        'WHERE r.server_id = :server_id AND r.dh_variant = :dh_variant'
    )
    row = await fetch_one(db, query, {'server_id': str(server_id), 'dh_variant': dh_variant})
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Latest result not found')
    return LatestResultOut.model_validate(row)
