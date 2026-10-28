from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all, fetch_one
from app.dependencies import get_db, pagination_params, require_api_key
from app.ip_filter import ip_condition
from app.schemas import IKEResult, LatestResultOut
from app.vantage import MODE_QUERY, resolve_mode, resolve_vantage_label, vantage_label_pattern

router = APIRouter(prefix='/latest-results', tags=['latest-results'], dependencies=[Depends(require_api_key)])

LATEST_RESULT_COLUMNS = (
    'r.server_id, r.vantage_id, v.label AS vantage_label, r.mode, '
    's.country, s.iso3, s.mcc, s.mnc, s.operator, s.network, s.target_ip, '
    'r.dh_variant, r.scan_id, r.observed_at, r.inserted_at, r.result, r.raw_state, '
    'r.dh_group, r.encr_id, r.encr_key_len, r.integ_id, r.prf_id, r.key_hex, r.nonce_hex'
)

LATEST_RESULT_FROM = (
    'FROM latest_epdg_result r '
    'JOIN epdg_server s ON s.id = r.server_id '
    'JOIN vantage_point v ON v.id = r.vantage_id '
)

SORT_ALLOWLIST = {
    'inserted_at': 'r.inserted_at',
    'observed_at': 'r.observed_at',
    'vantage_label': 'v.label',
    'country': 's.country',
    'iso3': 's.iso3',
    'mcc': 's.mcc',
    'mnc': 's.mnc',
    'operator': 's.operator',
    'network': 's.network',
    'target_ip': 's.target_ip',
    'dh_variant': 'r.dh_variant',
    'result': 'r.result',
    'dh_group': 'r.dh_group',
    'encr_key_len': 'r.encr_key_len',
    'key_hex': 'r.key_hex',
}


@router.get('', response_model=list[LatestResultOut])
async def list_latest_results(
    server_id: UUID | None = None,
    vantage: str | None = Query(
        default=None,
        description="Only results measured from this vantage point (uuid or label; "
                    "a partial label matches as a substring). "
                    "Omit to list results from every vantage point -- rows carry "
                    "vantage_label so they stay distinguishable.",
    ),
    mode: str | None = Query(
        default=None,
        description="Only results measured this way (full, full_warp, "
                    "dh2048_warp, local). Omit to list every mode -- rows carry "
                    "mode so they stay distinguishable.",
    ),
    country: str | None = None,
    iso3: str | None = None,
    mcc: str | None = None,
    mnc: str | None = None,
    operator: str | None = None,
    network: str | None = None,
    ip: str | None = Query(
        default=None,
        description="Server IP. A complete address matches exactly, a partial "
                    "one as a prefix ('212.95.').",
    ),
    dh_variant: str | None = None,
    exclude_dh_variant: str | None = Query(
        default=None,
        description="Leave out results of this DH variant (exact name, "
                    "e.g. 'DOWNGRADE_DH2048').",
    ),
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
    if vantage is not None:
        # by label: callers shouldn't need to know which exit holds the snapshot.
        conditions.append('v.label ILIKE :vantage_label')
        params['vantage_label'] = await vantage_label_pattern(db, vantage)
    if mode is not None:
        conditions.append('r.mode = :mode')
        params['mode'] = resolve_mode(mode)
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
    if ip is not None:
        condition, params['ip'] = ip_condition('s.target_ip', ip)
        conditions.append(condition)
    if dh_variant is not None:
        conditions.append('r.dh_variant ILIKE :dh_variant')
        params['dh_variant'] = f'%{dh_variant.strip()}%'
    if exclude_dh_variant is not None:
        conditions.append('r.dh_variant <> :exclude_dh_variant')
        params['exclude_dh_variant'] = exclude_dh_variant.strip()
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
        f'{LATEST_RESULT_FROM}'
        f'{where_clause} '
        f'ORDER BY {sort_column} {sort_direction}, r.server_id ASC, r.dh_variant ASC, v.label ASC '
        'OFFSET :offset LIMIT :limit'
    )
    rows = await fetch_all(db, query, params)
    return [LatestResultOut.model_validate(row) for row in rows]


@router.get('/{server_id}/{dh_variant}', response_model=LatestResultOut)
async def get_latest_result(
    server_id: UUID,
    dh_variant: str,
    vantage: str | None = Query(
        default=None,
        description="Vantage point to read this result from; defaults to the reference one.",
    ),
    mode: str = MODE_QUERY,
    db: AsyncSession = Depends(get_db),
):
    # one result per vantage point and mode: pin both (the table's primary key).
    query = (
        f'SELECT {LATEST_RESULT_COLUMNS} '
        f'{LATEST_RESULT_FROM}'
        'WHERE r.server_id = :server_id AND r.dh_variant = :dh_variant '
        'AND v.label = :vantage_label AND r.mode = :mode'
    )
    row = await fetch_one(
        db,
        query,
        {
            'server_id': str(server_id),
            'dh_variant': dh_variant,
            'vantage_label': await resolve_vantage_label(db, vantage),
            'mode': resolve_mode(mode),
        },
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Latest result not found')
    return LatestResultOut.model_validate(row)
