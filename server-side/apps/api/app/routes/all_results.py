from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all
from app.dependencies import get_db, pagination_params, require_api_key
from app.ip_filter import ip_condition
from app.schemas import AllResultOut, IKEResult
from app.vantage import resolve_mode, vantage_label_pattern

router = APIRouter(
    prefix="/all-results", tags=["all-results"], dependencies=[Depends(require_api_key)]
)

ALL_RESULT_COLUMNS = (
    "r.id, r.inserted_at, r.scan_id, r.server_id, "
    "sc.vantage_id, v.label AS vantage_label, sc.mode, "
    "r.observed_at, r.raw_state, r.result, "
    "r.dh_group, r.encr_id, r.encr_key_len, r.integ_id, r.prf_id, r.key_hex, r.nonce_hex, "
    "sc.dh_variant, "
    "s.epdg_domain, s.target_ip, s.mcc, s.mnc, s.country, s.iso3, s.network, s.operator, s.itu_region"
)

SORT_ALLOWLIST = {
    "inserted_at": "r.inserted_at",
    "observed_at": "r.observed_at",
    "vantage_label": "v.label",
    "country": "s.country",
    "operator": "s.operator",
    "network": "s.network",
    "target_ip": "s.target_ip",
    "mcc": "s.mcc",
    "mnc": "s.mnc",
    "dh_variant": "sc.dh_variant",
    "result": "r.result",
    "dh_group": "r.dh_group",
    "encr_key_len": "r.encr_key_len",
    "key_hex": "r.key_hex",
}


@router.get("", response_model=list[AllResultOut])
async def list_all_results(
    scan_id: UUID | None = None,
    server_id: UUID | None = None,
    vantage: str | None = Query(
        default=None,
        description="Only results measured from this vantage point (uuid or label; "
                    "a partial label matches as a substring). "
                    "Omit to list results from every vantage point.",
    ),
    mode: str | None = Query(
        default=None,
        description="Only results measured this way (full, full_warp, "
                    "dh2048_warp, local). Omit to list every mode.",
    ),
    country: str | None = None,
    operator: str | None = None,
    network: str | None = None,
    ip: str | None = Query(
        default=None,
        description="Server IP. A complete address matches exactly, a partial "
                    "one as a prefix ('212.95.').",
    ),
    mcc: str | None = None,
    mnc: str | None = None,
    dh_variant: str | None = None,
    exclude_dh_variant: str | None = Query(
        default=None,
        description="Leave out results of this DH variant (exact name, "
                    "e.g. 'DOWNGRADE_DH2048').",
    ),
    result: IKEResult | None = Query(default=None),
    dh_group: int | None = Query(default=None),
    key_hex: str | None = None,
    observed_from: datetime | None = Query(default=None),
    observed_to: datetime | None = Query(default=None),
    sort_by: str = Query(default="inserted_at"),
    sort_dir: str = Query(default="desc"),
    pagination: tuple[int, int] = Depends(pagination_params),
    db: AsyncSession = Depends(get_db),
):
    offset, limit = pagination

    conditions: list[str] = []
    params: dict[str, object] = {"offset": offset, "limit": limit}

    if scan_id is not None:
        conditions.append("r.scan_id = :scan_id")
        params["scan_id"] = str(scan_id)
    if server_id is not None:
        conditions.append("r.server_id = :server_id")
        params["server_id"] = str(server_id)
    if vantage is not None:
        # by label: each exit has its own id, so one id would miss earlier exits.
        conditions.append("v.label ILIKE :vantage_label")
        params["vantage_label"] = await vantage_label_pattern(db, vantage)
    if mode is not None:
        conditions.append("sc.mode = :mode")
        params["mode"] = resolve_mode(mode)
    if country is not None:
        conditions.append("s.country ILIKE :country")
        params["country"] = f"%{country.strip()}%"
    if operator is not None:
        conditions.append("s.operator ILIKE :operator")
        params["operator"] = f"%{operator.strip()}%"
    if network is not None:
        conditions.append("s.network ILIKE :network")
        params["network"] = f"%{network.strip()}%"
    if ip is not None:
        condition, params["ip"] = ip_condition("s.target_ip", ip)
        conditions.append(condition)
    if mcc is not None:
        conditions.append("s.mcc = :mcc")
        params["mcc"] = mcc.strip()
    if mnc is not None:
        conditions.append("s.mnc = :mnc")
        params["mnc"] = mnc.strip()
    if dh_variant is not None:
        conditions.append("sc.dh_variant ILIKE :dh_variant")
        params["dh_variant"] = f"%{dh_variant.strip()}%"
    if exclude_dh_variant is not None:
        conditions.append("sc.dh_variant <> :exclude_dh_variant")
        params["exclude_dh_variant"] = exclude_dh_variant.strip()
    if result is not None:
        conditions.append("r.result = :result")
        params["result"] = result.value
    if dh_group is not None:
        conditions.append("r.dh_group = :dh_group")
        params["dh_group"] = dh_group
    if key_hex is not None:
        conditions.append("r.key_hex ILIKE :key_hex")
        params["key_hex"] = f"%{key_hex.strip()}%"
    if observed_from is not None:
        conditions.append("r.observed_at >= :observed_from")
        params["observed_from"] = observed_from
    if observed_to is not None:
        conditions.append("r.observed_at <= :observed_to")
        params["observed_to"] = observed_to

    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    sort_column = SORT_ALLOWLIST.get(sort_by, SORT_ALLOWLIST["inserted_at"])
    sort_direction = "ASC" if sort_dir.lower() == "asc" else "DESC"
    query = (
        f"SELECT {ALL_RESULT_COLUMNS} "
        "FROM epdg_result r "
        "JOIN epdg_server s ON s.id = r.server_id "
        "JOIN scan sc ON sc.id = r.scan_id "
        "JOIN vantage_point v ON v.id = sc.vantage_id "
        f"{where_clause} "
        f"ORDER BY {sort_column} {sort_direction}, r.id ASC "
        "OFFSET :offset LIMIT :limit"
    )
    rows = await fetch_all(db, query, params)
    return [AllResultOut.model_validate(row) for row in rows]
