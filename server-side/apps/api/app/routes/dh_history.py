from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all
from app.dependencies import get_db, require_api_key
from app.vantage import MODE_QUERY, resolve_mode, resolve_vantage_label
from app.schemas import (
    DhGroupSeriesOut,
    DhTimelineOut,
    HistoryServerOut,
    OperatorListItemOut,
    TimelinePointOut,
)

router = APIRouter(prefix="/dh-history", tags=["dh-history"], dependencies=[Depends(require_api_key)])

# probe variants that don't represent a real DH group offering, kept out of the timeline.
EXCLUDED_VARIANTS = ("DOWNGRADE_DH2048", "TOLERATE_DH1024", "UNKNOWN")

# By label: each exit has its own id, so one id would miss earlier exits.
VANTAGE_SCOPE = (
    "sc.vantage_id IN (SELECT id FROM vantage_point WHERE label = :vantage_label)"
    " AND sc.mode = :mode"
)

# same support semantics as the country_operator_snapshot materialized view.
SUPPORT_STATE_CASE = (
    "CASE "
    "WHEN bool_or(r.result = 'NO_PROPOSAL_CHOSEN') THEN 'NOT_SUPPORTED' "
    "WHEN bool_or(r.result = 'SUCCESS') THEN 'SUPPORTED' "
    "WHEN bool_and(r.result = 'NO_SUCCESS') THEN 'NO_SUCCESS' "
    "WHEN bool_and(r.result = 'NO_RESPONSE') THEN 'NO_RESPONSE' "
    "ELSE 'UNKNOWN' END"
)


@router.get("/operators", response_model=list[OperatorListItemOut])
async def list_operators(db: AsyncSession = Depends(get_db)):
    query = (
        "SELECT s.mcc, s.mnc, s.operator, s.network, s.country, s.iso3, "
        "COUNT(DISTINCT s.id) AS server_count "
        "FROM epdg_server s "
        "WHERE s.operator IS NOT NULL "
        "AND EXISTS (SELECT 1 FROM epdg_result r WHERE r.server_id = s.id) "
        "GROUP BY s.mcc, s.mnc, s.operator, s.network, s.country, s.iso3 "
        "ORDER BY s.country, s.operator"
    )
    rows = await fetch_all(db, query)
    return [OperatorListItemOut.model_validate(row) for row in rows]


@router.get("/servers", response_model=list[HistoryServerOut])
async def list_operator_servers(
    mcc: str = Query(...),
    mnc: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    query = (
        "SELECT id AS server_id, target_ip, epdg_domain "
        "FROM epdg_server WHERE mcc = :mcc AND mnc = :mnc "
        "ORDER BY target_ip"
    )
    rows = await fetch_all(db, query, {"mcc": mcc.strip(), "mnc": mnc.strip()})
    return [HistoryServerOut.model_validate(row) for row in rows]


@router.get("", response_model=DhTimelineOut)
async def get_timeline(
    mcc: str = Query(...),
    mnc: str = Query(...),
    server_id: list[UUID] | None = Query(default=None),
    vantage: str | None = Query(
        default=None,
        description="Vantage point to plot the timeline for (uuid or label); "
                    "defaults to the reference one.",
    ),
    mode: str = MODE_QUERY,
    observed_from: datetime | None = Query(default=None),
    observed_to: datetime | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    params: dict[str, object] = {"mcc": mcc.strip(), "mnc": mnc.strip()}
    server_filter = _server_filter(server_id, params)

    # one series per vantage point and mode; mixing them interleaves unrelated scans.
    params["vantage_label"] = await resolve_vantage_label(db, vantage)
    params["mode"] = resolve_mode(mode)

    # groups the operator has ever supported, over full history so a time window can't hide them.
    # without a window the main query covers full history, so it answers this in the same pass.
    windowed = observed_from is not None or observed_to is not None
    if windowed:
        supported_variants = await _ever_supported_variants(db, server_filter, params)
        if not supported_variants:
            return _empty_timeline(mcc, mnc, server_id)

    conditions = ["s.mcc = :mcc", "s.mnc = :mnc", VANTAGE_SCOPE]
    if server_filter:
        conditions.append(server_filter)
    if observed_from is not None:
        conditions.append("sc.inserted_at >= :observed_from")
        params["observed_from"] = observed_from
    if observed_to is not None:
        conditions.append("sc.inserted_at <= :observed_to")
        params["observed_to"] = observed_to

    query = (
        f"SELECT sc.dh_variant, sc.inserted_at AS ts, {SUPPORT_STATE_CASE} AS state, "
        "bool_or(r.result = 'SUCCESS') AS any_success "
        "FROM epdg_result r "
        "JOIN scan sc ON sc.id = r.scan_id "
        "JOIN epdg_server s ON s.id = r.server_id "
        f"WHERE {' AND '.join(conditions)} "
        "GROUP BY sc.id, sc.dh_variant, sc.inserted_at "
        "ORDER BY sc.dh_variant, sc.inserted_at"
    )
    rows = await fetch_all(db, query, params)

    if not windowed:
        supported_variants = {
            row["dh_variant"] for row in rows if row["any_success"]
        } - set(EXCLUDED_VARIANTS)
        if not supported_variants:
            return _empty_timeline(mcc, mnc, server_id)

    groups: dict[str, list[TimelinePointOut]] = {}
    for row in rows:
        variant = row["dh_variant"]
        if variant not in supported_variants:
            continue
        groups.setdefault(variant, []).append(
            TimelinePointOut(ts=row["ts"], state=row["state"])
        )

    meta = await _operator_meta(db, params)
    return DhTimelineOut(
        operator=meta.get("operator") if meta else None,
        mcc=mcc,
        mnc=mnc,
        network=meta.get("network") if meta else None,
        country=meta.get("country") if meta else None,
        server_ids=list(server_id) if server_id else [],
        groups=[DhGroupSeriesOut(dh_variant=v, points=p) for v, p in groups.items()],
    )


def _server_filter(server_id: list[UUID] | None, params: dict) -> str:
    """Build an IN clause for the selected servers and add its params, or '' for all servers."""
    if not server_id:
        return ""
    placeholders = []
    for i, sid in enumerate(server_id):
        key = f"sid_{i}"
        placeholders.append(f":{key}")
        params[key] = str(sid)
    return f"r.server_id IN ({', '.join(placeholders)})"


async def _ever_supported_variants(db: AsyncSession, server_filter: str, params: dict) -> set[str]:
    conditions = [
        "s.mcc = :mcc",
        "s.mnc = :mnc",
        "r.result = 'SUCCESS'",
        VANTAGE_SCOPE,
    ]
    if server_filter:
        conditions.append(server_filter)
    excluded = ", ".join(f"'{v}'" for v in EXCLUDED_VARIANTS)
    query = (
        "SELECT DISTINCT sc.dh_variant "
        "FROM epdg_result r "
        "JOIN scan sc ON sc.id = r.scan_id "
        "JOIN epdg_server s ON s.id = r.server_id "
        f"WHERE {' AND '.join(conditions)} AND sc.dh_variant NOT IN ({excluded})"
    )
    rows = await fetch_all(db, query, params)
    return {row["dh_variant"] for row in rows}


async def _operator_meta(db: AsyncSession, params: dict) -> dict | None:
    query = (
        "SELECT operator, network, country FROM epdg_server "
        "WHERE mcc = :mcc AND mnc = :mnc LIMIT 1"
    )
    rows = await fetch_all(db, query, {"mcc": params["mcc"], "mnc": params["mnc"]})
    return dict(rows[0]) if rows else None


def _empty_timeline(mcc: str, mnc: str, server_id: list[UUID] | None) -> DhTimelineOut:
    return DhTimelineOut(
        mcc=mcc, mnc=mnc, server_ids=list(server_id) if server_id else [], groups=[]
    )
