from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all, fetch_one
from app.dependencies import get_db, require_api_key
from app.schemas import VantageExitOut, VantagePointOut
from app.vantage import resolve_vantage_label

router = APIRouter(
    prefix="/vantage-points",
    tags=["vantage-points"],
    dependencies=[Depends(require_api_key)],
)

# One row per label (newest exit via DISTINCT ON); counts and first_seen span all exits.
# scan_count and modes let the map skip never-run and DH2048-only vantage points.
_SELECT = (
    "WITH per_label AS ("
    "  SELECT v.label, "
    "         count(DISTINCT v.id) AS exit_count, "
    "         count(sc.id)         AS scan_count, "
    "         min(v.first_seen)    AS first_seen, "
    "         array_remove(array_agg(DISTINCT sc.mode ORDER BY sc.mode), NULL) AS modes "
    "    FROM vantage_point v "
    "    LEFT JOIN scan sc ON sc.vantage_id = v.id "
    "   GROUP BY v.label"
    ") "
    "SELECT DISTINCT ON (v.label) "
    "  v.id, v.label, v.provider, v.vpn_type, v.requested_country, v.iso3, "
    "  v.server_location, v.exit_ip, v.exit_country, v.warp_ip, v.warp_country, "
    "  p.first_seen, v.last_seen, p.scan_count, p.exit_count, p.modes "
    "FROM vantage_point v "
    "JOIN per_label p ON p.label = v.label "
)

# DISTINCT ON order (display order is applied outside); id breaks last_seen ties
# between exits registered in one transaction.
_PICK_NEWEST_EXIT = "ORDER BY v.label, v.last_seen DESC, v.id DESC"


@router.get("", response_model=list[VantagePointOut])
async def list_vantage_points(db: AsyncSession = Depends(get_db)):
    rows = await fetch_all(
        db,
        f"SELECT * FROM ({_SELECT} {_PICK_NEWEST_EXIT}) t "
        "ORDER BY t.server_location DESC, t.label ASC",
    )
    return [VantagePointOut.model_validate(row) for row in rows]


@router.get("/{vantage}", response_model=VantagePointOut)
async def get_vantage_point(vantage: str, db: AsyncSession = Depends(get_db)):
    """One logical vantage point, by label or any of its exit ids."""
    row = await fetch_one(
        db,
        f"{_SELECT} WHERE v.label = :label {_PICK_NEWEST_EXIT}",
        {"label": await resolve_vantage_label(db, vantage)},
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Vantage point not found"
        )
    return VantagePointOut.model_validate(row)


@router.get("/{vantage}/exits", response_model=list[VantageExitOut])
async def list_vantage_exits(vantage: str, db: AsyncSession = Depends(get_db)):
    """Every exit of this vantage point, newest first (ids = scan.vantage_id)."""
    rows = await fetch_all(
        db,
        "SELECT v.id, v.label, v.exit_ip, v.exit_country, v.warp_ip, v.warp_country, "
        "       v.first_seen, v.last_seen, "
        "       COALESCE(s.scan_count, 0) AS scan_count "
        "FROM vantage_point v "
        "LEFT JOIN (SELECT vantage_id, count(*) AS scan_count FROM scan GROUP BY vantage_id) s "
        "  ON s.vantage_id = v.id "
        "WHERE v.label = :label "
        "ORDER BY v.last_seen DESC",
        {"label": await resolve_vantage_label(db, vantage)},
    )
    return [VantageExitOut.model_validate(row) for row in rows]
