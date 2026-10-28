from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all, fetch_one
from app.dependencies import get_db, require_api_key
from app.schemas import CountrySnapshotOut
from app.vantage import DEFAULT_MODE, resolve_mode, resolve_vantage_label

router = APIRouter(
    prefix="/map",
    tags=["map"],
    dependencies=[Depends(require_api_key)],
)

MAP_COLUMNS = "vantage_label, mode, country, iso3, operators"

# Merged pictures (mode 'all'): per server and DH group the latest valid answer, per
# country (vantage_label = ISO3) or overall (vantage_label 'all'); see 003_schema.sql.
MERGED = "all"

# A country has one row per (vantage point, mode), so every query pins both.
VANTAGE_QUERY = Query(
    default=None,
    description=(
        "Vantage point to view the world from: a uuid or a label such as "
        "'austria' or 'surfshark-de', or 'all' for every vantage point and mode "
        "merged. Defaults to the reference vantage point."
    ),
)

MODE_QUERY = Query(
    default=DEFAULT_MODE,
    description=(
        "How the measurement was taken: 'full', 'full_warp', 'dh2048_warp' or "
        "'local', or 'all' for everything measured from the vantage point's "
        "country merged (every vantage point there, all modes). Ignored for "
        "vantage=all, which merges every vantage point and mode."
    ),
)


async def _scope(db: AsyncSession, vantage: str | None, mode: str) -> dict[str, str]:
    """Rows to read: one vantage point and mode, its country merged, or everything merged."""
    if vantage is not None and vantage.strip().lower() == MERGED:
        return {"vantage_label": MERGED, "mode": MERGED}
    label = await resolve_vantage_label(db, vantage)
    if mode.strip().lower() != MERGED:
        return {"vantage_label": label, "mode": resolve_mode(mode)}
    # merged rows are keyed by country: any vantage point there gives the same picture.
    row = await fetch_one(
        db,
        "SELECT COALESCE(iso3, label) AS place FROM vantage_point "
        "WHERE label = :label ORDER BY last_seen DESC LIMIT 1",
        {"label": label},
    )
    return {"vantage_label": row["place"], "mode": MERGED}


@router.get("", response_model=list[CountrySnapshotOut])
async def list_countries(
    vantage: str | None = VANTAGE_QUERY,
    mode: str = MODE_QUERY,
    db: AsyncSession = Depends(get_db),
):
    params = await _scope(db, vantage, mode)
    query = f"""
        SELECT {MAP_COLUMNS}
        FROM country_operator_snapshot
        WHERE vantage_label = :vantage_label AND mode = :mode
        ORDER BY country, iso3
    """
    rows = await fetch_all(db, query, params)
    return [CountrySnapshotOut.model_validate(row) for row in rows]


@router.get("/{country}", response_model=CountrySnapshotOut)
async def get_country(
    country: str,
    vantage: str | None = VANTAGE_QUERY,
    mode: str = MODE_QUERY,
    db: AsyncSession = Depends(get_db),
):
    params = {"country": country, **await _scope(db, vantage, mode)}
    query = f"""
        SELECT {MAP_COLUMNS}
        FROM country_operator_snapshot
        WHERE country = :country
          AND vantage_label = :vantage_label
          AND mode = :mode
        ORDER BY iso3
        LIMIT 1
    """
    row = await fetch_one(db, query, params)

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Country not found",
        )

    return CountrySnapshotOut.model_validate(row)
