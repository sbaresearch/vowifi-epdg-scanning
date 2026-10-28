"""Resolve the `vantage` parameter (uuid or label) to a label.

A label spans several rows (one per exit and WARP hop), so routes filter by label + mode.
"""

from fastapi import HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_one

# Scan modes, recorded on every scan row:
#   full         DNS discovery in the tunnel, all testcases, via the VPN exit
#   full_warp    targets from epdg_server, all testcases, via Cloudflare WARP
#   dh2048_warp  targets from epdg_server, DH2048 only, via WARP
#   local        the host itself, untunnelled
# Modes observe from different positions, so aggregating routes pin one.
SCAN_MODES = ("full", "full_warp", "dh2048_warp", "local")
DEFAULT_MODE = "full"

MODE_QUERY = Query(
    default=DEFAULT_MODE,
    description=(
        "How the measurement was taken: 'full' (VPN exit, discovery in the "
        "tunnel), 'full_warp' (via a Cloudflare WARP hop), 'dh2048_warp' "
        "(DH2048 only, via WARP) or 'local' (the scanning host itself)."
    ),
)


def resolve_mode(mode: str | None) -> str:
    """Validate a scan mode; default 'full'."""
    if mode is None:
        return DEFAULT_MODE
    candidate = mode.strip()
    if candidate not in SCAN_MODES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown scan mode '{mode}'. Known modes: {', '.join(SCAN_MODES)}",
        )
    return candidate


async def resolve_vantage_label(db: AsyncSession, vantage: str | None) -> str:
    """Label for a uuid or label (shared by all its exits); the reference one if omitted."""
    if vantage is None:
        row = await fetch_one(
            db,
            "SELECT label FROM vantage_point WHERE server_location "
            "ORDER BY last_seen DESC LIMIT 1",
        )
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No reference vantage point configured",
            )
        return str(row["label"])

    row = await fetch_one(
        db,
        # id::text so a non-uuid label can't fail the cast.
        "SELECT label FROM vantage_point "
        "WHERE label = :vantage OR id::text = :vantage LIMIT 1",
        {"vantage": vantage.strip()},
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown vantage point '{vantage}'",
        )
    return str(row["label"])


async def vantage_label_pattern(db: AsyncSession, vantage: str) -> str:
    """ILIKE pattern: a known label/uuid exactly, anything else as a substring."""
    try:
        return await resolve_vantage_label(db, vantage)
    except HTTPException:
        return f"%{vantage.strip()}%"

