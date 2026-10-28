from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all
from app.dependencies import get_db, require_api_key
from app.schemas import GeoblockingCountryOut, ReachOut

router = APIRouter(
    prefix="/geoblocking",
    tags=["geoblocking"],
    dependencies=[Depends(require_api_key)],
)

# Per operator from operator_reachability (004_geoblocking.sql): geoblocking if it
# blocks any country, open if it answers abroad, else home only / no answers.
# vpn_silent: geoblocking, yet it answered only the host's direct scans.
OVERVIEW_QUERY = """
    WITH op AS (
        SELECT
            country,
            iso3,
            operator,
            CASE
                WHEN bool_or(state = 'blocks') THEN 'geoblocking'
                WHEN bool_or(state = 'answers' AND seen_from IS DISTINCT FROM iso3) THEN 'open'
                WHEN bool_and(state = 'no_answers') THEN 'no_answers'
                ELSE 'home_only'
            END AS state,
            COALESCE(
                array_agg(seen_from::text ORDER BY seen_from) FILTER (WHERE state = 'blocks'),
                '{}'
            ) AS blocks,
            count(*) FILTER (WHERE state = 'answers') AS answers,
            bool_or(state = 'blocks') AND sum(vpn_answered) = 0 AS vpn_silent
        FROM operator_reachability
        GROUP BY country, iso3, operator
    )
    SELECT
        country,
        iso3,
        jsonb_agg(
            jsonb_build_object(
                'operator', operator,
                'state', state,
                'blocks', to_jsonb(blocks),
                'answers', answers,
                'vpn_silent', vpn_silent
            )
            ORDER BY operator
        ) AS operators
    FROM op
    GROUP BY country, iso3
    ORDER BY country, iso3
"""


@router.get("", response_model=list[GeoblockingCountryOut])
async def list_countries(db: AsyncSession = Depends(get_db)):
    rows = await fetch_all(db, OVERVIEW_QUERY)
    return [GeoblockingCountryOut.model_validate(row) for row in rows]


# query parameters, not path: operator names may contain '/'.
@router.get("/reach", response_model=list[ReachOut])
async def get_reach(
    country: str = Query(..., description="Operator's home country, as in /geoblocking."),
    operator: str = Query(..., description="Operator name, as in /geoblocking."),
    db: AsyncSession = Depends(get_db),
):
    query = """
        SELECT seen_from, probes, answered, state
        FROM operator_reachability
        WHERE country = :country AND operator = :operator
        ORDER BY seen_from
    """
    rows = await fetch_all(db, query, {"country": country, "operator": operator})

    if not rows:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Operator not found",
        )

    return [ReachOut.model_validate(row) for row in rows]
