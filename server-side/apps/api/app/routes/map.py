from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import fetch_all, fetch_one
from app.dependencies import get_db, require_api_key
from app.schemas import CountrySnapshotOut

router = APIRouter(
    prefix="/map",
    tags=["map"],
    dependencies=[Depends(require_api_key)],
)


@router.get("", response_model=list[CountrySnapshotOut])
async def list_countries(db: AsyncSession = Depends(get_db)):
    query = """
        SELECT country, iso3, operators
        FROM country_operator_snapshot
        ORDER BY country, iso3
    """
    rows = await fetch_all(db, query, {})
    return [CountrySnapshotOut.model_validate(row) for row in rows]


@router.get("/{country}", response_model=CountrySnapshotOut)
async def get_country(country: str, db: AsyncSession = Depends(get_db)):
    query = """
        SELECT country, iso3, operators
        FROM country_operator_snapshot
        WHERE country = :country
        ORDER BY iso3
        LIMIT 1
    """
    row = await fetch_one(db, query, {"country": country})

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Country not found",
        )

    return CountrySnapshotOut.model_validate(row)
