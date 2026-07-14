import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from app.config import get_settings
from app.dependencies import require_api_key

logger = logging.getLogger("backend_api.takeout")
settings = get_settings()

router = APIRouter(
    prefix="/takeout", tags=["takeout"], dependencies=[Depends(require_api_key)]
)

CSV_ZIP_NAME = "vowifi-csv-takeout.zip"
SQL_GZ_NAME = "vowifi-db-takeout.sql.gz"
METADATA_NAME = "metadata.json"


def _takeout_path(name: str) -> Path:
    return Path(settings.takeout_dir) / name


def _generated_date() -> str:
    # reads timestamp from metadata to serve with downloaded file.
    try:
        meta = json.loads(_takeout_path(METADATA_NAME).read_text())
        return datetime.fromisoformat(meta["generated_at"]).strftime("%Y%m%d")
    except (OSError, ValueError, KeyError):
        return datetime.now(timezone.utc).strftime("%Y%m%d")


def _serve(name: str, media_type: str, download_stem: str, ext: str) -> FileResponse:
    path = _takeout_path(name)
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Takeout not available yet; a scan run must complete first.",
        )
    filename = f"{download_stem}-{_generated_date()}.{ext}"
    return FileResponse(path, media_type=media_type, filename=filename)


@router.get("/csv")
async def takeout_csv():
    """Serve the cached per-table CSV zip generated after the last scan run."""
    return _serve(CSV_ZIP_NAME, "application/zip", "vowifi-csv-takeout", "zip")


@router.get("/sql")
async def takeout_sql():
    """Serve the cached gzipped pg_dump generated after the last scan run."""
    return _serve(SQL_GZ_NAME, "application/gzip", "vowifi-sql-takeout", "sql.gz")
