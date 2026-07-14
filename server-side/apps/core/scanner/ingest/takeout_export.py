"""Generate the cached database takeouts served by the API.

Runs after each scan run completes. Writes a per-table CSV zip and a gzipped
pg_dump to the takeout volume so the API can serve them
as staticly.
"""

import gzip
import json
import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import psycopg

from scanner.ingest.scan_analyzer_insert import get_required_env

log = logging.getLogger(__name__)

# tables included in CSV dump.
EXPORT_TABLES = (
    "epdg_server",
    "scan",
    "epdg_result",
    "latest_epdg_result",
    "collision_keys",
)

CSV_ZIP_NAME = "vowifi-csv-takeout.zip"
SQL_GZ_NAME = "vowifi-db-takeout.sql.gz"
# metadata only contains timestamp. maybe useful later to add more. not really needed atm.
METADATA_NAME = "metadata.json"


def _takeout_dir() -> Path:
    override = os.getenv("TAKEOUT_DIR")
    if override:
        return Path(override)
    data_dir = Path(os.getenv("DATA_DIR", "/data/data"))
    return data_dir.parent / "takeout"


def _conn_kwargs() -> dict:
    return {
        "host": get_required_env("POSTGRES_HOST"),
        "port": int(get_required_env("POSTGRES_PORT")),
        "dbname": get_required_env("POSTGRES_DB"),
        "user": get_required_env("POSTGRES_USER"),
        "password": get_required_env("POSTGRES_PASSWORD"),
    }


def _generate_csv_zip(dest: Path) -> None:
    # streaming tables to zip to not hog memory and take it away from server (tables will get very large).
    with psycopg.connect(**_conn_kwargs()) as conn, zipfile.ZipFile(
        dest, "w", compression=zipfile.ZIP_DEFLATED
    ) as zf:
        for table in EXPORT_TABLES:
            copy_sql = f"COPY {table} TO STDOUT WITH (FORMAT csv, HEADER true)"
            with zf.open(f"{table}.csv", "w") as entry, conn.cursor() as cur:
                with cur.copy(copy_sql) as copy:
                    for block in copy:
                        entry.write(block)


def _generate_sql_gz(dest: Path) -> None:
    env = os.environ.copy()
    env["PGPASSWORD"] = get_required_env("POSTGRES_PASSWORD")
    cmd = [
        "pg_dump",
        "--no-owner",
        "--no-privileges",
        "-h",
        get_required_env("POSTGRES_HOST"),
        "-p",
        get_required_env("POSTGRES_PORT"),
        "-U",
        get_required_env("POSTGRES_USER"),
        "-d",
        get_required_env("POSTGRES_DB"),
    ]
    # compress sql file to gzip to save bandwidth.
    sql_name = SQL_GZ_NAME.removesuffix(".gz")
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf, env=env)
        assert proc.stdout is not None
        with open(dest, "wb") as raw, gzip.GzipFile(
            filename=sql_name, mode="wb", fileobj=raw
        ) as gz:
            shutil.copyfileobj(proc.stdout, gz)
        proc.wait()
        if proc.returncode != 0:
            errf.seek(0)
            detail = errf.read().decode(errors="replace").strip()
            raise RuntimeError(f"pg_dump failed rc={proc.returncode}: {detail}")


def generate_takeouts() -> None:
    """Regenerate the cached CSV zip + gzipped SQL dump, replacing them atomically."""
    out_dir = _takeout_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    log.info("generating takeouts in %s (this will take a while)...", out_dir)

    # write temp files in the same dir, then os.replace to keep downloads working without interruption.
    tmp_zip = out_dir / (CSV_ZIP_NAME + ".tmp")
    tmp_sql = out_dir / (SQL_GZ_NAME + ".tmp")
    tmp_meta = out_dir / (METADATA_NAME + ".tmp")
    try:
        _generate_csv_zip(tmp_zip)
        _generate_sql_gz(tmp_sql)
        meta = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "csv_zip_bytes": tmp_zip.stat().st_size,
            "sql_gz_bytes": tmp_sql.stat().st_size,
        }
        tmp_meta.write_text(json.dumps(meta))
        # replace old files with new once done.
        os.replace(tmp_zip, out_dir / CSV_ZIP_NAME)
        os.replace(tmp_sql, out_dir / SQL_GZ_NAME)
        os.replace(tmp_meta, out_dir / METADATA_NAME)
        log.info(
            "takeouts generated: csv=%d bytes, sql.gz=%d bytes",
            meta["csv_zip_bytes"],
            meta["sql_gz_bytes"],
        )
    finally:
        for tmp in (tmp_zip, tmp_sql, tmp_meta):
            tmp.unlink(missing_ok=True)


def _existing_takeouts_present() -> bool:
    out_dir = _takeout_dir()
    return (out_dir / CSV_ZIP_NAME).is_file() and (out_dir / SQL_GZ_NAME).is_file()


def generate_if_missing() -> None:
    """Generate takeout files at startup if none exist (e.g. a fresh deploy or update), so
    API can serve downloads immediately."""
    if _existing_takeouts_present():
        log.info("takeouts present, skipping...")
        return
    log.info("takeouts missing, generating...")
    generate_takeouts()


if __name__ == "__main__":
    from scanner.common.logging_config import configure_logging

    configure_logging("%(asctime)s [%(levelname)s]: %(message)s")
    generate_takeouts()
