"""Vantage points: where a scan runs from (the host itself or a VPN exit).

`label` is the logical vantage point; each distinct exit gets its own row and uuid.
Used by the scanner (local vantage point) and the orchestrator (VPN endpoints).
"""

import json
import logging
import os
import time
import unicodedata
from pathlib import Path

import requests

from scanner.ingest.scan_analyzer_insert import clean_text, connect

log = logging.getLogger(__name__)

COUNTRY_ISO3_JSON = Path(__file__).resolve().parent / "data" / "db_to_iso3.json"

# Public-IP lookup for the local vantage point (VPN ones ask gluetun). Overridable.
PUBLIC_IP_URL = os.getenv("PUBLIC_IP_URL", "https://wtfismyip.com/json")
PUBLIC_IP_FIELD = os.getenv("PUBLIC_IP_FIELD", "YourFuckingIPAddress")
PUBLIC_IP_COUNTRY_FIELD = os.getenv("PUBLIC_IP_COUNTRY_FIELD", "YourFuckingCountry")
PUBLIC_IP_TIMEOUT = 15

_iso3_map: dict[str, str] | None = None
_iso3_norm: dict[str, str] = {}
_iso3_unknown: set[str] = set()


def _norm(text: str) -> str:
    """Fold case, accents and punctuation (as in fix_countries.py)."""
    text = unicodedata.normalize("NFKD", text.strip().lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return " ".join("".join(ch if ch.isalnum() else " " for ch in text).split())


def country_to_iso3(country: str | None) -> str | None:
    """ISO3 for a country from db_to_iso3.json; an unknown name warns once, returns None."""
    global _iso3_map
    name = clean_text(country)
    if not name:
        return None
    if _iso3_map is None:
        try:
            _iso3_map = json.loads(COUNTRY_ISO3_JSON.read_text(encoding="utf-8"))
        except Exception:
            log.warning("could not read %s, vantage iso3 stays empty", COUNTRY_ISO3_JSON)
            _iso3_map = {}
        # fallback: match ignoring case, accents and punctuation.
        for key, iso3 in _iso3_map.items():
            _iso3_norm.setdefault(_norm(key), iso3)
    iso3 = _iso3_map.get(name) or _iso3_norm.get(_norm(name))
    if not iso3 and name not in _iso3_unknown:
        _iso3_unknown.add(name)
        log.warning("no iso3 for country %r, add it to MANUAL in fix_countries.py", name)
    return iso3


def public_ip_info() -> tuple[str | None, str | None]:
    """The host's public (ip, country), or (None, None) on failure; never raises."""
    try:
        payload = requests.get(PUBLIC_IP_URL, timeout=PUBLIC_IP_TIMEOUT).json()
        ip = clean_text(payload.get(PUBLIC_IP_FIELD))
        country = clean_text(payload.get(PUBLIC_IP_COUNTRY_FIELD))
        return ip or None, country or None
    except Exception:
        log.warning(
            "could not determine our own public IP from %s, "
            "the local vantage point is recorded without one",
            PUBLIC_IP_URL,
            exc_info=True,
        )
        return None, None


def upsert_vantage_point(
    cursor,
    label: str,
    provider: str,
    vpn_type: str | None = None,
    requested_country: str | None = None,
    exit_ip: str | None = None,
    exit_country: str | None = None,
    warp_ip: str | None = None,
    warp_country: str | None = None,
    server_location: bool = False,
) -> str:
    """Register or refresh one (label, exit_ip, warp_ip) path; returns its id.

    A new exit or WARP hop gets its own row. Only the local registration sets server_location.
    """
    cursor.execute(
        """
        insert into vantage_point (
            label, provider, vpn_type, requested_country, iso3,
            exit_ip, exit_country, warp_ip, warp_country, server_location
        )
        values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        on conflict (label, exit_ip, warp_ip) do update
          set provider          = excluded.provider,
              vpn_type          = excluded.vpn_type,
              requested_country = excluded.requested_country,
              iso3              = excluded.iso3,
              exit_country      = coalesce(excluded.exit_country, vantage_point.exit_country),
              warp_country      = coalesce(excluded.warp_country, vantage_point.warp_country),
              server_location   = excluded.server_location,
              last_seen         = now()
        returning id
        """,
        (
            label,
            provider,
            vpn_type,
            clean_text(requested_country),
            country_to_iso3(requested_country),
            clean_text(exit_ip) or None,
            clean_text(exit_country) or None,
            clean_text(warp_ip) or None,
            clean_text(warp_country) or None,
            server_location,
        ),
    )
    return cursor.fetchone()[0]


def get_reference_vantage_id(cursor) -> str | None:
    """The scanning host's current vantage point (newest of its rows)."""
    cursor.execute(
        "select id from vantage_point where server_location "
        "order by last_seen desc limit 1"
    )
    row = cursor.fetchone()
    return row[0] if row else None


def ensure_local_vantage_point(attempts: int = 30, delay: int = 5) -> str:
    """Register the host's own untunnelled vantage point (LOCAL_VANTAGE_LABEL).

    Called every round, as the public IP can change; retries while Postgres starts.
    """
    label = os.getenv("LOCAL_VANTAGE_LABEL", "austria")
    country = os.getenv("LOCAL_VANTAGE_COUNTRY", "Austria")
    exit_ip, exit_country = public_ip_info()

    for attempt in range(1, attempts + 1):
        try:
            with connect() as conn:
                with conn.cursor() as cursor:
                    vantage_id = upsert_vantage_point(
                        cursor,
                        label=label,
                        provider="none",
                        requested_country=country,
                        exit_ip=exit_ip,
                        exit_country=exit_country,
                        server_location=True,
                    )
                    # after a label change, only the new label is the reference.
                    cursor.execute(
                        "update vantage_point set server_location = false "
                        "where server_location and label <> %s",
                        (label,),
                    )
            log.info(
                "local vantage point %s (%s) via %s -> %s",
                label,
                country,
                exit_ip or "unknown IP",
                vantage_id,
            )
            return vantage_id
        except Exception:
            if attempt == attempts:
                raise
            log.warning(
                "database not ready for vantage point registration "
                "(attempt %d/%d), retrying in %ds",
                attempt,
                attempts,
                delay,
            )
            time.sleep(delay)
