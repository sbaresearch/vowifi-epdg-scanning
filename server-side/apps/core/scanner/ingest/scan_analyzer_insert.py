import json, logging, os, re
from pathlib import Path
from typing import Any

import psycopg
from scanner.common.logging_config import configure_logging

log = logging.getLogger(__name__)
MCC = re.compile(r"\bmcc(\d{3})\b")
MNC = re.compile(r"\bmnc(\d{3})\b")
ISO3 = re.compile(r"^[A-Z]{3}$")
DEFAULT_COUNTRY_ISO3_JSON = Path(__file__).resolve().parent / "data" / "db_to_iso3.json"


def get_required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


# sanatizing and splitting of data. primarily extracting MCC and MNC.
def normalize(entry):
    if not isinstance(entry, dict):
        return None

    domain = entry.get("domain") or ""
    response = entry.get("response") or {}
    if not isinstance(response, dict):
        response = {"state": str(response)}

    mcc = MCC.search(domain)
    mnc = MNC.search(domain)

    normalized_record = {
        "timestamp": entry.get("timestamp"),
        "domain": domain,
        "ip": entry.get("ip"),
        "mcc": mcc.group(1) if mcc else None,
        "mnc": mnc.group(1) if mnc else None,
        "state": response.get("state"),
    }
    normalized_record.update(response)
    return normalized_record


# convert strings to enum like states for easier handlingin on DB side.
def state_to_enum(state: str | None) -> str:
    input = (state or "").strip().lower()
    if input == "successful key exchange":
        return "SUCCESS"
    if input == "no ikev2 resp":
        return "NO_RESPONSE"
    if input == "no proposal chosen":
        return "NO_PROPOSAL_CHOSEN"
    return "UNDEFINED"


def normalize_dh_group(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def derive_result(dh_variant: str, original_result: str, dh_group: Any) -> str:
    """
    if dh_variant == "DOWNGRADE_DH2048" and original_result == "SUCCESS":
        normalized_group = normalize_dh_group(dh_group)
        if normalized_group in {1, 3, 5}:
            return "SUCCESS"
        return "NO_SUCCESS"
    """
    return original_result


# build mcc mnc mapping to scraped data.
def load_mcc_mnc_map(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("mapping JSON must be a list")

    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in data:
        if not isinstance(row, dict):
            continue
        mcc = row.get("mcc")
        mnc = row.get("mnc")
        if (
            isinstance(mcc, str)
            and isinstance(mnc, str)
            and len(mcc) == 3
            and len(mnc) == 3
        ):
            out[(mcc, mnc)] = row
    return out


def load_country_iso3_map(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("country ISO3 mapping JSON must be an object")

    out: dict[str, str] = {}
    for country, iso3 in data.items():
        if not isinstance(country, str) or not isinstance(iso3, str):
            continue
        normalized_country = clean_text(country)
        normalized_iso3 = iso3.strip().upper()
        if not normalized_country:
            continue
        if not ISO3.fullmatch(normalized_iso3):
            continue
        out[normalized_country] = normalized_iso3
    return out


# insertion of scan run.
def insert_run(
    cursor, dh_variant: str, header_text: str | None, source_file: str
) -> str:
    cursor.execute(
        """
        insert into scan (dh_variant, header_text, source_file)
        values (%s, %s, %s)
        returning id
        """,
        (dh_variant, header_text, source_file),
    )
    return cursor.fetchone()[0]


# insertion of epdg domain.
def upsert_target(
    cursor,
    domain: str,
    ip: str,
    mcc: str | None,
    mnc: str | None,
    country: str | None,
    iso3: str | None,
    network: str | None,
    operator: str | None,
    itu_region: str | None,
) -> str:
    cursor.execute(
        """
        insert into epdg_server (
          epdg_domain, target_ip, mcc, mnc,
          country, iso3, network, operator,
          itu_region
        )
        values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        on conflict (epdg_domain, target_ip) do update
          set mcc        = excluded.mcc,
              mnc        = excluded.mnc,
              country    = excluded.country,
              iso3       = excluded.iso3,
              network   = excluded.network,
              operator   = excluded.operator,
              itu_region = excluded.itu_region
        returning id
        """,
        (domain, ip, mcc, mnc, country, iso3, network, operator, itu_region),
    )
    return cursor.fetchone()[0]


# strips strings.
def clean_text(x: Any) -> str | None:
    if x is None:
        return None
    s = str(x).strip()
    return s or None


# connection to DB and insertion of domain scan data.
def analyze_and_insert(
    path: Path, mapping_json: Path, country_iso3_json: Path = DEFAULT_COUNTRY_ISO3_JSON
) -> None:
    """
    Reads newline-delimited JSON scan results from `path`, extracts MCC/MNC from the domain,
    enriches targets using `mapping_json` (list of {mcc,mnc,country,network,operator,...}),
    enriches country metadata with ISO3 from `country_iso3_json`,
    then upserts into epdg_server and epdg_result.
    """
    mccmnc_map = load_mcc_mnc_map(mapping_json)
    country_iso3_map = load_country_iso3_map(country_iso3_json)

    lines = path.read_text(encoding="utf-8").splitlines()

    header_text = next((ln.strip() for ln in lines if ln.strip().startswith("#")), None)

    m = re.search(r"SUPPORT_DH_([^_]+)_|(TOLERATE_DH\d+|DOWNGRADE_DH\d+)", path.name)
    if m:
        dh_variant = m.group(1) or m.group(2)
    else:
        dh_variant = "UNKNOWN"

    conn = psycopg.connect(
        host=get_required_env("POSTGRES_HOST"),
        port=int(get_required_env("POSTGRES_PORT")),
        dbname=get_required_env("POSTGRES_DB"),
        user=get_required_env("POSTGRES_USER"),
        password=get_required_env("POSTGRES_PASSWORD"),
    )

    # commits on success, rollbacks on exception.
    with conn:
        with conn.cursor() as cursor:
            run_id = insert_run(cursor, dh_variant, header_text, str(path))
            log.info("scan=%s dh_variant=%s", run_id, dh_variant)

            rows = []
            for line_counter, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    rec = normalize(json.loads(line))
                except json.JSONDecodeError:
                    log.warning("bad json line %d", line_counter)
                    continue

                if not rec or not rec.get("domain") or not rec.get("ip"):
                    continue

                # add datan from domain country mapping web scrape.
                meta = None
                if rec.get("mcc") and rec.get("mnc"):
                    meta = mccmnc_map.get((rec["mcc"], rec["mnc"]))

                country = clean_text(meta.get("country")) if meta else None
                iso3 = country_iso3_map.get(country) if country else None
                network = clean_text(meta.get("network")) if meta else None
                operator = clean_text(meta.get("operator")) if meta else None
                itu_region = clean_text(meta.get("itu_region")) if meta else None

                server_id = upsert_target(
                    cursor,
                    rec["domain"],
                    rec["ip"],
                    rec.get("mcc"),
                    rec.get("mnc"),
                    country,
                    iso3,
                    network,
                    operator,
                    itu_region,
                )

                rows.append(
                    (
                        run_id,
                        server_id,
                        rec.get("timestamp"),
                        rec.get("state"),
                        derive_result(
                            dh_variant,
                            state_to_enum(rec.get("state")),
                            rec.get("group"),
                        ),
                        normalize_dh_group(rec.get("group")),
                        rec.get("encr_id"),
                        rec.get("encr_key_len"),
                        rec.get("integ_id"),
                        rec.get("prf_id"),
                        rec.get("ke"),
                        rec.get("nonce"),
                    )
                )

            if rows:
                cursor.executemany(
                    """
                    insert into epdg_result (
                      scan_id, server_id, observed_at, raw_state, result,
                      dh_group, encr_id, encr_key_len, integ_id, prf_id,
                      key_hex, nonce_hex
                    )
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    on conflict (scan_id, server_id) do update
                      set observed_at  = excluded.observed_at,
                          raw_state    = excluded.raw_state,
                          result       = excluded.result,
                          dh_group     = excluded.dh_group,
                          encr_id      = excluded.encr_id,
                          encr_key_len = excluded.encr_key_len,
                          integ_id     = excluded.integ_id,
                          prf_id       = excluded.prf_id,
                          key_hex      = excluded.key_hex,
                          nonce_hex    = excluded.nonce_hex
                    """,
                    rows,
                )

                # trigger rebuild of the quick access table.
                cursor.execute(
                    "select refresh_latest_snapshot(%s)",
                    (run_id,),
                )
                # rebuild leaflet API snapshot (materialized view)
                cursor.execute(
                    "select refresh_country_operator_snapshot()",
                )

            log.info("inserted/updated %d results", len(rows))

    conn.close()


def refresh_collision_keys() -> None:
    conn = psycopg.connect(
        host=get_required_env("POSTGRES_HOST"),
        port=int(get_required_env("POSTGRES_PORT")),
        dbname=get_required_env("POSTGRES_DB"),
        user=get_required_env("POSTGRES_USER"),
        password=get_required_env("POSTGRES_PASSWORD"),
    )
    with conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT refresh_collision_keys()")
    conn.close()


if __name__ == "__main__":
    configure_logging("%(levelname)s: %(message)s")
    analyze_and_insert()
