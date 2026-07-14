import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import requests
from scanner.common.logging_config import configure_logging

API_URL = "https://mcc-mnc.com/api/v1/mcc-mnc.php"
HEADERS = {
    "User-Agent": "MCC_MNC_parser/1.0 (personal use.)",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "application/json",
}

OUTPUT_FILE = Path("mcc_mnc_website.json")
DEFAULT_OUTPUT_DIR = Path(".")
logger = logging.getLogger(__name__)


def write_json(data: List[Dict[str, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def scraper() -> List[dict]:
    request = requests.get(API_URL, headers=HEADERS, timeout=60)
    request.raise_for_status()
    payload = request.json()
    data_normalized = normalize_api_payload(payload)

    logger.info(
        "loaded %d normalized MCC/MNC rows from API version=%s generated=%s",
        len(data_normalized),
        payload.get("version") if isinstance(payload, dict) else None,
        payload.get("generated") if isinstance(payload, dict) else None,
    )
    return data_normalized


def normalizer(rows: List[dict]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue

        mcc = str(row.get("mcc", ""))
        mnc = str(row.get("mnc", ""))
        if not (mcc.isdigit() and len(mcc) == 3 and mnc.isdigit()):
            continue

        out.append(
            {
                "country": str(row.get("country", "")),
                "iso": str(row.get("iso", "")).upper(),
                "mcc": mcc,
                "mnc": mnc.zfill(3),
                "network": str(row.get("network", "")),
            }
        )

    out.sort(key=lambda x: (x["mcc"], x["mnc"]))
    return out


def normalize_api_payload(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    if not isinstance(payload, dict):
        raise RuntimeError("Expected API payload to be a JSON object.")

    rows = payload.get("data")
    if not isinstance(rows, list):
        raise RuntimeError(
            "Unexpected API format: missing required top-level 'data' array."
        )

    expected_count = payload.get("count")
    if isinstance(expected_count, int) and expected_count != len(rows):
        logger.warning(
            "API count mismatch: payload count=%d actual rows=%d",
            expected_count,
            len(rows),
        )

    return normalizer(rows)


def mcc_mnc_com_scraper(output_path: Path = DEFAULT_OUTPUT_DIR) -> Path:
    output_file = output_path / OUTPUT_FILE
    data_normalized = scraper()

    if not data_normalized:
        raise RuntimeError(
            "no data fetched. something is broken. "
            "most likely due to schema changes on the API end."
        )

    write_json(data_normalized, output_file)
    logger.info("wrote %d normalized API rows -> %s", len(data_normalized), output_file)
    return output_file


if __name__ == "__main__":
    configure_logging("%(asctime)s [%(levelname)s]: %(message)s")
    mcc_mnc_com_scraper()
