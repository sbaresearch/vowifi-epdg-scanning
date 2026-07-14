import datetime
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple
from scanner.common.logging_config import configure_logging
from scanner.enrichment import mcc_mnc_com_scraper
from scanner.enrichment import mcc_mnc_wikipedia_scraper

logger = logging.getLogger(__name__)


WIKIPEDIA_FILE = Path("mcc_mnc_wikipedia_itu.json")
WEBSITE_FILE = Path("mcc_mnc_website.json")


def norm3(x: Any) -> str:
    s = "" if x is None else str(x).strip()
    # whitespace sanity check.
    s = "".join(ch for ch in s if ch.isdigit())
    return s.zfill(3)


def is_missing(v: Any) -> bool:
    return v is None or (isinstance(v, str) and v.strip() == "")


def load_json_array(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON array at the top level")
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"{path}[{i}] is not an object")
    return data


def scraper(output_path: Path = Path(".")) -> None:
    output_path.mkdir(parents=True, exist_ok=True)

    logger.info("scraping data from wikipedia..")
    mcc_mnc_wikipedia_scraper.wikipedia_mcc_mnc_scraper(output_path)

    logger.info("scraping data from mcc-mnc.com..")
    mcc_mnc_com_scraper.mcc_mnc_com_scraper(output_path)

    logger.info("merging results..")

    wikipedia_file = output_path / WIKIPEDIA_FILE
    website_file = output_path / WEBSITE_FILE

    base = load_json_array(wikipedia_file)
    website = load_json_array(website_file)
    base_row_count = len(base)
    logger.info(
        "loaded %d wikipedia rows and %d API rows for merge",
        base_row_count,
        len(website),
    )

    # if duplicate, keep wikipedia, ignore other.
    web_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for w in website:
        mcc = norm3(w.get("mcc"))
        mnc = norm3(w.get("mnc"))
        key = (mcc, mnc)

        if key in web_map:
            prev = web_map[key]
            if (prev.get("iso") != w.get("iso")) or (
                prev.get("network") != w.get("network")
            ):
                logger.debug(
                    f"duplicate entry for mcc:{mcc} mnc:{mnc} differs. keeping wikipedia."
                )
            continue

        web_map[key] = w

    # normalizing base MCC/MNC
    base_keys: set[Tuple[str, str]] = set()
    filled_iso = 0
    filled_network = 0
    for b in base:
        b["mcc"] = norm3(b.get("mcc"))
        b["mnc"] = norm3(b.get("mnc"))
        key = (b["mcc"], b["mnc"])
        base_keys.add(key)

        # completing iso entries for wikipedia json.
        w = web_map.get(key)
        if w:
            if is_missing(b.get("iso")) and not is_missing(w.get("iso")):
                b["iso"] = str(w.get("iso")).strip()
                filled_iso += 1
            if is_missing(b.get("network")) and not is_missing(w.get("network")):
                b["network"] = str(w.get("network")).strip()
                filled_network += 1

    # appending website entries not present in base
    appended_rows = 0
    for key, w in web_map.items():
        if key in base_keys:
            continue

        new_obj: Dict[str, Any] = {
            "itu_region": None,
            "country": w.get("country"),
            "mcc": key[0],
            "mnc": key[1],
            "operator": None,
            "iso": w.get("iso"),
            "network": w.get("network"),
            "status": None,
        }

        base.append(new_obj)
        base_keys.add(key)
        appended_rows += 1

    logger.info(
        "merge summary: base_rows=%d filled_iso=%d filled_network=%d api_only_appended=%d final_rows=%d",
        base_row_count,
        filled_iso,
        filled_network,
        appended_rows,
        len(base),
    )

    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    output_file = output_path / f"mcc_mnc_output_{timestamp}.json"

    output_file.write_text(
        json.dumps(base, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    logger.info(f"Wrote merged output to: {output_file}")

    # deleting merged input files
    for path in (wikipedia_file, website_file):
        try:
            path.unlink()
            logger.info(f"Deleted input file: {path}")
        except FileNotFoundError:
            logger.warning(f"Input file already missing: {path}")
        except Exception as e:
            logger.error(f"Failed to delete {path}: {e}")


if __name__ == "__main__":
    configure_logging("%(asctime)s [%(levelname)s]: %(message)s")
    scraper()
