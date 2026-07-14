import json
import logging
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple
import requests
from bs4 import BeautifulSoup, Tag
from scanner.common.logging_config import configure_logging

logger = logging.getLogger(__name__)

URLS: List[Tuple[str, str]] = [
    (
        "europe",
        "https://en.wikipedia.org/wiki/Mobile_network_codes_in_ITU_region_2xx_(Europe)",
    ),
    (
        "north_america",
        "https://en.wikipedia.org/wiki/Mobile_network_codes_in_ITU_region_3xx_(North_America)",
    ),
    (
        "asia",
        "https://en.wikipedia.org/wiki/Mobile_network_codes_in_ITU_region_4xx_(Asia)",
    ),
    (
        "oceania",
        "https://en.wikipedia.org/wiki/Mobile_network_codes_in_ITU_region_5xx_(Oceania)",
    ),
    (
        "africa",
        "https://en.wikipedia.org/wiki/Mobile_network_codes_in_ITU_region_6xx_(Africa)",
    ),
    (
        "south_america",
        "https://en.wikipedia.org/wiki/Mobile_network_codes_in_ITU_region_7xx_(South_America)",
    ),
]

OUTFILE = Path("mcc_mnc_wikipedia_itu.json")
DEFAULT_OUTPUT_DIR = Path(".")

HEADERS = {
    "User-Agent": "MCC_MNC_parser/1.0 (personal use.)",
    "Accept-Language": "en-US,en",
}


def clean_text(s: str) -> str:
    s = re.sub(r"\[\d+\]", "", s)  # remove citation markers like [1]
    s = re.sub(r"\s+", " ", s).strip()  # normalize whitespace
    return s


def cell_text(td: Tag) -> str:
    for sup in td.select("sup"):
        sup.decompose()
    return clean_text(td.get_text(" ", strip=True))


def normalize_mnc(mnc: str) -> str:
    # Always store MNC as 3 digits (zero-padded)
    return f"{int(mnc):03d}"


def pick_table_for_heading(heading_div: Tag) -> Optional[Tag]:
    """
    Wikipedia pages sometimes have multiple wikitables after a heading.
    We want the table that actually contains MCC/MNC.
    """
    for tbl in heading_div.find_all_next("table", class_="wikitable", limit=3):
        first_tr = tbl.find("tr")
        if not first_tr:
            continue
        ths = first_tr.find_all("th")
        header_text = " ".join(
            clean_text(th.get_text(" ", strip=True)).lower() for th in ths
        )
        if "mcc" in header_text and "mnc" in header_text:
            return tbl
    return None


def scrape_url(url: str, region: str) -> List[Dict[str, str]]:
    r = requests.get(url, timeout=30, headers=HEADERS)
    logger.debug(f"HTTP {r.status_code} from {url}")
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "lxml")
    results: List[Dict[str, str]] = []

    # Each country block is: <div class="mw-heading mw-heading4"> ... </div> followed by a <table class="wikitable">
    for heading_div in soup.select("div.mw-heading.mw-heading4"):
        h4 = heading_div.find("h4")
        if not h4:
            continue

        # Country name is the <a> text in the h4, like "Afghanistan"
        country_a = h4.find("a")
        if not country_a:
            continue
        country = clean_text(country_a.get_text(strip=True))

        table = pick_table_for_heading(heading_div)
        if not table:
            continue

        # Read header to find column indices.
        header_row = table.find("tr")
        header_cells = header_row.find_all("th") if header_row else []
        headers = [
            clean_text(th.get_text(" ", strip=True)).lower() for th in header_cells
        ]

        def col(name: str) -> int:
            try:
                return headers.index(name.lower())
            except ValueError:
                return -1

        mcc_i = col("mcc")
        mnc_i = col("mnc")
        operator_i = col("operator")
        status_i = col("status")

        # Fallback to known layout if header parsing fails
        # Default Wikipedia table layout:
        # 0: MCC | 1: MNC | 2: Brand | 3: Operator | 4: Status
        if mcc_i == -1:
            mcc_i = 0
        if mnc_i == -1:
            mnc_i = 1
        if operator_i == -1:
            operator_i = 3
        if status_i == -1:
            status_i = 4

        # Parse rows
        for tr in table.find_all("tr"):
            tds = tr.find_all("td")
            if not tds:
                continue
            if max(mcc_i, mnc_i, operator_i, status_i) >= len(tds):
                continue

            mcc = cell_text(tds[mcc_i])
            mnc_raw = cell_text(tds[mnc_i])
            operator = cell_text(tds[operator_i])
            status = cell_text(tds[status_i])

            # Basic sanity: MCC 3 digits, MNC 1-3 digits
            if not re.fullmatch(r"\d{3}", mcc):
                continue
            if not re.fullmatch(r"\d{1,3}", mnc_raw):
                continue

            results.append(
                {
                    "itu_region": region,
                    "country": country,
                    "mcc": mcc,
                    "mnc": normalize_mnc(mnc_raw),
                    "operator": operator,
                    "status": status,
                }
            )

    return results


def scrape_all() -> List[Dict[str, str]]:
    all_rows: List[Dict[str, str]] = []
    for region, url in URLS:
        rows = scrape_url(url, region=region)
        all_rows.extend(rows)
        logger.info(f"{region}: {len(rows)} rows from wikipedia.")
    return all_rows


def wikipedia_mcc_mnc_scraper(output_path: Path = DEFAULT_OUTPUT_DIR) -> None:
    output_file = output_path / OUTFILE

    data = scrape_all()

    data.sort(
        key=lambda d: (
            d["country"].lower(),
            d["itu_region"],
            int(d["mcc"]),
            int(d["mnc"]),
        )
    )

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    logger.debug(f"wrote {len(data)} rows to {output_file}")


if __name__ == "__main__":
    configure_logging("%(asctime)s [%(levelname)s]: %(message)s")
    wikipedia_mcc_mnc_scraper()
