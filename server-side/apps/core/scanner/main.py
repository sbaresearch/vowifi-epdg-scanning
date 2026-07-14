import datetime
import time
import os.path
import os
import json
import glob
import logging
import ipaddress
from pathlib import Path
from scanner.common import file_compressor
from scanner.common.logging_config import configure_logging
from scanner.discovery import epdg_generator
from scanner.discovery import zdns_runner
from scanner.enrichment import mcc_mnc_scraper_start
from scanner.ikev2 import epdg_scanner
from scanner.ingest import scan_analyzer_insert
from scanner.ingest import takeout_export

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))

GENERATED_DIR = DATA_DIR / "generated"
SCANS_DIR = DATA_DIR / "scans"
RAW_DIR = SCANS_DIR / "raw"
FILTERED_DIR = SCANS_DIR / "filtered"
EPDGS_DIR = DATA_DIR / "epdgs"
CONFIG_DIR = DATA_DIR / "config"
RESULTS_DIR = DATA_DIR / "results"
MAPPINGS_DIR = DATA_DIR / "mappings"

SLEEPTIME = 28800  # 8 hours.

TESTCASES = [
    "SUPPORT_DH_768MODP",
    "SUPPORT_DH_1024MODP",
    "SUPPORT_DH_1536MODP",
    "SUPPORT_DH_2048MODP",
    "SUPPORT_DH_3072MODP",
    "SUPPORT_DH_4096MODP",
    "SUPPORT_DH_6144MODP",
    "SUPPORT_DH_8192MODP",
    "SUPPORT_DH_256ECP",
    "SUPPORT_DH_384ECP",
    "SUPPORT_DH_512ECP",
    "SUPPORT_DH_192ECP",
    "SUPPORT_DH_224ECP",
    "SUPPORT_DH_X25519",
    "TOLERATE_DH1024",
    "DOWNGRADE_DH2048",
]


# takes a file directory and the base name of a file to find the latest version of a group of files within a directory.
def latest_file_picker(file_dir, file_base_name):
    logger.debug(f"looking for latest {file_base_name} in {file_dir}.")

    pattern = os.path.join(str(file_dir), file_base_name)

    # list matching files
    files = glob.glob(pattern)

    if not files:
        logger.debug("no matching files found.")
    else:
        # pick latest file by modification time (actual file one, NOT the one in the name.)
        latest_file = max(files, key=os.path.getmtime)
        logger.debug(f"latest matching file: {latest_file}.")
        return latest_file


# checks if filesystem is setup properly, otherwise sets it up.
def environment_setup_check():
    logger.info("checking environment...")

    for directory in (
        GENERATED_DIR,
        RAW_DIR,
        FILTERED_DIR,
        EPDGS_DIR,
        CONFIG_DIR,
    ):
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"{directory} directory created.")

    # generates possible ePDGs if not already existing.
    epdg_file = GENERATED_DIR / "epdg_domains_generated.txt"
    if not epdg_file.exists():
        epdg_generator.generator(epdg_file)
        logger.debug("ePDG file generated.")

    # creates config file for zdns if not already existing.
    zdns_config_file = CONFIG_DIR / "zdns_config.ini"
    if not zdns_config_file.exists():
        zdns_config = (
            "[Application Options]\n" "iterative=true\n" "[A]\n" "[AAAA]\n" "[CNAME]\n"
        )
        zdns_config_file.write_text(zdns_config, encoding="utf-8")
        logger.debug("zdns config created.")

    logger.info("environment all set up.")


# filters the latest raw zdns scan to clean out loopbacks/obvious junk and errors.
# keeps entries if they have at least one usable IP (v4/v6) OR are CNAME-only.
def filter_zdns_scan_results():
    logger.info("filtering zdns scan...")

    latest_raw_dns_scan = latest_file_picker(RAW_DIR, "epdg_dns_scan_*.json")
    logger.debug("filtering the raw DNS scans.")

    filtered_dns_entries: list[dict] = []
    drop_counts = {
        "no_A_or_AAAA": 0,
        "status_not_noerror": 0,  # at least one A/AAAA existed but none had NOERROR
        "no_answers": 0,
        "no_ip_answer": 0,
        "only_nonglobal_ip": 0,
        "kept_cname_only": 0,
    }

    def _looks_like_hostname(s: str) -> bool:
        return "." in s and " " not in s and "/" not in s

    def _is_acceptable_ip(ip: ipaddress._BaseAddress) -> bool:
        return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)

    with open(latest_raw_dns_scan) as f:
        for line in f:
            scan = json.loads(line)
            results = scan.get("results") or {}

            a = results.get("A")
            aaaa = results.get("AAAA")
            if not a and not aaaa:
                drop_counts["no_A_or_AAAA"] += 1
                continue

            answers: list[dict] = []
            any_non_noerror = False
            for res in (a, aaaa):
                if not res:
                    continue
                if res.get("status") != "NOERROR":
                    any_non_noerror = True
                    continue
                answers.extend((res.get("data") or {}).get("answers") or [])

            if not answers:
                drop_counts[
                    "status_not_noerror" if any_non_noerror else "no_answers"
                ] += 1
                continue

            saw_any_ip = False
            has_cname = False
            kept = False

            for ans in answers:
                raw = ans.get("answer")
                if not raw:
                    continue

                ans_type = (ans.get("type") or "").upper()
                if ans_type == "CNAME":
                    has_cname = True

                try:
                    ip = ipaddress.ip_address(raw)
                    saw_any_ip = True
                    if _is_acceptable_ip(ip):
                        filtered_dns_entries.append(scan)
                        kept = True
                        break
                except ValueError:
                    if ans_type == "CNAME" or _looks_like_hostname(raw):
                        has_cname = True

            if not kept and has_cname:
                filtered_dns_entries.append(scan)
                drop_counts["kept_cname_only"] += 1
                kept = True

            if not kept:
                drop_counts[
                    "no_ip_answer" if not saw_any_ip else "only_nonglobal_ip"
                ] += 1

    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    out_path = FILTERED_DIR / f"epdg_dns_scan_filtered_{timestamp}.json"

    with open(out_path, "w") as out:
        json.dump(filtered_dns_entries, out, indent=2)

    logger.debug(f"Filtered DNS entries written: {len(filtered_dns_entries)}")
    logger.debug(f"Drop counts: {drop_counts}")


# extracts the ePDG domains from the filtered DNS scans and saves them to a timestamped file.
def extract_domains_from_filtered_scans():
    logger.info("extracting ePDG domains...")

    # looking up latest filtered DNS scan file.
    latest_filtered_dns_scan = latest_file_picker(
        FILTERED_DIR,
        "epdg_dns_scan_filtered_*.json",
    )

    with open(latest_filtered_dns_scan, "r") as epdg_dns_scan_filtered_file:
        logger.debug(f"reading from {latest_filtered_dns_scan}.")
        filtered_dns_scan = json.load(epdg_dns_scan_filtered_file)

    # extract ePDG domains.
    logger.debug("extracting ePDG domains from json.")
    epdg_list = [scan["name"] for scan in filtered_dns_scan if "name" in scan]

    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    epdgs_output_file = EPDGS_DIR / f"epdg_scanned_{timestamp}.json"

    with open(epdgs_output_file, "w") as f:
        logger.debug(f"writing to epdg_scanned_{timestamp}.json.")
        for epdg in epdg_list:
            f.write(epdg + "\n")


# overrides the old ePDG domains in epdg_domains.txt.
def override_edpg_domains():
    logger.info("replacing old ePDG domains...")

    # looking up latest extracted ePDG domains file.
    latest_epdg_domains = latest_file_picker(
        EPDGS_DIR,
        "epdg_scanned_*.json",
    )

    epdg_domains = []
    # this file is not really valid json.
    with open(latest_epdg_domains, "r") as epdg_domains_json_file:
        logger.debug(f"reading from {latest_epdg_domains}.")
        for line in epdg_domains_json_file:
            domain = line.strip()
            if domain:
                epdg_domains.append(domain)

    epdg_domains_output_file = DATA_DIR / "epdg_domains.txt"

    with open(epdg_domains_output_file, "w") as epdg_domains_txt_file:
        logger.debug("writing to epdg_domains.txt.")
        for epdg in epdg_domains:
            epdg_domains_txt_file.write(epdg + "\n")


def run_epdg_scanning_tool():
    logger.info("running ePDG scanning tool...")

    for tc in TESTCASES:
        logger.info(f"running scan for {tc}...")
        epdg_scanner.epdg_scanner("any", "ipv4v6", tc)
        latest_results = latest_file_picker(
            RESULTS_DIR,
            f"{tc}*.json",
        )
        latest_mappings = latest_file_picker(
            MAPPINGS_DIR,
            "mcc_mnc_output_*.json",
        )
        scan_analyzer_insert.analyze_and_insert(
            Path(latest_results), Path(latest_mappings)
        )


if __name__ == "__main__":
    configure_logging("%(asctime)s [%(levelname)s]: %(message)s")
    logger.info("starting up...")
    environment_setup_check()
    logger.info("checking if database takeouts exist.")
    try:
        takeout_export.generate_if_missing()
    except Exception:
        # ignore if failed, just serve nothing until first scan run completes.
        logger.exception("startup takeout generation failed")
    while True:
        zdns_runner.zdns_runner(CONFIG_DIR, GENERATED_DIR, RAW_DIR)
        filter_zdns_scan_results()
        extract_domains_from_filtered_scans()
        override_edpg_domains()
        mcc_mnc_scraper_start.scraper(Path(MAPPINGS_DIR))
        run_epdg_scanning_tool()
        scan_analyzer_insert.refresh_collision_keys()
        logger.info("done.")
        logger.info("compressing zdns output files.")
        file_compressor.compress_files(
            RAW_DIR,
            latest_file_picker(
                RAW_DIR,
                "epdg_dns_scan_*.json",
            ),
        )
        logger.info("compression done.")
        logger.info("generating database takeouts.")
        try:
            takeout_export.generate_takeouts()
            logger.info("takeout generation done.")
        except Exception:
            # ignore if failed, just keep serving last export. try again next time.
            logger.exception("takeout generation failed. keep serving last export.")
        logger.info("waiting...")
        time.sleep(SLEEPTIME)
        logger.info("continuing...")
