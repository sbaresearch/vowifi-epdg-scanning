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
from scanner.ikev2.ikev2_class import usable_ip_versions
from scanner.ingest import scan_analyzer_insert
from scanner.ingest import takeout_export
from scanner.ingest import vantage_points

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

# process role:
#   full          discovery, enrichment, scan, ingest, takeouts, in a loop
#   vantage_scan  one scan pass in gluetun's netns, no DB, no loop
SCANNER_ROLE = os.getenv("SCANNER_ROLE", "full")

VANTAGE_RUNS_DIR = DATA_DIR / "vantage_runs"

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


import datetime
import ipaddress
import json


# filters the latest raw zdns scan to clean out loopbacks/obvious junk and errors.
# keeps entries if they have at least one usable IP (v4/v6) OR are CNAME-only.
def filter_zdns_scan_results(raw_dir=None, filtered_dir=None):
    logger.info("filtering zdns scan...")

    raw_dir = Path(raw_dir) if raw_dir else RAW_DIR
    filtered_dir = Path(filtered_dir) if filtered_dir else FILTERED_DIR
    filtered_dir.mkdir(parents=True, exist_ok=True)

    latest_raw_dns_scan = latest_file_picker(raw_dir, "epdg_dns_scan_*.json")
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
    out_path = filtered_dir / f"epdg_dns_scan_filtered_{timestamp}.json"

    with open(out_path, "w") as out:
        json.dump(filtered_dns_entries, out, indent=2)

    logger.debug(f"Filtered DNS entries written: {len(filtered_dns_entries)}")
    logger.debug(f"Drop counts: {drop_counts}")


# extracts the ePDG domains from the filtered DNS scans and saves them to a timestamped file.
def extract_domains_from_filtered_scans(filtered_dir=None, epdgs_dir=None):
    logger.info("extracting ePDG domains...")

    filtered_dir = Path(filtered_dir) if filtered_dir else FILTERED_DIR
    epdgs_dir = Path(epdgs_dir) if epdgs_dir else EPDGS_DIR
    epdgs_dir.mkdir(parents=True, exist_ok=True)

    # looking up latest filtered DNS scan file.
    latest_filtered_dns_scan = latest_file_picker(
        filtered_dir,
        "epdg_dns_scan_filtered_*.json",
    )

    with open(latest_filtered_dns_scan, "r") as epdg_dns_scan_filtered_file:
        logger.debug(f"reading from {latest_filtered_dns_scan}.")
        filtered_dns_scan = json.load(epdg_dns_scan_filtered_file)

    # extract ePDG domains.
    logger.debug("extracting ePDG domains from json.")
    epdg_list = [scan["name"] for scan in filtered_dns_scan if "name" in scan]

    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    epdgs_output_file = epdgs_dir / f"epdg_scanned_{timestamp}.json"

    with open(epdgs_output_file, "w") as f:
        logger.debug(f"writing to epdg_scanned_{timestamp}.json.")
        for epdg in epdg_list:
            f.write(epdg + "\n")


# writes the extracted domains as one target list (default: shared epdg_domains.txt).
def override_edpg_domains(epdgs_dir=None, output_file=None):
    logger.info("replacing old ePDG domains...")

    epdgs_dir = Path(epdgs_dir) if epdgs_dir else EPDGS_DIR

    # looking up latest extracted ePDG domains file.
    latest_epdg_domains = latest_file_picker(
        epdgs_dir,
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

    epdg_domains_output_file = (
        Path(output_file) if output_file else DATA_DIR / "epdg_domains.txt"
    )
    epdg_domains_output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(epdg_domains_output_file, "w") as epdg_domains_txt_file:
        logger.debug(f"writing to {epdg_domains_output_file}.")
        for epdg in epdg_domains:
            epdg_domains_txt_file.write(epdg + "\n")

    logger.info(
        f"wrote {len(epdg_domains)} ePDG domains to {epdg_domains_output_file}."
    )
    return epdg_domains_output_file


# testcases for this pass; TESTCASES_OVERRIDE shortens smoke tests (full pass ~10h).
def selected_testcases():
    override = os.getenv("TESTCASES_OVERRIDE")
    if not override:
        return TESTCASES

    wanted = [tc.strip() for tc in override.split(",") if tc.strip()]
    unknown = [tc for tc in wanted if tc not in epdg_scanner.TEST_CONFIG]
    if unknown:
        raise ValueError(f"unknown testcases in TESTCASES_OVERRIDE: {unknown}")
    logger.info(f"TESTCASES_OVERRIDE active, running only: {wanted}")
    return wanted


# runs one IKEv2 testcase, returns its results file.
def run_testcase(testcase, results_dir=None):
    logger.info(f"running scan for {testcase}...")
    return epdg_scanner.epdg_scanner("any", "ipv4v6", testcase, results_dir=results_dir)


# ingests one result file of the host's own untunnelled scan (mode "local").
def ingest_result(results_file, vantage_id=None):
    latest_mappings = latest_file_picker(
        MAPPINGS_DIR,
        "mcc_mnc_output_*.json",
    )
    if not latest_mappings:
        raise FileNotFoundError(f"no MCC/MNC mapping file found in {MAPPINGS_DIR}")

    scan_analyzer_insert.analyze_and_insert(
        Path(results_file),
        Path(latest_mappings),
        vantage_id=vantage_id,
        mode="local",
    )


def run_epdg_scanning_tool(vantage_id=None):
    logger.info("running ePDG scanning tool...")

    # ingest per testcase, so results land before the ~10h pass ends.
    for tc in selected_testcases():
        try:
            results_file = run_testcase(tc)
            ingest_result(results_file, vantage_id=vantage_id)
        except Exception:
            # one bad testcase must not end the pipeline.
            logger.exception(f"testcase {tc} failed")


# ------------------------------------------------- one scan pass in a VPN tunnel
# no DB (gluetun's netns, no credentials): results and a manifest go to the shared
# volume for the orchestrator to ingest.


# true if the file holds results beyond its header (empty would read as "unsupported").
def _has_measurements(results_file):
    try:
        with open(results_file, encoding="utf-8") as handle:
            return any(line.startswith("{") for line in handle)
    except OSError:
        return False


# recursive resolver for in-tunnel discovery; iterative gets rate-limited (see below).
TUNNEL_RESOLVER = "1.1.1.1"


# writes the discovery input: real MCCs only (~232 of 1000), all 1000 MNCs each.
def real_mcc_domains(output_file):
    latest = latest_file_picker(MAPPINGS_DIR, "mcc_mnc_output_*.json")
    if not latest:
        logger.warning("no MCC/MNC mapping, sweeping the full generated list")
        return None

    with open(latest, encoding="utf-8") as handle:
        rows = json.load(handle)
    mccs = sorted({str(row.get("mcc")).strip() for row in rows if row.get("mcc")})
    mccs = [mcc for mcc in mccs if mcc.isdigit()]
    if not mccs:
        logger.warning("mapping file has no usable MCCs, sweeping the full list")
        return None

    with open(output_file, "w", encoding="utf-8") as handle:
        for mcc in mccs:
            for mnc in range(1000):
                handle.write(
                    f"epdg.epc.mnc{mnc:03d}.mcc{int(mcc):03d}"
                    f".pub.3gppnetwork.org\n"
                )
    logger.info(
        f"discovery input: {len(mccs)} real MCCs x 1000 MNCs = "
        f"{len(mccs) * 1000} names (of 1,100,000 possible)"
    )
    return output_file


# DNS discovery through this tunnel (GeoDNS) into its own dirs; returns the domain list.
def discover_in_tunnel(label, mode):
    run_dir = DATA_DIR / "vantage_discovery" / label / mode
    raw_dir = run_dir / "raw"
    filtered_dir = run_dir / "filtered"
    epdgs_dir = run_dir / "epdgs"
    for directory in (raw_dir, filtered_dir, epdgs_dir):
        directory.mkdir(parents=True, exist_ok=True)

    # zdns_runner derives its files from these dirs; the run dir keeps them separate.
    input_dir = GENERATED_DIR
    if real_mcc_domains(run_dir / "epdg_domains_generated.txt"):
        input_dir = run_dir

    # own recursive config: the shared iterative one gets the exit rate-limited
    # after ~207k queries (then SERVFAIL, ~70% of domains lost).
    (run_dir / "zdns_config.ini").write_text(
        "[Application Options]\n"
        "iterative=false\n"
        f"name-servers={TUNNEL_RESOLVER}\n"
        "[A]\n[AAAA]\n[CNAME]\n",
        encoding="utf-8",
    )
    config_dir = run_dir
    logger.info(
        f"vantage discovery [{label}/{mode}] resolving recursively via "
        f"{TUNNEL_RESOLVER}"
    )

    logger.info(f"vantage discovery [{label}] starting zdns in-tunnel -> {run_dir}")
    zdns_runner.zdns_runner(config_dir, input_dir, raw_dir)
    filter_zdns_scan_results(raw_dir=raw_dir, filtered_dir=filtered_dir)
    extract_domains_from_filtered_scans(filtered_dir=filtered_dir, epdgs_dir=epdgs_dir)
    domains_file = override_edpg_domains(
        epdgs_dir=epdgs_dir,
        output_file=run_dir / "epdg_domains.txt",
    )

    # fail fast: an empty list otherwise looks like a slow scan.
    if not Path(domains_file).stat().st_size:
        raise RuntimeError(
            f"in-tunnel discovery found no ePDG domains at all ({domains_file} is "
            f"empty). The sweep ran but nothing resolved -- check the DNS path out "
            f"of this tunnel before trusting any result from it."
        )

    # drop the files rebuilt every run (~1.3 GB raw output, ~10 MB input).
    for stale in raw_dir.glob("epdg_dns_scan_*.json"):
        stale.unlink(missing_ok=True)
    (run_dir / "epdg_domains_generated.txt").unlink(missing_ok=True)

    return domains_file


def run_vantage_scan():
    label = os.environ["VANTAGE_LABEL"]
    vantage_id = os.environ["VANTAGE_ID"]
    mode = os.getenv("SCAN_MODE", "full")
    exit_ip = os.getenv("VANTAGE_EXIT_IP")
    exit_country = os.getenv("VANTAGE_EXIT_COUNTRY")
    warp_ip = os.getenv("VANTAGE_WARP_IP")
    warp_country = os.getenv("VANTAGE_WARP_COUNTRY")

    results_dir = RESULTS_DIR / (
        os.getenv("RESULTS_SUBDIR") or f"vantage/{label}/{mode}"
    )
    manifest_path = Path(
        os.getenv("VANTAGE_MANIFEST") or VANTAGE_RUNS_DIR / f"{label}-{mode}.json"
    )

    logger.info(
        f"vantage scan [{label}/{mode}] via {exit_ip} ({exit_country}) -> {results_dir}"
    )

    # `full` discovers its own targets; other modes get a list from the orchestrator.
    if mode == "full" and not os.getenv("EPDG_DOMAINS_FILE"):
        os.environ["EPDG_DOMAINS_FILE"] = str(discover_in_tunnel(label, mode))

    domains_file = os.getenv("EPDG_DOMAINS_FILE") or str(DATA_DIR / "epdg_domains.txt")
    if not Path(domains_file).exists():
        raise FileNotFoundError(
            f"target list {domains_file} missing -- mode {mode} needs it before "
            "any testcase can run"
        )

    # reachable address families, recorded so a v4-only round is identifiable.
    # explicit None shares the scanner's lru_cache entry (() and (None,) differ).
    ip_versions = list(usable_ip_versions(None))
    logger.info(f"vantage scan [{label}] can reach: {', '.join(ip_versions) or 'nothing'}")

    started_at = datetime.datetime.now(datetime.timezone.utc)
    since = started_at.timestamp()
    for tc in selected_testcases():
        try:
            run_testcase(tc, results_dir=results_dir)
        except Exception:
            # one failed testcase must not cost the others.
            logger.exception(f"testcase {tc} failed at vantage point {label}")

    # from disk, not clean returns: a testcase that raised can still leave real results.
    produced = sorted(
        path
        for path in results_dir.glob("*.json")
        if path.stat().st_mtime >= since and _has_measurements(path)
    )

    manifest = {
        "vantage_id": vantage_id,
        "vantage_label": label,
        "mode": mode,
        # warp_ip: the Cloudflare hop in front of exit_ip, null without one.
        "exit_ip": exit_ip,
        "exit_country": exit_country,
        "warp_ip": warp_ip,
        "warp_country": warp_country,
        "domains_file": domains_file,
        "ip_versions": ip_versions,
        "started_at": started_at.isoformat(),
        "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        # relative to DATA_DIR, resolved against the orchestrator's mount.
        "results": [str(Path(p).relative_to(DATA_DIR)) for p in produced],
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info(f"wrote manifest with {len(produced)} result files to {manifest_path}")


def run_full_pipeline():
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
        # per round: the public IP (and so the vantage point) can change.
        local_vantage_id = vantage_points.ensure_local_vantage_point()
        run_epdg_scanning_tool(vantage_id=local_vantage_id)
        # global rebuilds, once per round.
        scan_analyzer_insert.refresh_country_operator_snapshot()
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


if __name__ == "__main__":
    configure_logging("%(asctime)s [%(levelname)s]: %(message)s")

    if SCANNER_ROLE == "vantage_scan":
        run_vantage_scan()
    elif SCANNER_ROLE == "full":
        run_full_pipeline()
    else:
        raise SystemExit(
            f"unknown SCANNER_ROLE {SCANNER_ROLE!r}, expected 'full' or 'vantage_scan'"
        )


"""
- find out whats 'no ikev2 resp' vs 'no proposal chosen' vs 'unknown payload' are they all counted towards failed?.
        no ikev2 resp --> no response at all.
        no proposal chosen --> doesn't like any of the encryptions that were proposed.
        unknown payload --> idk.

- (DONE) wireshark (protocol, artefakte serverseitig (hardware manufacturer)) (in gitlab repo)

- soft: database (process). pull out of log file or feed as discovered? -> pull out of logfile. batching?
"""
