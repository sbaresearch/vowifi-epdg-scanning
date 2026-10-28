"""Run ePDG scans from VPN vantage points in parallel (ported from scanywhere).

The scanner runs in a gluetun netns without DB access: it writes result files, this
process ingests them (serialized). Volume paths are host paths, hence HOST_PROJECT_DIR.
"""

import json
import logging
import os
import random
import re
import signal
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

import docker

from scanner.common.logging_config import configure_logging

# canonical testcase list for the progress count.
from scanner.main import TESTCASES
from scanner.ingest import scan_analyzer_insert
from scanner.ingest.scan_analyzer_insert import connect
from scanner.ingest.vantage_points import upsert_vantage_point
from vantage import gluetun, providers, servers

log = logging.getLogger(__name__)

DATA_DIR = Path(os.getenv("DATA_DIR", "/data/data"))
VANTAGE_RUNS_DIR = DATA_DIR / "vantage_runs"

# host-side project path: the host daemon resolves volume binds.
HOST_PROJECT_DIR = os.environ.get("HOST_PROJECT_DIR", "")

SCANNER_IMAGE = os.getenv("SCANNER_IMAGE", "epdg-scanner:latest")
VANTAGE_POINTS_FILE = Path(
    os.getenv("VANTAGE_POINTS_FILE", "/config/vantage_points.json")
)
CONTROL_NETWORK_SUFFIX = os.getenv(
    "VANTAGE_CONTROL_NETWORK_SUFFIX", "vantage_control_net"
)

# how often the combined progress table is logged.
PROGRESS_SECONDS = int(os.getenv("VANTAGE_PROGRESS_SECONDS", "900"))
# floor on a scheduler loop, so an idle mode cannot spin.
MIN_ROUND_GAP = 60
# how often a scheduler checks for an empty queue.
QUEUE_POLL_SECONDS = 10

# ---------------------------------------------------------------- scan modes
# all run continuously:
#   full         zdns discovery in the tunnel, all testcases, via the VPN exit
#   full_warp    targets from epdg_server, all testcases, via WARP
#   dh2048_warp  targets from epdg_server, DH2048 only, via WARP
# stored per scan row, so modes don't overwrite each other (003_schema.sql).
WARP_IMAGE = os.getenv("WARP_IMAGE", "warp-hop:latest")

# parallel: vantage points at once per mode; timeout: watchdog per scan.
MODES = {
    "full": {
        # the scanner discovers its own list in the tunnel.
        "targets": "tunnel",
        "warp": False,
        "testcases": None,
        "parallel": int(os.getenv("VANTAGE_FULL_PARALLEL", "2")),
        "timeout": int(os.getenv("VANTAGE_FULL_TIMEOUT_SECONDS", str(30 * 3600))),
    },
    "full_warp": {
        "targets": "database",
        "warp": True,
        "testcases": None,
        "parallel": int(os.getenv("VANTAGE_FULL_WARP_PARALLEL", "3")),
        "timeout": int(os.getenv("VANTAGE_FULL_WARP_TIMEOUT_SECONDS", str(20 * 3600))),
    },
    "dh2048_warp": {
        "targets": "database",
        "warp": True,
        "testcases": "SUPPORT_DH_2048MODP",
        "parallel": int(os.getenv("VANTAGE_DH2048_WARP_PARALLEL", "2")),
        "timeout": int(os.getenv("VANTAGE_DH2048_TIMEOUT_SECONDS", str(2 * 3600))),
    },
}

# Cloudflare WARP endpoint (anycast: the PoP nearest the exit answers).
WARP_ENDPOINT_IP = os.getenv("WARP_ENDPOINT_IP", "162.159.192.1")
WARP_ENDPOINT_PORT = os.getenv("WARP_ENDPOINT_PORT", "2408")
# one WireGuard profile per slot, kept (holds private keys).
WARP_PROFILE_DIR = Path(os.getenv("WARP_PROFILE_DIR", "/warp"))
# tunnels to try for the WARP hop (2 = one retry on a fresh exit).
WARP_HOP_ATTEMPTS = int(os.getenv("WARP_HOP_ATTEMPTS", "2"))

# target lists built from the database.
TARGETS_DIR = DATA_DIR / "vantage_targets"

# containers we started, stopped on Ctrl-C.
_started_containers: list[str] = []
_containers_lock = threading.Lock()
_ingest_lock = threading.Lock()
_shutdown = threading.Event()

# one semaphore per VPN service (its device limit), shared by all schedulers.
_device_slots: dict[str, threading.BoundedSemaphore] = {}
_device_slots_lock = threading.Lock()

# per-mode concurrency; a semaphore so each vantage point can take its device slot first.
_mode_slots = {
    mode: threading.BoundedSemaphore(max(1, spec["parallel"]))
    for mode, spec in MODES.items()
}

# operator report logged only on change; sentinel, since a missing config reads as None.
_UNREAD = object()
_config_signature: object = _UNREAD
_config_lock = threading.Lock()

# shuffled country rotation per (operator, mode); in memory, reshuffled on restart.
_rotations: dict[tuple[str, str], list[str]] = {}
_rotation_lock = threading.Lock()

# state of each drawn vantage point until teardown (progress table, schedulers).
_progress: dict[str, dict] = {}
_progress_lock = threading.Lock()

# states without a tunnel slot yet (the queue).
QUEUED_STATES = ("queued", "waiting")


# sets a vantage point's state, merging details (set-once fields survive).
def _set_progress(label, state, **details):
    with _progress_lock:
        entry = _progress.setdefault(label, {})
        entry["state"] = state
        entry.update(details)


def _clear_progress(label):
    with _progress_lock:
        _progress.pop(label, None)


# label -> state for this mode's vantage points in flight.
def in_flight(mode):
    states = {}
    with _progress_lock:
        for key, entry in _progress.items():
            label, _, key_mode = key.partition("/")
            if key_mode == mode:
                states[label] = entry["state"]
    return states


def _track(name):
    with _containers_lock:
        _started_containers.append(name)


def _untrack(name):
    with _containers_lock:
        if name in _started_containers:
            _started_containers.remove(name)


def stop_all_started_containers(client):
    with _containers_lock:
        names = list(reversed(_started_containers))
    for name in names:
        gluetun.stop_container(client, name)
        _untrack(name)


# ---------------------------------------------------------------- configuration


# (name, subnet) of the network shared with the tunnels; compose prefixes its name.
def discover_control_network(client):
    # HOSTNAME is the container id; container_name as fallback.
    me = None
    for identifier in (os.getenv("HOSTNAME"), "vantage-orchestrator"):
        if not identifier:
            continue
        try:
            me = client.containers.get(identifier)
            break
        except Exception:
            continue
    if me is None:
        raise RuntimeError(
            "could not identify this container through the Docker socket; "
            "is /var/run/docker.sock mounted?"
        )

    networks = me.attrs["NetworkSettings"]["Networks"]
    for name in networks:
        if name.endswith(CONTROL_NETWORK_SUFFIX):
            config = client.networks.get(name).attrs["IPAM"]["Config"]
            subnet = config[0]["Subnet"] if config else ""
            log.info("control network %s (%s)", name, subnet)
            return name, subnet
    raise RuntimeError(
        f"no network ending in {CONTROL_NETWORK_SUFFIX!r} attached to this container; "
        f"attached: {sorted(networks)}"
    )


SERVER_LIST_HINT = (
    "fetch gluetun's server lists first:\n"
    "  docker run --rm -v $(pwd)/infrastructure/gluetun:/gluetun "
    'qmcgaw/gluetun update -enduser -providers "surfshark,nordvpn,cyberghost"'
)


# usable VPN services from the config; re-read every loop, reported on change.
def load_operators():
    global _config_signature

    configured_text = (
        VANTAGE_POINTS_FILE.read_text(encoding="utf-8")
        if VANTAGE_POINTS_FILE.exists()
        else None
    )
    # locked: the schedulers start together.
    with _config_lock:
        announce = configured_text != _config_signature
        _config_signature = configured_text

    if configured_text is None:
        if announce:
            log.warning("no VPN operator config at %s", VANTAGE_POINTS_FILE)
        return []

    configured = json.loads(configured_text)
    usable_providers = providers.available_providers()

    # skips are logged with the report, else at DEBUG.
    skipped = log.warning if announce else log.debug

    operators = []
    seen = set()
    for entry in configured:
        provider_key = (entry.get("provider") or "").strip()

        if not provider_key:
            skipped("skipping operator entry with no provider: %r", entry)
            continue
        if provider_key in seen:
            skipped("skipping duplicate operator %r", provider_key)
            continue
        if provider_key not in providers.PROVIDERS:
            skipped(
                "skipping %r: unknown provider (known: %s)",
                provider_key,
                sorted(providers.PROVIDERS),
            )
            continue
        if provider_key not in usable_providers:
            skipped(
                "skipping %r: missing credentials %s",
                provider_key,
                providers.missing_credentials(provider_key),
            )
            continue

        # no server list, no countries (gluetun writes it only after a tunnel ran).
        gluetun_provider = providers.PROVIDERS[provider_key]["provider"]
        if not servers.available_countries(gluetun_provider):
            skipped(
                "skipping %r: no server list for %s, so no countries to draw from",
                provider_key,
                gluetun_provider,
            )
            continue

        seen.add(provider_key)
        operators.append(provider_key)

    if not operators and configured:
        raise RuntimeError(
            f"none of the {len(configured)} configured operators is usable. "
            f"If the credentials are set, this is the server lists: "
            f"{SERVER_LIST_HINT}"
        )

    if announce:
        log.info(
            "%d of %d configured VPN operators usable: %s (%s)",
            len(operators),
            len(configured),
            operators,
            ", ".join(
                f"{providers.PROVIDERS[key]['provider']} "
                f"{len(servers.available_countries(providers.PROVIDERS[key]['provider']))}"
                for key in operators
            ),
        )
    return operators


# 'United States' -> 'united-states'.
def _slug(text):
    return re.sub(r"[^a-z0-9]+", "-", (text or "").strip().casefold()).strip("-")


# a vantage point's label, '<service>-<country>': 'surfshark-japan'.
def _label(service, country):
    return f"{_slug(service)}-{_slug(country)}"


# next country from the (operator, mode) rotation, each once per pass. skips `taken`
# labels still in flight, which would share a WARP key, manifest and results dir.
def next_country(provider_key, mode, taken=()):
    gluetun_provider = providers.PROVIDERS[provider_key]["provider"]
    key = (provider_key, mode)
    with _rotation_lock:
        pool = _rotations.get(key)
        if not pool:
            pool = servers.available_countries(gluetun_provider)
            if not pool:
                return None
            random.shuffle(pool)
            log.info(
                "[%s] new country rotation for %s: %d countries",
                mode,
                gluetun_provider,
                len(pool),
            )
            _rotations[key] = pool
        # from the end, like pop(); a skipped country keeps its place.
        for index in reversed(range(len(pool))):
            if _label(gluetun_provider, pool[index]) not in taken:
                return pool.pop(index)
        return None


# one vantage point per operator, random country; shuffled so config order doesn't pick.
def draw_vantage_points(operators, mode):
    # own labels count too: nord_open and nord_wg are one service.
    taken = set(in_flight(mode))
    vantage_points = []
    for provider_key in operators:
        country = next_country(provider_key, mode, taken)
        if country is None:
            log.warning("[%s] no countries left to draw for %s", mode, provider_key)
            continue
        label = _label(providers.PROVIDERS[provider_key]["provider"], country)
        taken.add(label)
        vantage_points.append(
            {
                "label": label,
                "provider": provider_key,
                "country": country,
            }
        )

    random.shuffle(vantage_points)
    return vantage_points


# device-limit semaphore per gluetun service (nord_open and nord_wg share one).
def device_slot_for(vantage_point):
    spec = providers.PROVIDERS[vantage_point["provider"]]
    service, cap = spec["provider"], spec["max_devices"]
    if cap is None:
        return None
    with _device_slots_lock:
        if service not in _device_slots:
            _device_slots[service] = threading.BoundedSemaphore(cap)
        return _device_slots[service]


# per-service concurrency for the round log: 'surfshark 2', 'nordvpn 6 of 7'.
def describe_device_caps(vantage_points):
    counts = {}
    for vantage_point in vantage_points:
        service = providers.PROVIDERS[vantage_point["provider"]]["provider"]
        counts[service] = counts.get(service, 0) + 1

    described = []
    for service in sorted(counts):
        cap = next(
            spec["max_devices"]
            for spec in providers.PROVIDERS.values()
            if spec["provider"] == service
        )
        if cap is None or counts[service] <= cap:
            described.append(f"{service} {counts[service]}")
        else:
            described.append(f"{service} {cap} of {counts[service]}")
    return ", ".join(described)


# ---------------------------------------------------------------- targets and WARP


# writes this round's target list: every domain in epdg_server. one file per
# round (rounds overlap; scanners re-read it per testcase), removed afterwards.
def build_target_list(mode):
    TARGETS_DIR.mkdir(parents=True, exist_ok=True)
    target_file = TARGETS_DIR / f"{mode}-{uuid.uuid4().hex[:8]}.txt"

    with connect() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "select distinct epdg_domain from epdg_server "
                "where epdg_domain is not null order by 1"
            )
            domains = [row[0] for row in cursor.fetchall()]

    if not domains:
        raise RuntimeError(
            f"mode {mode} scans the domains in epdg_server, and there are none yet"
        )

    tmp = target_file.with_suffix(".txt.tmp")
    tmp.write_text("\n".join(domains) + "\n", encoding="utf-8")
    # atomic: no half-written list.
    tmp.replace(target_file)
    log.info("mode %s targets: %d domains from epdg_server", mode, len(domains))
    return target_file


# this slot's WARP settings; registers inside the VPN netns, for a PoP near the exit.
def warp_profile(client, gluetun_container, label, mode):
    slot = f"{label}-{mode}"
    conf = WARP_PROFILE_DIR / f"{slot}.conf"
    if not conf.exists() or conf.stat().st_size == 0:
        log.info("[%s/%s] no WARP profile yet, registering an account", label, mode)
        client.containers.run(
            image=WARP_IMAGE,
            network_mode=f"container:{gluetun_container.id}",
            entrypoint="sh",
            command=[
                "-c",
                f"wgcf register --accept-tos --config /warp/{slot}.toml "
                f"&& wgcf generate --config /warp/{slot}.toml --profile /warp/{slot}.conf",
            ],
            volumes={
                f"{HOST_PROJECT_DIR}/infrastructure/warp": {
                    "bind": "/warp",
                    "mode": "rw",
                }
            },
            remove=True,
        )
        if not conf.exists():
            raise RuntimeError(f"wgcf reported success but wrote no profile at {conf}")

    settings = {}
    for line in conf.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = (part.strip() for part in line.split("=", 1))
            settings.setdefault(key, []).append(value)

    def one(key):
        values = settings.get(key)
        if not values:
            raise RuntimeError(f"WARP profile {conf} has no {key}")
        return values[0]

    # IPv4 only: gluetun won't start with IPv6 on the IPv4-only control network.
    address = next(
        (addr for addr in settings.get("Address", []) if ":" not in addr), None
    )
    if not address:
        raise RuntimeError(f"WARP profile {conf} has no IPv4 address")

    return {
        "VPN_SERVICE_PROVIDER": "custom",
        "VPN_TYPE": "wireguard",
        "WIREGUARD_PRIVATE_KEY": one("PrivateKey"),
        "WIREGUARD_PUBLIC_KEY": one("PublicKey"),
        "WIREGUARD_ADDRESSES": address,
        "WIREGUARD_ENDPOINT_IP": WARP_ENDPOINT_IP,
        "WIREGUARD_ENDPOINT_PORT": WARP_ENDPOINT_PORT,
        "WIREGUARD_MTU": one("MTU"),
    }


# brings up the WARP hop (a second gluetun behind the VPN); raises, never falls back.
def start_warp_hop(client, gluetun_container, network, subnet, label, mode):
    environment = warp_profile(client, gluetun_container, label, mode)

    # WireGuard packets (MTU + 80 worst case) must fit the VPN tunnel, else WARP stalls (CyberGhost: 1296).
    tun_mtu = int(gluetun_container.exec_run("cat /sys/class/net/tun0/mtu").output)
    environment["WIREGUARD_MTU"] = str(min(int(environment["WIREGUARD_MTU"]), tun_mtu - 80))

    # VPN container's control-network address (the hop's gateway), set at start.
    gluetun_container.reload()
    networks = gluetun_container.attrs["NetworkSettings"]["Networks"]
    gateway_ip = networks[network]["IPAddress"]
    if not gateway_ip:
        raise RuntimeError(f"tunnel container has no address on {network}")
    environment["WARP_GATEWAY_IP"] = gateway_ip

    container = gluetun.start_gluetun(
        client,
        environment,
        network,
        subnet,
        config_dir=f"{HOST_PROJECT_DIR}/infrastructure/gluetun",
        name_prefix=f"warp-{label}-{mode}",
        label=f"{label}/{mode} warp",
        image=WARP_IMAGE,
    )
    _track(container.name)
    # stopped here on failure: the caller never sees it, and the retry reuses its WARP key.
    try:
        egress_ip, egress_country = gluetun.wait_for_tunnel(
            container.name, label=f"{label}/{mode} warp"
        )

        # scapy ignores gluetun's policy rules, so without this the probes would
        # skip WARP. Runs once the tunnel device exists.
        client.containers.run(
            image=WARP_IMAGE,
            network_mode=f"container:{container.id}",
            cap_add=["NET_ADMIN"],
            entrypoint="/warp-routes.sh",
            remove=True,
        )
    except Exception:
        gluetun.stop_container(client, container.name)
        _untrack(container.name)
        raise
    return container, egress_ip, egress_country


# ---------------------------------------------------------------- one vantage point


# registers this run's exit (a new exit is a new row); warp_ip NULL without WARP.
def register_vantage_point(
    vantage_point, exit_ip=None, exit_country=None, warp_ip=None, warp_country=None
):
    spec = providers.PROVIDERS[vantage_point["provider"]]
    with connect() as conn:
        with conn.cursor() as cursor:
            return upsert_vantage_point(
                cursor,
                label=vantage_point["label"],
                provider=spec["provider"],
                vpn_type=spec["vpn_type"],
                requested_country=vantage_point["country"],
                exit_ip=exit_ip,
                exit_country=exit_country,
                warp_ip=warp_ip,
                warp_country=warp_country,
            )


# testcases the scanner will run: the mode's list, TESTCASES_OVERRIDE, or all.
def expected_testcase_count(mode):
    override = (
        MODES[mode]["testcases"] or os.getenv("TESTCASES_OVERRIDE") or ""
    ).strip()
    if not override:
        return len(TESTCASES)
    return len([tc for tc in override.split(",") if tc.strip()])


# compact elapsed time: '42s', '32m', '1h44m'.
def format_duration(seconds):
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    hours, minutes = divmod(int(seconds) // 60, 60)
    return f"{hours}h{minutes:02d}m"


# MB of zdns output so far for a discovering `full` run (first ~40 min), else None.
def discovery_progress(key):
    try:
        label, mode = key.split("/", 1)
        raw = DATA_DIR / "vantage_discovery" / label / mode / "raw"
        written = sum(f.stat().st_size for f in raw.glob("epdg_dns_scan_*.json"))
        return written / 1e6 if written else None
    except Exception:
        return None


# (testcases started, current one), from the scan's result files; never raises.
def scan_progress(key, since):
    try:
        label, mode = key.split("/", 1)
        results_dir = DATA_DIR / "results" / "vantage" / label / mode
        current = [
            path for path in results_dir.glob("*.json") if path.stat().st_mtime >= since
        ]
        if not current:
            return 0, None
        newest = max(current, key=lambda p: p.stat().st_mtime)
        # "SUPPORT_DH_2048MODP_2026-08-31T12:00:00Z.json" -> the testcase.
        return len(current), newest.stem.rsplit("_", 1)[0]
    except Exception:
        return 0, None


def start_scanner(
    client,
    gluetun_container,
    vantage_point,
    vantage_id,
    exit_ip,
    exit_country,
    manifest_path,
    mode,
    target_file=None,
    warp_ip=None,
    warp_country=None,
):
    label = vantage_point["label"]
    spec = MODES[mode]
    name = f"epdg-scanner-{label}-{mode}-{uuid.uuid4().hex[:8]}"
    container = client.containers.run(
        image=SCANNER_IMAGE,
        name=name,
        # shares gluetun's network stack: every packet leaves through the tunnel.
        network_mode=f"container:{gluetun_container.id}",
        cap_add=["NET_ADMIN", "NET_RAW"],
        volumes={f"{HOST_PROJECT_DIR}/epdg-container": {"bind": "/data", "mode": "rw"}},
        sysctls={"net.ipv6.conf.all.disable_ipv6": "0"},
        # built explicitly, not inherited: no DB credentials go in the tunnel.
        environment={
            "SCANNER_ROLE": "vantage_scan",
            "DATA_DIR": "/data/data",
            "VANTAGE_ID": str(vantage_id),
            "VANTAGE_LABEL": label,
            "SCAN_MODE": mode,
            "VANTAGE_EXIT_IP": exit_ip or "",
            "VANTAGE_EXIT_COUNTRY": exit_country or "",
            # WARP hop, empty without one.
            "VANTAGE_WARP_IP": warp_ip or "",
            "VANTAGE_WARP_COUNTRY": warp_country or "",
            # empty for `full` (discovers its own list).
            "EPDG_DOMAINS_FILE": str(target_file) if target_file else "",
            "RESULTS_SUBDIR": f"vantage/{label}/{mode}",
            "VANTAGE_MANIFEST": str(manifest_path),
            # the mode's list, else the global override.
            "TESTCASES_OVERRIDE": spec["testcases"]
            or os.getenv("TESTCASES_OVERRIDE", ""),
            "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
            "PYTHONUNBUFFERED": "1",
        },
        detach=True,
        remove=False,
        # tini as PID 1: otherwise SIGTERM is ignored and stops time out.
        init=True,
    )
    log.info(
        "[%s/%s] scan started (vantage id %s), %d testcases, container %s",
        label,
        mode,
        vantage_id,
        expected_testcase_count(mode),
        name,
    )
    return container


# polls until the scan finishes (per-mode deadline); True if it exited cleanly.
def wait_for_scanner(client, container_name, label, started, mode):
    deadline = started + MODES[mode]["timeout"]
    # silent loop; the progress reporter covers it.
    _set_progress(label, "scanning", since=started)

    while gluetun.is_container_running(client, container_name):
        if _shutdown.is_set():
            log.warning("[%s] shutting down, abandoning scan", label)
            return False
        if time.time() > deadline:
            log.error(
                "[%s] scan exceeded %ds, giving up on it",
                label,
                MODES[mode]["timeout"],
            )
            return False
        time.sleep(10)

    try:
        exit_code = client.containers.get(container_name).attrs["State"]["ExitCode"]
    except Exception:
        log.warning("[%s] scan container vanished before we read its exit code", label)
        return False

    if exit_code != 0:
        log.error("[%s] scan exited with code %s", label, exit_code)
        return False
    log.info(
        "[%s] scan finished after %s", label, format_duration(time.time() - started)
    )
    return True


# ingests one vantage point's results, serialized.
def ingest_manifest(manifest_path):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mode = manifest.get("mode") or "full"
    label = f"{manifest['vantage_label']}/{mode}"
    results = manifest.get("results") or []
    if not results:
        log.warning("[%s] manifest lists no result files", label)
        return 0

    mapping_file = _latest_mapping_file()
    ingested = 0
    with _ingest_lock:
        for relative in results:
            results_file = DATA_DIR / relative
            try:
                scan_analyzer_insert.analyze_and_insert(
                    results_file,
                    mapping_file,
                    vantage_id=manifest["vantage_id"],
                    exit_ip=manifest.get("exit_ip") or None,
                    exit_country=manifest.get("exit_country") or None,
                    mode=mode,
                    warp_ip=manifest.get("warp_ip") or None,
                    warp_country=manifest.get("warp_country") or None,
                )
                ingested += 1
            except Exception:
                # one bad file must not cost the rest.
                log.exception("[%s] failed to ingest %s", label, results_file)

    log.info("[%s] ingested %d of %d result files", label, ingested, len(results))
    return ingested


def _latest_mapping_file():
    mappings = sorted(
        (DATA_DIR / "mappings").glob("mcc_mnc_output_*.json"),
        key=lambda p: p.stat().st_mtime,
    )
    if not mappings:
        raise FileNotFoundError(f"no MCC/MNC mapping file in {DATA_DIR / 'mappings'}")
    return mappings[-1]


# one vantage point: tunnel, scan, ingest, teardown. device slot before mode slot,
# or one provider starves the others.
def run_vantage_point(client, vantage_point, network, subnet, mode, target_file):
    label = vantage_point["label"]
    key = f"{label}/{mode}"
    spec = providers.PROVIDERS[vantage_point["provider"]]
    device_slot = device_slot_for(vantage_point)

    with ExitStack() as slot_stack:
        # registered first, so it runs last: the progress entry goes on every
        # path, after teardown (it blocks redrawing the label).
        slot_stack.callback(_clear_progress, key)

        if device_slot is not None and not device_slot.acquire(blocking=False):
            _set_progress(key, "waiting", service=spec["provider"])
            log.info(
                "[%s] waiting for one of %s's %d device slots...",
                key,
                spec["provider"],
                spec["max_devices"],
            )
            device_slot.acquire()
        if device_slot is not None:
            slot_stack.callback(device_slot.release)

        _mode_slots[mode].acquire()
        slot_stack.callback(_mode_slots[mode].release)

        if _shutdown.is_set():
            return False

        # after the slot waits: "done in X" excludes queueing.
        started = time.time()
        _set_progress(key, "tunnel", since=started)
        log.info(
            "[%s] starting: %s/%s -> %s",
            key,
            spec["provider"],
            spec["vpn_type"],
            vantage_point["country"],
        )
        return _run_vantage_point(
            client, vantage_point, network, subnet, key, started, mode, target_file
        )


# the run itself, once the slots are held.
def _run_vantage_point(
    client, vantage_point, network, subnet, key, started, mode, target_file
):
    gluetun_container = None
    # WARP tunnel (WARP modes); the scanner joins its netns, so probes leave via Cloudflare.
    warp_container = None
    scanner_name = None

    label = vantage_point["label"]
    warp = MODES[mode]["warp"]

    try:
        environment = providers.build_environment(
            vantage_point["provider"], vantage_point["country"]
        )

        warp_ip = warp_country = None
        # a failed WARP hop retries on a new tunnel (WARP failures are per server;
        # gluetun picks a fresh one). Only the hop is retried, never the scan.
        for attempt in range(1, max(1, WARP_HOP_ATTEMPTS) + 1):
            _set_progress(key, "tunnel", since=started)
            gluetun_container = gluetun.start_gluetun(
                client,
                environment,
                network,
                subnet,
                config_dir=f"{HOST_PROJECT_DIR}/infrastructure/gluetun",
                name_prefix=f"gluetun-{label}-{mode}",
                label=key,
                # allow WARP egress past gluetun's OUTPUT DROP; survives reconnects.
                post_rules=(
                    f"{HOST_PROJECT_DIR}/infrastructure/gluetun/post-rules-warp.txt"
                    if warp
                    else None
                ),
            )
            _track(gluetun_container.name)

            exit_ip, exit_country = gluetun.wait_for_tunnel(
                gluetun_container.name, label=key
            )
            # this attempt's exit, so a retry shows up in the progress table.
            _set_progress(key, "tunnel", exit=exit_ip, attempt=attempt)
            # not fatal (results carry the real exit country), but worth a warning.
            if (
                exit_country
                and vantage_point["country"]
                and exit_country.strip().casefold()
                != vantage_point["country"].strip().casefold()
            ):
                log.warning(
                    "[%s] exit country is %s, expected %s",
                    key,
                    exit_country,
                    vantage_point["country"],
                )

            if not warp:
                break

            # WARP hop: exit_ip stays the VPN's, warp_ip is what the ePDG sees.
            _set_progress(key, "warp", since=time.time())
            try:
                warp_container, warp_ip, warp_country = start_warp_hop(
                    client, gluetun_container, network, subnet, label, mode
                )
            except (RuntimeError, TimeoutError) as exc:
                if attempt >= max(1, WARP_HOP_ATTEMPTS):
                    raise
                log.warning(
                    "[%s] warp hop failed (%s); trying tunnel %d of %d",
                    key,
                    exc,
                    attempt + 1,
                    max(1, WARP_HOP_ATTEMPTS),
                )
                # dropped here: `finally` only sees the last attempt's containers.
                if warp_container is not None:
                    gluetun.stop_container(client, warp_container.name)
                    _untrack(warp_container.name)
                    warp_container = None
                gluetun.stop_container(client, gluetun_container.name)
                _untrack(gluetun_container.name)
                gluetun_container = None
                continue

            _set_progress(key, "warp", egress=warp_ip)
            # both hops on one line, so an egress outside the country stands out.
            log.info(
                "[%s] warp egress %s (%s) via %s (%s)",
                key,
                warp_ip,
                warp_country,
                exit_ip,
                exit_country,
            )
            break

        vantage_id = register_vantage_point(
            vantage_point, exit_ip, exit_country, warp_ip, warp_country
        )

        manifest_path = VANTAGE_RUNS_DIR / f"{label}-{mode}.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        # drop a previous round's manifest.
        manifest_path.unlink(missing_ok=True)

        # before the container starts, so all its result files are newer.
        scan_started = time.time()
        scanner = start_scanner(
            client,
            # innermost tunnel (WARP hop, else VPN): its exit is what ePDGs see.
            warp_container or gluetun_container,
            vantage_point,
            vantage_id,
            exit_ip,
            exit_country,
            manifest_path,
            mode=mode,
            target_file=target_file,
            warp_ip=warp_ip,
            warp_country=warp_country,
        )
        scanner_name = scanner.name
        _track(scanner_name)

        if not wait_for_scanner(client, scanner_name, key, scan_started, mode):
            return False
        if not manifest_path.exists():
            log.error("[%s] scan finished but wrote no manifest", key)
            return False

        _set_progress(key, "ingesting", since=time.time())
        ingest_manifest(manifest_path)
        return True

    except TimeoutError as exc:
        # the message names the container (WARP hop or VPN).
        log.error("[%s] tunnel never came up (%s), skipping this round", key, exc)
        return False
    except Exception:
        log.exception("[%s] vantage point run failed", key)
        return False
    finally:
        if scanner_name:
            gluetun.stop_container(client, scanner_name)
            _untrack(scanner_name)
        # innermost first: WARP routes through the VPN.
        if warp_container is not None:
            gluetun.stop_container(client, warp_container.name)
            _untrack(warp_container.name)
        if gluetun_container is not None:
            gluetun.stop_container(client, gluetun_container.name)
            _untrack(gluetun_container.name)
        log.info(
            "[%s] tunnel down, done in %s", key, format_duration(time.time() - started)
        )


# ---------------------------------------------------------------- rounds


# one table of everything in flight ("<label>/<mode>"), every PROGRESS_SECONDS.
def report_round_progress(round_started):
    with _progress_lock:
        snapshot = sorted(_progress.items())
    if not snapshot:
        return

    now = time.time()
    header = ("vantage point/mode", "country", "vpn", "vpn exit", "warp ip", "state")
    # queued runs listed separately, below the live ones.
    live, queued = [], []
    for label, entry in snapshot:
        state = entry["state"]
        since = entry.get("since")

        if state == "queued":
            detail = "queued for a slot"
        elif state == "waiting":
            detail = f"waiting for a {entry.get('service', 'device')} slot"
        elif state == "tunnel":
            detail = "bringing the tunnel up"
        elif state == "warp":
            detail = "bringing the WARP hop up"
        elif state == "ingesting":
            detail = "ingesting results"
        else:
            done, testcase = scan_progress(label, since)
            written = discovery_progress(label) if not done else None
            # the key is "<label>/<mode>": a dh2048_warp run expects 1, not 16.
            expected = expected_testcase_count(label.split("/", 1)[-1])
            if written is not None:
                detail = f"discovering ({written:.0f} MB)"
                testcase = None
            else:
                detail = f"scanning {done}/{expected}"
            if testcase:
                detail += f" ({testcase})"
        # shown in every state: a retried tunnel means a refused WARP hop.
        if entry.get("attempt", 1) > 1:
            detail += f" [tunnel {entry['attempt']}]"
        if since:
            detail += f", {format_duration(now - since)}"

        # both hops ("n/a": no WARP in this mode, "-": not up yet).
        vpn_exit = entry.get("exit") or "-"
        warp_ip = entry.get("egress") or ("-" if entry.get("warp") else "n/a")
        row = (
            label,
            entry.get("country", "?"),
            entry.get("vpn", "?"),
            vpn_exit,
            warp_ip,
            detail,
        )
        (queued if state in QUEUED_STATES else live).append(row)

    # widths span both sections, so columns line up.
    rows = [header] + live + queued
    # all columns but the trailing state are padded.
    widths = [max(len(row[i]) for row in rows) for i in range(5)]

    def render(row):
        return "  " + "  ".join(c.ljust(w) for c, w in zip(row, widths)) + "  " + row[5]

    lines = [render(header)] + [render(r) for r in live]
    if queued:
        lines.append(f"  -- queued ({len(queued)}) " + "-" * (sum(widths) + 8))
        lines += [render(r) for r in queued]

    log.info(
        "round progress: %d running, %d queued, %s elapsed\n%s",
        len(live),
        len(queued),
        format_duration(now - round_started),
        "\n".join(lines),
    )


def run_round(client, vantage_points, network, subnet, mode, target_file):
    # names this round's countries, in slot order.
    log.info(
        "starting %s round over %d vantage points, at most %d at a time (%s): %s",
        mode,
        len(vantage_points),
        MODES[mode]["parallel"],
        describe_device_caps(vantage_points),
        ", ".join(vp["label"] for vp in vantage_points),
    )
    started = time.time()

    # one thread per vantage point; the semaphores do the limiting.
    try:
        with ThreadPoolExecutor(max_workers=max(1, len(vantage_points))) as pool:
            outcomes = list(
                pool.map(
                    lambda vp: run_vantage_point(
                        client, vp, network, subnet, mode, target_file
                    ),
                    vantage_points,
                )
            )
    except Exception:
        # own thread: nothing above would report this.
        log.exception("[%s] round failed", mode)
        return
    finally:
        # every scanner that read it has exited by now.
        if target_file is not None:
            target_file.unlink(missing_ok=True)

    succeeded = sum(1 for ok in outcomes if ok)
    # pool.map keeps input order.
    failed = [vp["label"] for vp, ok in zip(vantage_points, outcomes) if not ok]
    log.info(
        "%s round finished: %d of %d vantage points succeeded in %.1fh (failed: %s)",
        mode,
        succeeded,
        len(vantage_points),
        (time.time() - started) / 3600,
        ", ".join(failed) if failed else "none",
    )

    if not succeeded:
        log.warning("no vantage point produced data, skipping the global rebuilds")
        return

    # global rebuilds once per round, under the ingest lock (rounds can finish together).
    # no takeouts: the scanner builds them; concurrent runs would clobber the temp files.
    with _ingest_lock:
        for name, refresh in (
            (
                "country/operator snapshot",
                scan_analyzer_insert.refresh_country_operator_snapshot,
            ),
            ("collision keys", scan_analyzer_insert.refresh_collision_keys),
        ):
            try:
                log.info("refreshing %s...", name)
                refresh()
            except Exception:
                log.exception("refreshing %s failed", name)


# ---------------------------------------------------------------- schedulers
# one thread per mode; they coordinate only through the slot pools above.


# one mode's rounds, forever: each round on its own thread, the next drawn once
# nothing waits for a slot, so freed slots never idle.
def mode_scheduler(client, network, subnet, mode):
    log.info("[%s] scheduling with a round always queued", mode)

    while not _shutdown.is_set():
        started = time.time()
        try:
            operators = load_operators()
            vantage_points = draw_vantage_points(operators, mode)
            if not vantage_points:
                log.info("[%s] no usable VPN operators configured, waiting...", mode)
            else:
                # once per round, before marking queued (a failure leaves no entry).
                target_file = None
                if MODES[mode]["targets"] == "database":
                    target_file = build_target_list(mode)

                # marked before the thread starts, or the check below redraws at once.
                for vantage_point in vantage_points:
                    spec = providers.PROVIDERS[vantage_point["provider"]]
                    _set_progress(
                        f"{vantage_point['label']}/{mode}",
                        "queued",
                        vpn=f"{spec['provider']}/{spec['vpn_type']}",
                        country=vantage_point["country"],
                        warp=MODES[mode]["warp"],
                    )
                threading.Thread(
                    target=run_round,
                    args=(client, vantage_points, network, subnet, mode, target_file),
                    name=f"round-{mode}",
                    daemon=True,
                ).start()

                while not _shutdown.wait(QUEUE_POLL_SECONDS):
                    if not any(
                        state in QUEUED_STATES for state in in_flight(mode).values()
                    ):
                        break
        except Exception:
            # a dead scheduler loses the mode for good.
            log.exception("[%s] round failed", mode)

        # a floor, not a schedule: stops a failing loop from spinning.
        _shutdown.wait(max(0, MIN_ROUND_GAP - (time.time() - started)))


def main():
    configure_logging("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if os.getenv("VANTAGE_ENABLED", "true").lower() not in ("1", "true", "yes"):
        log.info("VANTAGE_ENABLED is off, nothing to do")
        return
    if not HOST_PROJECT_DIR:
        raise SystemExit(
            "HOST_PROJECT_DIR must be set to the project directory's path on the "
            "host: the Docker daemon resolves our volume binds, not this container"
        )

    client = docker.from_env()

    def handle_signal(signum, _frame):
        log.warning("signal %s received, stopping tunnels and scans", signum)
        _shutdown.set()
        stop_all_started_containers(client)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    network, subnet = discover_control_network(client)
    # a fresh server has no gluetun server lists yet (gitignored): fetch them once.
    servers.fetch_missing(
        client,
        f"{HOST_PROJECT_DIR}/infrastructure/gluetun",
        {spec["provider"] for spec in providers.available_providers().values()},
    )

    threads = [
        threading.Thread(
            target=mode_scheduler,
            args=(client, network, subnet, mode),
            name=f"sched-{mode}",
            daemon=True,
        )
        for mode in MODES
    ]

    started = time.time()

    def reporter():
        while not _shutdown.wait(PROGRESS_SECONDS):
            try:
                report_round_progress(started)
            except Exception:
                # a progress line must never take a round down with it.
                log.debug("progress report failed", exc_info=True)

    threads.append(threading.Thread(target=reporter, name="progress", daemon=True))

    # once: credentials only change on restart.
    log.info("VPN providers:\n%s", providers.describe_availability())
    log.info(
        "tunnels: %s (%d total); schedulers: %s",
        ", ".join(f"{mode} {spec['parallel']}" for mode, spec in MODES.items()),
        sum(spec["parallel"] for spec in MODES.values()),
        ", ".join(t.name for t in threads),
    )

    try:
        for thread in threads:
            thread.start()
        # park until shutdown (schedulers are daemons).
        _shutdown.wait()
    finally:
        _shutdown.set()
        for thread in threads:
            thread.join(timeout=5)
        stop_all_started_containers(client)


if __name__ == "__main__":
    main()
