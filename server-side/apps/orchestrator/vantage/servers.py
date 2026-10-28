"""Reads gluetun's server lists (from scanywhere); missing ones are fetched at startup.

Refresh by hand:
  docker run --rm -v $(pwd)/infrastructure/gluetun:/gluetun qmcgaw/gluetun update \\
    -enduser -providers "mullvad,nordvpn,private internet access,protonvpn,surfshark,hidemyass,cyberghost,ivpn"
"""

import json
import logging
import os
from pathlib import Path

from vantage.gluetun import GLUETUN_IMAGE

log = logging.getLogger(__name__)

SERVERS_DIR = Path(os.getenv("GLUETUN_SERVERS_DIR", "/gluetun-config/servers"))

_cache: dict[str, list[dict]] = {}


# server entries for a gluetun provider, [] if the list is missing.
def read_gluetun_servers(provider):
    if provider in _cache:
        return _cache[provider]

    path = SERVERS_DIR / f"{provider}.json"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
        servers = parsed.get("servers") or []
    except FileNotFoundError:
        log.warning("no server list for %r at %s", provider, path)
        servers = []
    except (json.JSONDecodeError, OSError):
        log.warning("could not parse server list %s", path, exc_info=True)
        servers = []

    _cache[provider] = servers
    return servers


# sorted, de-duplicated country names the provider offers.
def available_countries(provider):
    countries = {
        (server.get("country") or "").strip()
        for server in read_gluetun_servers(provider)
    }
    countries.discard("")
    return sorted(countries)


# writes gluetun's server lists once for providers without one (fresh server).
def fetch_missing(client, config_dir, gluetun_providers):
    missing = sorted(
        p for p in gluetun_providers if not (SERVERS_DIR / f"{p}.json").exists()
    )
    if not missing:
        return
    log.info("fetching gluetun server lists for %s", ", ".join(missing))
    try:
        client.containers.run(
            GLUETUN_IMAGE,
            ["update", "-enduser", "-providers", ",".join(missing)],
            volumes={config_dir: {"bind": "/gluetun", "mode": "rw"}},
            remove=True,
        )
    except Exception:
        # the bundled lists are written before the online update, which may fail.
        if any(not (SERVERS_DIR / f"{p}.json").exists() for p in missing):
            log.warning("could not fetch gluetun server lists", exc_info=True)
