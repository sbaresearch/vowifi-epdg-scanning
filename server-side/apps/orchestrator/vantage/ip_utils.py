"""Polls gluetun's control server for a public IP (from scanywhere's ip_utils.py)."""

import logging
import time

import requests

log = logging.getLogger(__name__)


SLEEP_SECONDS = 2
HEARTBEAT_SECONDS = 30


# polls url until it reports an IP; TimeoutError after maxwait.
def get_ip_info(url, maxwait=60 * 5, label=None):
    prefix = f"[{label}] " if label else ""
    time_start = time.time()
    next_heartbeat = HEARTBEAT_SECONDS
    while True:
        try:
            response = requests.get(url, timeout=30).json()
            ip = response["public_ip"]
            country = response.get("country")
            if ip:
                return ip, country
        except Exception as exc:
            log.debug("waiting for %s: %s", url, exc)

        waited = time.time() - time_start
        if waited > maxwait:
            raise TimeoutError(f"no public IP from {url} within {maxwait}s")
        if waited >= next_heartbeat:
            log.info("%sstill waiting for tunnel (%ds/%ds)", prefix, waited, maxwait)
            next_heartbeat = waited + HEARTBEAT_SECONDS
        time.sleep(SLEEP_SECONDS)
