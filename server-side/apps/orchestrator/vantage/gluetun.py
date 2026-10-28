"""Start, probe and stop gluetun tunnels (from scanywhere's run_gluetun).

Control servers are reached by container name on a shared network, not host ports.
"""

import logging
import time
import uuid

from vantage.ip_utils import get_ip_info

log = logging.getLogger(__name__)

GLUETUN_IMAGE = "qmcgaw/gluetun:latest"
CONTROL_PORT = 8000

# max wait for a tunnel's public IP.
TUNNEL_TIMEOUT_SECONDS = 300


# starts gluetun without waiting for the tunnel; post_rules is an iptables file
# the WARP modes use to make it a router.
def start_gluetun(
    client,
    environment,
    network,
    outbound_subnets,
    config_dir,
    name_prefix="gluetun",
    label=None,
    post_rules=None,
    image=None,
):
    prefix = f"[{label}] " if label else ""
    name = f"{name_prefix}-{uuid.uuid4().hex[:12]}"
    # logged first: an image pull looks like a hung tunnel.
    # never log `environment`: it holds the VPN credentials.
    log.info("%stunnel starting (container %s)", prefix, name)
    volumes = {config_dir: {"bind": "/gluetun", "mode": "rw"}}
    if post_rules:
        # gluetun re-applies it after each reconnect; outside rules would be lost.
        volumes[post_rules] = {"bind": "/iptables/post-rules.txt", "mode": "ro"}

    container = client.containers.run(
        image=image or GLUETUN_IMAGE,
        name=name,
        network=network,
        cap_add=["NET_ADMIN"],
        devices=["/dev/net/tun:/dev/net/tun"],
        sysctls={"net.ipv6.conf.all.disable_ipv6": "0"},
        volumes=volumes,
        environment=environment
        | {
            "HTTP_CONTROL_SERVER_ADDRESS": f":{CONTROL_PORT}",
            # else gluetun drops our control server replies.
            "FIREWALL_OUTBOUND_SUBNETS": outbound_subnets,
        },
        detach=True,
        remove=False,
    )
    return container


# blocks until the tunnel reports a public IP. returns (ip, country).
def wait_for_tunnel(container_name, maxwait=TUNNEL_TIMEOUT_SECONDS, label=None):
    prefix = f"[{label}] " if label else ""
    url = f"http://{container_name}:{CONTROL_PORT}/v1/publicip/ip"
    log.info("%swaiting for tunnel, up to %ds...", prefix, maxwait)
    started = time.time()
    ip, country = get_ip_info(url, maxwait=maxwait, label=label)
    log.info("%stunnel up in %ds: %s (%s)", prefix, time.time() - started, ip, country)
    return ip, country


def get_container_status(client, container_name):
    try:
        return client.containers.get(container_name).status
    except Exception:
        return None


def is_container_running(client, container_name):
    return get_container_status(client, container_name) in (
        "created",
        "running",
        "restarting",
    )


# stops and removes a container; already gone is fine.
def stop_container(client, container_name):
    try:
        container = client.containers.get(container_name)
    except Exception:
        # already gone (scanner exited on its own).
        return
    try:
        container.stop(timeout=15)
    except Exception:
        log.warning("could not stop %s", container_name, exc_info=True)
    try:
        container.remove(force=True)
    except Exception:
        pass
    log.info("stopped %s", container_name)
