"""VPN providers for gluetun (from scanywhere; credentials from .env.secrets, same names).

A provider is available once all its credentials are set.
"""

import logging
import os

log = logging.getLogger(__name__)

# Applied to every provider.
ENVIRONMENT_BASE = {
    "OPENVPN_IPV6": "on",
    # updater off: tunnels share one /gluetun dir (race). Refresh by hand, see servers.py.
    "UPDATER_PERIOD": "0",
    # DNS: gluetun's default, resolved through the tunnel so GeoDNS sees the exit
    # country. Not DNS_KEEP_NAMESERVER: that resolves from the host's country.
}

# key -> gluetun provider, tunnel type, credentials (gluetun var -> our env var).
PROVIDERS = {
    # nordvpn: max 6 devices
    "nord_open": {
        "provider": "nordvpn",
        "vpn_type": "openvpn",
        "credentials": {
            "OPENVPN_USER": "NORD_OPENVPN_USER",
            "OPENVPN_PASSWORD": "NORD_OPENVPN_PASSWORD",
        },
        "max_devices": 6,
    },
    "nord_wg": {
        "provider": "nordvpn",
        "vpn_type": "wireguard",
        "credentials": {"WIREGUARD_PRIVATE_KEY": "NORD_WIREGUARD_PRIVATE_KEY"},
        "max_devices": 6,
    },
    # mullvad: max 5 devices, wireguard only.
    "mullvad_wg": {
        "provider": "mullvad",
        "vpn_type": "wireguard",
        "credentials": {
            "WIREGUARD_PRIVATE_KEY": "MULLVAD_WIREGUARD_PRIVATE_KEY",
            "WIREGUARD_ADDRESSES": "MULLVAD_WIREGUARD_ADDRESSES",
        },
        "max_devices": 5,
    },
    # surfshark: unlimited devices.
    "surfshark_open": {
        "provider": "surfshark",
        "vpn_type": "openvpn",
        "credentials": {
            "OPENVPN_USER": "SURFSHARK_OPENVPN_USER",
            "OPENVPN_PASSWORD": "SURFSHARK_OPENVPN_PASSWORD",
        },
        "max_devices": None,
    },
    "surfshark_wg": {
        "provider": "surfshark",
        "vpn_type": "wireguard",
        "credentials": {
            "WIREGUARD_PRIVATE_KEY": "SURFSHARK_WIREGUARD_PRIVATE_KEY",
            "WIREGUARD_ADDRESSES": "SURFSHARK_WIREGUARD_ADDRESSES",
        },
        "max_devices": None,
    },
    # proton: max 10 devices; openvpn, as wireguard needs per-server keys.
    "proton_open": {
        "provider": "protonvpn",
        "vpn_type": "openvpn",
        "credentials": {
            "OPENVPN_USER": "PROTON_OPENVPN_USER",
            "OPENVPN_PASSWORD": "PROTON_OPENVPN_PASSWORD",
        },
        "max_devices": 10,
    },
    # private internet access: unlimited
    "pia_open": {
        "provider": "private internet access",
        "vpn_type": "openvpn",
        "credentials": {
            "OPENVPN_USER": "PIA_OPENVPN_USER",
            "OPENVPN_PASSWORD": "PIA_OPENVPN_PASSWORD",
        },
        "max_devices": None,
    },
    # hidemyass: max 5 devices
    "hma_open": {
        "provider": "hidemyass",
        "vpn_type": "openvpn",
        "credentials": {
            "OPENVPN_USER": "HMA_OPENVPN_USER",
            "OPENVPN_PASSWORD": "HMA_OPENVPN_PASSWORD",
        },
        "max_devices": 5,
    },
    # cyberghost: max 7 devices
    "cyberghost_open": {
        "provider": "cyberghost",
        "vpn_type": "openvpn",
        "credentials": {
            "OPENVPN_USER": "CYBERGHOST_OPENVPN_USER",
            "OPENVPN_PASSWORD": "CYBERGHOST_OPENVPN_PASSWORD",
            "OPENVPN_KEY": "CYBERGHOST_OPENVPN_KEY",
            "OPENVPN_CERT": "CYBERGHOST_OPENVPN_CERT",
        },
        "max_devices": 7,
    },
    # ivpn: max 7 devices; fixed openvpn password.
    "ivpn_open": {
        "provider": "ivpn",
        "vpn_type": "openvpn",
        "credentials": {"OPENVPN_USER": "IVPN_OPENVPN_USER"},
        "static": {"OPENVPN_PASSWORD": "ivpn"},
        "max_devices": 7,
    },
    "ivpn_wg": {
        "provider": "ivpn",
        "vpn_type": "wireguard",
        "credentials": {
            "WIREGUARD_PRIVATE_KEY": "IVPN_WIREGUARD_PRIVATE_KEY",
            "WIREGUARD_ADDRESSES": "IVPN_WIREGUARD_ADDRESSES",
        },
        "max_devices": 7,
    },
}

# scanywhere's EC2, Tor, hide.me and Warp providers need more than credentials; left out.


# credential env vars this provider is missing.
def missing_credentials(key):
    spec = PROVIDERS[key]
    return [
        env_var
        for env_var in spec["credentials"].values()
        if not (os.getenv(env_var) or "").strip()
    ]


# provider keys whose credentials are fully configured.
def available_providers():
    return {
        key: spec for key, spec in PROVIDERS.items() if not missing_credentials(key)
    }


# gluetun environment for one provider, optionally pinned to a country.
def build_environment(key, country=None):
    spec = PROVIDERS[key]
    missing = missing_credentials(key)
    if missing:
        raise RuntimeError(f"provider {key} is missing credentials: {missing}")

    environment = dict(ENVIRONMENT_BASE)
    environment["VPN_SERVICE_PROVIDER"] = spec["provider"]
    environment["VPN_TYPE"] = spec["vpn_type"]
    environment.update(spec.get("static", {}))
    for gluetun_var, env_var in spec["credentials"].items():
        environment[gluetun_var] = os.environ[env_var].strip()
    if country:
        environment["SERVER_COUNTRIES"] = country
    return environment


# human readable availability report, used by --list and at startup.
def describe_availability():
    lines = []
    for key in sorted(PROVIDERS):
        missing = missing_credentials(key)
        if missing:
            lines.append(f"  [ ] {key:<16} missing: {', '.join(missing)}")
        else:
            cap = PROVIDERS[key]["max_devices"]
            cap_text = "unlimited devices" if cap is None else f"max {cap} devices"
            lines.append(f"  [x] {key:<16} available ({cap_text})")
    return "\n".join(lines)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    print("VPN providers:")
    print(describe_availability())
    usable = available_providers()
    print(f"\n{len(usable)} of {len(PROVIDERS)} providers available: {sorted(usable)}")
