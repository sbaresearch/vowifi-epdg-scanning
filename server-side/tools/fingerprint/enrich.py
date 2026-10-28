import json
import socket
import sys
from urllib.request import Request, urlopen

# the same API under both domains; if one fails, the other is used.
APIS = (
    "https://vowifi-watchdog.sec.univie.ac.at/api/v1",
    "https://vowifi.mobileatlas.eu/api/v1",
)
# public key, shipped in the watchdog's table page (static/js/table.js)
API_KEY = "82qTWlonsL1CjFJMi-8rDFrmA3Mms0AfaW3kCzyMtcbiuBgRV5YxQoeWf0YmZ6P7"
LIMIT = 200  # the API's max_limit
TIMEOUT = 10  # seconds without an answer before a domain counts as failed


def fetch_pages(api: str, endpoint: str) -> list[dict]:
    """Fetch every row of a paginated endpoint from one domain."""
    rows = []
    offset = 0

    while True:
        req = Request(
            f"{api}/{endpoint}?limit={LIMIT}&offset={offset}",
            headers={"X-API-Key": API_KEY},
        )
        with urlopen(req, timeout=TIMEOUT) as res:
            page = json.load(res)

        rows += page
        if len(page) < LIMIT:
            return rows
        offset += LIMIT


def fetch_all(endpoint: str) -> list[dict]:
    """Fetch every row of a paginated API endpoint, from the other domain if one fails."""
    for api, fallback in zip(APIS, APIS[1:]):
        try:
            return fetch_pages(api, endpoint)
        # URLError, HTTPError and timeouts are OSErrors; a page that isn't JSON is a ValueError.
        except (OSError, ValueError) as e:
            print(f"{api} failed ({e}), trying {fallback}", file=sys.stderr)
    return fetch_pages(APIS[-1], endpoint)


def fetch_servers() -> dict[str, set[str]]:
    """Map each ePDG IP to "operator (epdg_domain)" of every server on it."""
    servers = {}
    for s in fetch_all("servers"):
        servers.setdefault(s["target_ip"], set()).add(
            f"{s['operator']} ({s['epdg_domain']})"
        )
    return servers


def fetch_asns(ips: list[str]) -> dict[str, str]:
    """Map each IP to "AS<number> <name>" of the network announcing it (Team Cymru bulk whois)."""
    with socket.create_connection(("whois.cymru.com", 43), timeout=30) as s:
        s.sendall(("begin\n" + "\n".join(ips) + "\nend\n").encode())
        lines = s.makefile().read().splitlines()[1:]

    asns = {}
    for line in lines:
        asn, ip, name = map(str.strip, line.split("|"))
        asns[ip] = f"AS{asn} {name}"
    return asns
