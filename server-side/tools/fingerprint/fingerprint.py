#!/usr/bin/env python3

import _csv as csv
import argparse
import hashlib
import subprocess
from collections import Counter
from datetime import date, datetime
from pathlib import Path

from enrich import fetch_servers

SCRIPT_DIR = Path(__file__).parent
CSV_DIR = SCRIPT_DIR / "csv"
PCAP_DIR = SCRIPT_DIR / "pcap"

DH_GROUPS = {
    "768MODP": 1,
    "1024MODP": 2,
    "1536MODP": 5,
    "2048MODP": 14,
    "3072MODP": 15,
    "4096MODP": 16,
    "6144MODP": 17,
    "8192MODP": 18,
    "256ECP": 19,
    "384ECP": 20,
    "512ECP": 21,
    "192ECP": 25,
    "224ECP": 26,
    "X25519": 31,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument("pcap", nargs="?", type=Path)
    parser.add_argument("--output", "-o", type=Path)

    return parser.parse_args()


def nonce_to_byte_len(rows: list[list[str]]):
    i = rows[0].index("isakmp.nonce")

    for row in rows[1:]:
        if row[i]:
            row[i] = str(len(bytes.fromhex(row[i])))


def pcap_to_csv(pcap):
    res = subprocess.run(
        [
            "tshark",
            "-r",
            pcap,
            "-Tfields",
            "-Eheader=y",
            "-Eseparator=,",
            "-Eaggregator=-",
            "-Equote=d",
            "-eip.src",
            "-eisakmp.prop.protoid",
            "-eisakmp.tf.id.encr",
            "-eisakmp.tf.id.prf",
            "-eisakmp.tf.id.integ",
            "-eisakmp.tf.id.dh",
            "-eisakmp.key_exchange.dh_group",
            "-eisakmp.nonce",
            "-eisakmp.ike2.attr.type",
            "-eisakmp.tf.type",
            "isakmp.flag_r == 1",
        ],
        capture_output=True,
    )

    rows = list(csv.reader(res.stdout.decode().splitlines()))
    nonce_to_byte_len(rows)

    # csv.writer(sys.stdout, lineterminator="\n").writerows(rows)
    print(pcap.stem + " processed.")

    out = CSV_DIR / (Path(pcap).stem + ".csv")
    out.parent.mkdir(parents=True, exist_ok=True)

    with open(out, "w", newline="") as f:
        csv.writer(f, lineterminator="\n").writerows(rows)

    return rows


def main():
    args = parse_args()
    pcaps = [args.pcap] if args.pcap else PCAP_DIR.glob("*.pcap")
    groups = {}

    for pcap in sorted(pcaps, key=lambda p: DH_GROUPS[p.stem.split("_")[2]]):
        for ip, *fields in pcap_to_csv(pcap)[1:]:
            groups.setdefault(ip, [ip]).extend(fields)

    with open(CSV_DIR / f"merged_{date.today()}.csv", "w", newline="") as f:
        csv.writer(f, lineterminator="\n").writerows(groups.values())

    hashes = {
        ip: hashlib.md5(",".join(fields).encode()).hexdigest()
        for ip, *fields in groups.values()
    }

    with open(CSV_DIR / f"hashes_{datetime.now():%FT%T}.csv", "w", newline="") as f:
        csv.writer(f, lineterminator="\n").writerows(hashes.items())

    servers = fetch_servers()

    for h, n in Counter(hashes.values()).most_common():
        if n > 1:
            print(h, n)
            for ip in (ip for ip, v in hashes.items() if v == h):  # TODO: temp
                print(f"  {ip}", *servers.get(ip, ["unknown"]), sep="\t")


if __name__ == "__main__":
    main()
