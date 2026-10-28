#!/bin/sh
# puts the WARP tunnel into the MAIN table (run once it is up): scapy ignores
# `ip rule` and would probe out of the VPN exit. Safe: gluetun's rule 100 keeps
# WireGuard's own packets out of main.
set -eu

# gluetun's tunnel device, from its table.
DEV=$(ip route show table 51820 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
[ -n "$DEV" ] || { echo "[warp] no tunnel device in table 51820" >&2; exit 1; }

SRC=$(ip -4 addr show dev "$DEV" 2>/dev/null | sed -n 's|.*inet \([0-9.]*\)/.*|\1|p' | head -1)
[ -n "$SRC" ] || { echo "[warp] $DEV has no IPv4 address" >&2; exit 1; }

# /2 quarters beat `default via eth0` by prefix length; `src` matches scapy to the kernel.
for quarter in 0.0.0.0/2 64.0.0.0/2 128.0.0.0/2 192.0.0.0/2; do
    ip route replace "$quarter" dev "$DEV" src "$SRC"
done

echo "[warp] main table -> $DEV src $SRC" >&2
