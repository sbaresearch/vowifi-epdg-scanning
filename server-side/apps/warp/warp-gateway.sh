#!/bin/sh
# routes the uplink via the VPN container (its bridge address survives reconnects),
# then starts gluetun, so WARP egresses in the VPN's exit country.
set -eu

: "${WARP_GATEWAY_IP:?WARP_GATEWAY_IP is required}"

# replaced: Docker's default route would egress from this host.
ip route del default 2>/dev/null || true
ip route add default via "$WARP_GATEWAY_IP" dev eth0

echo "[warp] uplink -> $WARP_GATEWAY_IP" >&2

exec /gluetun-entrypoint "$@"
