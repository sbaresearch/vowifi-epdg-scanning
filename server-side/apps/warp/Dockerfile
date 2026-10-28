# Cloudflare WARP hop: a second gluetun (WireGuard, "custom" provider) uplinked
# through the VPN container. gluetun, not a WireGuard sidecar: the sidecar's route
# broke on VPN reconnects. Ported from scanywhere's docker/gluetun-warp.
FROM qmcgaw/gluetun:latest

ARG WGCF_VERSION=2.2.22
ARG TARGETARCH=amd64

# wgcf: anonymous WARP account + WireGuard profile (version pinned).
ADD https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VERSION}/wgcf_${WGCF_VERSION}_linux_${TARGETARCH} /usr/local/bin/wgcf
RUN chmod +x /usr/local/bin/wgcf

COPY warp-gateway.sh /warp-gateway.sh
# run once the tunnel is up, so scapy routes through WARP (see the script).
COPY warp-routes.sh /warp-routes.sh
RUN chmod +x /warp-gateway.sh /warp-routes.sh

ENTRYPOINT ["/warp-gateway.sh"]
