#!/usr/bin/env bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
	echo "uninstall.sh must run as root" >&2
	exit 1
fi

systemctl disable --now sandboxd >/dev/null 2>&1 || true
rm -f /etc/systemd/system/sandboxd.service
rm -rf /etc/systemd/system/sandboxd.service.d
rm -rf /etc/sandboxd
rm -f /usr/local/bin/sandboxd /usr/local/bin/toolboxd

# --ingress-proxy-routing: the *.rt.internal resolver link. Without sandboxd
# its responder is gone, so leaving the link would only break that zone.
if [[ -f /etc/systemd/network/10-aerolvm-rt.network ]]; then
	rm -f /etc/systemd/network/10-aerolvm-rt.network /etc/systemd/network/10-aerolvm-rt.netdev
	ip link delete aerolvm-rt >/dev/null 2>&1 || true
	systemctl restart systemd-networkd systemd-resolved >/dev/null 2>&1 || true
fi
rm -f /etc/systemd/resolved.conf.d/aerolvm-route-dns.conf

systemctl daemon-reload

echo "AerolVM removed. Docker, Caddy, and sandbox data were left in place."