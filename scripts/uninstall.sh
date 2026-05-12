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

systemctl daemon-reload

echo "AerolVM removed. Docker, Caddy, and sandbox data were left in place."