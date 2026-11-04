#!/usr/bin/env bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
	echo "uninstall.sh must run as root" >&2
	exit 1
fi

systemctl disable --now sandboxd >/dev/null 2>&1 || true

# Firecracker VMs run in a cgroup of their own so a sandboxd restart leaves
# them running; with sandboxd gone for good, nothing would manage them.
vm_cgroup=/sys/fs/cgroup/aerolvm-vmm
if [[ -d $vm_cgroup ]]; then
	if [[ -f $vm_cgroup/cgroup.kill ]]; then
		echo 1 >"$vm_cgroup/cgroup.kill" 2>/dev/null || true
	else
		while read -r pid; do
			kill -KILL "$pid" 2>/dev/null || true
		done <"$vm_cgroup/cgroup.procs"
	fi
	# cgroupfs files report size 0, so read rather than test -s.
	for _ in $(seq 1 50); do
		[[ -n $(cat "$vm_cgroup/cgroup.procs" 2>/dev/null) ]] || break
		sleep 0.1
	done
	rmdir "$vm_cgroup" 2>/dev/null || true
fi
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