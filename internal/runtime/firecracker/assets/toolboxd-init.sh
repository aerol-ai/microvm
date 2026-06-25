#!/bin/sh
# toolboxd-init — PID 1 for cold-boot Firecracker guests booted from a
# stock OCI image.
#
# A plain OCI image (alpine, ubuntu, ...) has no init that brings up the
# AerolVM agent, so the host's Create handshake (vsock CID 3 port 1024)
# and exec/files/sessions (HTTP on :2280) have nothing to talk to. The
# cold-boot driver injects this script as init=/usr/local/bin/toolboxd-init
# so the very first userspace process is us: mount the pseudo-filesystems
# toolboxd needs, load the per-sandbox env, then exec the agent as PID 1.
#
# The kernel `ip=` autoconf should configure the interface before userspace,
# but not every host kernel/image combination has CONFIG_IP_PNP wired the way
# we need. Re-apply the same static address from userspace as a fallback before
# toolboxd starts accepting host HTTP traffic on :2280.
#
# This script must run under the guest's /bin/sh (busybox or bash). Keep
# it POSIX and dependency-free. If toolboxd exits, PID 1 exits and the
# kernel panics; boot args carry `panic=1` so the VMM exits cleanly and
# the host's cleanup contract fires rather than leaving a hung guest.

mount -t proc     proc /proc        2>/dev/null || true
mount -t sysfs    sys  /sys         2>/dev/null || true
mount -t devtmpfs dev  /dev         2>/dev/null || true
mount -t tmpfs    tmp  /tmp         2>/dev/null || true

find_cmd() {
	if command -v "$1" >/dev/null 2>&1; then
		command -v "$1"
		return 0
	fi
	for dir in /sbin /bin /usr/sbin /usr/bin; do
		if [ -x "$dir/$1" ]; then
			printf '%s\n' "$dir/$1"
			return 0
		fi
	done
	return 1
}

# Per-sandbox environment (token, port) injected alongside this script.
if [ -f /etc/toolboxd.env ]; then
	# shellcheck disable=SC1091
	. /etc/toolboxd.env
	export SB_TOOLBOX_TOKEN SB_TOOLBOX_PORT SB_TOOLBOX_GUEST_IP SB_TOOLBOX_GATEWAY_IP SB_TOOLBOX_NETMASK SB_TOOLBOX_PREFIX_LEN
fi

configure_network() {
	[ -n "${SB_TOOLBOX_GUEST_IP:-}" ] || return 0
	[ -n "${SB_TOOLBOX_GATEWAY_IP:-}" ] || return 0
	[ -n "${SB_TOOLBOX_PREFIX_LEN:-}" ] || return 0

	iface=""
	for dev in /sys/class/net/*; do
		[ -e "$dev" ] || continue
		name=${dev##*/}
		[ "$name" = "lo" ] && continue
		iface=$name
		break
	done
	[ -n "$iface" ] || return 0

	ip_cmd=$(find_cmd ip || true)
	ifconfig_cmd=$(find_cmd ifconfig || true)
	route_cmd=$(find_cmd route || true)

	if [ -n "$ip_cmd" ]; then
		"$ip_cmd" link set lo up 2>/dev/null || true
		"$ip_cmd" link set "$iface" up 2>/dev/null || true
		"$ip_cmd" addr add "$SB_TOOLBOX_GUEST_IP/$SB_TOOLBOX_PREFIX_LEN" dev "$iface" 2>/dev/null || true
		"$ip_cmd" route replace default via "$SB_TOOLBOX_GATEWAY_IP" dev "$iface" 2>/dev/null || true
	elif [ -n "$ifconfig_cmd" ]; then
		"$ifconfig_cmd" lo up 2>/dev/null || true
		if [ -n "${SB_TOOLBOX_NETMASK:-}" ]; then
			"$ifconfig_cmd" "$iface" "$SB_TOOLBOX_GUEST_IP" netmask "$SB_TOOLBOX_NETMASK" up 2>/dev/null || true
		else
			"$ifconfig_cmd" "$iface" "$SB_TOOLBOX_GUEST_IP" up 2>/dev/null || true
		fi
		if [ -n "$route_cmd" ]; then
			"$route_cmd" add default gw "$SB_TOOLBOX_GATEWAY_IP" "$iface" 2>/dev/null || true
		fi
	fi
}

configure_network

exec /usr/local/bin/toolboxd
