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
# eth0 is already configured by the kernel `ip=` autoconf (CONFIG_IP_PNP)
# the driver appends to the boot args, so there is no network setup here.
#
# This script must run under the guest's /bin/sh (busybox or bash). Keep
# it POSIX and dependency-free. If toolboxd exits, PID 1 exits and the
# kernel panics; boot args carry `panic=1` so the VMM exits cleanly and
# the host's cleanup contract fires rather than leaving a hung guest.

mount -t proc     proc /proc        2>/dev/null || true
mount -t sysfs    sys  /sys         2>/dev/null || true
mount -t devtmpfs dev  /dev         2>/dev/null || true
mount -t tmpfs    tmp  /tmp         2>/dev/null || true

# Per-sandbox environment (token, port) injected alongside this script.
if [ -f /etc/toolboxd.env ]; then
	# shellcheck disable=SC1091
	. /etc/toolboxd.env
	export SB_TOOLBOX_TOKEN SB_TOOLBOX_PORT
fi

exec /usr/local/bin/toolboxd
