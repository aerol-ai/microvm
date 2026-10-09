package containerd

import (
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/pkg/oci"
)

// securitySpecOpts assembles the default non-privileged security envelope
// matching dockerd's runc defaults as closely as contrib/seccomp allows.
func securitySpecOpts() []oci.SpecOpts {
	return []oci.SpecOpts{
		seccomp.WithDefaultProfile(),
		oci.WithAddedCapabilities(defaultCapabilities()),
		// containerd's base spec already grants CAP_NET_RAW, so leaving it out
		// of the added set is not enough; it has to be dropped explicitly.
		oci.WithDroppedCapabilities(droppedCapabilities()),
		oci.WithMaskedPaths(defaultMaskedPaths()),
		oci.WithReadonlyPaths(defaultReadonlyPaths()),
		oci.WithNoNewPrivileges,
	}
}

func defaultCapabilities() []string {
	return []string{
		"CAP_AUDIT_WRITE",
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_FOWNER",
		"CAP_FSETID",
		"CAP_KILL",
		"CAP_MKNOD",
		"CAP_NET_BIND_SERVICE",
		"CAP_SETFCAP",
		"CAP_SETGID",
		"CAP_SETPCAP",
		"CAP_SETUID",
		"CAP_SYS_CHROOT",
	}
}

// droppedCapabilities are removed from every non-privileged sandbox.
// CAP_NET_RAW lets a sandbox craft packets with a neighbour's source IP, which
// would defeat every per-IP egress rule and poison the egress gateway's
// source-IP identity (plans/egress-domain-filtering.md P0-2, CEO D8). Without
// NET_RAW or NET_ADMIN the kernel enforces the configured source address.
// ping and other raw-socket tools stop working inside sandboxes.
func droppedCapabilities() []string {
	return []string{"CAP_NET_RAW"}
}

func defaultMaskedPaths() []string {
	return []string{
		"/proc/acpi",
		"/proc/asound",
		"/proc/kcore",
		"/proc/keys",
		"/proc/latency_stats",
		"/proc/timer_list",
		"/proc/timer_stats",
		"/proc/sched_debug",
		"/proc/scsi",
		"/sys/firmware",
		"/sys/devices/virtual/powercap",
	}
}

func defaultReadonlyPaths() []string {
	return []string{
		"/proc/asound",
		"/proc/bus",
		"/proc/fs",
		"/proc/irq",
		"/proc/sys",
		"/proc/sysrq-trigger",
	}
}
