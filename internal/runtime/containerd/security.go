package containerd

import (
	"github.com/containerd/containerd/contrib/seccomp"
	"github.com/containerd/containerd/oci"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// securitySpecOpts assembles the default non-privileged security envelope
// matching dockerd's runc defaults as closely as contrib/seccomp allows.
func securitySpecOpts() []oci.SpecOpts {
	return []oci.SpecOpts{
		seccomp.WithDefaultProfile(),
		oci.WithAddedCapabilities(defaultCapabilities()),
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
		"CAP_NET_RAW",
		"CAP_SETFCAP",
		"CAP_SETGID",
		"CAP_SETPCAP",
		"CAP_SETUID",
		"CAP_SYS_CHROOT",
	}
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

// compile-time check that specs import stays referenced for mount builders.
var _ = specs.LinuxNamespace{}
