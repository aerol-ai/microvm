// Package rootpolicy is the security envelope of a containerd sandbox,
// written once as pure functions.
//
// Two sides use it. The agent's spec builder (internal/runtime/containerd)
// takes its rule data from here: the capability set, the masked and
// read-only paths, the runtime and annotation names. The root helper's
// containerd gate (internal/rootd/gate) checks every write the agent sends
// against the same rules before containerd, which runs as root, acts on it.
// One package for both is what keeps the builder and the checker from
// drifting apart (plans/security-gaps-m1-m4.md §3.3, eng review D6): a
// builder change the checker would refuse fails the conformance test in
// internal/runtime/containerd before it ships.
//
// Nothing here does I/O. Every check reads only its arguments and a
// Policy, and the Policy is the helper's own configuration, never a field
// of a request: a request cannot widen the envelope it is checked against.
//
// The rules are allowlists. A field, mount type, option, annotation or
// runtime the agent does not produce today is refused, so a new containerd
// or runtime-spec field is refused until someone decides about it.
package rootpolicy

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
	"github.com/aerol-ai/microvm/internal/runscwrap"
)

// Names the agent's builder writes and the checker expects.
const (
	// RuntimeRunc is containerd's runc shim. A create that names no runtime
	// gets it (containerd's defaults.DefaultRuntime).
	RuntimeRunc = "io.containerd.runc.v2"
	// RuntimeRunsc is the gVisor shim.
	RuntimeRunsc = "io.containerd.runsc.v1"
	// RunscOptionsTypeURL is the discriminator the runsc shim requires
	// inside runtimeoptions.Options (its TypeUrl field, not the Any's URL).
	RunscOptionsTypeURL = "io.containerd.runsc.v1.options"

	// SpecTypeURL is the type URL containerd stores a container's OCI spec
	// under. containerd writes the Any's bytes to config.json unchanged,
	// so those bytes are what runc and runsc read.
	SpecTypeURL = "types.containerd.io/opencontainers/runtime-spec/1/Spec"
	// ResourcesTypeURL is the type URL of a task update's resources.
	ResourcesTypeURL = "types.containerd.io/opencontainers/runtime-spec/1/LinuxResources"

	// CRIContainerTypeAnnotation marks a runsc container as a CRI pod
	// sandbox. Without it the runsc shim treats the container as a pod
	// sub-container and task create deadlocks (runtime_gvisor.go).
	CRIContainerTypeAnnotation = "io.kubernetes.cri.container-type"
	// CRIContainerTypeSandbox is the only value the agent gives it.
	CRIContainerTypeSandbox = "sandbox"
	// RestoreAnnotation names the staged checkpoint a moved gVisor sandbox
	// is restored from (aerolvm-runsc, internal/runscwrap).
	RestoreAnnotation = runscwrap.RestoreAnnotation

	// rootfsPath is the only root a spec may name: containerd mounts the
	// task's snapshot at <bundle>/rootfs. An absolute path such as "/"
	// would make the host's own filesystem the sandbox's root.
	rootfsPath = "rootfs"
)

// SandboxCapabilities is the trimmed capability set every non-privileged
// sandbox gets: dockerd's runc defaults without CAP_NET_RAW.
func SandboxCapabilities() []string {
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

// DroppedCapabilities are removed from every non-privileged sandbox.
// containerd's base spec grants CAP_NET_RAW, so leaving it out of the added
// set is not enough; the builder drops it explicitly. CAP_NET_RAW lets a
// sandbox craft packets with a neighbour's source IP, which defeats every
// per-IP egress rule and the egress gateway's source-IP identity
// (plans/egress-domain-filtering.md P0-2).
func DroppedCapabilities() []string {
	return []string{"CAP_NET_RAW"}
}

// privilegedCapabilities is what a sandbox gets when the builder skips the
// envelope (SB_CONTAINER_PRIVILEGED): containerd's default set, which is
// the trimmed set plus CAP_NET_RAW. Nothing beyond it, even then.
func privilegedCapabilities() []string {
	return append(SandboxCapabilities(), DroppedCapabilities()...)
}

// MaskedPaths are hidden from every non-privileged sandbox.
func MaskedPaths() []string {
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

// ReadonlyPaths are read-only in every non-privileged sandbox.
func ReadonlyPaths() []string {
	return []string{
		"/proc/asound",
		"/proc/bus",
		"/proc/fs",
		"/proc/irq",
		"/proc/sys",
		"/proc/sysrq-trigger",
	}
}

// allowedSysctls are the only sysctls a spec may set, with their only
// value: IPv6 off inside the sandbox's own namespace (ipv6.go). Any other
// net.* sysctl is refused: ip_nonlocal_bind, for one, would let a sandbox
// send from a neighbour's address without CAP_NET_RAW.
var allowedSysctls = map[string]string{
	hostnet.SysctlAllDisableIPv6:     "1",
	hostnet.SysctlDefaultDisableIPv6: "1",
}

// builtinForbiddenRoots are never a bind source and never contain one.
// "/" itself is refused separately: everything is inside it.
var builtinForbiddenRoots = []string{"/proc", "/sys", "/dev"}

// Policy is the helper's own description of where a sandbox may reach on
// the host. It comes from the helper's config, never from a request.
type Policy struct {
	// Namespace is the containerd namespace the agent works in. The gate
	// refuses every call made in another one.
	Namespace string
	// Snapshotter names the snapshotter sandboxes' root filesystems come
	// from (containerd's default, "overlayfs").
	Snapshotter string
	// SnapshotterRoot is that snapshotter's data folder. Root filesystem
	// and Diff mounts may name only a layer's own folder in it,
	// <root>/snapshots/<id>/fs or .../work, where the overlayfs snapshotter
	// keeps every layer.
	SnapshotterRoot string
	// NetnsDir is where named network namespaces live (/run/netns).
	NetnsDir string
	// CgroupParent is the cgroup every sandbox sits directly under. Empty
	// means containerd's default, /<Namespace>.
	CgroupParent string
	// BindRoots: a bind mount's source must be strictly inside one of
	// these folders (the external mounts), and may be a folder there.
	BindRoots []string
	// BindFiles: or be exactly one of these files (the toolbox binary).
	BindFiles []string
	// HelperFileRoots: or be one file the root helper made in one of its
	// own folders (its host files and ready socket names, internal/rootd),
	// exactly <root>/<container id>/<name>, bound read-only. Only root can
	// write these folders, and that is what keeps a name in them from
	// being swapped for a link before runc's mount; a sandbox runs as uid
	// 0, so no bind may give it one of them, or a file in them, to write
	// (checkHelperFile).
	HelperFileRoots []string
	// ForbiddenRoots are never a bind source and never contain one, on top
	// of /, /proc, /sys and /dev: the sockets folders (the helper's own,
	// containerd's).
	ForbiddenRoots []string
	// MovesDir holds gVisor checkpoints. Checkpoint and restore image
	// paths must be inside it.
	MovesDir string
	// FIFODir holds task stdio FIFOs. Task IO paths must be inside it. The
	// helper makes the FIFOs, in a folder only root can write, and the
	// gate checks on disk that each one is such a FIFO (gate.StdioChecker):
	// the shim opens them as root and follows links.
	FIFODir string
	// RunscConfigPaths are the runsc shim configs the helper writes and
	// owns. A runsc container must name one of them: a runsc TOML can set
	// the binary the shim runs and turn on host networking.
	RunscConfigPaths []string
	// RuncBinaryNames, RuncRoots and RuncShimCgroups are the values the
	// runc shim's options may name. Empty (the default) allows none, which
	// is what the agent sends: no runc options at all.
	RuncBinaryNames []string
	RuncRoots       []string
	RuncShimCgroups []string
	// Privileged mirrors SB_CONTAINER_PRIVILEGED in the helper's own
	// config. When set, a spec may go without the envelope the builder
	// then skips (seccomp, the trimmed capabilities, masked and read-only
	// paths). Every other rule still holds.
	Privileged bool
	// Limits bound every sandbox's resources: the node's own limits, from
	// the helper's config. Validate requires all three, so a policy can't
	// leave a resource unbounded by forgetting it.
	Limits Limits
}

// Limits is the most one sandbox may have. Every container's spec must set
// a memory, pids and CPU limit, each above zero and within these, and a
// resize must stay within them too. Pids is the host cgroup's limit, which
// for gVisor is above the in-sandbox one (pkg/gvisorpids).
type Limits struct {
	MemoryBytes int64
	Pids        int64
	CPUs        float64
}

// Validate checks the policy itself, once, when the helper starts. A policy
// that would let a bind of / or /proc through is refused here rather than
// trusted at every check.
func (p Policy) Validate() error {
	if err := checkNamespaceName(p.Namespace); err != nil {
		return fmt.Errorf("policy namespace: %w", err)
	}
	if strings.TrimSpace(p.Snapshotter) == "" {
		return fmt.Errorf("policy: snapshotter is required")
	}
	for name, dir := range map[string]string{
		"snapshotter root": p.SnapshotterRoot,
		"netns dir":        p.NetnsDir,
		"moves dir":        p.MovesDir,
		"FIFO dir":         p.FIFODir,
	} {
		if !cleanAbs(dir) || dir == "/" {
			return fmt.Errorf("policy %s %q: want a clean absolute folder other than /", name, dir)
		}
	}
	if p.CgroupParent != "" && (!cleanAbs(p.CgroupParent) || p.CgroupParent == "/") {
		return fmt.Errorf("policy cgroup parent %q: want a clean absolute path other than /", p.CgroupParent)
	}
	for _, r := range p.ForbiddenRoots {
		if !cleanAbs(r) || r == "/" {
			return fmt.Errorf("policy forbidden root %q: want a clean absolute folder other than /", r)
		}
	}
	for _, roots := range []struct {
		what  string
		roots []string
	}{{"bind root", p.BindRoots}, {"helper file root", p.HelperFileRoots}} {
		for _, r := range roots.roots {
			if !cleanAbs(r) || r == "/" {
				return fmt.Errorf("policy %s %q: want a clean absolute folder other than /", roots.what, r)
			}
			if f, ok := p.forbiddenFor(r); ok {
				return fmt.Errorf("policy %s %q is inside forbidden %s", roots.what, r, f)
			}
		}
	}
	for _, f := range p.BindFiles {
		if !cleanAbs(f) || f == "/" {
			return fmt.Errorf("policy bind file %q: want a clean absolute path", f)
		}
		if fr, ok := p.forbiddenFor(f); ok {
			return fmt.Errorf("policy bind file %q is inside forbidden %s", f, fr)
		}
	}
	for _, c := range p.RunscConfigPaths {
		if !cleanAbs(c) || c == "/" {
			return fmt.Errorf("policy runsc config %q: want a clean absolute path", c)
		}
	}
	if err := p.validateOverlaps(); err != nil {
		return err
	}
	if p.Limits.MemoryBytes <= 0 || p.Limits.Pids <= 0 || !(p.Limits.CPUs > 0) {
		return fmt.Errorf("policy limits %+v: memory, pids and CPUs are all required", p.Limits)
	}
	return nil
}

// cgroupParent is the parent every sandbox's cgroup must sit directly under.
func (p Policy) cgroupParent() string {
	if p.CgroupParent != "" {
		return p.CgroupParent
	}
	return path.Join("/", p.Namespace)
}

// snapshotsDir is where the overlayfs snapshotter keeps its layers.
func (p Policy) snapshotsDir() string {
	return path.Join(p.SnapshotterRoot, "snapshots")
}

// forbiddenFor reports the forbidden root that p equals or is inside.
func (p Policy) forbiddenFor(src string) (string, bool) {
	for _, r := range builtinForbiddenRoots {
		if equalOrWithin(src, r) {
			return r, true
		}
	}
	for _, r := range p.ForbiddenRoots {
		if equalOrWithin(src, r) {
			return r, true
		}
	}
	return "", false
}

func (p Policy) capabilities() []string {
	if p.Privileged {
		return privilegedCapabilities()
	}
	return SandboxCapabilities()
}

// cleanAbs reports whether p is an absolute path already in clean form: no
// "..", ".", doubled or trailing slashes. Comparing clean forms is what makes
// a prefix test sound.
func cleanAbs(p string) bool {
	return p != "" && path.IsAbs(p) && path.Clean(p) == p
}

// within reports whether p is strictly inside root. Both must be clean.
func within(p, root string) bool {
	if root == "/" {
		return p != "/" && strings.HasPrefix(p, "/")
	}
	return strings.HasPrefix(p, root+"/")
}

func equalOrWithin(p, root string) bool {
	return p == root || within(p, root)
}

// withinAny reports whether p is strictly inside one of roots.
func withinAny(p string, roots []string) bool {
	return slices.ContainsFunc(roots, func(r string) bool { return within(p, r) })
}
