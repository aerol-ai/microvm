package isolate

// JailConfig is the OS-confinement request for a group's workerd process. It is
// projected from the driver's JailSpec (internal/runtime/isolate/jail.go, which
// this package cannot import), carrying only the primitives the spawner applies.
//
// Require=true is load-bearing for SECURITY, not a hint: when set, Start MUST
// either realize the confinement or refuse to spawn. It must never run workerd
// unconfined while Require is true — that is the false-confinement bug this
// gate exists to prevent (an operator sets SB_ISOLATE_USE_JAIL=true and
// believes untrusted tenant JS is boxed in). See applyJail / jailRealizable.
//
// What "realized" means on Linux (host_jail_linux.go, shim_linux.go):
//
//   - chroot into ChrootDir, a per-group directory hard-linked from the base
//     tree PrepareJailBase built at daemon start (workerd + its shared libs +
//     /dev nodes), with the group's run dir the only writable place;
//   - cgroup v2 under CgroupRoot/CgroupName with cpu.max / memory.max from the
//     group's caps (the tenant's blast radius);
//   - privilege drop to UID/GID with no supplementary groups;
//   - PR_SET_NO_NEW_PRIVS and a seccomp allowlist (SeccompAllow + SeccompArgRules)
//     installed before workerd is exec'd, so the dynamic loader itself already
//     runs under the filter.
//
// The last two cannot be expressed through os/exec's SysProcAttr, so the
// spawner execs the daemon binary itself (ShimPath) in a tiny mode that
// performs them and then execs workerd — the same re-exec shape as
// --wasm-worker.
type JailConfig struct {
	Require       bool
	ChrootDir     string
	UID           int
	GID           int
	CgroupRoot    string
	CgroupName    string
	CPUQuota      float64
	MemoryLimitMB int
	Jitless       bool
	// SeccompMode is one of SeccompEnforce (unlisted syscalls kill the
	// process), SeccompAudit (unlisted syscalls are logged by the kernel and
	// allowed — for the first real-host run against a new workerd build) or
	// SeccompOff (no filter; only for isolating a suspected filter fault).
	SeccompMode string
	// SeccompAllow are syscall names the group process may make;
	// SeccompArgRules narrow some of them by argument. Names unknown to the
	// running architecture are skipped (they cannot be invoked there).
	SeccompAllow    []string
	SeccompArgRules []SeccompArgRule
	// ShimPath is the daemon binary re-exec'd as the jail shim.
	ShimPath string
}

// Seccomp modes.
const (
	SeccompEnforce = "enforce"
	SeccompAudit   = "audit"
	SeccompOff     = "off"
)

// SeccompArgMask is one argument test: (args[Arg] & Mask) != 0.
type SeccompArgMask struct {
	Arg  int
	Mask uint32
}

// SeccompArgRule denies Syscall when every mask in DenyIfAll is non-zero on
// the call's arguments and allows it otherwise. It is how --jitless keeps
// mprotect (the loader's RELRO needs it) while refusing PROT_EXEC flips.
type SeccompArgRule struct {
	Syscall   string
	DenyIfAll []SeccompArgMask
}

// JailRealizable is the exported platform-capability check the daemon logs at
// boot so operators can see whether SB_ISOLATE_USE_JAIL can actually be honored
// on this host (Linux) or whether isolate creates will fail closed until it is
// disabled or the host is Linux.
func JailRealizable() bool { return jailRealizable() }

// JailWorkerdPath is where the workerd binary lives inside every group chroot.
const JailWorkerdPath = "/workerd"

// JailRunDirName is the group's writable run directory inside its chroot
// (sockets, generated config). The supervisor places the host-side RunDir at
// ChrootDir/JailRunDirName so both sides name the same inodes.
const JailRunDirName = "run"
