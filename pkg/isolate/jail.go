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
type JailConfig struct {
	Require       bool
	ChrootDir     string
	UID           int
	GID           int
	CgroupName    string
	MemoryLimitMB int
	Jitless       bool
}

// JailRealizable is the exported platform-capability check the daemon logs at
// boot so operators can see whether SB_ISOLATE_USE_JAIL can actually be honored
// on this host (Linux) or whether isolate creates will fail closed until it is
// disabled or the host is Linux.
func JailRealizable() bool { return jailRealizable() }
