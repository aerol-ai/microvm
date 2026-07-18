package isolate

import (
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// Group granularity values, mirrored from internal/config so the driver does
// not force every consumer (tests, future pkg/isolate) through daemon config.
const (
	GroupPerTenant  = config.IsolateGroupPerTenant
	GroupPerSandbox = config.IsolateGroupPerSandbox
)

// Config holds host-side isolate runtime settings.
type Config struct {
	// WorkerdPath is the workerd binary that hosts isolate groups. Ping()
	// stats it so /healthz reports a missing binary before the first create.
	WorkerdPath string
	// RunDir holds per-group runtime state (sockets, capnp configs,
	// per-sandbox egress UDS endpoints).
	RunDir string
	// GroupGranularity is the isolate-group key granularity (§2.1):
	// GroupPerTenant (default) or GroupPerSandbox (hostile-code tier).
	GroupGranularity string
	// UseJail wraps each workerd group process in the isolate jail (jail.go).
	UseJail bool
	// JailChrootBase is the parent directory for per-group chroots.
	JailChrootBase string
	// JailUID / JailGID are the unprivileged uid/gid workerd drops to.
	JailUID int
	JailGID int
	// Jitless runs V8 with --jitless so the seccomp allowlist can drop the
	// W^X/JIT syscall surface (per-sandbox paranoid tier, §2.1).
	Jitless bool
	// IdleTTL is how long a group may sit without Create/Invoke before the
	// idle reaper tears it down. Zero disables the reaper.
	IdleTTL time.Duration
	// EgressPoolSize is the per-group egress-slot pool size (§4): the cap on
	// concurrently-egressing sandboxes in a group. Zero → pkg/isolate default.
	EgressPoolSize int
}

// FromDaemonConfig projects the isolate slice of daemon config into driver config.
func FromDaemonConfig(cfg config.Config) Config {
	return Config{
		WorkerdPath:      cfg.IsolateWorkerdPath,
		RunDir:           cfg.IsolateRunDir,
		GroupGranularity: cfg.IsolateGroupGranularity,
		UseJail:          cfg.IsolateUseJail,
		JailChrootBase:   cfg.IsolateJailChrootBase,
		JailUID:          cfg.IsolateJailUID,
		JailGID:          cfg.IsolateJailGID,
		Jitless:          cfg.IsolateJitless,
		IdleTTL:          cfg.IsolateGroupIdleTTL,
		EgressPoolSize:   cfg.IsolateEgressPoolSize,
	}
}
