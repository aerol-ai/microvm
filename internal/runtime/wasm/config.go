package wasm

import (
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// Config holds host-side WASM runtime settings.
type Config struct {
	RunDir             string
	ModulesDir         string
	DefaultMemoryMB    int
	DefaultWallTimeout time.Duration
	DrainTimeout       time.Duration
	// ResidentHostEnabled routes non-listen creates to a shared resident
	// compile-once/instantiate-many host per (ownerRef, digest, memoryMB) bucket
	// instead of a fresh per-sandbox worker (plans/wasm-resident-module-host.md).
	// Default false; requires a resident supervisor wired via SetResidentHostSupervisor.
	ResidentHostEnabled bool
	// ResidentHostMaxInstances caps co-tenants per host process; 0 = unbounded.
	// When full, the driver spills to <bucket>-2.sock (SB_WASM_RESIDENT_HOST_MAX_INSTANCES).
	ResidentHostMaxInstances int
	// ResidentHostIdleTTL reaps a resident host holding zero instances for this
	// long; 0 disables the reaper (SB_WASM_RESIDENT_HOST_IDLE_TTL).
	ResidentHostIdleTTL time.Duration
	// MaxStreamsPerSandbox caps live streaming runs (exec streams and
	// code-runs) per sandbox; 0 means defaultMaxStreamsPerSandbox.
	// SB_WASM_MAX_STREAMS_PER_SANDBOX.
	MaxStreamsPerSandbox int
	// CodeRunModules maps a code-run language to the module ref that runs
	// it (SB_WASM_CODERUN_MODULES).
	CodeRunModules map[string]string
	// Daytona-style session caps (sessions.go); 0 means the default.
	// SessionLogBytes is kept per stream per command
	// (SB_WASM_SESSION_LOG_BYTES), MaxSessionsPerSandbox caps sessions
	// (SB_WASM_MAX_SESSIONS_PER_SANDBOX), SessionCommandsKept caps the
	// finished commands a session keeps and the ones waiting to run
	// (SB_WASM_SESSION_COMMANDS_KEPT), and SessionLogBudget caps all
	// session log storage of one sandbox (SB_WASM_SESSION_LOG_BUDGET_BYTES).
	SessionLogBytes       int
	MaxSessionsPerSandbox int
	SessionCommandsKept   int
	SessionLogBudget      int64
	// InterpMaxContexts caps code interpreter contexts per sandbox; 0 means
	// defaultInterpMaxContexts. SB_WASM_INTERP_MAX_CONTEXTS.
	InterpMaxContexts int
	// InterpIdleTTL stops an idle context's interpreter; 0 means
	// defaultInterpIdleTTL. SB_WASM_INTERP_IDLE_TTL.
	InterpIdleTTL time.Duration
}

// FromDaemonConfig projects the WASM slice of daemon config into driver config.
func FromDaemonConfig(cfg config.Config) Config {
	return Config{
		RunDir:                   cfg.WasmRunDir,
		ModulesDir:               cfg.WasmModulesDir,
		DefaultMemoryMB:          cfg.WasmDefaultMemoryMB,
		DefaultWallTimeout:       cfg.WasmDefaultTimeout,
		DrainTimeout:             cfg.WasmDrainTimeout,
		ResidentHostEnabled:      cfg.WasmResidentHostEnabled,
		ResidentHostMaxInstances: cfg.WasmResidentHostMaxInstances,
		ResidentHostIdleTTL:      cfg.WasmResidentHostIdleTTL,
		MaxStreamsPerSandbox:     cfg.WasmMaxStreamsPerSandbox,
		CodeRunModules:           cfg.WasmCodeRunModules,
		SessionLogBytes:          cfg.WasmSessionLogBytes,
		MaxSessionsPerSandbox:    cfg.WasmMaxSessionsPerSandbox,
		SessionCommandsKept:      cfg.WasmSessionCommandsKept,
		SessionLogBudget:         cfg.WasmSessionLogBudget,
		InterpMaxContexts:        cfg.WasmInterpMaxContexts,
		InterpIdleTTL:            cfg.WasmInterpIdleTTL,
	}
}
