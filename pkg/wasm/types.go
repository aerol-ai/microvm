package wasm

// Capabilities configures WASI preopens, env, args, and resource limits for an instance.
type Capabilities struct {
	Env           map[string]string `json:"env,omitempty"`
	Preopens      []Preopen         `json:"preopens,omitempty"`
	Args          []string          `json:"args,omitempty"`
	MemoryMB      int               `json:"memory_mb,omitempty"`
	WallTimeoutNs int64             `json:"wall_timeout_ns,omitempty"`
	// WASIListenPort enables wasip1 pre-open TCP listeners when >= 0 (0 = ephemeral).
	// When unset, use -1 to disable.
	WASIListenPort int    `json:"wasi_listen_port,omitempty"`
	WASIListenHost string `json:"wasi_listen_host,omitempty"`
}

// Preopen maps a host directory into the guest filesystem.
type Preopen struct {
	GuestPath string `json:"guest_path"`
	HostPath  string `json:"host_path"`
}

// UsageStats captures per-invocation metering for billing (UC-42a on wazero).
type UsageStats struct {
	WallDurationMs int64 `json:"wall_duration_ms"`
	// Instructions is populated only on the wasmtime engine seam (UC-42b).
	Instructions int64 `json:"instructions,omitempty"`
}

// RunResult captures a single invocation's outcome.
type RunResult struct {
	ExitCode int        `json:"exit_code"`
	Stdout   string     `json:"stdout,omitempty"`
	Stderr   string     `json:"stderr,omitempty"`
	Usage    UsageStats `json:"usage,omitempty"`
}
