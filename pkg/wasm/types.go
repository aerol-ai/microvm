package wasm

// Capabilities configures WASI preopens, env, and args for an instance.
type Capabilities struct {
	Env      map[string]string `json:"env,omitempty"`
	Preopens []Preopen         `json:"preopens,omitempty"`
	Args     []string          `json:"args,omitempty"`
}

// Preopen maps a host directory into the guest filesystem.
type Preopen struct {
	GuestPath string `json:"guest_path"`
	HostPath  string `json:"host_path"`
}

// RunResult captures a single invocation's outcome.
type RunResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
}
