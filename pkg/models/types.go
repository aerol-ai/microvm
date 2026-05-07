package models

import "time"

type SandboxStatus string

// Sandbox lifecycle states.
//
// SandboxStatusDestroyed marks a sandbox whose container is gone — either
// because the user called DELETE /sandboxes/{id}, or because the container
// died out-of-band and the event monitor / reconcile loop noticed. The DB
// row is retained indefinitely as an audit record by default; operators
// who want automatic cleanup of old destroyed rows can set
// SB_DESTROYED_ROW_TTL (e.g. "720h" for 30 days) to have them purged by the
// reconcile sweep. There is no automatic row-level GC otherwise — by
// design, so post-incident "what ran last week?" questions remain
// answerable from the DB.
const (
	SandboxStatusCreating  SandboxStatus = "creating"
	SandboxStatusStarted   SandboxStatus = "started"
	SandboxStatusStopped   SandboxStatus = "stopped"
	SandboxStatusDestroyed SandboxStatus = "destroyed"
	SandboxStatusError     SandboxStatus = "error"
)

type RegistryAuth struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type CreateSandboxRequest struct {
	Image string `json:"image"`
	// CPU is the number of CPU cores to allocate. Fractional values are
	// supported (e.g. 0.5 = half a core, 1.5 = one and a half cores).
	// Translates to Docker's CpuQuota at 100ms periods.
	CPU              float64           `json:"cpu"`
	MemoryMB         int               `json:"memory_mb"`
	DiskGB           int               `json:"disk_gb"`
	Env              map[string]string `json:"env"`
	OSUser           string            `json:"os_user"`
	NetworkBlockAll  bool              `json:"network_block_all"`
	Registry         *RegistryAuth     `json:"registry,omitempty"`
	ContainerCommand []string          `json:"container_command,omitempty"`
	Mounts           []MountSpec       `json:"mounts,omitempty"`
}

type ResizeSandboxRequest struct {
	CPU      float64 `json:"cpu"`
	MemoryMB int     `json:"memory_mb"`
	DiskGB   int     `json:"disk_gb"`
}

type Sandbox struct {
	ID               string            `json:"id"`
	Image            string            `json:"image"`
	Status           SandboxStatus     `json:"status"`
	PublicURL        string            `json:"public_url"`
	ContainerID      string            `json:"container_id,omitempty"`
	ContainerIP      string            `json:"container_ip,omitempty"`
	CPU              float64           `json:"cpu"`
	MemoryMB         int               `json:"memory_mb"`
	DiskGB           int               `json:"disk_gb"`
	OSUser           string            `json:"os_user"`
	Env              map[string]string `json:"env,omitempty"`
	NetworkBlockAll  bool              `json:"network_block_all"`
	ToolboxEnabled   bool              `json:"toolbox_enabled"`
	ToolboxToken     string            `json:"-"`
	SSHPublicKey     string            `json:"ssh_public_key,omitempty"`
	ExposedPorts     []ExposedPort     `json:"exposed_ports,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
	LastActiveAt     time.Time         `json:"last_active_at"`
	LastError        string            `json:"last_error,omitempty"`
	ContainerCommand []string          `json:"container_command,omitempty"`
}

// CreateSandboxResponse is what the API returns from POST /v1/sandboxes.
// SSHPrivateKey is generated server-side per sandbox and returned exactly once
// — it is never persisted and never returned again. The corresponding public
// key is stored on the sandbox record and is the only key authorized to SSH
// into that sandbox.
type CreateSandboxResponse struct {
	Sandbox
	SSHPrivateKey string `json:"ssh_private_key,omitempty"`
}

type ExposedPort struct {
	SandboxID string    `json:"sandbox_id"`
	Port      int       `json:"port"`
	PublicURL string    `json:"public_url"`
	CreatedAt time.Time `json:"created_at"`
}

type HealthStatus struct {
	Status     string `json:"status"`
	Sandboxes  int    `json:"sandboxes"`
	Docker     string `json:"docker"`
	Caddy      string `json:"caddy"`
	SSHGateway string `json:"ssh_gateway"`
	Version    string `json:"version"`
}

type ExecRequest struct {
	Command        string            `json:"command"`
	WorkDir        string            `json:"workdir,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

type ExecResult struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
