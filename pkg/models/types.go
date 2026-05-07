package models

import "time"

type SandboxStatus string

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
	Image            string            `json:"image"`
	CPU              int               `json:"cpu"`
	MemoryMB         int               `json:"memory_mb"`
	DiskGB           int               `json:"disk_gb"`
	Env              map[string]string `json:"env"`
	OSUser           string            `json:"os_user"`
	NetworkBlockAll  bool              `json:"network_block_all"`
	Registry         *RegistryAuth     `json:"registry,omitempty"`
	ContainerCommand []string          `json:"container_command,omitempty"`
}

type ResizeSandboxRequest struct {
	CPU      int `json:"cpu"`
	MemoryMB int `json:"memory_mb"`
	DiskGB   int `json:"disk_gb"`
}

type Sandbox struct {
	ID               string            `json:"id"`
	Image            string            `json:"image"`
	Status           SandboxStatus     `json:"status"`
	PublicURL        string            `json:"public_url"`
	ContainerID      string            `json:"container_id,omitempty"`
	ContainerIP      string            `json:"container_ip,omitempty"`
	CPU              int               `json:"cpu"`
	MemoryMB         int               `json:"memory_mb"`
	DiskGB           int               `json:"disk_gb"`
	OSUser           string            `json:"os_user"`
	Env              map[string]string `json:"env,omitempty"`
	NetworkBlockAll  bool              `json:"network_block_all"`
	ToolboxEnabled   bool              `json:"toolbox_enabled"`
	ToolboxToken     string            `json:"-"`
	ExposedPorts     []ExposedPort     `json:"exposed_ports,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
	LastActiveAt     time.Time         `json:"last_active_at"`
	LastError        string            `json:"last_error,omitempty"`
	ContainerCommand []string          `json:"container_command,omitempty"`
}

type ExposedPort struct {
	SandboxID string    `json:"sandbox_id"`
	Port      int       `json:"port"`
	PublicURL string    `json:"public_url"`
	CreatedAt time.Time `json:"created_at"`
}

type HealthStatus struct {
	Status    string `json:"status"`
	Sandboxes int    `json:"sandboxes"`
	Docker    string `json:"docker"`
	Caddy     string `json:"caddy"`
	Version   string `json:"version"`
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
