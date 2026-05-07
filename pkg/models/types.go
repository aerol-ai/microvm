package models

import (
	"errors"
	"fmt"
	"time"
)

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

// Lifecycle declares automatic stop/destroy timers for a sandbox. Each field
// is a duration; zero means "disabled" for that axis. Idle triggers measure
// time since LastActiveAt (i.e. since the last toolbox/exec/SSH activity).
// Age triggers measure time since CreatedAt — they are absolute deadlines
// that do not reset on Stop+Start, so a "destroy at 24h" sandbox stays
// destroyable even if the user restarts it minutes before the deadline.
//
// Multiple fields can be set; whichever timer fires first wins. Destroy
// supersedes Stop for the same trigger axis. The lifecycle sweep runs every
// minute, so deadlines are honored to roughly that resolution.
type Lifecycle struct {
	StopIfIdleFor    time.Duration `json:"stop_if_idle_for,omitempty"`
	DestroyIfIdleFor time.Duration `json:"destroy_if_idle_for,omitempty"`
	StopAtAge        time.Duration `json:"stop_at_age,omitempty"`
	DestroyAtAge     time.Duration `json:"destroy_at_age,omitempty"`
}

// MaxLifecycleDuration caps each Lifecycle field. 30 days is generous for
// any reasonable workload while still rejecting typos like "87600h" that
// would otherwise sit in the DB pretending to be useful.
const MaxLifecycleDuration = 30 * 24 * time.Hour

// Validate enforces the invariants we rely on at sweep time:
//   - no negative durations (zero means disabled, negative is meaningless),
//   - each field <= MaxLifecycleDuration,
//   - if both stop and destroy of the same trigger are set, destroy must
//     not fire before stop. Without this we could surprise a user who set
//     "stop at 2h, destroy at 1h" by skipping the stop entirely.
func (l Lifecycle) Validate() error {
	if l.StopIfIdleFor < 0 || l.DestroyIfIdleFor < 0 || l.StopAtAge < 0 || l.DestroyAtAge < 0 {
		return errors.New("lifecycle durations must be non-negative")
	}
	checks := []struct {
		name string
		v    time.Duration
	}{
		{"stop_if_idle_for", l.StopIfIdleFor},
		{"destroy_if_idle_for", l.DestroyIfIdleFor},
		{"stop_at_age", l.StopAtAge},
		{"destroy_at_age", l.DestroyAtAge},
	}
	for _, c := range checks {
		if c.v > MaxLifecycleDuration {
			return fmt.Errorf("%s exceeds maximum of %s", c.name, MaxLifecycleDuration)
		}
	}
	if l.StopIfIdleFor > 0 && l.DestroyIfIdleFor > 0 && l.DestroyIfIdleFor < l.StopIfIdleFor {
		return errors.New("destroy_if_idle_for must be >= stop_if_idle_for")
	}
	if l.StopAtAge > 0 && l.DestroyAtAge > 0 && l.DestroyAtAge < l.StopAtAge {
		return errors.New("destroy_at_age must be >= stop_at_age")
	}
	return nil
}

// IsZero reports whether all four timers are disabled. Useful for skipping
// Lifecycle inspection in the sweep when there's nothing to evaluate.
func (l Lifecycle) IsZero() bool {
	return l.StopIfIdleFor == 0 && l.DestroyIfIdleFor == 0 &&
		l.StopAtAge == 0 && l.DestroyAtAge == 0
}

// UpdateLifecycleRequest is the body for PUT /v1/sandboxes/{id}/lifecycle.
// Full-replacement semantics: send all four fields. To clear a field, set
// it to zero. To preserve a field, send its current value (read it via GET
// first if the caller doesn't already have it).
type UpdateLifecycleRequest struct {
	Lifecycle
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
	Lifecycle        *Lifecycle        `json:"lifecycle,omitempty"`
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
	Lifecycle        Lifecycle         `json:"lifecycle"`
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
