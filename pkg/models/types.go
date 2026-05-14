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
// died out-of-band and the event monitor noticed. The status exists as a
// transient marker only: the API-driven destroy path deletes the row in the
// same call, and the reconcile loop deletes any row whose container has
// gone missing on its next pass. Destroyed rows are not retained — keeping
// them around would also keep their host_port reservations in
// exposed_ports, slowly exhausting the L4 TCP allocator pool over the
// daemon's lifetime.
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

// SandboxRuntimeState is the runtime view of a sandbox returned by the
// container runtime layer (Docker today, gVisor/native runsc tomorrow). It
// carries only what the service needs to reconcile and route — anything else
// belongs on models.Sandbox or stays in the runtime implementation.
type SandboxRuntimeState struct {
	SandboxID   string
	ContainerID string
	ContainerIP string
	Status      SandboxStatus
}

// User-facing runtime identifiers. These are the values the API, SDK, and
// stored sandbox row carry — chosen to match what an operator searching for
// "Docker" or "gVisor isolation" would type. The pkg/docker layer translates
// each one to the underlying OCI runtime binary name (runc / runsc / ...)
// when shaping the daemon request.
//
// The empty string is reserved for legacy rows that pre-date the runtime
// field — those resolve to the host default at start time.
const (
	RuntimeDocker = "docker" // Docker's standard runc-backed runtime.
	RuntimeGvisor = "gvisor" // gVisor (runsc). User-space kernel for untrusted workloads.
	RuntimeKata   = "kata"   // Reserved: Kata Containers. Not yet implemented; rejected at create time.
)

// ErrRuntimeNotImplemented is returned when a runtime is recognized as a valid
// identifier but the implementation has not been wired up yet. Today only
// "kata" hits this path. Surfaced through the API as a 4xx so operators get
// an actionable error instead of a generic 500.
var ErrRuntimeNotImplemented = errors.New("runtime not yet implemented on this build")

// GPUVendor identifies the GPU hardware vendor for sandbox GPU allocation.
type GPUVendor string

const (
	// GPUVendorNVIDIA selects NVIDIA GPUs via nvidia-container-runtime.
	// Requires nvidia-container-toolkit installed on the host.
	GPUVendorNVIDIA GPUVendor = "nvidia"
	// GPUVendorAMD selects AMD GPUs via ROCm device bind-mounts (/dev/kfd,
	// /dev/dri). Requires ROCm drivers on the host.
	GPUVendorAMD GPUVendor = "amd"
	// GPUVendorApple selects Apple Silicon GPU via Docker Desktop's
	// experimental Metal support. Only functional on macOS with Docker Desktop;
	// Linux hosts will receive a Docker daemon error at container creation.
	GPUVendorApple GPUVendor = "apple"
)

// GPURequest describes the GPU resources to attach to a sandbox. The parent
// CreateSandboxRequest.GPUs field is a pointer, so omitting it entirely means
// no GPU — this struct only appears when the caller explicitly opts in.
type GPURequest struct {
	// Vendor is required. Allowed values: "nvidia", "amd", "apple".
	Vendor GPUVendor `json:"vendor"`
	// Count is the number of GPUs to allocate. Use -1 to request all GPUs on
	// the host. Zero is treated as 1 (default). Ignored for AMD (all AMD GPUs
	// on the host are exposed via /dev/kfd and /dev/dri).
	Count int `json:"count,omitempty"`
	// DeviceIDs pins the sandbox to specific GPU device indices or UUIDs.
	// For NVIDIA: GPU indices ("0", "1") or UUIDs ("GPU-abc123...").
	// For AMD and Apple: ignored.
	DeviceIDs []string `json:"device_ids,omitempty"`
}

// Validate checks GPURequest fields for consistency.
func (g *GPURequest) Validate() error {
	if g == nil {
		return nil
	}
	switch g.Vendor {
	case GPUVendorNVIDIA, GPUVendorAMD, GPUVendorApple:
	default:
		return fmt.Errorf("unsupported GPU vendor %q (allowed: %s, %s, %s)", g.Vendor, GPUVendorNVIDIA, GPUVendorAMD, GPUVendorApple)
	}
	if g.Count < -1 {
		return fmt.Errorf("gpu count must be -1 (all), 0 (default 1), or a positive integer")
	}
	return nil
}

// ValidRuntime normalizes and validates a user-facing runtime identifier.
// Empty input passes through unchanged so the caller can substitute the host
// default; any other value must be one of the recognized names. The intent
// here is "fail fast at the API boundary" — by the time a request reaches
// the runtime layer, we should already know the value is one we can act on.
func ValidRuntime(value string) (string, error) {
	switch value {
	case "", RuntimeDocker, RuntimeGvisor, RuntimeKata:
		return value, nil
	default:
		return "", fmt.Errorf("unsupported runtime %q (allowed: %s, %s, %s)", value, RuntimeDocker, RuntimeGvisor, RuntimeKata)
	}
}

// ResolveOCIRuntime maps a user-facing runtime identifier to the OCI runtime
// binary name to set on Docker's HostConfig.Runtime. Returns the binary name
// and true on success, or ErrRuntimeNotImplemented if the identifier is valid
// but the build does not implement it yet (today: kata).
//
// The empty string is treated as "no override" — the caller leaves
// HostConfig.Runtime unset and Docker uses its compiled-in default. The
// "docker" identifier maps to "" for the same reason: avoiding an explicit
// "runc" entry means the daemon is happy even when /etc/docker/daemon.json
// has no runtimes.runc map entry, which is the common case.
func ResolveOCIRuntime(value string) (string, error) {
	switch value {
	case "", RuntimeDocker:
		return "", nil
	case RuntimeGvisor:
		return "runsc", nil
	case RuntimeKata:
		return "", ErrRuntimeNotImplemented
	default:
		return "", fmt.Errorf("unsupported runtime %q", value)
	}
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
	// Runtime selects the container runtime for this sandbox. Empty falls back
	// to the host default (SB_CONTAINER_RUNTIME). Allowed values: "docker"
	// (standard runc-backed Docker runtime, default), "gvisor" (runsc-backed
	// userspace kernel — use for untrusted workloads), or "kata" (reserved,
	// not yet implemented).
	Runtime string `json:"runtime,omitempty"`
	// GPUs attaches GPU resources to the sandbox. Nil means no GPU. GPU access
	// is not supported with the gVisor runtime — the API returns an error if
	// both GPUs and runtime="gvisor" are set.
	GPUs *GPURequest `json:"gpus,omitempty"`
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
	// Runtime is the container runtime this sandbox uses (one of "docker",
	// "gvisor", or "kata"). Pre-migration rows carry "" and resolve to the
	// host default at start time; new sandboxes always store the resolved
	// value so the choice cannot drift across host restarts.
	Runtime string `json:"runtime"`
	// GPUs is the GPU configuration this sandbox was created with. Nil means
	// no GPU was requested.
	GPUs *GPURequest `json:"gpus,omitempty"`
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

// CreateSandboxSnapshotRequest creates a reusable local image snapshot from an
// existing sandbox container. Name is the image reference callers can later
// pass back into CreateSandboxRequest.Image.
type CreateSandboxSnapshotRequest struct {
	Name string `json:"name"`
}

// SandboxSnapshot is the persisted metadata for a committed sandbox image.
// Image is the reusable image reference; ImageID is the content-addressed
// Docker image ID returned by the runtime after the commit succeeds.
type SandboxSnapshot struct {
	Name            string    `json:"name"`
	Image           string    `json:"image"`
	ImageID         string    `json:"image_id,omitempty"`
	SourceSandboxID string    `json:"source_sandbox_id"`
	CreatedAt       time.Time `json:"created_at"`
}

// ExposePortRequest is the optional JSON body for POST /v1/sandboxes/{id}/ports/{port}.
// Empty body or empty Protocol falls back to "http" — the historical default —
// so old SDK callers keep working unchanged.
type ExposePortRequest struct {
	Protocol string `json:"protocol,omitempty"`
}

// ExposePortResponse is the JSON body returned by POST /v1/sandboxes/{id}/ports/{port}.
// Protocol is the canonical value the daemon picked ("http", "tcp", or "tls"),
// PublicURL is the dialable URL for the exposure, and Host/HostPort are populated
// only on the raw-TCP path so SDKs can hand them to native protocol clients
// without parsing tcp://host:port out of PublicURL.
type ExposePortResponse struct {
	Protocol  string `json:"protocol"`
	PublicURL string `json:"public_url"`
	Host      string `json:"host,omitempty"`
	HostPort  int    `json:"host_port,omitempty"`
}

type ExposedPort struct {
	SandboxID string `json:"sandbox_id"`
	Port      int    `json:"port"`
	// Protocol is one of "http" (default — Caddy HTTP reverse proxy), "tcp"
	// (caddy-l4 listener bound to HostPort, raw TCP forward to the container),
	// or "tls" (caddy-l4 SNI route on the shared TLS listener). Pre-migration
	// rows carry "http" via the column default.
	Protocol string `json:"protocol"`
	// HostPort is the parent-host TCP listener allocated for protocol="tcp"
	// from the configured pool (default [22000, 23000]). Zero for http/tls
	// modes, which don't reserve a per-exposure host port.
	HostPort  int       `json:"host_port,omitempty"`
	PublicURL string    `json:"public_url"`
	CreatedAt time.Time `json:"created_at"`
}

// Exposed port protocols. http is the original behavior (Caddy HTTP reverse
// proxy); tcp and tls are the caddy-l4 paths added with the L4 work.
const (
	ExposedPortProtocolHTTP = "http"
	ExposedPortProtocolTCP  = "tcp"
	ExposedPortProtocolTLS  = "tls"
)

// ValidExposedPortProtocol normalizes "" to http (the historical default) and
// rejects unknown values. Any caller that surfaces user input must run it
// through this before persistence.
func ValidExposedPortProtocol(value string) (string, error) {
	switch value {
	case "", ExposedPortProtocolHTTP:
		return ExposedPortProtocolHTTP, nil
	case ExposedPortProtocolTCP:
		return ExposedPortProtocolTCP, nil
	case ExposedPortProtocolTLS:
		return ExposedPortProtocolTLS, nil
	default:
		return "", fmt.Errorf("invalid port protocol %q (allowed: %s, %s, %s)", value, ExposedPortProtocolHTTP, ExposedPortProtocolTCP, ExposedPortProtocolTLS)
	}
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
