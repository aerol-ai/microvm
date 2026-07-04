package models

import (
	"errors"
	"fmt"
	"strings"
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
	// SandboxStatusPassivated marks a WASM sandbox checkpointed to disk,
	// awaiting rehydrate after daemon restart (plans/wasm-runtime.md §4.3).
	SandboxStatusPassivated SandboxStatus = "passivated"
	// SandboxStatusAwaitingRuntime marks a passivated/durable WASM row found
	// when EnableWasm=false — reconcile holds the row until WASM is re-enabled.
	SandboxStatusAwaitingRuntime SandboxStatus = "awaiting_runtime"
	// SandboxStatusPassivateFailed marks a WASM sandbox whose drain checkpoint
	// timed out or failed; durability is preserved for operator inspection.
	SandboxStatusPassivateFailed SandboxStatus = "passivate_failed"
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
	// WASM-only: resolved module metadata returned by the wasm driver on create.
	ModuleRef    string
	ModuleDigest string
	// ModulePath / ModuleSizeBytes are the resolved local artifact location and
	// size. The service persists them onto the catalogue row so the row is
	// resolvable by catalogue id instead of a misleading empty-path "ready" row
	// (codex P1). Empty when resolution did not yield a local path.
	ModulePath      string
	ModuleSizeBytes int64
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
	// RuntimeFirecracker selects the native Firecracker microVM runtime
	// (no Docker in the path). Plumbed through ValidRuntime so the API
	// accepts the identifier ahead of the implementation; CreateSandbox
	// rejects with ErrRuntimeNotImplemented until the per-host operator
	// opts in via SB_ENABLE_FIRECRACKER=true AND the driver has actually
	// landed. See plans/snapshot-clone-fast-boot.md.
	//
	// Distinct from RuntimeKata, which stays reserved for Kata Containers
	// (a different shape — Kata-with-Firecracker abstracts the snapshot
	// API away and is not what this constant refers to).
	RuntimeFirecracker = "firecracker"
	// RuntimeWasm selects the WASM/WASI runtime (plans/wasm-runtime.md).
	// ValidRuntime accepts the identifier ahead of the implementation; create
	// rejects with ErrRuntimeNotImplemented until SB_ENABLE_WASM lands.
	RuntimeWasm = "wasm"
)

// Durability class for sandbox restart/survival semantics (plans/wasm-runtime.md §4.2).
const (
	DurabilityEphemeral    = "ephemeral"
	DurabilityPassivatable = "passivatable"
	DurabilityDurable      = "durable"
)

// ErrRuntimeNotImplemented is returned when a runtime is recognized as a valid
// identifier but the implementation has not been wired up yet. Today only
// "kata" hits this path. Surfaced through the API as a 4xx so operators get
// an actionable error instead of a generic 500.
var ErrRuntimeNotImplemented = errors.New("runtime not yet implemented on this build")

// ErrSnapshotCorrupt is returned when a runtime snapshot fails checksum
// verification at load time — the on-disk artifact does not match the
// checksum stamped at capture. Firecracker templates and WASM boundary
// checkpoints both surface this; the service layer intercepts with
// errors.Is to mark the backing artifact unhealthy and kick rebuild.
var ErrSnapshotCorrupt = errors.New("snapshot integrity verification failed")

// ErrSnapshotFenced is returned when a snapshot's clone_generation is older
// than the store row's current token (§4.8 zombie-write guard).
var ErrSnapshotFenced = errors.New("snapshot clone generation fenced")

// ErrTemplateNotRebuildable is returned by RequestTemplateRebuild when the
// row is in a state where re-running the snapshot phase is unsafe or
// unsupported:
//
//   - pending / building_rootfs / snapshotting: the initial build is in
//     flight; the goroutine owns the row's state machine and a concurrent
//     rebuild would race the goroutine's status writes.
//   - ready_no_snapshot: the snapshot phase failed during initial build and
//     the row has no usable snapshot artifact to re-derive from. A full
//     from-scratch rebuild requires source-image access (deferred — see
//     internal/service/template_health.go comments).
//   - failed: terminal state from a failed initial build; operator must
//     delete + recreate.
//
// apihttp.WriteStoreAwareError maps this to 412 Precondition Failed so the
// operator's tooling can distinguish "row not in a rebuildable state" from
// "row missing" (404) and "invalid request" (400).
var ErrTemplateNotRebuildable = errors.New("template not eligible for rebuild")

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
	case "", RuntimeDocker, RuntimeGvisor, RuntimeKata, RuntimeFirecracker, RuntimeWasm:
		return value, nil
	default:
		return "", fmt.Errorf("unsupported runtime %q (allowed: %s, %s, %s, %s, %s)",
			value, RuntimeDocker, RuntimeGvisor, RuntimeKata, RuntimeFirecracker, RuntimeWasm)
	}
}

// ValidDurability normalizes and validates a durability class. Empty input
// passes through so the caller can apply a runtime-specific default.
func ValidDurability(value string) (string, error) {
	switch value {
	case "", DurabilityEphemeral, DurabilityPassivatable, DurabilityDurable:
		return value, nil
	default:
		return "", fmt.Errorf("unsupported durability %q (allowed: %s, %s, %s)",
			value, DurabilityEphemeral, DurabilityPassivatable, DurabilityDurable)
	}
}

// DefaultDurabilityForRuntime returns the API default when the caller omits
// durability on create. WASM defaults to ephemeral; container/VM runtimes
// default to passivatable (they survive restarts natively).
func DefaultDurabilityForRuntime(runtime string) string {
	if runtime == RuntimeWasm {
		return DurabilityEphemeral
	}
	return DurabilityPassivatable
}

// NormalizeCreateDurability validates req.Durability, applies the runtime
// default when empty, and rejects classes the chosen runtime cannot honor yet.
func NormalizeCreateDurability(value, runtime string) (string, error) {
	normalized, err := ValidDurability(value)
	if err != nil {
		return "", err
	}
	if normalized == "" {
		normalized = DefaultDurabilityForRuntime(runtime)
	}
	if normalized == DurabilityDurable {
		if runtime != RuntimeWasm {
			return "", fmt.Errorf("durability %q is not supported for runtime %q", normalized, runtime)
		}
		return "", fmt.Errorf("durability %q: %w", normalized, ErrRuntimeNotImplemented)
	}
	return normalized, nil
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
	case RuntimeFirecracker, RuntimeWasm:
		// Firecracker and WASM are not OCI runtimes Docker can shell out to.
		// Reaching this branch means the service layer failed to dispatch the
		// request away from the Docker driver.
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
	// Serverless opts the sandbox into HTTP-wake behavior: stops driven by
	// lifecycle (idle timer / age) or involuntary exits arm the sandbox to
	// be transparently restarted on the next inbound HTTP request. Manual
	// StopSandbox calls clear the arming so the sandbox stays down.
	// Requires StopIfIdleFor to be set explicitly; there is no implicit
	// default — see Validate.
	Serverless bool `json:"serverless,omitempty"`
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
	// Serverless requires an explicit idle timer. We deliberately reject
	// the request rather than substituting a default so the operator has
	// to make a conscious choice about how long an idle sandbox should
	// linger before stopping (and incurring a future wake-time cold
	// start). A silent default would hide cost from the caller and make
	// behavior depend on server build version.
	if l.Serverless && l.StopIfIdleFor == 0 {
		return errors.New("serverless requires stop_if_idle_for to be set explicitly")
	}
	return nil
}

// ValidateWithBypassFloor runs Validate then additionally enforces the
// activity-floor constraint that HTTP-wake direct-route bypass imposes
// on serverless sandboxes: the netstats poller is the per-sandbox
// activity signal in the bypass shape, and the idle sweep needs at
// least one full netstats tick + one reconcile pass to observe "no
// traffic" without false-stopping a busy sandbox. The floor is
// 2 × pollInterval + reconcileInterval; sub-floor StopIfIdleFor values
// would let the sweep fire between netstats ticks and stop a sandbox
// that was actively serving the whole time.
//
// Callers in the wake-aware (non-bypass) shape must use Validate()
// directly — the floor does not apply when every request still bumps
// LastActiveAt through sandboxd's ingress proxy. See
// plans/warm-direct-route-bypass.md D4.
func (l Lifecycle) ValidateWithBypassFloor(pollInterval, reconcileInterval time.Duration) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if !l.Serverless || l.StopIfIdleFor == 0 {
		return nil
	}
	floor := 2*pollInterval + reconcileInterval
	if l.StopIfIdleFor < floor {
		return fmt.Errorf(
			"stop_if_idle_for (%s) is below the %s floor required by direct-route bypass (2 × netstats poll interval + reconcile interval); raise stop_if_idle_for or disable SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED/SB_L4_WAKE_DIRECT_BYPASS_ENABLED",
			l.StopIfIdleFor, floor,
		)
	}
	return nil
}

// IsZero reports whether all four timers are disabled. Useful for skipping
// Lifecycle inspection in the sweep when there's nothing to evaluate.
func (l Lifecycle) IsZero() bool {
	return l.StopIfIdleFor == 0 && l.DestroyIfIdleFor == 0 &&
		l.StopAtAge == 0 && l.DestroyAtAge == 0 && !l.Serverless
}

// UpdateLifecycleRequest is the body for PUT /v1/sandboxes/{id}/lifecycle.
// Full-replacement semantics: send all four fields. To clear a field, set
// it to zero. To preserve a field, send its current value (read it via GET
// first if the caller doesn't already have it).
type UpdateLifecycleRequest struct {
	Lifecycle
}

// DefaultCPU, DefaultMemoryMB, DefaultDiskGB are the values normalizeCreateRequest
// substitutes when the caller leaves them at zero. Exported so any code path that
// has to reason about an un-normalized CreateSandboxRequest (placement scoring on
// the way IN, failover-recreate target selection on the way OUT) uses the same
// numbers — drift here causes placement to score against ghost capacity that
// doesn't match the eventual admission reservation.
const (
	DefaultCPU      float64 = 1
	DefaultMemoryMB int     = 1024
	DefaultDiskGB   int     = 10
)

const (
	ImageDistributionExternalRegistry = "external_registry"
	ImageDistributionAOCR             = "aocr"
	ImageDistributionLocalOnly        = "local_only"
	// ImageDistributionAOCRImported is the post-auto-import distribution mode:
	// the bytes have been re-mounted under the cluster's own AOCR namespace
	// (`cluster/<id>/_imported/...`) and subsequent pulls use the cluster PAT,
	// not the user's upstream credentials. The user-visible Image field is
	// preserved; only the RegistryRef and mode flip. See F21 of the
	// cluster-mirror-and-snapshot-distribution plan for the full rationale —
	// the short version is that this is what makes `failover.policy: recreate`
	// survive upstream credential rotation.
	ImageDistributionAOCRImported = "aocr_imported"
)

// SnapshotPushState tracks the lifecycle of the optional background push of a
// local snapshot to the AOCR registry. The two terminal states a polling SDK
// cares about are "active" (snapshot is ready everywhere it can be) and
// "error" (push failed; the snapshot is still usable on the originating node
// and the reconciler will retry). "pending" / "pushing" are transient.
//
// When SB_SNAPSHOT_PUSH_ENABLED is false, or when the snapshot's image already
// lives in a remote registry, new rows are written with state "active"
// directly — making the response shape identical to today's behavior.
const (
	SnapshotPushStateActive  = "active"
	SnapshotPushStatePending = "pending"
	SnapshotPushStatePushing = "pushing"
	SnapshotPushStateError   = "error"
)

const (
	FailoverPolicyNone     = "none"
	FailoverPolicyRecreate = "recreate"
)

// Failover controls what the cluster should do if the sandbox's owner node is
// declared dead. Empty or omitted means "none": orphan the placement and return
// 410 Gone. "recreate" opts the sandbox into best-effort recreation from its
// replicated create spec on another worker.
type Failover struct {
	Policy string `json:"policy,omitempty"`
}

func NormalizeFailoverPolicy(policy string) (string, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(policy)); normalized {
	case "", FailoverPolicyNone:
		return FailoverPolicyNone, nil
	case FailoverPolicyRecreate:
		return FailoverPolicyRecreate, nil
	default:
		return "", fmt.Errorf("invalid failover policy %q", policy)
	}
}

func (f Failover) NormalizedPolicy() string {
	policy, err := NormalizeFailoverPolicy(f.Policy)
	if err != nil {
		return ""
	}
	return policy
}

func (f Failover) ShouldRecreate() bool {
	return f.NormalizedPolicy() == FailoverPolicyRecreate
}

func (f Failover) Validate() error {
	_, err := NormalizeFailoverPolicy(f.Policy)
	return err
}

// ImageDistributionMetadata describes whether an image can be materialized on
// an arbitrary worker. It is deliberately metadata only: registries, AOCR, and
// cache services remain pluggable deployment choices outside the core daemon.
type ImageDistributionMetadata struct {
	Mode        string     `json:"mode,omitempty"`
	Digest      string     `json:"digest,omitempty"`
	RegistryRef string     `json:"registry_ref,omitempty"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
}

func NormalizeImageDistributionMode(mode string) (string, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(mode)); normalized {
	case "":
		return "", nil
	case ImageDistributionExternalRegistry, ImageDistributionAOCR, ImageDistributionAOCRImported, ImageDistributionLocalOnly:
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid image distribution mode %q", mode)
	}
}

func (m ImageDistributionMetadata) IsZero() bool {
	return strings.TrimSpace(m.Mode) == "" &&
		strings.TrimSpace(m.Digest) == "" &&
		strings.TrimSpace(m.RegistryRef) == "" &&
		m.VerifiedAt == nil
}

type CreateSandboxRequest struct {
	Image string `json:"image"`
	// ImageDistributionMode classifies whether Image can be pulled on any
	// worker (external_registry/aocr) or is pinned to the local node
	// (local_only). Empty is resolved by the service from snapshot metadata
	// or by the default image distribution provider.
	ImageDistributionMode string     `json:"image_distribution_mode,omitempty"`
	ImageDigest           string     `json:"image_digest,omitempty"`
	ImageRegistryRef      string     `json:"image_registry_ref,omitempty"`
	ImageVerifiedAt       *time.Time `json:"image_verified_at,omitempty"`
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
	// PlatformVolumes references named, operator-backed persistent volumes by
	// name only — the user never supplies storage coordinates or credentials.
	// The service translates each entry into a synthesized, tenant-scoped
	// MountSpec against the operator's shared backend (see
	// plans/e2b-volume-mounts.md). All facades (E2B volumeMounts, Daytona
	// volumes) and the native SDKs populate this single neutral field so the
	// translation lives in one version-agnostic place.
	PlatformVolumes []PlatformVolumeMount `json:"platform_volumes,omitempty"`
	Lifecycle       *Lifecycle            `json:"lifecycle,omitempty"`
	Failover        *Failover             `json:"failover,omitempty"`
	// Name is an optional human-readable identifier. When set, it must be
	// unique across all sandboxes — the store enforces this with a partial
	// unique index. Empty means no name; the sandbox can only be referenced
	// by ID. The Daytona facade requires names; the native /v1 API and other
	// facades may set or omit it.
	//
	// Duplicate names are rejected with HTTP 409 Conflict. Use a unique name
	// per sandbox or omit this field to let the daemon assign an ID instead.
	Name string `json:"name,omitempty"`
	// Tags is an optional free-form key/value map associated with the
	// sandbox. Used by facades that expose label-style metadata (Daytona
	// labels, E2B metadata).
	Tags map[string]string `json:"tags,omitempty"`
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
	// NetworkBytesInLimit caps lifetime ingress bytes for the sandbox. Zero
	// means unlimited. When the cumulative counter crosses the limit, the
	// reconcile loop installs an ingress DROP rule. The "we already paid for
	// the bytes you see in the meter" caveat applies — host-side ingress is
	// counted after the NIC has accepted the packet.
	NetworkBytesInLimit int64 `json:"network_bytes_in_limit,omitempty"`
	// NetworkBytesOutLimit caps lifetime egress bytes. Zero means unlimited.
	// Crossing the limit installs an egress DROP rule via the same primitive
	// NetworkBlockAll uses.
	NetworkBytesOutLimit int64 `json:"network_bytes_out_limit,omitempty"`
	// NetworkAllowOut is an egress allowlist of CIDRs: when non-empty the
	// sandbox may reach only these destinations and everything else is
	// dropped. Mutually exclusive with NetworkDenyOut. Enforced by the host
	// firewall (EnableNetworkRules) and a no-op when network rules are off.
	NetworkAllowOut []string `json:"network_allow_out,omitempty"`
	// NetworkDenyOut is an egress blocklist of CIDRs: the sandbox may reach
	// anything except these destinations. Mutually exclusive with
	// NetworkAllowOut. Blocking the entire space is expressed as
	// NetworkBlockAll, not a denyOut of 0.0.0.0/0.
	NetworkDenyOut []string `json:"network_deny_out,omitempty"`
	// AllowPublicTraffic controls whether the sandbox may be exposed to the
	// public internet. On create, omitted (nil) defaults to private — no
	// <id>.<domain> ingress route, empty public_url, and expose_port fails.
	// Pass an explicit true to opt in to public exposure. False always refuses
	// exposure. The sandbox stays reachable via the platform's own paths
	// (toolbox exec/file proxy, SSH gateway), which do not route through the
	// public ingress.
	AllowPublicTraffic *bool `json:"allow_public_traffic,omitempty"`
	// MaskRequestHost, when non-empty, rewrites the upstream Host header on
	// ingress to exposed HTTP ports to this value. Dev servers and frameworks
	// that validate the Host header (Vite allowedHosts, webpack-dev-server,
	// Django ALLOWED_HOSTS, Rails host authorization) reject requests whose
	// Host is the per-sandbox public hostname; masking it to a value the app
	// accepts (e.g. "localhost") unblocks them. Empty = pass through whatever
	// the route would otherwise send (today's behavior). HTTP-only; TCP/TLS
	// exposures ignore it (no Host header in raw passthrough).
	MaskRequestHost string `json:"mask_request_host,omitempty"`
	// CustomDomains attaches operator-provided public hostnames to the
	// sandbox at create time. Each hostname must resolve (via DNS) to the
	// cluster's ingress host before HTTPS can serve traffic — see
	// plans/custom-domains.md. Bare strings on the wire; the response shape
	// (Sandbox.CustomDomains) carries per-hostname status. Capped by
	// MaxCustomDomainsPerCreateRequest.
	CustomDomains []string `json:"custom_domains,omitempty"`
	// TemplateID, when set alongside Runtime="firecracker", skips the
	// per-create OCI→ext4 build and reuses a previously prepared
	// rootfs.ext4 from a Firecracker template (POST /v1/templates). The
	// template must be in status="ready" or Create rejects with a
	// not-ready error. Ignored on the Docker path — templates are a
	// Firecracker-only concept (see plans/snapshot-clone-fast-boot.md
	// Phase 2). Pre-snapshot phase: the rootfs is the only artifact a
	// template provides; Phase 3 layers snapshot.memory/state on top.
	TemplateID string `json:"template_id,omitempty"`
	// OverlaySizeGB, when > 0 and Runtime="firecracker", attaches a
	// per-sandbox writable virtio-blk device (drive_id="overlay") of
	// this size at /dev/vdb. On the snapshot-load fast-boot path the
	// device must exist in the template snapshot's virtio-blk state —
	// templates built before Phase 3 PR-B (has_overlay=false) reject
	// this field with an error pointing at POST /v1/templates for a
	// rebuild. The host allocates a sparse file; the guest is
	// responsible for mkfs and mount (or set SB_FIRECRACKER_OVERLAY_MKFS
	// on the daemon to have the host mkfs.ext4 the file at create time).
	// Ignored on the Docker path. Capped at 1024 GiB by request
	// validation; the daemon's admission control may reject smaller.
	OverlaySizeGB int `json:"overlay_size_gb,omitempty"`
	// Durability selects the sandbox survival class across restarts (§4.2 in
	// plans/wasm-runtime.md). Empty defaults per runtime: passivatable for
	// docker/firecracker/gvisor; ephemeral for wasm. "durable" is WASM-only
	// and not yet implemented on any runtime.
	Durability string `json:"durability,omitempty"`
	// ModuleRef selects the WASM module for runtime=wasm. When set, Image may
	// be omitted; when empty, Image is treated as the module reference.
	ModuleRef string `json:"module_ref,omitempty"`
}

func (r CreateSandboxRequest) ImageDistribution() ImageDistributionMetadata {
	return ImageDistributionMetadata{
		Mode:        r.ImageDistributionMode,
		Digest:      r.ImageDigest,
		RegistryRef: r.ImageRegistryRef,
		VerifiedAt:  r.ImageVerifiedAt,
	}
}

func (r *CreateSandboxRequest) ApplyImageDistribution(meta ImageDistributionMetadata) {
	if r == nil {
		return
	}
	r.ImageDistributionMode = strings.TrimSpace(meta.Mode)
	r.ImageDigest = strings.TrimSpace(meta.Digest)
	r.ImageRegistryRef = strings.TrimSpace(meta.RegistryRef)
	r.ImageVerifiedAt = meta.VerifiedAt
}

func (r CreateSandboxRequest) ShouldRecreateOnFailover() bool {
	return r.Failover != nil && r.Failover.ShouldRecreate()
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
	Failover         *Failover         `json:"failover,omitempty"`
	// Name is the optional unique identifier set at create time. Empty when
	// the sandbox was created without one (the common path on /v1 today).
	Name string `json:"name,omitempty"`
	// Tags is the optional key/value bag set at create time. Facades use it
	// for label-style metadata (Daytona labels, E2B metadata) but the field
	// is facade-agnostic — anything that wants attribute-tagged sandboxes
	// can write here.
	Tags map[string]string `json:"tags,omitempty"`
	// Runtime is the container runtime this sandbox uses (one of "docker",
	// "gvisor", or "kata"). Pre-migration rows carry "" and resolve to the
	// host default at start time; new sandboxes always store the resolved
	// value so the choice cannot drift across host restarts.
	Runtime string `json:"runtime"`
	// GPUs is the GPU configuration this sandbox was created with. Nil means
	// no GPU was requested.
	GPUs *GPURequest `json:"gpus,omitempty"`
	// RegistryAuthSealed is the AES-GCM-encrypted JSON of the original
	// RegistryAuth supplied at create time, or nil/empty when the sandbox
	// pulled from a public registry. Persisted so cluster failover can hand
	// the credentials back to the new owner's docker pull. Never serialized
	// over the API — it is internal store ↔ service plumbing.
	RegistryAuthSealed []byte `json:"-"`
	// RegistryAuth is the transient, UNSEALED registry credential. It is never
	// persisted (no column) nor serialized (json:"-"); the service unseals
	// RegistryAuthSealed into it in-memory right before a WASM start/rehydrate
	// so a failover peer can re-pull a private oci:// module under the tenant's
	// identity (codex C4). Nil on the create/public path.
	RegistryAuth *RegistryAuth `json:"-"`
	// NetworkBytesIn / NetworkBytesOut are cumulative byte counters
	// maintained by the netstats poller. They survive container restarts —
	// a new veth resets in-memory baseline math but the persisted total is
	// preserved.
	NetworkBytesIn  int64 `json:"network_bytes_in"`
	NetworkBytesOut int64 `json:"network_bytes_out"`
	// NetworkBytesInLimit / NetworkBytesOutLimit are the caps the sandbox was
	// created or patched with. Zero = unlimited.
	NetworkBytesInLimit  int64 `json:"network_bytes_in_limit"`
	NetworkBytesOutLimit int64 `json:"network_bytes_out_limit"`
	// NetworkAllowOut / NetworkDenyOut are the egress CIDR policy the sandbox
	// was created with, persisted so the start and reconcile paths can
	// reinstall the host-firewall rules after a restart (parity with
	// NetworkBlockAll). Mutually exclusive; at most one is non-empty.
	NetworkAllowOut []string `json:"network_allow_out,omitempty"`
	NetworkDenyOut  []string `json:"network_deny_out,omitempty"`
	// AllowPublicTraffic mirrors the create-time flag. Nil means "not set"
	// (treated as allowed); a non-nil false makes ExposePort refuse to install
	// a public route. Persisted so the gate survives restarts.
	AllowPublicTraffic *bool `json:"allow_public_traffic,omitempty"`
	// MaskRequestHost mirrors the create-time flag: the value the ingress layer
	// rewrites the upstream Host header to for exposed HTTP ports. Persisted so
	// the direct Caddy route (baked at install time) and the serverless wake
	// proxy (read per request) agree on the same value after a restart.
	MaskRequestHost string `json:"mask_request_host,omitempty"`
	// NetworkQuotaExceeded reflects whether either lifetime byte counter has
	// crossed its limit. The reconcile loop installs DROP rules when this is
	// true; clearing requires raising the limit (or zeroing it for unlimited).
	NetworkQuotaExceeded bool `json:"network_quota_exceeded"`
	// NetworkQuotaExceededAt is the wall-clock time the limit was first
	// observed crossed. Nil while under quota.
	NetworkQuotaExceededAt *time.Time `json:"network_quota_exceeded_at,omitempty"`
	// AutoImportPending is set by the post-pull auto-import path when the
	// AOCR ImportAPI call failed. A background reconciler walks rows with
	// this flag and re-tries the import; once the import succeeds the flag
	// is cleared and the create spec's ImageDistributionMode flips to
	// `aocr_imported`. The flag is local-node bookkeeping — it is not
	// replicated via Raft, since each owner gets one opportunistic shot
	// at the import per pull.
	AutoImportPending bool `json:"-"`
	// WakeArmed indicates the sandbox is currently in the stopped state
	// because of a lifecycle-driven idle timeout or an involuntary exit
	// while Lifecycle.Serverless was true. Wake-aware control-plane proxies
	// transparently start the sandbox on the next inbound request when this
	// is set. Cleared on manual StopSandbox and after a successful wake.
	// Internal-only bookkeeping; never exposed over the wire.
	WakeArmed bool `json:"-"`
	// CustomDomains carries the per-hostname rows for any operator-attached
	// public hostnames. Status is server-managed (pending_dns → issuing →
	// ready / failed). Nil when the sandbox has no custom domains.
	CustomDomains []CustomDomain `json:"custom_domains,omitempty"`
	// TemplateID records the Firecracker template this sandbox was created
	// from, when one was supplied. Empty for Docker sandboxes and for
	// Firecracker sandboxes built from an ad-hoc Image. The Phase 2 template
	// GC reads this column via IsTemplateReferenced to decide whether a
	// template is still in use; the firecracker driver also reads it on
	// recreate so failover stays on the same rootfs.
	TemplateID string `json:"template_id,omitempty"`
	// OverlaySizeGB is the size of the per-sandbox writable overlay
	// drive (virtio-blk at /dev/vdb), echoed back from the create
	// request so callers can confirm what was provisioned. Zero means
	// no overlay was attached. Persisted because the runtime cleanup
	// path needs to know whether overlay.ext4 was allocated in the
	// per-sandbox runDir.
	OverlaySizeGB int `json:"overlay_size_gb,omitempty"`
	// OwnerRef is the account key this sandbox is attributed to, resolved by
	// the optional fleet control plane from a user token at create time.
	// Empty means operator/PAT-created (the only possibility on the
	// open-source build). Owner scoping uses it to fence user tokens to their
	// own sandboxes; the PAT bypasses scoping. Never exposed over the wire —
	// it is internal attribution, not caller-facing.
	OwnerRef string `json:"-"`
	// FleetSuspended marks a sandbox that was stopped by a fleet standing
	// directive (suspend), as opposed to a user/operator stop. Recovery
	// restarts exactly the sandboxes carrying this marker, then clears it.
	// Internal-only bookkeeping.
	FleetSuspended bool `json:"-"`
	// Durability is the survival class this sandbox was created with. Empty
	// on pre-migration rows resolves to passivatable at read time.
	Durability string `json:"durability,omitempty"`
	// ModuleRef is the WASM module reference when runtime=wasm.
	ModuleRef string `json:"module_ref,omitempty"`
	// ModuleDigest is the sha256 hex digest of the resolved .wasm bytes.
	ModuleDigest string `json:"module_digest,omitempty"`
	// CheckpointPath points at a local §4.8.1 mem.snap directory when status
	// is passivated. Internal-only; not exposed over the wire.
	CheckpointPath string `json:"-"`
	// CloneGeneration is the §4.8 fencing token for checkpoint/clone writes.
	CloneGeneration string `json:"-"`
	// WasmRegistryRef is the AOCR ref for the last pushed durable checkpoint.
	WasmRegistryRef string `json:"-"`
	// WasmRegistryDigest is the manifest digest from the last AOCR push.
	WasmRegistryDigest string `json:"-"`
}

// ModuleRefForCreate returns the WASM module reference from a create request.
func ModuleRefForCreate(req CreateSandboxRequest) string {
	if ref := strings.TrimSpace(req.ModuleRef); ref != "" {
		return ref
	}
	return strings.TrimSpace(req.Image)
}

// NetworkUsage is the response shape for GET /v1/sandboxes/{id}/network/usage.
// BytesInLimit / BytesOutLimit zero means unlimited.
type NetworkUsage struct {
	SandboxID       string     `json:"sandbox_id"`
	BytesIn         int64      `json:"bytes_in"`
	BytesOut        int64      `json:"bytes_out"`
	BytesInLimit    int64      `json:"bytes_in_limit"`
	BytesOutLimit   int64      `json:"bytes_out_limit"`
	QuotaExceeded   bool       `json:"quota_exceeded"`
	QuotaExceededAt *time.Time `json:"quota_exceeded_at,omitempty"`
	// LastSampledAt is omitted until the netstats poller has produced at
	// least one sample. Pointer + omitempty so we don't serialize the zero
	// time as "0001-01-01T00:00:00Z" before the first tick.
	LastSampledAt *time.Time `json:"last_sampled_at,omitempty"`
}

// UpdateNetworkLimitsRequest is the body for PATCH /v1/sandboxes/{id}/network/limits.
// Each field is a pointer so the handler can distinguish "leave alone" (nil)
// from "set to unlimited" (pointer to zero). Negative values are rejected at
// the service layer.
type UpdateNetworkLimitsRequest struct {
	NetworkBytesInLimit  *int64 `json:"network_bytes_in_limit,omitempty"`
	NetworkBytesOutLimit *int64 `json:"network_bytes_out_limit,omitempty"`
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
//
// Two creation paths populate this row:
//
//  1. Snapshot-of-a-running-sandbox (legacy) — SourceSandboxID is set,
//     resource fields stay zero, the image is committed by the runtime.
//  2. Snapshot-from-image (Daytona facade) — SourceSandboxID is empty,
//     resource fields and Entrypoint reflect the caller's create payload,
//     and Image is either the caller-supplied imageName or a freshly built
//     tag from a buildInfo Dockerfile.
type SandboxSnapshot struct {
	Name            string    `json:"name"`
	Image           string    `json:"image"`
	ImageID         string    `json:"image_id,omitempty"`
	SourceSandboxID string    `json:"source_sandbox_id"`
	CreatedAt       time.Time `json:"created_at"`
	// Image distribution metadata is the snapshot-level placement contract.
	// Local-only snapshots may be started only on the node whose Docker image
	// store contains Image; external_registry/aocr snapshots may be placed on
	// any worker that can pull RegistryRef/Image.
	ImageDistributionMode string     `json:"image_distribution_mode,omitempty"`
	ImageDigest           string     `json:"image_digest,omitempty"`
	ImageRegistryRef      string     `json:"image_registry_ref,omitempty"`
	ImageVerifiedAt       *time.Time `json:"image_verified_at,omitempty"`

	// Entrypoint is the optional command override the caller wants the
	// runtime to use when starting a sandbox from this snapshot.
	Entrypoint []string `json:"entrypoint,omitempty"`
	// RegionID echoes the region the caller requested when creating the
	// snapshot. The facade persists this verbatim for read-back; region
	// routing itself is not yet wired through the daemon.
	RegionID string `json:"region_id,omitempty"`
	// CPU / MemoryMB / DiskGB / GPU mirror the resource hints the caller
	// supplied on create — surfaced back to clients that poll the snapshot
	// after creation.
	CPU      float64 `json:"cpu,omitempty"`
	MemoryMB int     `json:"memory_mb,omitempty"`
	DiskGB   int     `json:"disk_gb,omitempty"`
	GPU      float64 `json:"gpu,omitempty"`

	// PushState reflects the AOCR-push lifecycle for this snapshot. See the
	// SnapshotPushState* constants above. When push is disabled (or the image
	// already lives in a remote registry) this is "active" from the moment
	// the row is inserted, matching pre-feature behavior. Otherwise it
	// transitions pending → pushing → active|error, and the cluster placement
	// path treats the snapshot as locally-pinned until it hits "active".
	PushState string `json:"push_state,omitempty"`
	// PushError is populated only when PushState is "error" — the last error
	// the reconciler saw, surfaced to the Daytona facade's errorReason field.
	PushError string `json:"push_error,omitempty"`
}

func (s SandboxSnapshot) ImageDistribution() ImageDistributionMetadata {
	return ImageDistributionMetadata{
		Mode:        s.ImageDistributionMode,
		Digest:      s.ImageDigest,
		RegistryRef: s.ImageRegistryRef,
		VerifiedAt:  s.ImageVerifiedAt,
	}
}

func (s *SandboxSnapshot) ApplyImageDistribution(meta ImageDistributionMetadata) {
	if s == nil {
		return
	}
	s.ImageDistributionMode = strings.TrimSpace(meta.Mode)
	s.ImageDigest = strings.TrimSpace(meta.Digest)
	s.ImageRegistryRef = strings.TrimSpace(meta.RegistryRef)
	s.ImageVerifiedAt = meta.VerifiedAt
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
	Status          string `json:"status"`
	Sandboxes       int    `json:"sandboxes"`
	Docker          string `json:"docker"`
	Caddy           string `json:"caddy"`
	Firecracker     string `json:"firecracker,omitempty"`
	Wasm            string `json:"wasm,omitempty"`
	SSHGateway      string `json:"ssh_gateway"`
	ClusterTopology string `json:"cluster_topology,omitempty"`
	ClusterNodes    int    `json:"cluster_nodes,omitempty"`
	Version         string `json:"version"`
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

// Facade names used by sandbox_compat_state, snapshot_aliases, and
// request_idempotency. The string is the only thing persisted, so renaming
// a facade later would require a one-shot UPDATE.
const (
	FacadeDaytona = "daytona"
	FacadeE2B     = "e2b"
)

// SandboxCompatState carries facade-private state that has no native
// meaning on its own — opaque wire-shape sugar like Daytona's `target` or
// E2B's `template_id`. The store treats StateJSON as a byte string;
// facades own the schema inside it.
type SandboxCompatState struct {
	SandboxID string
	Facade    string
	StateJSON string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SnapshotAlias maps a facade-shaped alternate identifier (e.g. E2B's
// base64-encoded `snapshot_*` token) onto a native sandbox_snapshots.name.
// ExtraNames carries additional facade-visible names that point at the
// same native snapshot.
type SnapshotAlias struct {
	Alias        string
	SnapshotName string
	Facade       string
	ExtraNames   []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Idempotent-request states for request_idempotency.state. Pending means
// a write is in flight and holds the row's lock; Ready means the write
// completed and retries within ReplayUntil should replay TargetID instead
// of running again.
const (
	RequestStatePending = "pending"
	RequestStateReady   = "ready"
)

// IdempotentRequestRecord is the row shape for request_idempotency. Scope
// is a facade-defined namespace string (e.g. "e2b.create") so the same
// fingerprint hash can be reused across facades without collision. The
// generic store helpers stay facade-agnostic — only the scope string says
// which caller owns the row.
type IdempotentRequestRecord struct {
	Scope       string
	Fingerprint string
	TargetID    string
	State       string
	LockedUntil time.Time
	ReplayUntil time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TemplateStatus tracks a Firecracker template through its async build.
// pending is the wire-visible state immediately after POST /v1/templates
// (matches Phase 2 — clients that simply poll for ready keep working).
// building_rootfs and snapshotting are intermediate states the Phase 3
// two-phase build goroutine walks through. ready means rootfs+snapshot
// are both on disk; ready_no_snapshot means rootfs is fine but the
// snapshot phase failed (CID alloc, snapshotter error) — sandboxes can
// still cold-boot from this template, just without fast-boot. failed
// means even the rootfs phase did not complete; LastError carries the
// reason for the operator to inspect. unhealthy is the Phase 6 PR-A
// terminal state for "snapshot was ready and worked at least once, then
// a load-time checksum mismatch proved the on-disk artifact is corrupt"
// — distinct from ready_no_snapshot (which is build-time degradation)
// so operators can alert on the runtime regression specifically. Cold-
// boot still works against unhealthy because the rootfs is unaffected;
// the service layer kicks an async rebuild that transitions back to
// ready once the snapshot phase succeeds.
type TemplateStatus string

const (
	TemplateStatusPending         TemplateStatus = "pending"
	TemplateStatusBuildingRootfs  TemplateStatus = "building_rootfs"
	TemplateStatusSnapshotting    TemplateStatus = "snapshotting"
	TemplateStatusReady           TemplateStatus = "ready"
	TemplateStatusReadyNoSnapshot TemplateStatus = "ready_no_snapshot"
	TemplateStatusFailed          TemplateStatus = "failed"
	TemplateStatusUnhealthy       TemplateStatus = "unhealthy"
)

// TemplatePushState tracks the lifecycle of the optional background push of a
// Firecracker template's artifacts (rootfs.ext4 + snapshot.memory + snapshot.state
// + manifest.json) to the AOCR registry under `cluster/<id>/templates/<tid>:latest`.
// Mirrors SnapshotPushState* — operators see one push-state vocabulary across
// snapshots and templates.
//
// "active" is the terminal value (push succeeded OR push is disabled / not
// applicable on this node). New rows on a daemon with push disabled stay
// "active" forever; the reconciler only picks "pending" and "error".
const (
	TemplatePushStateActive  = "active"
	TemplatePushStatePending = "pending"
	TemplatePushStatePushing = "pushing"
	TemplatePushStateError   = "error"
)

// Template is the persisted record for a Firecracker rootfs template.
// See plans/snapshot-clone-fast-boot.md Phase 2: an image is converted
// once into a rootfs.ext4 and many sandboxes can boot from it without
// re-running the skopeo+umoci+mkfs pipeline.
//
// RootfsPath is the absolute on-disk location of the prepared
// rootfs.ext4 (`<FirecrackerTemplatesDir>/<id>/rootfs.ext4`). It is
// json:"-" — the path is a server-internal detail that should not leak
// to API callers; clients reference templates by ID.
//
// Snapshot* fields are populated by the Phase 3 second build phase.
// HasSnapshot is the API-facing "this template fast-boots" flag — the
// path/checksum/CID fields stay json:"-" because they are pure server
// detail. SnapshotError carries the reason a template ended up
// ready_no_snapshot (rootfs is usable, snapshot phase failed) so the
// operator does not have to grep daemon logs.
type Template struct {
	ID                 string         `json:"id"`
	Image              string         `json:"image"`
	Status             TemplateStatus `json:"status"`
	RootfsPath         string         `json:"-"`
	RootfsSizeBytes    int64          `json:"rootfs_size_bytes,omitempty"`
	MinSizeMiB         int            `json:"min_size_mib,omitempty"`
	LastError          string         `json:"last_error,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
	ReadyAt            *time.Time     `json:"ready_at,omitempty"`
	SnapshotMemoryPath string         `json:"-"`
	SnapshotStatePath  string         `json:"-"`
	SnapshotSizeBytes  int64          `json:"snapshot_size_bytes,omitempty"`
	SnapshotChecksum   string         `json:"-"`
	SnapshotVsockCID   uint32         `json:"-"`
	SnapshotError      string         `json:"snapshot_error,omitempty"`
	HasSnapshot        bool           `json:"has_snapshot"`
	// HasOverlay is the API-facing "this template was built with a
	// per-sandbox overlay drive placeholder baked into its snapshot
	// state" flag. PR-A templates have it false; the snapshot-load path
	// rejects an OverlaySizeGB request against a HasOverlay=false
	// template because Firecracker cannot add a virtio-blk device
	// post-load — only PATCH an existing one's backing path. Operators
	// rebuild the template via POST /v1/templates to upgrade.
	HasOverlay bool `json:"has_overlay"`
	// PushState reflects the AOCR-push lifecycle for this template's
	// artifacts (Phase 6 PR 6-B.1). See the TemplatePushState* constants.
	// When push is disabled (or this is a warm-upgrade row) the value is
	// "active" from the moment the row is inserted, matching pre-feature
	// behaviour. Otherwise it transitions pending → pushing → active|error
	// driven by TemplateArtifactPushReconciler.
	PushState string `json:"push_state,omitempty"`
	// PushError is populated only when PushState is "error" — the last
	// error the reconciler saw, surfaced to operator-facing API responses.
	PushError string `json:"push_error,omitempty"`
	// RegistryRef is the canonical destination ref the push pipeline
	// wrote (`<host>/cluster/<id>/templates/<tid>:latest`). Populated
	// after a successful push; empty until then. Read by consumer-side
	// code in PR 6-B.2 to know where peers can pull the template from.
	RegistryRef string `json:"registry_ref,omitempty"`
	// PushDigest is the manifest digest (`sha256:...`) the registry
	// assigned to the pushed tag, as reported by the Docker push stream's
	// `aux` payload. Empty when the daemon did not surface one — older
	// daemons or registries that don't return a manifest digest leave
	// this blank.
	PushDigest string `json:"push_digest,omitempty"`
}

// CreateTemplateRequest is the body for POST /v1/templates. ID is
// optional — empty means "service generates one"; supplying an explicit
// ID lets a deploy pipeline assert idempotency across retries (the
// store rejects a duplicate ID with ErrTemplateIDConflict → API 409).
// Image is the skopeo-style ref ("docker://python:3.11",
// "oci-archive:/path.tar", etc.) passed through verbatim to
// pkg/oci.Builder. MinSizeMiB is an optional floor for the ext4 image —
// useful when the unpacked rootfs is small but the operator expects
// guests to write substantially more.
type CreateTemplateRequest struct {
	ID         string `json:"id,omitempty"`
	Image      string `json:"image"`
	MinSizeMiB int    `json:"min_size_mib,omitempty"`
}

// WasmModuleStatus is the catalogue lifecycle for POST /v1/wasm-modules rows.
type WasmModuleStatus string

const (
	WasmModuleStatusReady  WasmModuleStatus = "ready"
	WasmModuleStatusFailed WasmModuleStatus = "failed"
)

// WasmModule is one row in the wasm_modules catalogue (plans/wasm-runtime.md).
type WasmModule struct {
	ID              string           `json:"id"`
	ModuleRef       string           `json:"module_ref"`
	Status          WasmModuleStatus `json:"status"`
	ModulePath      string           `json:"-"`
	ModuleSizeBytes int64            `json:"module_size_bytes,omitempty"`
	Digest          string           `json:"digest,omitempty"`
	Entrypoint      string           `json:"entrypoint,omitempty"`
	HasWarm         bool             `json:"has_warm"`
	LastError       string           `json:"last_error,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	ReadyAt         *time.Time       `json:"ready_at,omitempty"`
}

// CreateWasmModuleRequest is the body for POST /v1/wasm-modules. ID is
// optional — empty means the service uses the module digest as the
// catalogue id. ModuleRef is resolved synchronously on this host.
type CreateWasmModuleRequest struct {
	ID         string `json:"id,omitempty"`
	ModuleRef  string `json:"module_ref"`
	Entrypoint string `json:"entrypoint,omitempty"`
}

// PushWasmModuleOptions is the SDK-side input for a BYO module upload. The
// wire form is the raw .wasm body plus name/tag query params and the caller's
// registry credentials as headers; this struct is the Go SDK's ergonomic shape.
type PushWasmModuleOptions struct {
	Name             string
	Tag              string
	Module           []byte
	RegistryUsername string
	RegistryToken    string
}

// PushWasmModuleResponse is returned by POST /v1/wasm-modules/push after the
// daemon validates a BYO .wasm upload and forwards it to the registry. The
// daemon stores nothing; the caller references ModuleRef (an oci:// ref) on a
// subsequent create.
type PushWasmModuleResponse struct {
	ModuleRef string `json:"module_ref"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"size_bytes"`
}
