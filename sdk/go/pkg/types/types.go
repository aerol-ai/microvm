package types

import "github.com/aerol-ai/microvm/pkg/models"

type CreateSandboxOptions = models.CreateSandboxRequest
type ResizeSandboxOptions = models.ResizeSandboxRequest
type Lifecycle = models.Lifecycle
type UpdateLifecycleOptions = models.UpdateLifecycleRequest
type ExecRequest = models.ExecRequest
type ExecResult = models.ExecResult
type ExposedPort = models.ExposedPort

// ExposeResult is the structured outcome of a successful expose call. Host
// and HostPort are populated only when Protocol == ExposeProtocolTCP — for
// HTTP and TLS exposures the dialable URL is in URL alone.
type ExposeResult = models.ExposePortResponse
type SandboxSnapshot = models.SandboxSnapshot

// ExposeProtocol selects the wire surface an exposure publishes through.
type ExposeProtocol string

const (
	// ExposeProtocolHTTP is the default — Caddy HTTP reverse proxy at
	// https://<id>-<port>.<domain> (or the path-mode equivalent on an
	// IP-only deployment).
	ExposeProtocolHTTP ExposeProtocol = "http"
	// ExposeProtocolTCP allocates a parent-host port from the configured
	// pool and forwards raw bytes to the container via caddy-l4.
	ExposeProtocolTCP ExposeProtocol = "tcp"
	// ExposeProtocolTLS adds a TLS-SNI route to the shared layer4 server.
	// Requires the daemon to have a domain configured AND
	// SB_L4_TLS_LISTEN set.
	ExposeProtocolTLS ExposeProtocol = "tls"
)

type HealthStatus = models.HealthStatus
type Sandbox = models.Sandbox
type MountSpec = models.MountSpec
type MountSpecRedacted = models.MountSpecRedacted
type MountType = models.MountType
type CreateSessionOptions = models.CreateSessionRequest
type Session = models.Session
type SessionStatus = models.SessionStatus

const (
	SessionStatusRunning = models.SessionStatusRunning
	SessionStatusExited  = models.SessionStatusExited
	SessionStatusKilled  = models.SessionStatusKilled
	SessionStatusFailed  = models.SessionStatusFailed
)

const (
	MountTypeS3     = models.MountTypeS3
	MountTypeNFS    = models.MountTypeNFS
	MountTypeSSHFS  = models.MountTypeSSHFS
	MountTypeRclone = models.MountTypeRclone
)

const (
	RuntimeDocker = models.RuntimeDocker
	RuntimeGvisor = models.RuntimeGvisor
	RuntimeKata   = models.RuntimeKata
)

type NetworkUsage = models.NetworkUsage
type SetNetworkLimitsOptions = models.UpdateNetworkLimitsRequest

// BuildImagePushOptions describes the per-request push directive for
// Client.BuildImageWithOptions. Credentials are forwarded to the daemon
// as a one-shot X-Registry-Auth header on the push call and are never
// persisted.
type BuildImagePushOptions struct {
	// Registry is the destination repository, e.g. "ghcr.io/my-org/my-image".
	Registry string
	// Tag is the destination tag. The daemon defaults to "latest" when empty.
	Tag string
	// Server is the registry serveraddress, e.g. "ghcr.io". Sent inside
	// X-Registry-Auth.
	Server   string
	Username string
	Password string
}

// BuildImageOptions are optional knobs for Client.BuildImageWithOptions.
type BuildImageOptions struct {
	Push *BuildImagePushOptions
}

// BuildImageResult is the response from Client.BuildImageWithOptions.
type BuildImageResult struct {
	// Image is the local content-addressed tag (always returned).
	Image string
	// Pushed is the pushed reference (e.g. "ghcr.io/x/y:v1") when push was
	// requested, otherwise empty.
	Pushed string
}

type GPURequest = models.GPURequest
type GPUVendor = models.GPUVendor

const (
	GPUVendorNVIDIA = models.GPUVendorNVIDIA
	GPUVendorAMD    = models.GPUVendorAMD
	GPUVendorApple  = models.GPUVendorApple
)
