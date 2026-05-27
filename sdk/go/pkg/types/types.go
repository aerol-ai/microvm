package types

import "github.com/aerol-ai/microvm/pkg/models"

type CreateSandboxOptions = models.CreateSandboxRequest
type ResizeSandboxOptions = models.ResizeSandboxRequest
type Lifecycle = models.Lifecycle
type Failover = models.Failover
type UpdateLifecycleOptions = models.UpdateLifecycleRequest
type ExecRequest = models.ExecRequest
type ExecResult = models.ExecResult
type ExposedPort = models.ExposedPort

// ExposeResult is the structured outcome of a successful expose call. Host
// and HostPort are populated only when Protocol == ExposeProtocolTCP — for
// HTTP and TLS exposures the dialable URL is in URL alone.
type ExposeResult = models.ExposePortResponse
type SandboxSnapshot = models.SandboxSnapshot

// Template is the server's Firecracker rootfs template row. Re-exported
// verbatim from pkg/models so the SDK stays aligned with the wire format.
type Template = models.Template

// CreateTemplateOptions is the request body for Client.CreateTemplate.
// Supplying an explicit ID lets retries be idempotent — a duplicate ID
// returns 409 so a re-run CI step does not register two rows for the same
// logical template.
type CreateTemplateOptions = models.CreateTemplateRequest

// TemplateStatus is the lifecycle of a Firecracker rootfs template.
// See plans/snapshot-clone-fast-boot.md for the state machine.
type TemplateStatus = models.TemplateStatus

const (
	TemplateStatusPending         = models.TemplateStatusPending
	TemplateStatusBuildingRootfs  = models.TemplateStatusBuildingRootfs
	TemplateStatusSnapshotting    = models.TemplateStatusSnapshotting
	TemplateStatusReady           = models.TemplateStatusReady
	TemplateStatusReadyNoSnapshot = models.TemplateStatusReadyNoSnapshot
	TemplateStatusFailed          = models.TemplateStatusFailed
	TemplateStatusUnhealthy       = models.TemplateStatusUnhealthy
)

// ExposeProtocol selects the wire surface an exposure publishes through.
type ExposeProtocol string

const (
	FailoverPolicyNone     = models.FailoverPolicyNone
	FailoverPolicyRecreate = models.FailoverPolicyRecreate
)

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
	RuntimeDocker      = models.RuntimeDocker
	RuntimeGvisor      = models.RuntimeGvisor
	RuntimeKata        = models.RuntimeKata
	RuntimeFirecracker = models.RuntimeFirecracker
)

type NetworkUsage = models.NetworkUsage
type SetNetworkLimitsOptions = models.UpdateNetworkLimitsRequest

// CustomDomain is the per-hostname row attached to a sandbox. Status moves
// pending_dns → issuing → ready (or failed), driven server-side by Caddy's
// on-demand TLS asks; clients read but never write Status.
type CustomDomain = models.CustomDomain

// CustomDomainStatus enumerates the lifecycle states surfaced on
// CustomDomain.Status.
type CustomDomainStatus = models.CustomDomainStatus

const (
	CustomDomainPendingDNS = models.CustomDomainPendingDNS
	CustomDomainIssuing    = models.CustomDomainIssuing
	CustomDomainReady      = models.CustomDomainReady
	CustomDomainFailed     = models.CustomDomainFailed
)

// IngressTarget is the cluster-published address(es) DNS for a custom domain
// must point at. Source disambiguates the shape: "hostname" — Hostname holds
// a stable name to CNAME at; "ips" — IPs holds one or more raw IPs to A/AAAA
// at; "mixed" — both are populated; "unknown" — neither is set, the cluster
// has not gossiped a public address yet.
type IngressTarget = models.IngressTarget

// IngressTarget Source values.
const (
	IngressTargetSourceHostname = models.IngressTargetSourceHostname
	IngressTargetSourceIPs      = models.IngressTargetSourceIPs
	IngressTargetSourceMixed    = models.IngressTargetSourceMixed
	IngressTargetSourceUnknown  = models.IngressTargetSourceUnknown
)

// DNSRecord is one ready-to-paste DNS row for a custom domain. Hostname is
// the full hostname; Name is the leftmost label (or "@" for apex); Value is
// the target. Notes carries provider-specific gotchas the daemon pre-renders.
type DNSRecord = models.DNSRecord

// DNS record types emitted in CustomDomainDNSRecords.
const (
	DNSRecordTypeCNAME = models.DNSRecordTypeCNAME
	DNSRecordTypeA     = models.DNSRecordTypeA
	DNSRecordTypeAAAA  = models.DNSRecordTypeAAAA
)

// CustomDomainDNSRecords is the response body for the per-sandbox
// custom-domain DNS helper. Records is the flat list (one row per custom
// domain × per ingress address); Target is the raw aggregation Records was
// composed from, useful when callers want to render their own UI.
type CustomDomainDNSRecords = models.CustomDomainDNSRecords

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

// RegisterSnapshotOptions is the input shape for Client.RegisterSnapshot.
// Exactly one of Image (a pre-built registry reference) or
// DockerfileContent (build inputs the daemon will compile) must be set.
//
// The remaining fields capture the resource hints the snapshot will report
// when listed or used in CreateSandboxOptions.Snapshot.
type RegisterSnapshotOptions struct {
	// Name is the human-readable identifier other callers use to reference
	// this snapshot in CreateSandboxOptions.Snapshot. Required.
	Name string
	// Image is a pre-built registry image reference (e.g. "python:3.12").
	// Mutually exclusive with DockerfileContent.
	Image string
	// DockerfileContent is the literal Dockerfile the daemon will build.
	// Mutually exclusive with Image. Use Image.Dockerfile() to obtain this
	// from an Image-builder graph, or RegisterSnapshotFromImage to skip the
	// indirection entirely.
	DockerfileContent string
	// ContextHashes references blobs uploaded ahead of time so COPY/ADD
	// steps in DockerfileContent can resolve. Requires the daemon to have
	// SB_IMAGE_BUILD_CONTEXT_ENABLED set; the resolver itself is not
	// implemented yet, so non-empty values currently return 501.
	ContextHashes []string
	// Entrypoint overrides the image's entrypoint. Echoed back on the
	// snapshot row so future sandbox-create calls inherit it.
	Entrypoint []string
	// RegionID pins the snapshot to a specific region for multi-region
	// deployments. Persisted on the row but not yet used for routing.
	RegionID string
	// CPU, GPU, MemoryMB, DiskGB are resource hints surfaced to clients.
	CPU      float64
	GPU      float64
	MemoryMB int
	DiskGB   int
}

type GPURequest = models.GPURequest
type GPUVendor = models.GPUVendor

const (
	GPUVendorNVIDIA = models.GPUVendorNVIDIA
	GPUVendorAMD    = models.GPUVendorAMD
	GPUVendorApple  = models.GPUVendorApple
)
