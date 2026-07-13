package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// snapshotRetentionSuffixPattern validates SB_SNAPSHOT_PUSH_TAG_SUFFIX. It
// mirrors AOCR's reaper suffix grammar (`--(ttl|idle)-<dur>`); the duration
// token is left to the registry to accept or reject, so a typo fails at boot
// rather than silently pushing an un-reaped tag.
var snapshotRetentionSuffixPattern = regexp.MustCompile(`^--(ttl|idle)-[a-z0-9]+$`)

const defaultToolboxPort = 2280

// DefaultContainerdRunDir is the single source of truth for the containerd
// per-sandbox host-file workdir default (resolv.conf, hosts, task logs).
// Referenced by both Load() and the containerd driver's FromDaemonConfig so
// the default cannot drift between the two layers.
const DefaultContainerdRunDir = "/var/lib/sandboxd/containerd"

// NodeRole values for SB_NODE_ROLE. The role partitions which components a
// cluster-mode daemon runs (Raft voter promotion, sandbox worker work, public
// ingress reconciler). Default is NodeRoleMixed — every node runs every
// component, matching pre-role behavior bit-for-bit. The split exists so a
// 200-worker cluster doesn't have 200 Raft voters and 200 nodes each holding
// a 10K-route public ingress table; see plans/data-plane-load-balancer.md.
//
// SB_NODE_ROLE accepts either a single token or a comma-separated combination
// of base roles, e.g. "worker,ingress" for a data-plane edge node or
// "server,ingress" for a control + ingress node. NodeRoleMixed remains the
// shorthand for "server,worker,ingress" and may not be combined with anything
// else. Runtime topology validation keeps mixed and hybrid-role nodes as a
// small-cluster convenience only; clusters above 10 live nodes must use
// dedicated server, worker, and ingress roles.
const (
	NodeRoleServer  = "server"
	NodeRoleWorker  = "worker"
	NodeRoleIngress = "ingress"
	NodeRoleMixed   = "mixed"
)

func validNodeRoles() []string {
	return []string{NodeRoleServer, NodeRoleWorker, NodeRoleIngress, NodeRoleMixed}
}

// parseNodeRoles splits raw on commas, lowercases and trims each segment,
// dedupes, and validates each token against the whitelist. It returns the
// sorted, deduped role set; an empty raw returns an empty slice (caller
// substitutes the default). The mixed token may not appear alongside any
// other role: it already means all three and combining it is almost always a
// misconfiguration, so we surface it at boot.
func parseNodeRoles(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	parts := strings.Split(trimmed, ",")
	seen := make(map[string]bool, len(parts))
	roles := make([]string, 0, len(parts))
	for _, p := range parts {
		tok := strings.ToLower(strings.TrimSpace(p))
		if tok == "" {
			return nil, fmt.Errorf("invalid SB_NODE_ROLE=%q: empty token (check for stray commas)", raw)
		}
		switch tok {
		case NodeRoleServer, NodeRoleWorker, NodeRoleIngress, NodeRoleMixed:
		default:
			return nil, fmt.Errorf("invalid SB_NODE_ROLE token %q in %q (allowed: %s)", tok, raw, strings.Join(validNodeRoles(), ", "))
		}
		if seen[tok] {
			continue
		}
		seen[tok] = true
		roles = append(roles, tok)
	}
	if seen[NodeRoleMixed] && len(roles) > 1 {
		return nil, fmt.Errorf("invalid SB_NODE_ROLE=%q: %q is shorthand for %q+%q+%q and may not be combined with other roles",
			raw, NodeRoleMixed, NodeRoleServer, NodeRoleWorker, NodeRoleIngress)
	}
	sort.Strings(roles)
	return roles, nil
}

// canonicalNodeRole renders a parsed role set back to its canonical wire
// form. Single tokens stay as-is (so "worker" stays "worker"). Multi-role
// sets become comma-separated and sorted ("ingress,worker"). The empty input
// is the caller's signal to apply the NodeRoleMixed default.
func canonicalNodeRole(roles []string) string {
	if len(roles) == 0 {
		return ""
	}
	if len(roles) == 1 {
		return roles[0]
	}
	return strings.Join(roles, ",")
}

type Config struct {
	PATToken                    string
	APIHost                     string
	APIPort                     int
	Domain                      string
	PublicHost                  string
	CaddyAdminURL               string
	CaddyServerID               string
	DBPath                      string
	DockerNetwork               string
	ToolboxBinaryPath           string
	ToolboxMountPath            string
	ToolboxPort                 int
	IdleTimeoutMinutes          int
	CreateSandboxTimeoutSeconds int
	ContainerPrivileged         bool
	ResourceLimitsOff           bool
	// Runtime is the host default container runtime for new sandboxes.
	// Per-sandbox CreateSandboxRequest.Runtime overrides it. Allowed values
	// are "docker" (default), "gvisor", or "kata"; validation lives in Load().
	Runtime string
	// ContainerEngine selects the host daemon that realizes OCI sandboxes
	// (dockerd vs native containerd). SB_CONTAINER_ENGINE; default docker.
	ContainerEngine string
	// ContainerdSocket is the containerd gRPC socket used when
	// ContainerEngine=containerd. SB_CONTAINERD_SOCKET.
	ContainerdSocket string
	// ContainerdNamespace is the containerd namespace for aerolvm-managed
	// workloads. SB_CONTAINERD_NAMESPACE; default aerolvm.
	ContainerdNamespace string
	// ContainerdRunDir is the host workdir for per-sandbox host files
	// (resolv.conf, hosts, task logs). SB_CONTAINERD_RUN_DIR.
	ContainerdRunDir string
	// ContainerdLogDir overrides per-task log file placement; defaults to
	// ${ContainerdRunDir}/logs. SB_CONTAINERD_LOG_DIR.
	ContainerdLogDir string
	// ContainerdNativeNetnsPoolEnabled gates the CNI-backed native netns pool
	// for containerd creates (Phase 2). Default off — dockerd path unchanged.
	ContainerdNativeNetnsPoolEnabled bool
	// ContainerdNetnsPoolDepth is the number of prepaid slots seeded at boot.
	ContainerdNetnsPoolDepth int
	// ContainerdCNIPluginDir locates CNI plugin binaries (default /opt/cni/bin).
	ContainerdCNIPluginDir string
	// ContainerdCNIConfPath is the bridge conflist used for ADD/DEL.
	ContainerdCNIConfPath string
	// ContainerdNetnsPoolRefillInterval drives native netns pool refill.
	ContainerdNetnsPoolRefillInterval time.Duration
	// ContainerdPoolEnabled gates the warm containerd task pool (Phase 3).
	// SB_CONTAINERD_POOL_ENABLED.
	ContainerdPoolEnabled bool
	// ContainerdPoolDepth is warm slots per image key. SB_CONTAINERD_POOL_DEPTH.
	ContainerdPoolDepth int
	// ContainerdPoolImages is a comma-separated list of pinned warm targets.
	// SB_CONTAINERD_POOL_IMAGES.
	ContainerdPoolImages []string
	// ContainerdPoolMaxImages caps miss-driven warm targets (LRU).
	// SB_CONTAINERD_POOL_MAX_IMAGES.
	ContainerdPoolMaxImages int
	// ContainerdPoolIdleTTL reaps idle self-warmed targets.
	// SB_CONTAINERD_POOL_IDLE_TTL.
	ContainerdPoolIdleTTL time.Duration
	// ContainerdPoolRefillInterval tops up the warm pool.
	// SB_CONTAINERD_POOL_REFILL_INTERVAL.
	ContainerdPoolRefillInterval time.Duration
	AutoReconcile                bool
	EnableCaddy                  bool
	EnableNetworkRules           bool
	// NetrulesBackend selects the RuleBackend for DOCKER-USER rules:
	// "netlink" (default, google/nftables) or "exec" (go-iptables). See
	// plans/warm-create-latency-tier1.md Phase 1. SB_NETRULES_BACKEND.
	NetrulesBackend    string
	EnableEventMonitor bool
	EnableSSHGateway   bool
	// EnableServerless gates wake behavior for sandboxes created with
	// Lifecycle.Serverless=true. Defaults to true so the wake path is on out
	// of the box; flip to false on a per-host basis to opt that host out of
	// wake-aware control-plane proxying (the serverless flag is still
	// accepted at the API surface so SDK callers don't 4xx, but the runtime
	// never arms wake on stop and the control-plane proxies never call
	// EnsureSandboxAwakeForHTTP). Acts as a rollout gate, not a per-sandbox
	// toggle.
	EnableServerless bool
	// EnableCustomDomains gates the operator-attached public hostname
	// feature. False (default) makes the v1 custom-domain routes return 412
	// Precondition Failed and the install-time Caddy config push omit the
	// on-demand TLS policy. Acts as a rollout switch, not a per-sandbox
	// toggle — same shape as EnableServerless. Requires SB_DOMAIN to be
	// set; the validator rejects EnableCustomDomains=true in IP mode.
	EnableCustomDomains bool
	// CustomDomainsMaxPerSandbox caps how many custom hostnames a single
	// sandbox can carry. Bounds the Caddy host-list fan-out per route and
	// the ACME burst when a sandbox is started for the first time. Default
	// 25; the per-create-request cap (set in pkg/models) is stricter to
	// avoid bursting issuance from one API call.
	CustomDomainsMaxPerSandbox int
	// CustomDomainVerifyPrefix sets the DNS TXT record name prefix for
	// proving custom domain ownership. Defaults to "_aerol-verify".
	CustomDomainVerifyPrefix string
	// CustomDomainVerifyValuePrefix sets the required prefix value for
	// the TXT record, followed by the sandbox ID. Defaults to "aerol-verify=".
	CustomDomainVerifyValuePrefix string
	// TLSOnDemandBurst is the daemon-side on-demand TLS issuance budget burst.
	// It is enforced by the TLS ask handler before Caddy starts an ACME order.
	// Default 5.
	TLSOnDemandBurst int
	// TLSOnDemandInterval is the daemon-side on-demand TLS issuance budget
	// refill interval. Default 1m.
	TLSOnDemandInterval time.Duration
	// ACMEDaemonBudgetFraction is the high-water mark on the daemon-wide
	// ACME issuance bucket — when usage crosses this fraction of Let's
	// Encrypt's published `new-orders` limit (300 / 3h), TLSAsk returns
	// 429 with Retry-After. 0.8 leaves headroom for cert renewals already
	// in flight. A misbehaving tenant burning the quota gets logged with
	// `sandbox_id` so the operator can intervene. The bucket is per-node;
	// LE limits are per-account, and the certmagic-s3 distributed lock
	// already serialises issuance across nodes.
	ACMEDaemonBudgetFraction float64
	// ACMEDaemonBudgetWindow is the LE rolling window. Default 3h —
	// matches the public per-account `new-orders` cap. Exposed only so
	// staging Pebble runs (T1A) can tighten it for tests; do not change
	// in production without a corresponding ACME directory change.
	ACMEDaemonBudgetWindow time.Duration
	// ACMEDaemonBudgetCapacity is the LE per-account `new-orders` cap
	// applied to the bucket. Default 300 — the published LE limit. See
	// ACMEDaemonBudgetWindow note about overrides.
	ACMEDaemonBudgetCapacity int
	// InternalIngressAddr is the loopback-only listen address for the
	// wake-aware HTTP ingress proxy. Caddy dials this address from
	// wake-aware HTTP port routes; it must NOT be exposed publicly.
	InternalIngressAddr string
	// InternalL4WakeAddr is the loopback-only TCP listener Caddy dials from
	// wake-aware raw-TCP routes. Caddy sends PROXY protocol v1 so sandboxd can
	// recover the public host_port and map the connection to an exposure.
	InternalL4WakeAddr string
	// InternalL4WakeDir holds per-exposure Unix sockets for wake-aware TLS-SNI
	// routes. Caddy terminates TLS before proxying, so the socket path carries
	// the sandbox/port identity that plaintext TCP no longer contains.
	InternalL4WakeDir string
	// L4WakeMaxPendingPerSandbox bounds L4 connections waiting for a single
	// sandbox wake. Excess connections are closed before they wait on the
	// per-sandbox wake single-flight.
	L4WakeMaxPendingPerSandbox int
	// L4WakeMaxPendingGlobal bounds all L4 connections waiting for wake on this
	// node. It protects sandboxd from a fleet-wide cold-start burst.
	L4WakeMaxPendingGlobal int
	// L4WakeMaxActivePerSandbox bounds active L4 proxy connections per sandbox
	// through the wake proxy after the sandbox is running.
	L4WakeMaxActivePerSandbox int
	// L4WakeMaxActiveGlobal bounds active L4 proxy connections on this node.
	L4WakeMaxActiveGlobal int
	// HTTPWakeMaxBuffer caps the request body buffered while a cold-start
	// wake is in progress. Requests with bodies larger than this are
	// rejected with 413 — see plan D2.
	HTTPWakeMaxBuffer int64
	// HTTPWakeUpstreamReadyTimeout bounds how long the ingress proxy
	// holds a caller's request waiting for the in-container service to
	// bind its TCP port after wake. Defaults to 30s; raise for workloads
	// with slow startups (JVM, large Python imports).
	HTTPWakeUpstreamReadyTimeout time.Duration
	// HTTPWakeMaxPendingPerSandbox caps cold-start HTTP requests
	// simultaneously holding the wake + readiness window for ONE
	// sandbox. Counterpart of L4WakeMaxPendingPerSandbox. Excess is
	// rejected with 503 + Retry-After. Required > 0 when serverless
	// is on.
	HTTPWakeMaxPendingPerSandbox int
	// HTTPWakeMaxPendingGlobal caps cold-start HTTP requests
	// simultaneously holding the wake + readiness window across ALL
	// sandboxes on this node. Counterpart of L4WakeMaxPendingGlobal.
	HTTPWakeMaxPendingGlobal int
	// HTTPWakeMaxBufferBytesGlobal caps total bytes buffered across all
	// in-flight cold-start requests at any moment. Prevents a flood of
	// near-MaxBuffer cold POSTs from exhausting node memory (10k × 8 MiB
	// = 80 GB worst case without this). Required > 0 when serverless
	// is on.
	HTTPWakeMaxBufferBytesGlobal int64
	// HTTPWakeDirectBypassEnabled flips the serverless HTTP ingress
	// shape between today's "Caddy → sandboxd ingress proxy → container"
	// (false, default in v1) and the warm direct shape
	// "Caddy → container" (true). See plans/warm-direct-route-bypass.md.
	// When true, every warm serverless HTTP request skips sandboxd
	// entirely; the wake-aware route is only installed while a sandbox
	// is Stopped+armed. Required co-requisite: the netstats poller is
	// the activity-floor signal — Validate() rejects per-sandbox
	// StopIfIdleFor values smaller than
	// 2 × NetstatsPollInterval + ReconcileInterval when this is on.
	HTTPWakeDirectBypassEnabled bool
	// HTTPWakeDirectRouteRetryDuration is the Caddy
	// load_balancing.try_duration applied to direct-shape HTTP routes
	// when bypass is enabled. Absorbs the ~10ms window between
	// container exit and the docker die event firing — the next
	// request transparently retries instead of immediately 502-ing.
	// Default 2s; raise if running unusually slow-binding containers.
	HTTPWakeDirectRouteRetryDuration time.Duration
	// CaddyCoalesceInterval is the per-tick batching window for Caddy
	// admin writes. Doubling the route-write volume (wake↔direct on
	// every Start/Stop) regresses Caddy admin p99 under churn unless
	// rapid flips for the same (id, port) collapse into one admin call.
	// Default 250ms; lower bound is the per-write latency budget the
	// node can tolerate before reconcile starts looking stale.
	CaddyCoalesceInterval time.Duration
	// L4WakeDirectBypassEnabled is the Phase 2 sibling of
	// HTTPWakeDirectBypassEnabled — same shape decision applied to
	// TCP and TLS exposures. False (default) keeps today's behavior
	// where every warm L4 byte is proxied through sandboxd's
	// proxyL4WakeConn path; true flips warm sandboxes to a direct
	// Caddy → container route and lets sandboxd's L4 active-connection
	// accounting become a cold-path-only counter. Gated separately
	// from the HTTP flag so each protocol can be canaried independently
	// (per plan §Phase 2: TCP/TLS may ship only after HTTP has been
	// default-on for two cycles). When either flag is enabled, the
	// idle sweep's netstats activity floor and stale-poll fallback
	// (D3/D4) become active — netstats observes container interface
	// bytes regardless of protocol so the floor covers both layers
	// with one mechanism. See plans/warm-direct-route-bypass.md
	// §Phase 2.
	L4WakeDirectBypassEnabled bool
	// TLSWakeListenerCloseDelay is the grace window between PATCHing a
	// TLS-SNI route from wake-aware to direct and closing the per-
	// exposure Unix socket. D2 of the bypass plan: a TLS handshake that
	// started against the wake-aware route may still be in flight when
	// PATCH lands; closing the socket immediately drops that handshake
	// mid-stream. 5s is enough for any reasonable handshake to complete
	// while keeping the socket short-lived enough that a flap doesn't
	// stack up listener FDs. Only consulted when L4WakeDirectBypassEnabled.
	TLSWakeListenerCloseDelay time.Duration
	// WakeStartConcurrency caps concurrent StartSandbox invocations
	// initiated by the wake path across the whole node. Inside the global
	// HTTP+L4 pending caps, up to (HTTPWakeMaxPendingGlobal +
	// L4WakeMaxPendingGlobal) different sandboxes may be in their cold-
	// start window at once; without this cap they all hit Docker create /
	// start and Caddy admin upserts simultaneously, overwhelming both. Per-
	// sandbox single-flight (wakeFlights) prevents same-id duplication;
	// this protects against cross-id storms. Default 64 — Docker daemon
	// handles ~100 concurrent creates cleanly, Caddy admin API serializes
	// writes but doesn't fall over. Operator-initiated StartSandbox calls
	// (API surface) bypass this cap — only wake-driven starts are gated.
	// Required > 0 when serverless is on.
	WakeStartConcurrency        int
	SSHListenAddr               string
	SSHHostKeyPath              string
	CredentialEncryptionKey     string
	CredentialEncryptionKeyPath string
	MountsRootPath              string
	MountsCredentialsRuntimeDir string
	MountWaitTimeout            time.Duration
	PlatformVolumes             PlatformVolumesConfig
	LogLevel                    string
	ShutdownTimeout             time.Duration
	HTTPClientTimeout           time.Duration
	DockerRuntimeWaitTimeout    time.Duration
	ToolboxWaitTimeout          time.Duration
	DockerReadySocketEnabled    bool
	DockerReadinessPollInitial  time.Duration
	DockerReadinessPollMax      time.Duration
	// DockerPoolEnabled gates the warm Docker container pool (default off in v1).
	// SB_DOCKER_POOL_ENABLED.
	DockerPoolEnabled bool
	// DockerPoolDepth is warm slots per image key. SB_DOCKER_POOL_DEPTH.
	DockerPoolDepth int
	// DockerPoolImages is a comma-separated list of pinned warm targets.
	// SB_DOCKER_POOL_IMAGES.
	DockerPoolImages []string
	// DockerPoolMaxImages caps miss-driven warm targets (LRU). SB_DOCKER_POOL_MAX_IMAGES.
	DockerPoolMaxImages int
	// DockerPoolIdleTTL reaps idle self-warmed targets. SB_DOCKER_POOL_IDLE_TTL.
	DockerPoolIdleTTL time.Duration
	// DockerPoolRefillInterval tops up the warm pool. SB_DOCKER_POOL_REFILL_INTERVAL.
	DockerPoolRefillInterval time.Duration
	// DockerNetnsPoolEnabled gates the image-agnostic pause-netns warm pool:
	// pre-started pause containers each hold a fully-built network namespace
	// (veth, bridge attach, IP, iptables), and a create of ANY image adopts
	// one via NetworkMode container:<id>, moving dockerd's per-container
	// network setup off the boot path. Complements — does not replace — the
	// per-image warm pool: this one helps every cold create regardless of
	// image spread. Default off. SB_DOCKER_NETNS_POOL_ENABLED.
	DockerNetnsPoolEnabled bool
	// DockerNetnsPoolDepth is the number of pre-built pause slots kept warm.
	// SB_DOCKER_NETNS_POOL_DEPTH.
	DockerNetnsPoolDepth int
	// DockerNetnsPoolPauseImage is the image for the netns-holding pause
	// containers. Pulled lazily by the refill loop, never on the create path.
	// SB_DOCKER_NETNS_POOL_PAUSE_IMAGE.
	DockerNetnsPoolPauseImage string
	// DockerNetnsPoolRefillInterval drives the refill/reap loop.
	// SB_DOCKER_NETNS_POOL_REFILL_INTERVAL.
	DockerNetnsPoolRefillInterval time.Duration
	ReconcileInterval             time.Duration
	NetstatsPollInterval          time.Duration
	UploadMaxBytes                int64
	// OTELMetricsEnabled starts a native OTLP/HTTP metric exporter that bridges
	// the daemon's aerolvm_* expvars into OpenTelemetry observations. It is
	// also enabled automatically when SB_OTEL_METRICS_ENDPOINT is set.
	OTELMetricsEnabled  bool
	OTELMetricsEndpoint string
	OTELMetricsInterval time.Duration
	// OTELTracesEnabled starts a native OTLP/HTTP trace exporter for API
	// request spans. It is also enabled automatically when
	// SB_OTEL_TRACES_ENDPOINT is set.
	OTELTracesEnabled     bool
	OTELTracesEndpoint    string
	OTELTracesSampleRatio float64
	OTELServiceName       string

	// Admission control. Admission is purely resource-math: CPU/memory
	// reservation ratios plus a live memory floor. There is no fixed sandbox
	// count cap — the host runs as many sandboxes as the math allows.
	CPUReservationRatio    float64
	MemoryReservationRatio float64
	MemoryFloorRatio       float64
	// CPUOverProvisionFactor and MemoryOverProvisionFactor multiply the
	// reservation budgets above. Docker --cpus is a CFS cap (not a hard
	// reservation) and Linux lazy-allocates memory pages, so a host with
	// mostly-idle sandboxes can safely accept far more reservations than its
	// nominal capacity. The live MemoryFloorRatio check is the backstop that
	// catches real pressure when reservations and reality diverge. 0 or <1
	// is clamped to 1.0 (no overcommit) — operators that want strict packing
	// should lower the reservation ratios instead.
	CPUOverProvisionFactor    float64
	MemoryOverProvisionFactor float64
	HostCPUCoresOverride      int
	HostMemoryMBOverride      int
	// DiskReservationRatio gates total per-sandbox disk reservations against
	// HostDiskGB, or the auto-detected host disk size when HostDiskGB is not
	// set. 0 disables disk admission while still reporting disk observability.
	// HostDiskGB remains the operator override for a stricter Docker-volume
	// budget when the host filesystem is larger than the sandbox pool.
	DiskReservationRatio float64
	HostDiskGB           int
	// HostGPUCount and HostGPUVendor describe the GPU inventory wired into
	// Docker via nvidia-container-runtime / amdgpu / etc. Used by placement
	// scheduling so a GPU sandbox is never forwarded to a GPU-less peer.
	HostGPUCount  int
	HostGPUVendor string
	// HostSupportedRuntimes is a comma-separated SB_HOST_RUNTIMES list
	// declaring which OCI runtimes this host has installed. Empty falls
	// back to ["docker"] in capacity.New so existing single-runtime hosts
	// don't need new env to keep accepting placements.
	HostSupportedRuntimes []string

	// EnableFirecracker opts this host in to the native Firecracker runtime
	// (see plans/snapshot-clone-fast-boot.md). False (the default) makes
	// `sandboxd` behave exactly as it does today: the Docker driver is the
	// only registered runtime and create requests with runtime="firecracker"
	// are rejected at the service layer with ErrRuntimeNotImplemented.
	//
	// When true, the Firecracker driver is constructed alongside the Docker
	// driver and dispatched per-sandbox by request.Runtime. Both gates
	// (this flag AND request.Runtime=="firecracker") must be on for a
	// sandbox to land on the new path. Existing Docker/gVisor sandboxes
	// are untouched. SB_ENABLE_FIRECRACKER.
	EnableFirecracker bool
	// EnableWasm opts this host in to the WASM/WASI runtime
	// (plans/wasm-runtime.md). False (the default) keeps WASM creates at
	// ErrRuntimeNotImplemented unless the operator flips SB_ENABLE_WASM.
	// SB_ENABLE_WASM.
	EnableWasm bool
	// WasmRunDir holds per-sandbox runtime state (worker sockets, scratch).
	// Default /run/sandboxd/wasm. SB_WASM_RUN_DIR.
	WasmRunDir string
	// WasmModulesDir is the content-addressed module + checkpoint cache root.
	// Required when EnableWasm is true. SB_WASM_MODULES_DIR.
	WasmModulesDir string
	// WasmCacheDir holds oci:// pulled modules as <digest>.wasm, kept separate
	// from the checkpoint root so eviction never touches a sandbox's mem.snap.
	// Default WasmModulesDir/cache. SB_WASM_CACHE_DIR.
	WasmCacheDir string
	// WasmRegistryAllowlist is the set of registry hosts an oci:// module_ref
	// may pull from. Empty = deny all remote pulls (the SSRF-safe default).
	// Comma-separated. SB_WASM_REGISTRY_ALLOWLIST.
	WasmRegistryAllowlist []string
	// WasmPullTimeout bounds a single oci:// module pull so it cannot stall
	// sandbox boot. 0 = no timeout. SB_WASM_PULL_TIMEOUT.
	WasmPullTimeout time.Duration
	// WasmStandardModules maps reserved-keyword aliases to staged filenames
	// under WasmModulesDir (e.g. "python=python.wasm,javascript=quickjs.wasm").
	// Provisioned identically on every node by Ansible — the fleet-wide
	// standard-module contract, deliberately NOT DB-backed. SB_WASM_STANDARD_MODULES.
	WasmStandardModules map[string]string
	// WasmRegistryUsername is the AOCR login used for oci:// module pulls when
	// the create request carries no per-tenant credentials. SB_WASM_REGISTRY_USERNAME.
	WasmRegistryUsername string
	// WasmRegistryPATPath is the file holding the AOCR token for module pulls.
	// SB_WASM_REGISTRY_PAT_PATH.
	WasmRegistryPATPath string
	// WasmRegistryPushHost is the AOCR host the stateless module-push proxy
	// (POST /v1/wasm-modules/push) forwards uploads to. Empty disables the
	// proxy. The daemon never stores the bytes — it validates and forwards to
	// AOCR under the caller's own PAT. SB_WASM_REGISTRY_PUSH_HOST.
	WasmRegistryPushHost string
	// WasmEngine selects the guest engine backend (wazero or wasmtime). Default wazero.
	// wasmtime requires building sandboxd with -tags wasmtime. SB_WASM_ENGINE.
	WasmEngine string
	// WasmMaxInstances caps live WASM sandboxes on this host. 0 = unlimited.
	// SB_WASM_MAX_INSTANCES.
	WasmMaxInstances int
	// WasmDefaultMemoryMB is the guest linear-memory cap when a create omits memory_mb.
	// SB_WASM_DEFAULT_MEMORY_MB.
	WasmDefaultMemoryMB int
	// WasmDefaultTimeout is the default wall-clock budget for guest invocations.
	// SB_WASM_DEFAULT_TIMEOUT.
	WasmDefaultTimeout time.Duration
	// WasmPoolEnabled gates the in-memory warm-worker pool (Phase 5). Default on:
	// warm workers are the primary WASM create latency path; disable explicitly
	// on memory-constrained nodes via SB_WASM_POOL_ENABLED=false.
	// SB_WASM_POOL_ENABLED.
	WasmPoolEnabled bool
	// WasmPoolDepthDefault is the target number of warm workers per module digest.
	// SB_WASM_POOL_DEPTH_DEFAULT.
	WasmPoolDepthDefault int
	// WasmPoolRefillInterval is how often the refill loop tops up the pool.
	// SB_WASM_POOL_REFILL_INTERVAL.
	WasmPoolRefillInterval time.Duration
	// WasmModuleDigestMode controls per-resolve module hashing: once (default) or always.
	// SB_WASM_MODULE_DIGEST_MODE.
	WasmModuleDigestMode string
	// WasmCompileCacheDir is the shared wazero compilation cache directory.
	// Default <WasmCacheDir>/wazero-compile. Empty disables the cache.
	// SB_WASM_COMPILE_CACHE_DIR.
	WasmCompileCacheDir string
	// WasmDrainTimeout bounds graceful drain checkpoint per sandbox (§4.3).
	// SB_WASM_DRAIN_TIMEOUT.
	WasmDrainTimeout time.Duration
	// WasmCheckpointMaxParallel caps concurrent drain/periodic checkpoint IPC.
	// SB_WASM_CHECKPOINT_MAX_PARALLEL.
	WasmCheckpointMaxParallel int
	// WasmCheckpointInterval triggers periodic boundary checkpoints for live
	// passivatable/durable WASM sandboxes. 0 = off. SB_WASM_CHECKPOINT_INTERVAL.
	WasmCheckpointInterval time.Duration
	// WasmDurablePushInterval re-pushes durable checkpoints missing AOCR metadata.
	// 0 = off (push still happens at passivation). SB_WASM_DURABLE_PUSH_INTERVAL.
	WasmDurablePushInterval time.Duration
	// WasmCheckpointKeepLastN retains the newest N AOCR push records per sandbox.
	// 0 disables pruning. Default 3. SB_WASM_CHECKPOINT_KEEP_LAST_N.
	WasmCheckpointKeepLastN int
	// WasmStateKVWritesPerSec caps per-sandbox durable host-KV writes (Set/Delete).
	// Host-KV writes land synchronously on the single-writer SQLite store, so a
	// chatty durable guest can otherwise contend with the CreateSandbox boot path
	// (plans/wasm-runtime.md §4.6). 0 disables limiting. SB_WASM_STATEKV_WRITES_PER_SEC.
	WasmStateKVWritesPerSec float64
	// WasmStateKVBurst is the host-KV write token-bucket capacity (allowed burst
	// above the steady rate). Ignored when WasmStateKVWritesPerSec is 0.
	// SB_WASM_STATEKV_BURST.
	WasmStateKVBurst int
	// WasmModuleGCEnabled gates the wasm_modules catalogue janitor.
	// SB_WASM_MODULE_GC_ENABLED.
	WasmModuleGCEnabled bool
	// WasmModuleGCInterval is the wasm_modules sweep cadence. SB_WASM_MODULE_GC_INTERVAL.
	WasmModuleGCInterval time.Duration
	// WasmModuleGCTTL drops unreferenced catalogue rows older than this.
	// SB_WASM_MODULE_GC_TTL.
	WasmModuleGCTTL time.Duration
	// WasmCacheGCTTL evicts a content-addressed oci:// cache file
	// (CacheDir/<digest>.wasm) whose mtime is older than this AND that no
	// sandbox or catalogue row still references. Guards against unbounded disk
	// growth from pull-on-create modules that were never registered. 0 disables
	// TTL eviction. SB_WASM_CACHE_GC_TTL.
	WasmCacheGCTTL time.Duration
	// WasmCacheMaxBytes is a soft cap on the total size of the oci:// cache. When
	// the cache exceeds it, the janitor evicts unreferenced files oldest-first
	// until back under the cap, independent of TTL. 0 = unlimited.
	// SB_WASM_CACHE_MAX_BYTES.
	WasmCacheMaxBytes int64
	// FirecrackerBinary is the absolute path to the `firecracker` VMM
	// binary on this host. Required only when EnableFirecracker is true.
	// Default /usr/local/bin/firecracker matches a typical install.
	// SB_FIRECRACKER_BINARY.
	FirecrackerBinary string
	// JailerBinary is the absolute path to the `jailer` helper that
	// chroots and cgroups the VMM process. Required only when
	// EnableFirecracker is true. SB_JAILER_BINARY.
	JailerBinary string
	// FirecrackerKernelImage is the absolute path to the uncompressed
	// guest kernel image (`vmlinux`) the Firecracker driver boots template
	// VMs with. One kernel per host is sufficient for Phase 1; future
	// phases may add per-template kernel selection. Required only when
	// EnableFirecracker is true. SB_FIRECRACKER_KERNEL.
	FirecrackerKernelImage string
	// FirecrackerRunDir is the parent directory that holds per-sandbox
	// runtime state (API sockets, jailer chroots, vsock UDS). Each
	// sandbox lives under <FirecrackerRunDir>/<sandbox-id>/. tmpfs is
	// recommended. Default /run/sandboxd/firecracker.
	// SB_FIRECRACKER_RUN_DIR.
	FirecrackerRunDir string
	// FirecrackerTemplatesDir is the parent directory where template
	// artifacts (kernel symlinks, rootfs.ext4, snapshot.memory,
	// snapshot.state, manifest.json) are persisted. Survives daemon
	// restarts. Default /var/lib/sandboxd/firecracker/templates.
	// SB_FIRECRACKER_TEMPLATES_DIR.
	FirecrackerTemplatesDir string
	// UseJailer wraps each Firecracker process in `jailer` for chroot +
	// cgroups + drop-priv. True is the only sane production setting; the
	// flag exists because the jailer needs root, a real user account
	// (JailerUID/GID), and a writable chroot tree — dev boxes and CI
	// without those bits boot Firecracker directly. Default true to make
	// "ship it" the path of least resistance; operators flip it off on
	// laptops. SB_FIRECRACKER_USE_JAILER.
	UseJailer bool
	// JailerChrootBase is the parent directory under which jailer creates
	// each sandbox's chroot (canonical layout: <base>/firecracker/<id>/root/).
	// Should be on a filesystem that supports the file types the guest
	// needs to see (no overlayfs underneath the rootfs.ext4 path). Default
	// /srv/jailer matches the jailer docs. SB_JAILER_CHROOT_BASE.
	JailerChrootBase string
	// JailerUID / JailerGID are the UID/GID the firecracker process drops
	// to inside the jail. The pair must exist on the host before the
	// daemon starts (jailer setresuid()s into them; a nonexistent UID is
	// accepted on Linux but is a security smell — assume the operator has
	// created a `firecracker` system user). Defaults 1000/1000 are
	// nominal; production setups override.
	// SB_JAILER_UID / SB_JAILER_GID.
	JailerUID int
	JailerGID int
	// FirecrackerTapBaseCIDR carves into /30 subnets, one per pool slot;
	// FirecrackerTapPoolSize is the number of /30s to lay out. Together
	// they cap concurrent Firecracker sandboxes on this host. Defaults
	// (172.16.0.0/20, 256) accommodate a ~256-sandbox host with room to
	// grow; production hosts override to match their networking plan.
	// See internal/network/tap.SeedConfig for the layout math.
	// SB_FIRECRACKER_TAP_BASE_CIDR / SB_FIRECRACKER_TAP_POOL_SIZE.
	FirecrackerTapBaseCIDR string
	FirecrackerTapPoolSize int
	// FirecrackerSkopeoBin / FirecrackerUmociBin / FirecrackerMkfs4Bin are
	// the absolute paths to the three subprocess binaries the OCI rootfs
	// builder shells out to. Required when EnableFirecracker is true;
	// pkg/oci.New stat-checks them at construction so a typo crashes the
	// daemon at boot rather than on first Create.
	// SB_FIRECRACKER_SKOPEO_BIN / SB_FIRECRACKER_UMOCI_BIN / SB_FIRECRACKER_MKFS_BIN.
	FirecrackerSkopeoBin string
	FirecrackerUmociBin  string
	FirecrackerMkfs4Bin  string
	// FirecrackerIPBinary is the path to the iproute2 `ip` binary. Empty
	// means "use $PATH" (the default works on every systemd host); set
	// this only when /usr/sbin is not in the daemon's PATH.
	// SB_FIRECRACKER_IP_BINARY.
	FirecrackerIPBinary string

	// FirecrackerTemplateGCEnabled gates the background sweep that drops
	// templates with no referencing sandbox and updated_at older than
	// FirecrackerTemplateGCTTL. Default true — disabling it means stale
	// templates accumulate on disk indefinitely, which is fine for dev
	// hosts but a footgun in production. SB_FIRECRACKER_TEMPLATE_GC_ENABLED.
	FirecrackerTemplateGCEnabled bool
	// FirecrackerTemplateGCInterval is the sweep cadence. Default 1h —
	// matches the order-of-magnitude of the TTL so the sweep runs ~7 times
	// per default TTL window. SB_FIRECRACKER_TEMPLATE_GC_INTERVAL.
	FirecrackerTemplateGCInterval time.Duration
	// FirecrackerTemplateGCTTL is the unreferenced-template grace window
	// before the sweep reclaims a template's row and on-disk artifacts.
	// Default 168h (7 days) per plans/snapshot-clone-fast-boot.md Phase 2.
	// Updated_at is the clock — building a sandbox from a template touches
	// nothing on the template row, so a template that is being used but
	// has no sandbox right now still ages out. Operators that want
	// long-lived templates should bump this. SB_FIRECRACKER_TEMPLATE_GC_TTL.
	FirecrackerTemplateGCTTL time.Duration

	// FirecrackerTemplateRotationInterval is the Phase 6 PR-E knob that
	// controls how often the rotation reconciler sweeps for templates
	// whose `ready_at` is older than FirecrackerTemplateMaxAge. Default
	// 0 = rotation disabled (rotation is opt-in because it triggers
	// rebuilds, and a misconfigured cluster could thrash the build queue
	// before the operator notices). When > 0, the reconciler ticks on a
	// dedicated goroutine and calls MarkTemplateUnhealthy(reason="rotation")
	// against each stale row, which re-uses the snapshot-corruption
	// rebuild path. SB_FIRECRACKER_TEMPLATE_ROTATION_INTERVAL.
	FirecrackerTemplateRotationInterval time.Duration
	// FirecrackerTemplateMaxAge is the age threshold that turns a healthy
	// `ready` template into a rotation candidate. Default 0 = rotation
	// disabled. Setting Interval without MaxAge is operator error — the
	// reconciler would scan and find nothing to do, ticking forever; we
	// log a warning at boot in that case but don't refuse to start. The
	// typical production value is 30d to pick up kernel and
	// toolbox-agent updates baked into newly-rebuilt templates.
	// SB_FIRECRACKER_TEMPLATE_MAX_AGE.
	FirecrackerTemplateMaxAge time.Duration

	// FirecrackerSnapshotEnabled gates the Phase 3 snapshot phase of the
	// template build pipeline. Default true. When false, templates stop
	// after rootfs.ext4 lands on disk and every Create uses the cold-boot
	// path. Useful for hosts where the snapshotter is misbehaving and
	// operators need to keep templates building.
	// SB_FIRECRACKER_SNAPSHOT_ENABLED.
	FirecrackerSnapshotEnabled bool
	// FirecrackerTemplateBuildTimeout caps the total wall-clock budget for
	// the async template build goroutine (rootfs build + optional snapshot
	// phase combined). Default 45 min — comfortably above every
	// real-world skopeo+umoci+mkfs+snapshot pipeline we've measured on
	// the fattest CUDA bases. The cap exists to bound stuck builds (a
	// wedged subprocess or a hung VMM), not to fail healthy ones.
	// SB_FIRECRACKER_TEMPLATE_BUILD_TIMEOUT.
	FirecrackerTemplateBuildTimeout time.Duration
	// FirecrackerTemplateMemoryMB / FirecrackerTemplateVCPU configure the
	// transient VMM used to capture a template snapshot. Defaults
	// 512 MiB / 1 vCPU keep snapshot.memory small — larger values
	// inflate the on-disk artifact without changing what a clone can
	// do (the clone's effective resources are pinned by the snapshot
	// state, which equals these). Treat as a tuning knob only flipped
	// when the template's init phase OOMs during the snapshot capture.
	// SB_FIRECRACKER_TEMPLATE_MEMORY_MB / SB_FIRECRACKER_TEMPLATE_VCPU.
	FirecrackerTemplateMemoryMB int
	FirecrackerTemplateVCPU     int
	// FirecrackerSnapshotVerifyOnLoad gates SHA256 verification of
	// snapshot.memory + snapshot.state before each LoadSnapshot. Default
	// true — paying ~one-pass-over-the-file at boot is preferable to
	// resuming from a corrupted snapshot, which surfaces as silent guest
	// memory damage hours later. Bypass only for benchmarking the raw
	// load path. SB_FIRECRACKER_SNAPSHOT_VERIFY_ON_LOAD.
	FirecrackerSnapshotVerifyOnLoad bool
	// FirecrackerSnapshotVerifyMode controls the load-time checksum
	// cadence when verification is enabled. "once" (default) verifies a
	// template once per daemon boot and file identity; "always" preserves
	// the previous per-create re-hash behavior for paranoid operators.
	// SB_FIRECRACKER_SNAPSHOT_VERIFY_MODE.
	FirecrackerSnapshotVerifyMode string

	// FirecrackerOverlayEnabled is the daemon-wide opt-out for the
	// per-sandbox writable overlay drive (Phase 3 PR-B). Default true.
	// When false, CreateSandbox rejects any request with
	// OverlaySizeGB > 0 — a safety hatch for a host whose overlay
	// machinery (sparse alloc, mkfs, virtio-blk PATCH) is misbehaving.
	// Templates can still be built with the overlay placeholder in
	// their snapshot state; only the per-clone path is bypassed.
	// SB_FIRECRACKER_OVERLAY_ENABLED.
	FirecrackerOverlayEnabled bool
	// FirecrackerOverlayMkfs makes the host run `mkfs.ext4 -F` on each
	// per-sandbox overlay.ext4 right after the sparse allocation and
	// before PutDrive/PatchDrive. Default false — the guest is normally
	// expected to mkfs /dev/vdb itself on first boot. Enabling adds
	// ~50ms to every Create that requests an overlay (one mkfs.ext4
	// subprocess invocation) and reuses the existing FirecrackerMkfs4Bin
	// path. Off by default to keep the boot path lean per pr-review.md
	// §2. SB_FIRECRACKER_OVERLAY_MKFS.
	FirecrackerOverlayMkfs bool
	// FirecrackerSnapshotPostResumeTimeout bounds the best-effort
	// post_resume vsock send from the driver to the guest toolboxd
	// (carries the host wall clock so the guest can resync
	// CLOCK_REALTIME and reseed its RNG). Default 2s. A failure inside
	// the timeout is logged and does not fail Create — the clone is
	// already resumed and serving, the guest just inherits the
	// template's clock/entropy for a little longer.
	// SB_FIRECRACKER_SNAPSHOT_POST_RESUME_TIMEOUT.
	FirecrackerSnapshotPostResumeTimeout time.Duration

	// FirecrackerVMMPoolEnabled gates the Phase 4 warm-VMM pool. The pool
	// is fully wired: pkg/daemon constructs it, runs the refill goroutine,
	// and injects it via Driver.SetWarmPool; Driver.Create.tryAcquireWarm
	// consumes a warm VMM ahead of the cold-spawn fallback. Kept off by
	// default deliberately (ship-dark) — the warm path is code-complete but
	// none of the benchmark gates in plans/firecracker-create-latency.md
	// have been re-measured yet, so a daemon with the flag unset behaves
	// identically to today. Do NOT flip the default until those gates pass.
	// SB_FIRECRACKER_VMM_POOL_ENABLED.
	FirecrackerVMMPoolEnabled bool
	// FirecrackerVMMPoolDepthDefault is the warm-slot floor PR 4-B's
	// refill goroutine will use for any template without an explicit
	// per-template override. 0 (the default) means "do not warm any
	// template by default" — operators opt in per template once the
	// per-template knob arrives in PR 4-C or via a future
	// POST /v1/templates payload field. SB_FIRECRACKER_VMM_POOL_DEPTH_DEFAULT.
	FirecrackerVMMPoolDepthDefault int
	// FirecrackerVMMPoolGCInterval is the cadence at which PR 4-B's
	// GC sweep walks the 'released' rows whose released_at is older
	// than FirecrackerVMMPoolGCTTL, tears the firecracker process
	// down (if still alive), and drops the row. Default 5m — slow
	// enough that an aggressive refresh doesn't churn SQLite, fast
	// enough that a steady-state stream of releases doesn't pile
	// stale rows up. SB_FIRECRACKER_VMM_POOL_GC_INTERVAL.
	FirecrackerVMMPoolGCInterval time.Duration
	// FirecrackerVMMPoolGCTTL is how long a slot stays in 'released'
	// before the GC sweep drops the row. The window exists so PR 4-B's
	// destroy path can observe a sandbox's release, finish tearing
	// down the VMM process, and update its in-memory bookkeeping
	// before the row disappears from under it. Default 1h.
	// SB_FIRECRACKER_VMM_POOL_GC_TTL.
	FirecrackerVMMPoolGCTTL time.Duration
	// FirecrackerVMMPoolRefillInterval is the cadence at which the
	// refill goroutine walks every warmable template and tops the
	// per-template slot count up to its configured depth. Default 5s —
	// short enough that a burst of Acquire-and-destroy churn refills
	// before the next request arrives, long enough that an idle daemon
	// isn't spawning serially. The first refill always fires at t=0
	// regardless of this value so the pool warms up promptly after
	// boot. SB_FIRECRACKER_VMM_POOL_REFILL_INTERVAL.
	FirecrackerVMMPoolRefillInterval time.Duration

	// FirecrackerRSSSamplerInterval is the cadence at which the Phase 5
	// per-VMM RSS sampler walks /proc/<pid>/statm for every registered
	// firecracker process and recomputes the aggregate admission reads.
	// Default 1s — matches the plan ("statm is fine at ~1Hz") and is
	// orders of magnitude cheaper than the firecracker spawn budget on
	// any host that can run them at all. Only consulted when
	// EnableFirecracker is true; the sampler is not constructed
	// otherwise. SB_FIRECRACKER_RSS_SAMPLER_INTERVAL.
	FirecrackerRSSSamplerInterval time.Duration
	// FirecrackerRSSWatermarkRatio is the Phase 5 effective-memory
	// safety floor as a fraction of host RAM. Admission refuses a new
	// create when (HostMem - sum-of-VMM-RSS - request) would drop below
	// this watermark. 0 disables the axis (the default) — operators opt
	// in by setting the env var. Typical setting is 0.10 (keep 10% of
	// RAM in reserve as RSS-spike headroom); higher means safer but less
	// dense, lower means denser but more sensitive to bursts. The check
	// is also gated on the sampler having produced at least one
	// observation, so a cold-start daemon falls back to nominal
	// accounting rather than admitting infinitely on the assumption that
	// "0 RSS" means "host is empty". SB_FIRECRACKER_RSS_WATERMARK_RATIO.
	FirecrackerRSSWatermarkRatio float64

	// L4PortRangeStart / L4PortRangeEnd bound the parent-host port pool that
	// raw-TCP sandbox exposures (caddy-l4) are allocated from. The allocator
	// picks a random candidate first; collisions fall back to a deterministic
	// scan. Both sides are inclusive.
	//
	// The default range [22000, 23000] sits ABOVE the Linux registered-ports
	// boundary (1024) and BELOW the default ephemeral-port range
	// (net.ipv4.ip_local_port_range, typically 32768-60999). Keeping the pool
	// out of the ephemeral range matters: if these ports overlapped, the
	// kernel could hand any of them to an unrelated outbound connection as a
	// source port, and the next L4 expose attempt to bind() that number would
	// race-fail with EADDRINUSE. 1000 slots is the deliberate concurrent-TCP-
	// exposure cap per host; raise it via the env vars if you need more, but
	// keep both bounds outside the host's ephemeral range.
	L4PortRangeStart int
	L4PortRangeEnd   int
	// L4TLSListen is the listen address for the shared TLS-SNI multiplexer.
	// Empty disables TLS-SNI exposure entirely (the daemon will reject
	// protocol="tls" requests). When set, caddy-l4 binds this address and
	// routes by SNI to per-sandbox subdomains.
	//
	// install.sh sets this to ":443" in domain mode (which always uses
	// DNS-01 wildcard issuance, so :443 is free of ACME traffic and caddy-l4
	// can own it). The HTTPS Caddy server is moved to 127.0.0.1:8443 in that
	// case. In IP/path mode (no --domain) this stays empty and caddy-l4
	// is never started.
	L4TLSListen string
	// L4TLSFallback is the local address caddy-l4 forwards a TLS connection
	// to when no per-sandbox SNI route matches — i.e. the regular HTTPS site
	// served by Caddy itself (sandbox API and the catch-all 404).
	// Required when L4TLSListen is non-empty; ignored otherwise. Default is
	// "127.0.0.1:8443" to match install.sh's relocated HTTPS listener.
	L4TLSFallback string

	// Cluster mode (Phase 1). When EnableCluster is false the daemon runs as
	// a standalone single-node sandbox runner — byte-identical to the legacy
	// behavior. When true, this node joins (or bootstraps) a Raft+gossip
	// cluster that owns the placement map (sandbox_id -> owner node). Each
	// sandbox is owned by exactly one node; the owner's local SQLite remains
	// the source of truth for sandbox state. Hot-path traffic (toolbox,
	// sessions, port forwards) is transparently reverse-proxied to the owner.
	EnableCluster bool
	// NodeRole partitions cluster-mode components across this daemon. Values
	// are one of NodeRoleServer / NodeRoleWorker / NodeRoleIngress /
	// NodeRoleMixed. Default NodeRoleMixed preserves pre-role behavior
	// (every component runs on every node). SB_NODE_ROLE. Ignored when
	// EnableCluster=false — single-node mode is implicitly "mixed".
	NodeRole string
	NodeID   string
	// NodeName is the operator-friendly label gossiped to peers and shown on
	// the dashboard (e.g. "node1", "wrk2"). Display-only; raft/gossip identity
	// stays on NodeID. SB_NODE_NAME; empty falls back to NodeID at display
	// time so single-node and pre-existing deployments need no config change.
	NodeName            string
	RaftBindAddr        string
	RaftAdvertiseAddr   string
	RaftDataDir         string
	GossipBindAddr      string
	GossipAdvertiseAddr string
	BootstrapPeers      []string
	ClusterBootstrap    bool
	SelfAPIAdvertiseURL string
	// DataPlaneAdvertiseHost is the host/IP other nodes use for sandbox
	// public ingress (HTTP/SNI passthrough and raw TCP proxying) when this
	// node owns a sandbox. It is intentionally separate from
	// SelfAPIAdvertiseURL: many deployments put API traffic behind a shared
	// load balancer or API-only DNS name that must not be used as the
	// owner-data-plane target. SB_DATA_PLANE_ADVERTISE_HOST.
	DataPlaneAdvertiseHost string
	// IngressAdvertiseHost is the *public* host the SDK and end users hit for
	// sandbox URLs in cluster mode. It is separate from PublicHost (which is
	// the local node's bind-or-NAT address) and from DataPlaneAdvertiseHost
	// (which is the peer-internal LAN address other nodes use). When set, the
	// Caddy client uses it as the hostname in composed sandbox URLs; when
	// empty, it falls back to PublicHost so single-node mode is unchanged.
	//
	// Operators point this at whatever the cluster's data-plane LB endpoint
	// is — a wildcard DNS record fronting the ingress nodes, a cloud NLB, a
	// MetalLB/BGP VIP, or DNS round-robin across ingress nodes. The build
	// itself does not run any load balancer; that's a deployment decision.
	// See plans/data-plane-load-balancer.md.
	// SB_INGRESS_ADVERTISE_HOST.
	IngressAdvertiseHost string
	// ClusterShardAwareIngress confirms that the public ingress router is
	// shard-aware when the live ingress tier is larger than
	// cluster.MaxReplicatedIngressRouteNodes. Above that size, each ingress
	// node only owns a subset of sandbox routes; a random LB must not spray
	// sandbox traffic across every ingress node. SB_CLUSTER_SHARD_AWARE_INGRESS.
	ClusterShardAwareIngress      bool
	ClusterRaftCommitTimeout      time.Duration
	ClusterCapacityGossipInterval time.Duration
	// ClusterMaxAutoVoters caps gossip-driven Raft voter promotion. Additional
	// nodes are added as non-voters so they still receive the placement log
	// without increasing quorum size. 0 means unlimited, preserving the old
	// behavior for tests or intentionally small fully-voting clusters.
	ClusterMaxAutoVoters int
	// ClusterCreateMaxPendingPerWorker caps reservation-stage creates per
	// worker. This is a leader-side queue guard: when a burst tries to send
	// more than this many not-yet-promoted creates to one worker, the leader
	// rejects with Retry-After instead of letting that worker absorb an
	// unbounded image-pull/docker-create storm. 0 disables the cap.
	// SB_CLUSTER_CREATE_MAX_PENDING_PER_WORKER.
	ClusterCreateMaxPendingPerWorker int
	// ClusterDeadOwnerGrace is how long the leader waits after memberlist marks
	// a node dead before orphaning its placements and removing it from the
	// raft configuration. Long enough to absorb transient gossip flap
	// (network blips, GC pauses) but short enough that operators don't have
	// to wait minutes to recover.
	ClusterDeadOwnerGrace time.Duration
	// ClusterGossipSecretKey, when non-empty, enables AES gossip encryption +
	// authentication. Accepts a base64-encoded 16/24/32-byte key (AES-128/192/256).
	// Required in cluster mode (Load() refuses to start otherwise). The escape
	// hatch is ClusterInsecureGossip below. SB_GOSSIP_SECRET_KEY.
	ClusterGossipSecretKey string
	// ClusterInsecureGossip explicitly opts out of the gossip-key requirement
	// when SB_ENABLE_CLUSTER=true. Only safe on a fully isolated network where
	// every peer that can reach gossip+raft ports is trusted. Default false —
	// the daemon refuses to boot in cluster mode without a gossip key. Use only
	// for ephemeral test setups. SB_CLUSTER_INSECURE_GOSSIP.
	ClusterInsecureGossip bool
	// ClusterInsecureCredentials opts out of the shared-credential-key
	// requirement in cluster mode. Without a key shared across nodes, sealed
	// registry passwords and per-mount credentials replicated via raft cannot
	// be decrypted by a failover owner — recovered sandboxes lose access to
	// private registries and credentialed mounts. Default false: the daemon
	// refuses to boot in cluster mode unless either SB_CREDENTIAL_ENCRYPTION_KEY
	// is set explicitly or a key file already exists at
	// SB_CREDENTIAL_ENCRYPTION_KEY_PATH (the operator may have distributed it
	// out of band). Set true only for ephemeral test setups that don't use
	// sealed creds. SB_CLUSTER_INSECURE_CREDENTIALS.
	ClusterInsecureCredentials bool

	// Cluster-internal mTLS. When enabled, leader-forwarded raft applies (and
	// any other future cluster-internal RPC) ride over a separate HTTPS listener
	// that requires a client certificate signed by the cluster CA. Without TLS
	// the same RPCs ride over the public API URL with only the shared PAT for
	// auth — fine on a private overlay, but a client-cert pin is the right
	// default for any internet-adjacent deployment.
	//
	// ClusterTLSDir holds ca.crt, ca.key (only on the bootstrap node and any
	// joiner that received the bundle), node.crt, node.key. cluster-init.sh
	// generates the CA and a node cert; cluster-join.sh signs a fresh node
	// cert from the bundled CA. SB_CLUSTER_TLS_DIR.
	ClusterTLSDir string
	// ClusterInternalListenAddr is the bind address for the mTLS internal
	// listener. SB_CLUSTER_INTERNAL_LISTEN. Default 0.0.0.0:7002.
	ClusterInternalListenAddr string
	// ClusterInternalAdvertiseURL is the URL peers dial for cluster-internal
	// RPCs. Falls back to https://<derived-host>:<internal-port> when empty.
	// Must be HTTPS — plaintext defeats the purpose. SB_CLUSTER_INTERNAL_ADVERTISE.
	ClusterInternalAdvertiseURL string
	// ImageBuildContextEnabled is the operator opt-in for the contextHashes
	// upload path — image builds whose context includes caller-supplied
	// local files (COPY/ADD). Off by default because the resolution path
	// needs an object-store + registry combo to push the resulting layered
	// image somewhere the docker daemon can pull from on the next sandbox
	// start. With this disabled, builds that only RUN commands (no
	// caller-side context) still work — they execute against a tar
	// containing just the Dockerfile.
	//
	// NOTE: enabling this is necessary but not sufficient. The context
	// resolver itself is not yet wired, so requests with contextHashes will
	// still return HTTP 501 even when this flag is true. The flag exists
	// so operators can explicitly opt in to that codepath as soon as the
	// resolver lands, without a daemon redeploy.
	ImageBuildContextEnabled bool
	// ImageBuildTimeout caps a single `docker build` (or `docker push`)
	// call from any image-build path: the native POST /v1/images/build
	// handler and the Daytona facade's createSandbox build-on-create flow.
	// Build time is opaque (depends on the Dockerfile) so the default is
	// generous; we bound it only to keep a runaway build from permanently
	// parking the HTTP handler.
	ImageBuildTimeout time.Duration
	// ImageBuildGCEnabled toggles BOTH image janitors: the built-image
	// sweep (locally-built BuiltImageNamespace tags older than the TTL
	// with no active reference) and the pending-image sweep (entries in
	// the pending_image_gc ledger scheduled by sandbox destroy paths,
	// older than the TTL with no active reference). Without the former,
	// images produced by standalone POST /v1/images/build calls — or
	// builds whose followup CreateSandbox failed — accumulate forever.
	// Without the latter, every sandbox destroy leaks its image until
	// the daemon is restarted. Disabling both with one switch matches
	// how operators reason about "image GC" as a single subsystem.
	ImageBuildGCEnabled bool
	// ImageBuildGCInterval is how often each janitor ticker fires.
	// Default 10m: cheap enough (one filtered /images/json call + one
	// indexed store lookup per built-image match for one janitor; one
	// indexed range scan over pending_image_gc for the other) that
	// running more often would only matter under churn that itself
	// indicates an upstream problem.
	ImageBuildGCInterval time.Duration
	// ImageBuildGCTTL is the minimum age before an image becomes
	// eligible for removal: for built images, measured from the
	// daemon's LastTagTime; for pending images, from the destroy
	// timestamp recorded in pending_image_gc.scheduled_at (which is
	// also refreshed forward by the create path's
	// RefreshPendingImageGCIfExists, so the clock restarts on most
	// recent use, not first destroy). Default 24h: wide enough that a
	// destroy/recreate cycle measured in hours doesn't pay a fresh
	// registry pull, while still bounded so a build-only host
	// (sandboxes never recreated) eventually reclaims disk. Tighten via
	// SB_IMAGE_BUILD_GC_TTL when disk pressure outweighs warm-start
	// latency.
	ImageBuildGCTTL time.Duration
	// ImageGCWhitelist is a list of image repositories or refs the janitors
	// must never remove. Three match shapes are honored against the image
	// string the sandbox stored (the same string passed to docker pull):
	//   1. exact ref equality                 ("alpine:latest" == "alpine:latest")
	//   2. repo equality, tag/digest agnostic ("ubuntu" matches "ubuntu:22.04",
	//      "ubuntu@sha256:...")
	//   3. registry/org prefix when the entry ends in "/"
	//      ("ghcr.io/myorg/" matches every image under that path; useful for
	//      "always keep my private builds cached")
	// Loaded from SB_IMAGE_GC_WHITELIST as a comma-separated list. An empty
	// list (the default) preserves today's behavior — every image is
	// eligible for GC. Whitelisted images also short-circuit the
	// pending_image_gc ledger insert so the ledger doesn't accumulate rows
	// the janitor would only ever skip.
	ImageGCWhitelist []string
	// ImageDistributionAOCRHost is the registry host treated as the optional
	// managed AOCR image-distribution provider. Empty configs constructed in
	// tests fall back to the product default in the service layer.
	ImageDistributionAOCRHost string
	// ImagePullMaxConcurrent caps simultaneous Docker /images/create streams
	// per worker. Pulls for the same image/auth key are still deduplicated; this
	// cap protects the daemon and registry when many different cold images are
	// requested at once. 0 disables the cap.
	ImagePullMaxConcurrent int
	// ImagePullFailureBackoff suppresses immediate retries for the same
	// image/auth key after Docker or the registry returns an error. This keeps a
	// bad tag or rate-limit response from turning into a per-create retry storm.
	ImagePullFailureBackoff time.Duration

	// AutoImportEnabled gates the F21 post-pull auto-import path: after a
	// successful pull of a private upstream image, sandboxd asks AOCR to
	// re-mount the bytes under `cluster/<id>/_imported/...` so future
	// recreates on other nodes pull with the cluster PAT and survive an
	// upstream credential rotation. Off by default; flipping it on requires
	// AutoImportHooksBaseURL, AutoImportClusterID, and a non-empty PAT file.
	// SB_AUTO_IMPORT_ENABLED.
	AutoImportEnabled bool
	// AutoImportHooksBaseURL is the AOCR hooks service root (no trailing
	// slash). The importer appends `/v1/internal/imports`.
	// SB_AUTO_IMPORT_HOOKS_URL.
	AutoImportHooksBaseURL string
	// AutoImportClusterID identifies this sandboxd cluster to AOCR. Goes
	// into the import request body and constrains the cluster PAT's scope
	// on the AOCR side. SB_AUTO_IMPORT_CLUSTER_ID.
	AutoImportClusterID string
	// AutoImportClusterPATPath is the file path to the bearer token
	// presented to the AOCR ImportAPI. File-sourced (not env) so the secret
	// is rotatable without restarting and never appears in process listings.
	// SB_AUTO_IMPORT_CLUSTER_PAT_PATH.
	AutoImportClusterPATPath string
	// AutoImportRetentionSuffix is appended to the imported tag in the
	// cluster namespace (e.g. `--idle-90d`). Must begin with `--` to match
	// AOCR's retention parser; empty falls back to the server-side default.
	// SB_AUTO_IMPORT_RETENTION_SUFFIX.
	AutoImportRetentionSuffix string
	// AutoImportRequestTimeout caps a single ImportAPI call. The mount-from-
	// repo flow is normally sub-second; the timeout guards against an
	// upstream that hangs on layer enumeration.
	// SB_AUTO_IMPORT_REQUEST_TIMEOUT.
	AutoImportRequestTimeout time.Duration
	// AutoImportReconcileInterval is the period between retry sweeps for
	// rows the post-pull path left flagged `auto_import_pending`. Too short
	// and a flapping AOCR causes a fan-out storm; too long and a transient
	// outage leaves the failover path on the F17 wrap-creds fallback for
	// longer than necessary. Default 5m.
	// SB_AUTO_IMPORT_RECONCILE_INTERVAL.
	AutoImportReconcileInterval time.Duration
	// AutoImportMaxInFlight bounds per-tick fan-out so a recovery storm
	// (everything pending at once after a long outage) cannot saturate
	// AOCR or the local Docker socket. Default 4.
	// SB_AUTO_IMPORT_MAX_IN_FLIGHT.
	AutoImportMaxInFlight int

	// MirrorHost is the AOCR pull-through mirror vhost
	// (e.g. `mirror.aocr.aerol.ai`). When non-empty AND at least one
	// upstream is configured, the docker client rewrites matching image
	// refs through this host before pulling. Empty disables rewriting and
	// pulls hit the upstream registry directly — the safety hatch for
	// nodes not running with AOCR mirror enabled. SB_MIRROR_HOST.
	MirrorHost string
	// MirrorPushHost is the AOCR push vhost (e.g. `aocr.aerol.ai`). Used
	// only for idempotency: a ref that already points at the push vhost
	// (e.g. a cluster snapshot or a previously-imported image) is not
	// re-rewritten. Optional. SB_MIRROR_PUSH_HOST.
	MirrorPushHost string
	// MirrorUpstreams is the comma-separated host=shortname mapping
	// (`ghcr.io=ghcr,gcr.io=gcr,quay.io=quay,registry.k8s.io=k8s`). Docker
	// Hub is intentionally absent — it's mirrored via the Docker daemon's
	// `registry-mirrors` daemon.json setting, not client-side rewriting.
	// SB_MIRROR_UPSTREAMS.
	MirrorUpstreams []MirrorUpstreamMapping
	// UpstreamWrapKeyPath is the file path to the per-cluster AES-GCM wrap
	// key used to seal docker `RegistryAuth` payloads before they reach
	// the mirror, so the mirror vhost never sees raw upstream PATs.
	// File-sourced (not env) with required mode 0400. When empty or
	// unreadable, the mirror falls back to anonymous pulls — fine for
	// public images, but private images will 401. SB_UPSTREAM_WRAP_KEY_PATH.
	UpstreamWrapKeyPath string

	// SnapshotPushEnabled gates the optional background push of sandbox
	// snapshots to the AOCR registry. When false (the default), snapshots
	// stay local-only — identical to pre-feature behavior. When true,
	// snapshots whose distribution mode is `local_only` (sandbox commits
	// and aerolvm-build/* tags) are pushed in the background to
	// `<MirrorPushHost|ImageDistributionAOCRHost>/cluster/<ClusterID>/snapshots/<name>`,
	// reusing the cluster PAT as the registry password. Requires
	// AutoImportClusterID and AutoImportClusterPATPath to be set —
	// validated at startup. SB_SNAPSHOT_PUSH_ENABLED.
	SnapshotPushEnabled bool
	// SnapshotPushReconcileInterval is the tick period for the background
	// retry of failed snapshot pushes. Default 5m — shorter wastes credit
	// when a registry is flapping; longer leaves new snapshots stuck in
	// `pending` for longer than necessary on cold paths.
	// SB_SNAPSHOT_PUSH_RECONCILE_INTERVAL.
	SnapshotPushReconcileInterval time.Duration
	// SnapshotPushMaxInFlight bounds per-tick fan-out so a burst of newly
	// created snapshots cannot saturate the local Docker daemon or the
	// AOCR registry. Default 2 — pushes are I/O-heavy per snapshot.
	// SB_SNAPSHOT_PUSH_MAX_IN_FLIGHT.
	SnapshotPushMaxInFlight int
	// SnapshotPushTagSuffix is an optional AOCR retention suffix appended to
	// pushed snapshot tags (`latest<suffix>`), e.g. "--ttl-1h" or
	// "--idle-30d". Empty (the default) pushes a plain `latest` tag the reaper
	// keeps indefinitely — the right posture for durable failover snapshots.
	// Ephemeral clusters (integration tests) set it so their snapshots are
	// auto-reaped. Validated at startup against `--(ttl|idle)-<dur>`.
	// SB_SNAPSHOT_PUSH_TAG_SUFFIX.
	SnapshotPushTagSuffix string

	// FleetControlPlaneEnabled gates the optional managed control-plane
	// integration (caller-token validation + fleet usage telemetry +
	// standing-driven quota enforcement). False (the default) keeps sandboxd
	// in pure open-source behavior: the only accepted credential is the
	// operator PAT, no usage is reported, and no enforcement loop runs.
	// Everything else about the integration is pulled at runtime from the
	// managed contract API — only the three fields below live in local config.
	// SB_FLEET_ENABLED.
	FleetControlPlaneEnabled bool
	// FleetControlPlaneEndpoint is the managed control-plane base URL (no
	// trailing slash). Required when FleetControlPlaneEnabled is true. The
	// contract, validate, and standing paths are appended to it by the client.
	// SB_FLEET_ENDPOINT.
	FleetControlPlaneEndpoint string
	// FleetControlPlaneToken is the fleet credential (avm_<32hex>) the client
	// presents to the control plane. Treat as secret; never logged. Rendered
	// from config/secrets.yml like the cluster PAT, or supplied directly via
	// the env var. Required when FleetControlPlaneEnabled is true.
	// SB_FLEET_TOKEN.
	FleetControlPlaneToken string
	// FleetControlPlaneContractRefresh is the only locally-pinned cadence: how
	// often the managed contract (which carries every other tunable) is
	// re-fetched. Default 5m. SB_FLEET_CONTRACT_REFRESH.
	FleetControlPlaneContractRefresh time.Duration
	// FleetLiveSampleInterval is the cadence of the opt-in live CPU/memory
	// sampler. 0 (the default) disables it: only the reserved axes are emitted,
	// which is the right posture for most fleets. When > 0 it is clamped up to a
	// 1s floor (≤1 Hz) so an aggressive value can't hammer the Docker stats
	// endpoint. Only has any effect on a managed build with a usage reporter
	// wired; the open-source build emits nothing regardless. SB_FLEET_LIVE_SAMPLE_INTERVAL.
	FleetLiveSampleInterval time.Duration
}

// MirrorUpstreamMapping is a single host=shortname pair parsed from
// SB_MIRROR_UPSTREAMS. Kept here (not in pkg/docker) so the config layer
// has no dependency on the docker package — main.go translates to
// docker.MirrorUpstream at wiring time.
type MirrorUpstreamMapping struct {
	Host      string
	Shortname string
}

// PlatformVolumesConfig holds the operator-level shared-storage settings that
// back named persistent volumes. Unlike per-sandbox external mounts, the
// *operator* owns the bucket/export and credentials here; end users reference
// volumes only by name. When Enabled is false every volume API returns 412 and
// none of the backend fields are read. See plans/e2b-volume-mounts.md.
type PlatformVolumesConfig struct {
	Enabled bool
	// Backend selects the storage protocol: "s3" or "nfs". Both ship in v1.
	Backend string
	// MaxPerTenant caps how many distinct volumes a single tenant may create.
	// 0 means unlimited.
	MaxPerTenant int

	// ReclaimInterval is how often the backend-reclaim janitor drains the
	// pending_volume_deletions ledger (deleting the S3 prefix / NFS directory of
	// deleted volumes). 0 disables the worker, leaving the ledger for an external
	// reconciler — the metadata delete still succeeds, only byte reclaim pauses.
	ReclaimInterval time.Duration

	// ReclaimMountRoot is the root-owned scratch dir transient NFS reclaim mounts
	// are created under. Ignored for the S3 backend.
	ReclaimMountRoot string

	// ReclaimConcurrency bounds how many backend deletes a single reclaim tick
	// runs in parallel. Each delete is a serial CLI / mount round-trip, so some
	// parallelism keeps a burst-delete backlog draining without unbounded fanout
	// against the backend. <=1 means serial.
	ReclaimConcurrency int

	// S3 backend (Backend == "s3").
	S3Bucket          string
	S3Prefix          string
	S3Region          string
	S3Endpoint        string
	S3AccessKeyID     string
	S3SecretAccessKey string

	// NFS backend (Backend == "nfs"). NFS is a credential-free kernel mount;
	// NFSExport is the base export path under which per-tenant/per-name
	// directories live.
	NFSServer  string
	NFSExport  string
	NFSOptions string
}

// Backend protocol constants for PlatformVolumesConfig.Backend.
const (
	PlatformVolumesBackendS3  = "s3"
	PlatformVolumesBackendNFS = "nfs"
)

// Validate enforces the gating contract: when platform volumes are enabled the
// selected backend's required fields must be present, so the daemon fails fast
// at boot rather than 500-ing on the first volume request. A disabled config is
// always valid (the backend fields are ignored).
func (p PlatformVolumesConfig) Validate() error {
	if !p.Enabled {
		return nil
	}
	if p.MaxPerTenant < 0 {
		return errors.New("SB_PLATFORM_VOLUMES_MAX_PER_TENANT must be >= 0")
	}
	switch p.Backend {
	case PlatformVolumesBackendS3:
		if strings.TrimSpace(p.S3Bucket) == "" {
			return errors.New("SB_PLATFORM_VOLUMES_S3_BUCKET is required when platform volumes use the s3 backend")
		}
	case PlatformVolumesBackendNFS:
		if strings.TrimSpace(p.NFSServer) == "" {
			return errors.New("SB_PLATFORM_VOLUMES_NFS_SERVER is required when platform volumes use the nfs backend")
		}
		if strings.TrimSpace(p.NFSExport) == "" {
			return errors.New("SB_PLATFORM_VOLUMES_NFS_EXPORT is required when platform volumes use the nfs backend")
		}
	default:
		return fmt.Errorf("SB_PLATFORM_VOLUMES_BACKEND must be %q or %q, got %q",
			PlatformVolumesBackendS3, PlatformVolumesBackendNFS, p.Backend)
	}
	return nil
}

func Load() (Config, error) {
	exe, _ := os.Executable()
	defaultToolboxPath := filepath.Join(filepath.Dir(exe), "toolboxd")

	cfg := Config{
		PATToken:                          strings.TrimSpace(os.Getenv("SB_PAT_TOKEN")),
		APIHost:                           getEnv("SB_API_HOST", "0.0.0.0"),
		APIPort:                           getEnvInt("SB_API_PORT", 21212),
		Domain:                            normalizeHost(os.Getenv("SB_DOMAIN")),
		PublicHost:                        normalizeHost(getEnv("SB_PUBLIC_HOST", "127.0.0.1")),
		CaddyAdminURL:                     getEnv("SB_CADDY_ADMIN_URL", "http://127.0.0.1:2019"),
		CaddyServerID:                     getEnv("SB_CADDY_SERVER_ID", "srv0"),
		DBPath:                            getEnv("SB_DB_PATH", "/var/lib/sandboxd/state.db"),
		DockerNetwork:                     getEnv("SB_DOCKER_NETWORK", "bridge"),
		ToolboxBinaryPath:                 getEnv("SB_TOOLBOX_BINARY_PATH", defaultToolboxPath),
		ToolboxMountPath:                  getEnv("SB_TOOLBOX_MOUNT_PATH", "/usr/local/bin/toolboxd"),
		ToolboxPort:                       getEnvInt("SB_TOOLBOX_PORT", defaultToolboxPort),
		IdleTimeoutMinutes:                getEnvInt("SB_IDLE_TIMEOUT_MIN", 0),
		CreateSandboxTimeoutSeconds:       getEnvInt("SB_CREATE_TIMEOUT_SEC", 600),
		ContainerPrivileged:               getEnvBool("SB_CONTAINER_PRIVILEGED", false),
		ResourceLimitsOff:                 getEnvBool("SB_RESOURCE_LIMITS_DISABLED", false),
		Runtime:                           getEnv("SB_CONTAINER_RUNTIME", models.RuntimeDocker),
		ContainerEngine:                   getEnv("SB_CONTAINER_ENGINE", models.ContainerEngineDocker),
		ContainerdSocket:                  getEnv("SB_CONTAINERD_SOCKET", "/run/containerd/containerd.sock"),
		ContainerdNamespace:               getEnv("SB_CONTAINERD_NAMESPACE", "aerolvm"),
		ContainerdRunDir:                  getEnv("SB_CONTAINERD_RUN_DIR", DefaultContainerdRunDir),
		ContainerdLogDir:                  strings.TrimSpace(os.Getenv("SB_CONTAINERD_LOG_DIR")),
		ContainerdNativeNetnsPoolEnabled:  getEnvBool("SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", false),
		ContainerdNetnsPoolDepth:          getEnvInt("SB_CONTAINERD_NETNS_POOL_DEPTH", 4),
		ContainerdCNIPluginDir:            getEnv("SB_CONTAINERD_CNI_PLUGIN_DIR", "/opt/cni/bin"),
		ContainerdCNIConfPath:             getEnv("SB_CONTAINERD_CNI_CONF_PATH", "/etc/cni/net.d/aerolvm.conflist"),
		ContainerdNetnsPoolRefillInterval: getEnvDuration("SB_CONTAINERD_NETNS_POOL_REFILL_INTERVAL", 2*time.Second),
		ContainerdPoolEnabled:             getEnvBool("SB_CONTAINERD_POOL_ENABLED", false),
		ContainerdPoolDepth:               getEnvInt("SB_CONTAINERD_POOL_DEPTH", 2),
		ContainerdPoolImages:              parseImageGCWhitelist(getEnv("SB_CONTAINERD_POOL_IMAGES", "")),
		ContainerdPoolMaxImages:           getEnvInt("SB_CONTAINERD_POOL_MAX_IMAGES", 8),
		ContainerdPoolIdleTTL:             getEnvDuration("SB_CONTAINERD_POOL_IDLE_TTL", 15*time.Minute),
		ContainerdPoolRefillInterval:      getEnvDuration("SB_CONTAINERD_POOL_REFILL_INTERVAL", 5*time.Second),
		AutoReconcile:                     getEnvBool("SB_AUTO_RECONCILE", true),
		EnableCaddy:                       getEnvBool("SB_ENABLE_CADDY", true),
		EnableNetworkRules:                getEnvBool("SB_ENABLE_NETWORK_RULES", true),
		NetrulesBackend:                   strings.ToLower(strings.TrimSpace(getEnv("SB_NETRULES_BACKEND", "netlink"))),
		EnableEventMonitor:                getEnvBool("SB_ENABLE_EVENT_MONITOR", true),
		EnableSSHGateway:                  getEnvBool("SB_ENABLE_SSH_GATEWAY", true),
		EnableServerless:                  getEnvBool("SB_ENABLE_SERVERLESS", true),
		EnableCustomDomains:               getEnvBool("SB_ENABLE_CUSTOM_DOMAINS", false),
		CustomDomainsMaxPerSandbox:        getEnvInt("SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX", models.MaxCustomDomainsPerSandbox),
		CustomDomainVerifyPrefix:          getEnv("SB_CUSTOM_DOMAIN_VERIFY_PREFIX", "_aerol-verify"),
		CustomDomainVerifyValuePrefix:     getEnv("SB_CUSTOM_DOMAIN_VERIFY_VALUE_PREFIX", "aerol-verify="),
		TLSOnDemandBurst:                  getEnvInt("SB_TLS_ON_DEMAND_BURST", 5),
		TLSOnDemandInterval:               getEnvDuration("SB_TLS_ON_DEMAND_INTERVAL", time.Minute),
		ACMEDaemonBudgetFraction:          getEnvFloat("SB_ACME_DAEMON_BUDGET_FRACTION", 0.8),
		ACMEDaemonBudgetWindow:            getEnvDuration("SB_ACME_DAEMON_BUDGET_WINDOW", 3*time.Hour),
		ACMEDaemonBudgetCapacity:          getEnvInt("SB_ACME_DAEMON_BUDGET_CAPACITY", 300),
		InternalIngressAddr:               getEnv("SB_INTERNAL_INGRESS_ADDR", "127.0.0.1:21213"),
		InternalL4WakeAddr:                getEnv("SB_INTERNAL_L4_WAKE_ADDR", "127.0.0.1:21214"),
		InternalL4WakeDir:                 getEnv("SB_INTERNAL_L4_WAKE_DIR", "/run/sandboxd/l4wake"),
		L4WakeMaxPendingPerSandbox:        getEnvInt("SB_L4_WAKE_MAX_PENDING_PER_SANDBOX", 256),
		L4WakeMaxPendingGlobal:            getEnvInt("SB_L4_WAKE_MAX_PENDING_GLOBAL", 4096),
		L4WakeMaxActivePerSandbox:         getEnvInt("SB_L4_WAKE_MAX_ACTIVE_PER_SANDBOX", 4096),
		L4WakeMaxActiveGlobal:             getEnvInt("SB_L4_WAKE_MAX_ACTIVE_GLOBAL", 65536),
		HTTPWakeMaxBuffer:                 int64(getEnvInt("SB_HTTP_WAKE_MAX_BUFFER", 8*1024*1024)),
		HTTPWakeUpstreamReadyTimeout:      getEnvDuration("SB_HTTP_WAKE_UPSTREAM_READY_TIMEOUT", 30*time.Second),
		HTTPWakeMaxPendingPerSandbox:      getEnvInt("SB_HTTP_WAKE_MAX_PENDING_PER_SANDBOX", 256),
		HTTPWakeMaxPendingGlobal:          getEnvInt("SB_HTTP_WAKE_MAX_PENDING_GLOBAL", 4096),
		HTTPWakeMaxBufferBytesGlobal:      int64(getEnvInt("SB_HTTP_WAKE_MAX_BUFFER_GLOBAL", 1024*1024*1024)),
		WakeStartConcurrency:              getEnvInt("SB_WAKE_START_CONCURRENCY", 64),
		HTTPWakeDirectBypassEnabled:       getEnvBool("SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED", false),
		HTTPWakeDirectRouteRetryDuration:  getEnvDuration("SB_HTTP_WAKE_DIRECT_ROUTE_RETRY_DURATION", 2*time.Second),
		CaddyCoalesceInterval:             getEnvDuration("SB_CADDY_COALESCE_INTERVAL", 250*time.Millisecond),
		L4WakeDirectBypassEnabled:         getEnvBool("SB_L4_WAKE_DIRECT_BYPASS_ENABLED", false),
		TLSWakeListenerCloseDelay:         getEnvDuration("SB_TLS_WAKE_LISTENER_CLOSE_DELAY", 5*time.Second),
		SSHListenAddr:                     getEnv("SB_SSH_LISTEN_ADDR", "0.0.0.0:2220"),
		SSHHostKeyPath:                    getEnv("SB_SSH_HOST_KEY_PATH", "/var/lib/sandboxd/ssh_host_ed25519_key"),
		CredentialEncryptionKey:           strings.TrimSpace(os.Getenv("SB_CREDENTIAL_ENCRYPTION_KEY")),
		CredentialEncryptionKeyPath:       getEnv("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", "/var/lib/sandboxd/credential_encryption.key"),
		MountsRootPath:                    getEnv("SB_MOUNTS_ROOT", "/var/lib/sandboxd/mounts"),
		MountsCredentialsRuntimeDir:       getEnv("SB_MOUNTS_CRED_DIR", "/run/sandboxd"),
		MountWaitTimeout:                  getEnvDuration("SB_MOUNT_WAIT_TIMEOUT", 30*time.Second),
		PlatformVolumes: PlatformVolumesConfig{
			Enabled:            getEnvBool("SB_PLATFORM_VOLUMES_ENABLED", false),
			Backend:            strings.ToLower(strings.TrimSpace(getEnv("SB_PLATFORM_VOLUMES_BACKEND", PlatformVolumesBackendS3))),
			MaxPerTenant:       getEnvInt("SB_PLATFORM_VOLUMES_MAX_PER_TENANT", 0),
			ReclaimInterval:    getEnvDuration("SB_PLATFORM_VOLUMES_RECLAIM_INTERVAL", 5*time.Minute),
			ReclaimMountRoot:   strings.TrimSpace(getEnv("SB_PLATFORM_VOLUMES_RECLAIM_MOUNT_ROOT", "/var/lib/aerolvm/volume-reclaim")),
			ReclaimConcurrency: getEnvInt("SB_PLATFORM_VOLUMES_RECLAIM_CONCURRENCY", 8),
			S3Bucket:           strings.TrimSpace(os.Getenv("SB_PLATFORM_VOLUMES_S3_BUCKET")),
			S3Prefix:           strings.TrimSpace(getEnv("SB_PLATFORM_VOLUMES_S3_PREFIX", "volumes")),
			S3Region:           strings.TrimSpace(os.Getenv("SB_PLATFORM_VOLUMES_S3_REGION")),
			S3Endpoint:         strings.TrimSpace(os.Getenv("SB_PLATFORM_VOLUMES_S3_ENDPOINT")),
			S3AccessKeyID:      strings.TrimSpace(os.Getenv("SB_PLATFORM_VOLUMES_S3_ACCESS_KEY_ID")),
			S3SecretAccessKey:  strings.TrimSpace(os.Getenv("SB_PLATFORM_VOLUMES_S3_SECRET_ACCESS_KEY")),
			NFSServer:          strings.TrimSpace(os.Getenv("SB_PLATFORM_VOLUMES_NFS_SERVER")),
			NFSExport:          strings.TrimSpace(os.Getenv("SB_PLATFORM_VOLUMES_NFS_EXPORT")),
			NFSOptions:         strings.TrimSpace(os.Getenv("SB_PLATFORM_VOLUMES_NFS_OPTIONS")),
		},
		LogLevel:                      strings.ToLower(getEnv("SB_LOG_LEVEL", "info")),
		ShutdownTimeout:               getEnvDuration("SB_SHUTDOWN_TIMEOUT", 10*time.Second),
		HTTPClientTimeout:             getEnvDuration("SB_HTTP_CLIENT_TIMEOUT", 180*time.Second),
		DockerRuntimeWaitTimeout:      getEnvDuration("SB_DOCKER_WAIT_TIMEOUT", 30*time.Second),
		ToolboxWaitTimeout:            getEnvDuration("SB_TOOLBOX_WAIT_TIMEOUT", 30*time.Second),
		DockerReadySocketEnabled:      getEnvBool("SB_DOCKER_READY_SOCKET_ENABLED", true),
		DockerReadinessPollInitial:    getEnvDuration("SB_DOCKER_READINESS_POLL_INITIAL", 20*time.Millisecond),
		DockerReadinessPollMax:        getEnvDuration("SB_DOCKER_READINESS_POLL_MAX", 300*time.Millisecond),
		DockerPoolEnabled:             getEnvBool("SB_DOCKER_POOL_ENABLED", false),
		DockerPoolDepth:               getEnvInt("SB_DOCKER_POOL_DEPTH", 2),
		DockerPoolImages:              parseImageGCWhitelist(getEnv("SB_DOCKER_POOL_IMAGES", "")),
		DockerPoolMaxImages:           getEnvInt("SB_DOCKER_POOL_MAX_IMAGES", 8),
		DockerPoolIdleTTL:             getEnvDuration("SB_DOCKER_POOL_IDLE_TTL", 15*time.Minute),
		DockerPoolRefillInterval:      getEnvDuration("SB_DOCKER_POOL_REFILL_INTERVAL", 5*time.Second),
		DockerNetnsPoolEnabled:        getEnvBool("SB_DOCKER_NETNS_POOL_ENABLED", false),
		DockerNetnsPoolDepth:          getEnvInt("SB_DOCKER_NETNS_POOL_DEPTH", 4),
		DockerNetnsPoolPauseImage:     getEnv("SB_DOCKER_NETNS_POOL_PAUSE_IMAGE", "registry.k8s.io/pause:3.10"),
		DockerNetnsPoolRefillInterval: getEnvDuration("SB_DOCKER_NETNS_POOL_REFILL_INTERVAL", 2*time.Second),
		ReconcileInterval:             getEnvDuration("SB_RECONCILE_INTERVAL", 5*time.Minute),
		NetstatsPollInterval:          getEnvDuration("SB_NETSTATS_POLL_INTERVAL", 10*time.Second),
		UploadMaxBytes:                int64(getEnvInt("SB_UPLOAD_MAX_BYTES", 256*1024*1024)),
		OTELMetricsEnabled:            getEnvBool("SB_OTEL_METRICS_ENABLED", false),
		OTELMetricsEndpoint:           firstNonEmpty(os.Getenv("SB_OTEL_METRICS_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")),
		OTELMetricsInterval:           getEnvDuration("SB_OTEL_METRICS_INTERVAL", 30*time.Second),
		OTELTracesEnabled:             getEnvBool("SB_OTEL_TRACES_ENABLED", false),
		OTELTracesEndpoint:            firstNonEmpty(os.Getenv("SB_OTEL_TRACES_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")),
		OTELTracesSampleRatio:         getEnvFloat("SB_OTEL_TRACES_SAMPLE_RATIO", 0.05),
		OTELServiceName:               getEnv("OTEL_SERVICE_NAME", "sandboxd"),

		CPUReservationRatio:       getEnvFloat("SB_CPU_RESERVATION_RATIO", 0.9),
		MemoryReservationRatio:    getEnvFloat("SB_MEMORY_RESERVATION_RATIO", 0.85),
		MemoryFloorRatio:          getEnvFloat("SB_MEMORY_FLOOR_RATIO", 0.05),
		CPUOverProvisionFactor:    getEnvFloat("SB_CPU_OVERPROVISION_FACTOR", 10.0),
		MemoryOverProvisionFactor: getEnvFloat("SB_MEMORY_OVERPROVISION_FACTOR", 10.0),
		HostCPUCoresOverride:      getEnvInt("SB_HOST_CPU_CORES", 0),
		HostMemoryMBOverride:      getEnvInt("SB_HOST_MEMORY_MB", 0),
		DiskReservationRatio:      getEnvFloat("SB_DISK_RESERVATION_RATIO", 0),
		HostDiskGB:                getEnvInt("SB_HOST_DISK_GB", 0),
		HostGPUCount:              getEnvInt("SB_HOST_GPU_COUNT", 0),
		HostGPUVendor:             strings.ToLower(strings.TrimSpace(os.Getenv("SB_HOST_GPU_VENDOR"))),
		HostSupportedRuntimes:     splitAndTrim(os.Getenv("SB_HOST_RUNTIMES"), ","),

		L4PortRangeStart: getEnvInt("SB_L4_PORT_RANGE_START", 22000),
		L4PortRangeEnd:   getEnvInt("SB_L4_PORT_RANGE_END", 23000),
		L4TLSListen:      strings.TrimSpace(os.Getenv("SB_L4_TLS_LISTEN")),
		L4TLSFallback:    getEnv("SB_L4_TLS_FALLBACK", "127.0.0.1:8443"),

		EnableCluster:                    getEnvBool("SB_ENABLE_CLUSTER", false),
		NodeRole:                         os.Getenv("SB_NODE_ROLE"),
		NodeID:                           strings.TrimSpace(os.Getenv("SB_NODE_ID")),
		NodeName:                         strings.TrimSpace(os.Getenv("SB_NODE_NAME")),
		RaftBindAddr:                     getEnv("SB_RAFT_BIND_ADDR", "0.0.0.0:7000"),
		RaftAdvertiseAddr:                strings.TrimSpace(os.Getenv("SB_RAFT_ADVERTISE_ADDR")),
		RaftDataDir:                      strings.TrimSpace(os.Getenv("SB_RAFT_DATA_DIR")),
		GossipBindAddr:                   getEnv("SB_GOSSIP_BIND_ADDR", "0.0.0.0:7001"),
		GossipAdvertiseAddr:              strings.TrimSpace(os.Getenv("SB_GOSSIP_ADVERTISE_ADDR")),
		BootstrapPeers:                   splitAndTrim(os.Getenv("SB_BOOTSTRAP_PEERS"), ","),
		ClusterBootstrap:                 getEnvBool("SB_CLUSTER_BOOTSTRAP", false),
		SelfAPIAdvertiseURL:              strings.TrimSpace(os.Getenv("SB_API_ADVERTISE_URL")),
		DataPlaneAdvertiseHost:           normalizeAdvertiseHost(os.Getenv("SB_DATA_PLANE_ADVERTISE_HOST")),
		IngressAdvertiseHost:             normalizeAdvertiseHost(os.Getenv("SB_INGRESS_ADVERTISE_HOST")),
		ClusterShardAwareIngress:         getEnvBool("SB_CLUSTER_SHARD_AWARE_INGRESS", false),
		ClusterRaftCommitTimeout:         getEnvDuration("SB_RAFT_COMMIT_TIMEOUT", 5*time.Second),
		ClusterCapacityGossipInterval:    getEnvDuration("SB_CAPACITY_GOSSIP_INTERVAL", 5*time.Second),
		ClusterMaxAutoVoters:             getEnvInt("SB_CLUSTER_MAX_AUTO_VOTERS", 5),
		ClusterCreateMaxPendingPerWorker: getEnvInt("SB_CLUSTER_CREATE_MAX_PENDING_PER_WORKER", 32),
		ClusterDeadOwnerGrace:            getEnvDuration("SB_DEAD_OWNER_GRACE", 30*time.Second),
		ClusterGossipSecretKey:           strings.TrimSpace(os.Getenv("SB_GOSSIP_SECRET_KEY")),
		ClusterInsecureGossip:            getEnvBool("SB_CLUSTER_INSECURE_GOSSIP", false),
		ClusterInsecureCredentials:       getEnvBool("SB_CLUSTER_INSECURE_CREDENTIALS", false),
		ClusterTLSDir:                    strings.TrimSpace(os.Getenv("SB_CLUSTER_TLS_DIR")),
		ClusterInternalListenAddr:        getEnv("SB_CLUSTER_INTERNAL_LISTEN", "0.0.0.0:7002"),
		ClusterInternalAdvertiseURL:      strings.TrimSpace(os.Getenv("SB_CLUSTER_INTERNAL_ADVERTISE")),
		ImageBuildContextEnabled:         getEnvBool("SB_IMAGE_BUILD_CONTEXT_ENABLED", false),
		ImageBuildTimeout:                getEnvDuration("SB_IMAGE_BUILD_TIMEOUT", 10*time.Minute),
		ImageBuildGCEnabled:              getEnvBool("SB_IMAGE_BUILD_GC_ENABLED", true),
		ImageBuildGCInterval:             getEnvDuration("SB_IMAGE_BUILD_GC_INTERVAL", 10*time.Minute),
		ImageBuildGCTTL:                  getEnvDuration("SB_IMAGE_BUILD_GC_TTL", 24*time.Hour),
		ImageGCWhitelist:                 parseImageGCWhitelist(os.Getenv("SB_IMAGE_GC_WHITELIST")),
		ImageDistributionAOCRHost:        strings.TrimSpace(getEnv("SB_IMAGE_DISTRIBUTION_AOCR_HOST", "aocr.aerol.ai")),
		ImagePullMaxConcurrent:           getEnvInt("SB_IMAGE_PULL_MAX_CONCURRENT", 4),
		ImagePullFailureBackoff:          getEnvDuration("SB_IMAGE_PULL_FAILURE_BACKOFF", 30*time.Second),
		AutoImportEnabled:                getEnvBool("SB_AUTO_IMPORT_ENABLED", false),
		AutoImportHooksBaseURL:           strings.TrimSpace(os.Getenv("SB_AUTO_IMPORT_HOOKS_URL")),
		AutoImportClusterID:              strings.TrimSpace(os.Getenv("SB_AUTO_IMPORT_CLUSTER_ID")),
		AutoImportClusterPATPath:         strings.TrimSpace(os.Getenv("SB_AUTO_IMPORT_CLUSTER_PAT_PATH")),
		AutoImportRetentionSuffix:        strings.TrimSpace(getEnv("SB_AUTO_IMPORT_RETENTION_SUFFIX", "--idle-90d")),
		AutoImportRequestTimeout:         getEnvDuration("SB_AUTO_IMPORT_REQUEST_TIMEOUT", 15*time.Second),
		AutoImportReconcileInterval:      getEnvDuration("SB_AUTO_IMPORT_RECONCILE_INTERVAL", 5*time.Minute),
		AutoImportMaxInFlight:            getEnvInt("SB_AUTO_IMPORT_MAX_IN_FLIGHT", 4),
		MirrorHost:                       strings.TrimSpace(os.Getenv("SB_MIRROR_HOST")),
		MirrorPushHost:                   strings.TrimSpace(os.Getenv("SB_MIRROR_PUSH_HOST")),
		MirrorUpstreams:                  parseMirrorUpstreams(getEnv("SB_MIRROR_UPSTREAMS", "ghcr.io=ghcr,gcr.io=gcr,quay.io=quay,registry.k8s.io=k8s")),
		UpstreamWrapKeyPath:              strings.TrimSpace(os.Getenv("SB_UPSTREAM_WRAP_KEY_PATH")),
		SnapshotPushEnabled:              getEnvBool("SB_SNAPSHOT_PUSH_ENABLED", false),
		SnapshotPushReconcileInterval:    getEnvDuration("SB_SNAPSHOT_PUSH_RECONCILE_INTERVAL", 5*time.Minute),
		SnapshotPushMaxInFlight:          getEnvInt("SB_SNAPSHOT_PUSH_MAX_IN_FLIGHT", 2),
		SnapshotPushTagSuffix:            strings.TrimSpace(getEnv("SB_SNAPSHOT_PUSH_TAG_SUFFIX", "")),

		FleetControlPlaneEnabled:         getEnvBool("SB_FLEET_ENABLED", false),
		FleetControlPlaneEndpoint:        strings.TrimSpace(os.Getenv("SB_FLEET_ENDPOINT")),
		FleetControlPlaneToken:           strings.TrimSpace(os.Getenv("SB_FLEET_TOKEN")),
		FleetControlPlaneContractRefresh: getEnvDuration("SB_FLEET_CONTRACT_REFRESH", 5*time.Minute),
		FleetLiveSampleInterval:          getEnvDuration("SB_FLEET_LIVE_SAMPLE_INTERVAL", 0),

		EnableFirecracker:         getEnvBool("SB_ENABLE_FIRECRACKER", false),
		EnableWasm:                getEnvBool("SB_ENABLE_WASM", false),
		WasmRunDir:                getEnv("SB_WASM_RUN_DIR", "/run/sandboxd/wasm"),
		WasmModulesDir:            getEnv("SB_WASM_MODULES_DIR", "/var/lib/sandboxd/wasm/modules"),
		WasmCacheDir:              getEnv("SB_WASM_CACHE_DIR", ""),
		WasmRegistryAllowlist:     parseImageGCWhitelist(getEnv("SB_WASM_REGISTRY_ALLOWLIST", "")),
		WasmPullTimeout:           getEnvDuration("SB_WASM_PULL_TIMEOUT", 60*time.Second),
		WasmStandardModules:       parseWasmStandardModules(getEnv("SB_WASM_STANDARD_MODULES", "")),
		WasmRegistryUsername:      getEnv("SB_WASM_REGISTRY_USERNAME", ""),
		WasmRegistryPATPath:       getEnv("SB_WASM_REGISTRY_PAT_PATH", ""),
		WasmRegistryPushHost:      getEnv("SB_WASM_REGISTRY_PUSH_HOST", ""),
		WasmEngine:                strings.ToLower(strings.TrimSpace(getEnv("SB_WASM_ENGINE", "wazero"))),
		WasmMaxInstances:          getEnvInt("SB_WASM_MAX_INSTANCES", 0),
		WasmDefaultMemoryMB:       getEnvInt("SB_WASM_DEFAULT_MEMORY_MB", 256),
		WasmDefaultTimeout:        getEnvDuration("SB_WASM_DEFAULT_TIMEOUT", 5*time.Minute),
		WasmDrainTimeout:          getEnvDuration("SB_WASM_DRAIN_TIMEOUT", 30*time.Second),
		WasmCheckpointMaxParallel: getEnvInt("SB_WASM_CHECKPOINT_MAX_PARALLEL", 64),
		WasmCheckpointInterval:    getEnvDuration("SB_WASM_CHECKPOINT_INTERVAL", 0),
		WasmDurablePushInterval:   getEnvDuration("SB_WASM_DURABLE_PUSH_INTERVAL", 0),
		WasmCheckpointKeepLastN:   getEnvInt("SB_WASM_CHECKPOINT_KEEP_LAST_N", 3),
		// Default is deliberately generous: the guard exists to stop a single
		// runaway guest (thousands of writes/sec hammering the single writer),
		// not to throttle normal durable workloads. Operators tune down for
		// stricter boot-path protection or set 0 to disable. WASM durable is new
		// in this release, so there are no existing guests this default can break.
		WasmStateKVWritesPerSec: getEnvFloat("SB_WASM_STATEKV_WRITES_PER_SEC", 50),
		WasmStateKVBurst:        getEnvInt("SB_WASM_STATEKV_BURST", 100),
		WasmModuleGCEnabled:     getEnvBool("SB_WASM_MODULE_GC_ENABLED", true),
		WasmModuleGCInterval:    getEnvDuration("SB_WASM_MODULE_GC_INTERVAL", 15*time.Minute),
		WasmModuleGCTTL:         getEnvDuration("SB_WASM_MODULE_GC_TTL", 7*24*time.Hour),
		WasmCacheGCTTL:          getEnvDuration("SB_WASM_CACHE_GC_TTL", 24*time.Hour),
		WasmCacheMaxBytes:       getEnvInt64("SB_WASM_CACHE_MAX_BYTES", 0),
		WasmPoolEnabled:         getEnvBool("SB_WASM_POOL_ENABLED", true),
		WasmPoolDepthDefault:    getEnvInt("SB_WASM_POOL_DEPTH_DEFAULT", 2),
		WasmPoolRefillInterval:  getEnvDuration("SB_WASM_POOL_REFILL_INTERVAL", 5*time.Second),
		WasmModuleDigestMode:    strings.ToLower(getEnv("SB_WASM_MODULE_DIGEST_MODE", "once")),
		WasmCompileCacheDir:     getEnv("SB_WASM_COMPILE_CACHE_DIR", ""),
		FirecrackerBinary:       getEnv("SB_FIRECRACKER_BINARY", "/usr/local/bin/firecracker"),
		JailerBinary:            getEnv("SB_JAILER_BINARY", "/usr/local/bin/jailer"),
		FirecrackerKernelImage:  getEnv("SB_FIRECRACKER_KERNEL", "/var/lib/sandboxd/firecracker/vmlinux"),
		FirecrackerRunDir:       getEnv("SB_FIRECRACKER_RUN_DIR", "/run/sandboxd/firecracker"),
		FirecrackerTemplatesDir: getEnv("SB_FIRECRACKER_TEMPLATES_DIR", "/var/lib/sandboxd/firecracker/templates"),
		UseJailer:               getEnvBool("SB_FIRECRACKER_USE_JAILER", true),
		JailerChrootBase:        getEnv("SB_JAILER_CHROOT_BASE", "/srv/jailer"),
		JailerUID:               getEnvInt("SB_JAILER_UID", 1000),
		JailerGID:               getEnvInt("SB_JAILER_GID", 1000),
		FirecrackerTapBaseCIDR:  getEnv("SB_FIRECRACKER_TAP_BASE_CIDR", "172.16.0.0/20"),
		FirecrackerTapPoolSize:  getEnvInt("SB_FIRECRACKER_TAP_POOL_SIZE", 256),
		FirecrackerSkopeoBin:    getEnv("SB_FIRECRACKER_SKOPEO_BIN", "/usr/bin/skopeo"),
		FirecrackerUmociBin:     getEnv("SB_FIRECRACKER_UMOCI_BIN", "/usr/bin/umoci"),
		FirecrackerMkfs4Bin:     getEnv("SB_FIRECRACKER_MKFS_BIN", "/sbin/mkfs.ext4"),
		FirecrackerIPBinary:     strings.TrimSpace(os.Getenv("SB_FIRECRACKER_IP_BINARY")),

		FirecrackerTemplateGCEnabled:  getEnvBool("SB_FIRECRACKER_TEMPLATE_GC_ENABLED", true),
		FirecrackerTemplateGCInterval: getEnvDuration("SB_FIRECRACKER_TEMPLATE_GC_INTERVAL", 1*time.Hour),
		FirecrackerTemplateGCTTL:      getEnvDuration("SB_FIRECRACKER_TEMPLATE_GC_TTL", 168*time.Hour),

		FirecrackerSnapshotEnabled:          getEnvBool("SB_FIRECRACKER_SNAPSHOT_ENABLED", true),
		FirecrackerTemplateBuildTimeout:     getEnvDuration("SB_FIRECRACKER_TEMPLATE_BUILD_TIMEOUT", 45*time.Minute),
		FirecrackerTemplateRotationInterval: getEnvDuration("SB_FIRECRACKER_TEMPLATE_ROTATION_INTERVAL", 0),
		FirecrackerTemplateMaxAge:           getEnvDuration("SB_FIRECRACKER_TEMPLATE_MAX_AGE", 0),
		FirecrackerTemplateMemoryMB:         getEnvInt("SB_FIRECRACKER_TEMPLATE_MEMORY_MB", 512),
		FirecrackerTemplateVCPU:             getEnvInt("SB_FIRECRACKER_TEMPLATE_VCPU", 1),
		FirecrackerSnapshotVerifyOnLoad:     getEnvBool("SB_FIRECRACKER_SNAPSHOT_VERIFY_ON_LOAD", true),
		FirecrackerSnapshotVerifyMode:       strings.ToLower(getEnv("SB_FIRECRACKER_SNAPSHOT_VERIFY_MODE", "once")),

		FirecrackerOverlayEnabled:            getEnvBool("SB_FIRECRACKER_OVERLAY_ENABLED", true),
		FirecrackerOverlayMkfs:               getEnvBool("SB_FIRECRACKER_OVERLAY_MKFS", false),
		FirecrackerSnapshotPostResumeTimeout: getEnvDuration("SB_FIRECRACKER_SNAPSHOT_POST_RESUME_TIMEOUT", 2*time.Second),

		// Phase 4 PR-A — warm-VMM pool. Inert in this commit: nothing
		// reads these knobs yet. They land here so PR 4-B's wiring is
		// a pure addition without schema or config churn.
		FirecrackerVMMPoolEnabled:        getEnvBool("SB_FIRECRACKER_VMM_POOL_ENABLED", false),
		FirecrackerVMMPoolDepthDefault:   getEnvInt("SB_FIRECRACKER_VMM_POOL_DEPTH_DEFAULT", 0),
		FirecrackerVMMPoolGCInterval:     getEnvDuration("SB_FIRECRACKER_VMM_POOL_GC_INTERVAL", 5*time.Minute),
		FirecrackerVMMPoolGCTTL:          getEnvDuration("SB_FIRECRACKER_VMM_POOL_GC_TTL", 1*time.Hour),
		FirecrackerVMMPoolRefillInterval: getEnvDuration("SB_FIRECRACKER_VMM_POOL_REFILL_INTERVAL", 5*time.Second),
		FirecrackerRSSSamplerInterval:    getEnvDuration("SB_FIRECRACKER_RSS_SAMPLER_INTERVAL", 1*time.Second),
		FirecrackerRSSWatermarkRatio:     getEnvFloat("SB_FIRECRACKER_RSS_WATERMARK_RATIO", 0),
	}
	if cfg.OTELMetricsEndpoint != "" || strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) != "" {
		cfg.OTELMetricsEnabled = true
	}
	if cfg.OTELTracesEndpoint != "" || strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) != "" {
		cfg.OTELTracesEnabled = true
	}

	if cfg.PATToken == "" {
		return Config{}, errors.New("SB_PAT_TOKEN is required")
	}

	if err := cfg.PlatformVolumes.Validate(); err != nil {
		return Config{}, err
	}

	if cfg.DBPath == "" {
		return Config{}, errors.New("SB_DB_PATH is required")
	}
	if cfg.OTELMetricsEnabled && cfg.OTELMetricsInterval <= 0 {
		return Config{}, errors.New("SB_OTEL_METRICS_INTERVAL must be > 0 when OTEL metrics are enabled")
	}
	if cfg.OTELTracesEnabled && (cfg.OTELTracesSampleRatio < 0 || cfg.OTELTracesSampleRatio > 1) {
		return Config{}, errors.New("SB_OTEL_TRACES_SAMPLE_RATIO must be between 0 and 1 when OTEL traces are enabled")
	}
	if cfg.ImagePullMaxConcurrent < 0 {
		return Config{}, errors.New("SB_IMAGE_PULL_MAX_CONCURRENT must be >= 0")
	}
	if cfg.ImagePullFailureBackoff < 0 {
		return Config{}, errors.New("SB_IMAGE_PULL_FAILURE_BACKOFF must be >= 0")
	}
	if cfg.FirecrackerSnapshotVerifyMode != "once" && cfg.FirecrackerSnapshotVerifyMode != "always" {
		return Config{}, errors.New("SB_FIRECRACKER_SNAPSHOT_VERIFY_MODE must be either once or always")
	}
	if cfg.AutoImportEnabled {
		if cfg.AutoImportHooksBaseURL == "" {
			return Config{}, errors.New("SB_AUTO_IMPORT_HOOKS_URL is required when SB_AUTO_IMPORT_ENABLED=true")
		}
		if cfg.AutoImportClusterID == "" {
			return Config{}, errors.New("SB_AUTO_IMPORT_CLUSTER_ID is required when SB_AUTO_IMPORT_ENABLED=true")
		}
		if cfg.AutoImportClusterPATPath == "" {
			return Config{}, errors.New("SB_AUTO_IMPORT_CLUSTER_PAT_PATH is required when SB_AUTO_IMPORT_ENABLED=true")
		}
		if cfg.AutoImportReconcileInterval <= 0 {
			return Config{}, errors.New("SB_AUTO_IMPORT_RECONCILE_INTERVAL must be > 0 when auto-import is enabled")
		}
		if cfg.AutoImportRetentionSuffix != "" && !strings.HasPrefix(cfg.AutoImportRetentionSuffix, "--") {
			return Config{}, fmt.Errorf("SB_AUTO_IMPORT_RETENTION_SUFFIX must start with `--`, got %q", cfg.AutoImportRetentionSuffix)
		}
	}

	if cfg.SnapshotPushEnabled {
		// Reuse the auto-import cluster identity + PAT. This is deliberate:
		// the AOCR registry endpoint accepts the same bearer the hooks API
		// does, so operators don't manage two credentials for the same
		// cluster. Push host falls back to ImageDistributionAOCRHost when
		// MirrorPushHost is unset — both have non-empty defaults so the
		// destination is always resolvable.
		if cfg.AutoImportClusterID == "" {
			return Config{}, errors.New("SB_AUTO_IMPORT_CLUSTER_ID is required when SB_SNAPSHOT_PUSH_ENABLED=true")
		}
		if cfg.AutoImportClusterPATPath == "" {
			return Config{}, errors.New("SB_AUTO_IMPORT_CLUSTER_PAT_PATH is required when SB_SNAPSHOT_PUSH_ENABLED=true")
		}
		if cfg.SnapshotPushReconcileInterval <= 0 {
			return Config{}, errors.New("SB_SNAPSHOT_PUSH_RECONCILE_INTERVAL must be > 0 when snapshot push is enabled")
		}
		if cfg.SnapshotPushMaxInFlight <= 0 {
			return Config{}, errors.New("SB_SNAPSHOT_PUSH_MAX_IN_FLIGHT must be > 0 when snapshot push is enabled")
		}
		if s := cfg.SnapshotPushTagSuffix; s != "" && !snapshotRetentionSuffixPattern.MatchString(s) {
			return Config{}, fmt.Errorf("SB_SNAPSHOT_PUSH_TAG_SUFFIX %q must be a retention suffix like --ttl-1h or --idle-30d", s)
		}
	}

	if cfg.FleetControlPlaneEnabled {
		// The control plane is contract-driven: only the reachability +
		// credential basics are validated locally, mirroring how auto-import
		// requires its hooks URL + cluster identity before it will boot.
		if cfg.FleetControlPlaneEndpoint == "" {
			return Config{}, errors.New("SB_FLEET_ENDPOINT is required when SB_FLEET_ENABLED=true")
		}
		if u, err := url.Parse(cfg.FleetControlPlaneEndpoint); err != nil || u.Scheme == "" || u.Host == "" {
			return Config{}, fmt.Errorf("SB_FLEET_ENDPOINT must be an absolute URL, got %q", cfg.FleetControlPlaneEndpoint)
		}
		if cfg.FleetControlPlaneToken == "" {
			return Config{}, errors.New("SB_FLEET_TOKEN is required when SB_FLEET_ENABLED=true")
		}
		if cfg.FleetControlPlaneContractRefresh <= 0 {
			return Config{}, errors.New("SB_FLEET_CONTRACT_REFRESH must be > 0 when SB_FLEET_ENABLED=true")
		}
	}

	if cfg.ToolboxMountPath == "" || !strings.HasPrefix(cfg.ToolboxMountPath, "/") {
		return Config{}, fmt.Errorf("SB_TOOLBOX_MOUNT_PATH must be an absolute path")
	}
	if cfg.DockerReadinessPollInitial <= 0 {
		return Config{}, errors.New("SB_DOCKER_READINESS_POLL_INITIAL must be > 0")
	}
	if cfg.DockerReadinessPollMax < cfg.DockerReadinessPollInitial {
		return Config{}, errors.New("SB_DOCKER_READINESS_POLL_MAX must be >= SB_DOCKER_READINESS_POLL_INITIAL")
	}

	if cfg.Domain == "" && cfg.PublicHost == "" {
		return Config{}, errors.New("SB_PUBLIC_HOST is required when SB_DOMAIN is empty")
	}

	// SB_CONTAINER_RUNTIME must be one of the runtimes we know how to drive.
	// We reject "" here too: the caller substitutes the host default when a
	// per-sandbox value is empty, but the host default itself must always be
	// explicit. "kata" and "firecracker" are valid identifiers but the host
	// default cannot resolve to a runtime the daemon won't actually drive:
	// we reject those at the env layer so misconfiguration surfaces at boot
	// rather than on every create call. Operators wanting Firecracker keep
	// SB_CONTAINER_RUNTIME=docker as the host default and select Firecracker
	// per-sandbox via the API (see plans/snapshot-clone-fast-boot.md).
	if _, err := models.ValidRuntime(cfg.Runtime); err != nil || cfg.Runtime == "" {
		return Config{}, fmt.Errorf("invalid SB_CONTAINER_RUNTIME=%q (allowed: %s, %s, %s, %s)",
			cfg.Runtime, models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeKata, models.RuntimeFirecracker)
	}
	if cfg.Runtime == models.RuntimeFirecracker {
		return Config{}, fmt.Errorf("SB_CONTAINER_RUNTIME=%q is not allowed as the host default; keep the default at %q and select Firecracker per-sandbox via the API once SB_ENABLE_FIRECRACKER=true",
			cfg.Runtime, models.RuntimeDocker)
	}
	if cfg.Runtime == models.RuntimeWasm {
		return Config{}, fmt.Errorf("SB_CONTAINER_RUNTIME=%q is not allowed as the host default; keep the default at %q and select WASM per-sandbox via the API once SB_ENABLE_WASM=true",
			cfg.Runtime, models.RuntimeDocker)
	}

	resolvedEngine, err := models.ResolveContainerEngine(cfg.ContainerEngine)
	if err != nil {
		return Config{}, fmt.Errorf("invalid SB_CONTAINER_ENGINE: %w", err)
	}
	cfg.ContainerEngine = resolvedEngine
	if cfg.ContainerEngine == models.ContainerEngineContainerd {
		if strings.TrimSpace(cfg.ContainerdSocket) == "" {
			return Config{}, errors.New("SB_CONTAINERD_SOCKET is required when SB_CONTAINER_ENGINE=containerd")
		}
		if strings.TrimSpace(cfg.ContainerdNamespace) == "" {
			return Config{}, errors.New("SB_CONTAINERD_NAMESPACE is required when SB_CONTAINER_ENGINE=containerd")
		}
	}

	// Firecracker host-side wiring is opt-in. The flag exists to gate the
	// driver registration in cmd/sandboxd/main.go; when it's off the
	// service rejects firecracker creates with ErrRuntimeNotImplemented.
	// When it's on, the binaries and the kernel must actually exist so we
	// fail at boot rather than on the first create — same model as
	// EnableSSHGateway. The paths are not stat()-ed here on purpose: the
	// runtime driver's Ping() does that and the daemon surfaces the result
	// via /healthz, which is the right place for operators to look.
	if cfg.EnableFirecracker {
		if cfg.FirecrackerBinary == "" {
			return Config{}, errors.New("SB_FIRECRACKER_BINARY is required when SB_ENABLE_FIRECRACKER=true")
		}
		if cfg.JailerBinary == "" {
			return Config{}, errors.New("SB_JAILER_BINARY is required when SB_ENABLE_FIRECRACKER=true")
		}
		if cfg.FirecrackerKernelImage == "" {
			return Config{}, errors.New("SB_FIRECRACKER_KERNEL is required when SB_ENABLE_FIRECRACKER=true")
		}
		if cfg.FirecrackerRunDir == "" {
			return Config{}, errors.New("SB_FIRECRACKER_RUN_DIR is required when SB_ENABLE_FIRECRACKER=true")
		}
		if cfg.FirecrackerTemplatesDir == "" {
			return Config{}, errors.New("SB_FIRECRACKER_TEMPLATES_DIR is required when SB_ENABLE_FIRECRACKER=true")
		}
		if cfg.UseJailer {
			if cfg.JailerChrootBase == "" {
				return Config{}, errors.New("SB_JAILER_CHROOT_BASE is required when SB_FIRECRACKER_USE_JAILER=true")
			}
			if cfg.JailerUID < 0 || cfg.JailerGID < 0 {
				return Config{}, fmt.Errorf("SB_JAILER_UID/SB_JAILER_GID must be >= 0 (got %d/%d)", cfg.JailerUID, cfg.JailerGID)
			}
		}
		if cfg.FirecrackerTapBaseCIDR == "" {
			return Config{}, errors.New("SB_FIRECRACKER_TAP_BASE_CIDR is required when SB_ENABLE_FIRECRACKER=true")
		}
		if cfg.FirecrackerTapPoolSize <= 0 {
			return Config{}, fmt.Errorf("SB_FIRECRACKER_TAP_POOL_SIZE must be > 0 (got %d)", cfg.FirecrackerTapPoolSize)
		}
		// The OCI rootfs builder requires three subprocess binaries.
		// Paths are validated by pkg/oci.New at construction time so
		// the daemon crashes at boot rather than on first Create — but
		// "empty path" is a config-shape error, not a runtime error;
		// catch it here so the env-var name is in the failure message.
		if cfg.FirecrackerSkopeoBin == "" {
			return Config{}, errors.New("SB_FIRECRACKER_SKOPEO_BIN is required when SB_ENABLE_FIRECRACKER=true")
		}
		if cfg.FirecrackerUmociBin == "" {
			return Config{}, errors.New("SB_FIRECRACKER_UMOCI_BIN is required when SB_ENABLE_FIRECRACKER=true")
		}
		if cfg.FirecrackerMkfs4Bin == "" {
			return Config{}, errors.New("SB_FIRECRACKER_MKFS_BIN is required when SB_ENABLE_FIRECRACKER=true")
		}
	}
	if cfg.EnableWasm {
		if cfg.WasmRunDir == "" {
			return Config{}, errors.New("SB_WASM_RUN_DIR is required when SB_ENABLE_WASM=true")
		}
		if cfg.WasmModulesDir == "" {
			return Config{}, errors.New("SB_WASM_MODULES_DIR is required when SB_ENABLE_WASM=true")
		}
		if cfg.WasmMaxInstances < 0 {
			return Config{}, errors.New("SB_WASM_MAX_INSTANCES must be >= 0")
		}
		if cfg.WasmDefaultMemoryMB < 0 {
			return Config{}, errors.New("SB_WASM_DEFAULT_MEMORY_MB must be >= 0")
		}
		if cfg.WasmCheckpointMaxParallel < 0 {
			return Config{}, errors.New("SB_WASM_CHECKPOINT_MAX_PARALLEL must be >= 0")
		}
		if cfg.WasmPoolDepthDefault < 0 {
			return Config{}, errors.New("SB_WASM_POOL_DEPTH_DEFAULT must be >= 0")
		}
		if cfg.WasmPoolEnabled && cfg.WasmPoolDepthDefault <= 0 {
			return Config{}, errors.New("SB_WASM_POOL_DEPTH_DEFAULT must be > 0 when SB_WASM_POOL_ENABLED=true")
		}
		switch cfg.WasmEngine {
		case "", "wazero", "wasmtime":
		default:
			return Config{}, fmt.Errorf("SB_WASM_ENGINE=%q: want wazero or wasmtime", cfg.WasmEngine)
		}
		if cfg.WasmModuleDigestMode != "once" && cfg.WasmModuleDigestMode != "always" {
			return Config{}, errors.New("SB_WASM_MODULE_DIGEST_MODE must be either once or always")
		}
	}

	// L4 port pool sanity. Out-of-range or inverted bounds would silently
	// brick raw-TCP exposure later; surface it at boot instead.
	if cfg.L4PortRangeStart < 1024 || cfg.L4PortRangeEnd > 65535 || cfg.L4PortRangeStart >= cfg.L4PortRangeEnd {
		return Config{}, fmt.Errorf("invalid SB_L4_PORT_RANGE_START/END (%d-%d): require 1024 <= start < end <= 65535",
			cfg.L4PortRangeStart, cfg.L4PortRangeEnd)
	}

	// If TLS-SNI multiplexing is enabled, the fallback HTTPS address must be
	// set — otherwise non-sandbox SNI (the API itself, the catch-all 404)
	// would land nowhere. An operator who explicitly sets
	// SB_L4_TLS_FALLBACK="" while also setting SB_L4_TLS_LISTEN is
	// misconfigured; surface it at boot.
	if cfg.L4TLSListen != "" && cfg.L4TLSFallback == "" {
		return Config{}, errors.New("SB_L4_TLS_FALLBACK must be set when SB_L4_TLS_LISTEN is set (caddy-l4 needs a target for non-sandbox SNI)")
	}

	// NodeRole defaults to "mixed" and must be one of the known values when
	// set. The role only changes daemon behavior in cluster mode; in
	// single-node mode it stays at "mixed" implicitly (and an explicit
	// non-default value would be a misconfiguration, not a silent override).
	// Hybrid combinations like "worker,ingress" are allowed; parseNodeRoles
	// validates each token and rejects illegal combos.
	parsedRoles, err := parseNodeRoles(cfg.NodeRole)
	if err != nil {
		return Config{}, err
	}
	if len(parsedRoles) == 0 {
		cfg.NodeRole = NodeRoleMixed
	} else {
		cfg.NodeRole = canonicalNodeRole(parsedRoles)
	}
	if cfg.NodeRole != NodeRoleMixed && !cfg.EnableCluster {
		return Config{}, fmt.Errorf("SB_NODE_ROLE=%q requires SB_ENABLE_CLUSTER=true (single-node mode is implicitly %q)", cfg.NodeRole, NodeRoleMixed)
	}

	// Cluster-mode invariants. Single-node mode (EnableCluster=false) skips
	// all of this — defaults are non-load-bearing in that case.
	if cfg.EnableCluster {
		if cfg.RaftDataDir == "" {
			cfg.RaftDataDir = filepath.Join(filepath.Dir(cfg.DBPath), "raft")
		}
		if cfg.RaftAdvertiseAddr == "" {
			cfg.RaftAdvertiseAddr = cfg.RaftBindAddr
		}
		if cfg.GossipAdvertiseAddr == "" {
			cfg.GossipAdvertiseAddr = cfg.GossipBindAddr
		}
		if cfg.SelfAPIAdvertiseURL == "" {
			host, _ := os.Hostname()
			if host == "" {
				host = "127.0.0.1"
			}
			cfg.SelfAPIAdvertiseURL = fmt.Sprintf("http://%s:%d", host, cfg.APIPort)
		}
		if cfg.DataPlaneAdvertiseHost == "" {
			cfg.DataPlaneAdvertiseHost = normalizeAdvertiseHost(cfg.SelfAPIAdvertiseURL)
		}
		if cfg.DataPlaneAdvertiseHost == "" {
			return Config{}, errors.New("SB_DATA_PLANE_ADVERTISE_HOST could not be derived; set it to the host/IP peers use for sandbox ingress")
		}
		if cfg.ClusterMaxAutoVoters < 0 {
			return Config{}, errors.New("SB_CLUSTER_MAX_AUTO_VOTERS must be >= 0")
		}
		if cfg.ClusterCreateMaxPendingPerWorker < 0 {
			return Config{}, errors.New("SB_CLUSTER_CREATE_MAX_PENDING_PER_WORKER must be >= 0")
		}
		if !cfg.ClusterBootstrap && len(cfg.BootstrapPeers) == 0 {
			return Config{}, errors.New("SB_BOOTSTRAP_PEERS is required when SB_ENABLE_CLUSTER=true and SB_CLUSTER_BOOTSTRAP=false")
		}
		// Worker and ingress nodes never seed a fresh Raft cluster — only
		// roles that include "server" (or the "mixed" shorthand) do. Catching
		// this at boot avoids a confusing half-bootstrapped cluster where a
		// non-voter tried to be the first voter. Hybrid combos like
		// "server,worker" pass; "worker,ingress" is rejected here.
		if cfg.ClusterBootstrap && !cfg.IsServer() {
			return Config{}, fmt.Errorf("SB_CLUSTER_BOOTSTRAP=true is incompatible with SB_NODE_ROLE=%q (only roles containing %q, or the %q shorthand, may bootstrap a cluster)", cfg.NodeRole, NodeRoleServer, NodeRoleMixed)
		}
		// Gossip auth gates voter auto-promotion. Without it, any reachable peer
		// can join the raft configuration. Refusing at boot is the safest default
		// — operators who genuinely want plaintext gossip on a fully isolated
		// network can set SB_CLUSTER_INSECURE_GOSSIP=true. The escape hatch is
		// loud (separate variable, must be deliberate) rather than silently
		// permissive.
		if cfg.ClusterGossipSecretKey == "" && !cfg.ClusterInsecureGossip {
			return Config{}, errors.New("SB_GOSSIP_SECRET_KEY is required when SB_ENABLE_CLUSTER=true (set SB_CLUSTER_INSECURE_GOSSIP=true to opt out — only safe on a fully isolated network)")
		}
		// Sealed registry passwords and per-mount credentials replicated via
		// raft are decrypted with this key on the failover owner. If every
		// node lazy-generates its own key (the default in single-node mode),
		// recovered sandboxes silently lose access to private registries and
		// credentialed mounts. Accept either an explicit env var or an
		// already-distributed key file on disk; refuse boot otherwise unless
		// the operator has acknowledged the trade-off via the insecure flag.
		if cfg.CredentialEncryptionKey == "" && !cfg.ClusterInsecureCredentials {
			if _, err := os.Stat(cfg.CredentialEncryptionKeyPath); err != nil {
				if os.IsNotExist(err) {
					return Config{}, fmt.Errorf("SB_CREDENTIAL_ENCRYPTION_KEY is required when SB_ENABLE_CLUSTER=true (or place a shared key at %s; set SB_CLUSTER_INSECURE_CREDENTIALS=true to opt out — sealed registry/mount creds will not survive failover without a shared key)", cfg.CredentialEncryptionKeyPath)
				}
				return Config{}, fmt.Errorf("stat %s: %w", cfg.CredentialEncryptionKeyPath, err)
			}
		}
	}

	if cfg.EnableServerless {
		if strings.TrimSpace(cfg.InternalIngressAddr) == "" {
			return Config{}, errors.New("SB_INTERNAL_INGRESS_ADDR must be set when SB_ENABLE_SERVERLESS=true")
		}
		if err := requireLoopbackAddr("SB_INTERNAL_INGRESS_ADDR", cfg.InternalIngressAddr); err != nil {
			return Config{}, err
		}
		if strings.TrimSpace(cfg.InternalL4WakeAddr) == "" {
			return Config{}, errors.New("SB_INTERNAL_L4_WAKE_ADDR must be set when SB_ENABLE_SERVERLESS=true")
		}
		if err := requireLoopbackAddr("SB_INTERNAL_L4_WAKE_ADDR", cfg.InternalL4WakeAddr); err != nil {
			return Config{}, err
		}
		if strings.TrimSpace(cfg.InternalL4WakeDir) == "" {
			return Config{}, errors.New("SB_INTERNAL_L4_WAKE_DIR must be set when SB_ENABLE_SERVERLESS=true")
		}
		if cfg.L4WakeMaxPendingPerSandbox <= 0 {
			return Config{}, errors.New("SB_L4_WAKE_MAX_PENDING_PER_SANDBOX must be > 0 when SB_ENABLE_SERVERLESS=true")
		}
		if cfg.L4WakeMaxPendingGlobal <= 0 {
			return Config{}, errors.New("SB_L4_WAKE_MAX_PENDING_GLOBAL must be > 0 when SB_ENABLE_SERVERLESS=true")
		}
		if cfg.L4WakeMaxActivePerSandbox <= 0 {
			return Config{}, errors.New("SB_L4_WAKE_MAX_ACTIVE_PER_SANDBOX must be > 0 when SB_ENABLE_SERVERLESS=true")
		}
		if cfg.L4WakeMaxActiveGlobal <= 0 {
			return Config{}, errors.New("SB_L4_WAKE_MAX_ACTIVE_GLOBAL must be > 0 when SB_ENABLE_SERVERLESS=true")
		}
		if cfg.HTTPWakeMaxBuffer <= 0 {
			return Config{}, errors.New("SB_HTTP_WAKE_MAX_BUFFER must be > 0 when SB_ENABLE_SERVERLESS=true")
		}
		if cfg.HTTPWakeMaxPendingPerSandbox <= 0 {
			return Config{}, errors.New("SB_HTTP_WAKE_MAX_PENDING_PER_SANDBOX must be > 0 when SB_ENABLE_SERVERLESS=true")
		}
		if cfg.HTTPWakeMaxPendingGlobal <= 0 {
			return Config{}, errors.New("SB_HTTP_WAKE_MAX_PENDING_GLOBAL must be > 0 when SB_ENABLE_SERVERLESS=true")
		}
		if cfg.HTTPWakeMaxBufferBytesGlobal <= 0 {
			return Config{}, errors.New("SB_HTTP_WAKE_MAX_BUFFER_GLOBAL must be > 0 when SB_ENABLE_SERVERLESS=true")
		}
		if cfg.WakeStartConcurrency <= 0 {
			return Config{}, errors.New("SB_WAKE_START_CONCURRENCY must be > 0 when SB_ENABLE_SERVERLESS=true")
		}
		if cfg.HTTPWakeDirectBypassEnabled || cfg.L4WakeDirectBypassEnabled {
			if cfg.NetstatsPollInterval <= 0 {
				return Config{}, errors.New("SB_NETSTATS_POLL_INTERVAL must be > 0 when direct-route bypass is enabled")
			}
			if cfg.ReconcileInterval <= 0 {
				return Config{}, errors.New("SB_RECONCILE_INTERVAL must be > 0 when direct-route bypass is enabled")
			}
		}
	}

	if cfg.EnableCustomDomains {
		// Custom-domain ingress relies on a wildcard cert under Domain and a
		// distinguishable apex to reject base-domain collisions. Without
		// Domain set, NormalizeCustomDomain can't enforce the "not under base"
		// rule and Caddy can't pick between wildcard vs on-demand TLS.
		if strings.TrimSpace(cfg.Domain) == "" {
			return Config{}, errors.New("SB_DOMAIN must be set when SB_ENABLE_CUSTOM_DOMAINS=true")
		}
		if cfg.CustomDomainsMaxPerSandbox <= 0 {
			return Config{}, errors.New("SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX must be > 0 when SB_ENABLE_CUSTOM_DOMAINS=true")
		}
		if cfg.TLSOnDemandBurst <= 0 {
			return Config{}, errors.New("SB_TLS_ON_DEMAND_BURST must be > 0 when SB_ENABLE_CUSTOM_DOMAINS=true")
		}
		if cfg.TLSOnDemandInterval <= 0 {
			return Config{}, errors.New("SB_TLS_ON_DEMAND_INTERVAL must be > 0 when SB_ENABLE_CUSTOM_DOMAINS=true")
		}
		// Budget bounds: a zero/negative fraction would mean "always refuse"
		// or "never refuse", neither of which is a useful operating mode. A
		// fraction >= 1 disables the safety margin against renewals already
		// in flight and risks hitting LE's hard limit. Capacity and window
		// must be positive or the bucket math divides by zero.
		if cfg.ACMEDaemonBudgetFraction <= 0 || cfg.ACMEDaemonBudgetFraction >= 1 {
			return Config{}, errors.New("SB_ACME_DAEMON_BUDGET_FRACTION must be in (0, 1) when SB_ENABLE_CUSTOM_DOMAINS=true")
		}
		if cfg.ACMEDaemonBudgetCapacity <= 0 {
			return Config{}, errors.New("SB_ACME_DAEMON_BUDGET_CAPACITY must be > 0 when SB_ENABLE_CUSTOM_DOMAINS=true")
		}
		if cfg.ACMEDaemonBudgetWindow <= 0 {
			return Config{}, errors.New("SB_ACME_DAEMON_BUDGET_WINDOW must be > 0 when SB_ENABLE_CUSTOM_DOMAINS=true")
		}
	}

	return cfg, nil
}

func splitAndTrim(s, sep string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (c Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.APIHost, c.APIPort)
}

func (c Config) DomainMode() bool {
	return c.Domain != ""
}

// Roles returns the base-role set this daemon should run. NodeRoleMixed
// expands to [server, worker, ingress]; hybrid comma-separated values
// ("worker,ingress") are split into their constituent base roles. The empty
// string maps to mixed for safety (callers that reach here via the validated
// config never see an empty string, but consumers that build a Config{} by
// hand in tests get the same default Load() applies). The returned slice is
// sorted and deduped.
func (c Config) Roles() []string {
	raw := c.NodeRole
	if strings.TrimSpace(raw) == "" {
		raw = NodeRoleMixed
	}
	roles, err := parseNodeRoles(raw)
	if err != nil || len(roles) == 0 {
		// A Config that didn't go through Load() may carry an invalid string;
		// fall back to "mixed" so the predicates degrade to pre-role behavior
		// rather than silently turning every gate off.
		return []string{NodeRoleServer, NodeRoleWorker, NodeRoleIngress}
	}
	if len(roles) == 1 && roles[0] == NodeRoleMixed {
		return []string{NodeRoleServer, NodeRoleWorker, NodeRoleIngress}
	}
	return roles
}

// hasRole reports whether the expanded role set contains target. Used by the
// IsServer / IsWorker / IsIngress predicates so they share one parsing path
// and treat "mixed", single roles, and hybrid combinations identically.
func (c Config) hasRole(target string) bool {
	return slices.Contains(c.Roles(), target)
}

// IsServer reports whether this daemon should run server-only responsibilities
// (Raft voter promotion, FSM ownership). Mixed nodes and any hybrid that
// includes "server" return true; pure worker, pure ingress, and the
// worker+ingress combo return false.
func (c Config) IsServer() bool { return c.hasRole(NodeRoleServer) }

// IsWorker reports whether this daemon owns sandboxes locally (Docker,
// lifecycle sweep, image GC, reservation replay). Pure ingress/server nodes
// return false; mixed and any hybrid that includes "worker" return true.
func (c Config) IsWorker() bool { return c.hasRole(NodeRoleWorker) }

// IsIngress reports whether this daemon installs owner-aware Caddy routes for
// remote sandboxes. Pure server/worker nodes return false; mixed and any
// hybrid that includes "ingress" return true.
func (c Config) IsIngress() bool { return c.hasRole(NodeRoleIngress) }

// EffectivePublicHost returns the hostname or IP that should appear in
// SDK-facing sandbox URLs. In cluster mode, operators set
// SB_INGRESS_ADVERTISE_HOST to whatever fronts the ingress tier (cloud NLB,
// MetalLB VIP, wildcard DNS, etc.); single-node mode and clusters that
// haven't configured an ingress host fall back to PublicHost, matching the
// pre-cluster behavior.
func (c Config) EffectivePublicHost() string {
	if c.IngressAdvertiseHost != "" {
		return c.IngressAdvertiseHost
	}
	return c.PublicHost
}

func (c Config) IdleTimeout() time.Duration {
	if c.IdleTimeoutMinutes <= 0 {
		return 0
	}
	return time.Duration(c.IdleTimeoutMinutes) * time.Minute
}

// CreateSandboxTimeout is the maximum wall-clock time allowed for a single
// createSandbox call (all runtimes). 0 means no limit. Configured via
// SB_CREATE_TIMEOUT_SEC (default 600s / 10 minutes).
func (c Config) CreateSandboxTimeout() time.Duration {
	if c.CreateSandboxTimeoutSeconds <= 0 {
		return 0
	}
	return time.Duration(c.CreateSandboxTimeoutSeconds) * time.Second
}

// DockerReadySocketEffective is true when push-based readiness is active.
// Cluster hosts enable by default; single-node hosts enable when the docker
// warm pool is on (adoption depends on the held socket).
func (c Config) DockerReadySocketEffective() bool {
	return c.DockerReadySocketEnabled && (c.EnableCluster || c.DockerPoolEnabled)
}

// DockerPoolEffective is true when the warm pool should run.
func (c Config) DockerPoolEffective() bool {
	return c.DockerPoolEnabled && c.DockerReadySocketEnabled
}

// ContainerdPoolEffective is true when the containerd warm pool should run.
func (c Config) ContainerdPoolEffective() bool {
	return c.ContainerEngine == models.ContainerEngineContainerd &&
		c.ContainerdPoolEnabled && c.DockerReadySocketEnabled
}

// DockerReadySocketDir is the host directory for per-create readiness sockets.
func (c Config) DockerReadySocketDir() string {
	base := strings.TrimSpace(c.MountsCredentialsRuntimeDir)
	if base == "" {
		base = "/run/sandboxd"
	}
	return filepath.Join(base, "docker", "ready")
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvFloat(key string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func normalizeHost(value string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://"))
}

// parseImageGCWhitelist splits a comma-separated SB_IMAGE_GC_WHITELIST into
// trimmed entries. Empty / blank entries are dropped so a stray trailing
// comma in the env file doesn't smuggle in an empty string that matches
// every image. Returns a non-nil zero-length slice on empty input so the
// service layer can range over it unconditionally.
func parseImageGCWhitelist(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		if entry := strings.TrimSpace(part); entry != "" {
			out = append(out, entry)
		}
	}
	return out
}

// parseWasmStandardModules parses the comma-separated alias=filename list for
// SB_WASM_STANDARD_MODULES into a reserved-keyword map. Aliases are lowercased
// (case-insensitive lookup). Malformed entries are skipped silently so one
// typo doesn't drop the rest. Returns a non-nil map for unconditional reads.
func parseWasmStandardModules(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		alias, filename, ok := strings.Cut(part, "=")
		alias = strings.ToLower(strings.TrimSpace(alias))
		filename = strings.TrimSpace(filename)
		if !ok || alias == "" || filename == "" {
			continue
		}
		out[alias] = filename
	}
	return out
}

// parseMirrorUpstreams parses the comma-separated host=shortname list for
// SB_MIRROR_UPSTREAMS. Tolerates surrounding whitespace and skips malformed
// entries silently — a typo in one entry shouldn't prevent the others from
// taking effect, and `MirrorConfig.Enabled()` already requires at least one
// valid entry. Empty input returns an empty (non-nil) slice so callers can
// range over it unconditionally.
func parseMirrorUpstreams(raw string) []MirrorUpstreamMapping {
	out := []MirrorUpstreamMapping{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, short, ok := strings.Cut(part, "=")
		host = strings.TrimSpace(host)
		short = strings.TrimSpace(short)
		if !ok || host == "" || short == "" {
			continue
		}
		out = append(out, MirrorUpstreamMapping{Host: host, Shortname: short})
	}
	return out
}

// requireLoopbackAddr rejects internal listen addrs that are not bound to a
// loopback interface. The wake-aware HTTP/L4 ingress proxies carry no auth —
// they trust that Caddy is the only client and assume reachability is limited
// to localhost. An operator who overrides SB_INTERNAL_INGRESS_ADDR /
// SB_INTERNAL_L4_WAKE_ADDR to 0.0.0.0 (or any routable interface) would
// silently publish an unauthenticated endpoint that can wake any sandbox by
// ID. Default values are loopback; this check enforces the field doc.
//
// Accepts: "localhost", any IPv4 127.0.0.0/8 address, "::1". Empty host
// (":21213" form) is treated as wildcard and rejected — be explicit.
func requireLoopbackAddr(envKey, value string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("%s=%q must be host:port: %w", envKey, value, err)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return fmt.Errorf("%s=%q must bind to a loopback interface (got wildcard); use 127.0.0.1 or localhost", envKey, value)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%s=%q host %q must be a loopback IP or \"localhost\"", envKey, value, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%s=%q must bind to a loopback interface (got %s); the wake ingress carries no auth", envKey, value, ip)
	}
	return nil
}

func normalizeAdvertiseHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		return strings.Trim(u.Hostname(), "[]")
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}
	trimmed := strings.Trim(value, "[]")
	if net.ParseIP(trimmed) != nil {
		return trimmed
	}
	if i := strings.LastIndex(value, ":"); i > -1 && !strings.Contains(value[i+1:], "/") && strings.Count(value, ":") == 1 {
		return strings.Trim(value[:i], "[]")
	}
	return trimmed
}
