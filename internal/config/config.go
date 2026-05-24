package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

const defaultToolboxPort = 2280

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
	PATToken            string
	APIHost             string
	APIPort             int
	Domain              string
	PublicHost          string
	CaddyAdminURL       string
	CaddyServerID       string
	DBPath              string
	DockerNetwork       string
	ToolboxBinaryPath   string
	ToolboxMountPath    string
	ToolboxPort         int
	IdleTimeoutMinutes  int
	ContainerPrivileged bool
	ResourceLimitsOff   bool
	// Runtime is the host default container runtime for new sandboxes.
	// Per-sandbox CreateSandboxRequest.Runtime overrides it. Allowed values
	// are "docker" (default), "gvisor", or "kata"; validation lives in Load().
	Runtime            string
	AutoReconcile      bool
	EnableCaddy        bool
	EnableNetworkRules bool
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
	// TLSOnDemandBurst is the Caddy on-demand TLS policy's per-interval
	// burst (matches the JSON shape `rate_limit.burst`). Bounds simultaneous
	// ACME orders Caddy will start before throttling. Default 5; the
	// daemon-wide ACME budget (acme_budget.go) is the second layer.
	TLSOnDemandBurst int
	// TLSOnDemandInterval is the Caddy on-demand TLS policy's refill
	// interval (`rate_limit.interval`). Default 1m.
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
	LogLevel                    string
	ShutdownTimeout             time.Duration
	HTTPClientTimeout           time.Duration
	DockerRuntimeWaitTimeout    time.Duration
	ToolboxWaitTimeout          time.Duration
	ReconcileInterval           time.Duration
	NetstatsPollInterval        time.Duration
	UploadMaxBytes              int64
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
}

// MirrorUpstreamMapping is a single host=shortname pair parsed from
// SB_MIRROR_UPSTREAMS. Kept here (not in pkg/docker) so the config layer
// has no dependency on the docker package — main.go translates to
// docker.MirrorUpstream at wiring time.
type MirrorUpstreamMapping struct {
	Host      string
	Shortname string
}

func Load() (Config, error) {
	exe, _ := os.Executable()
	defaultToolboxPath := filepath.Join(filepath.Dir(exe), "toolboxd")

	cfg := Config{
		PATToken:                         strings.TrimSpace(os.Getenv("SB_PAT_TOKEN")),
		APIHost:                          getEnv("SB_API_HOST", "0.0.0.0"),
		APIPort:                          getEnvInt("SB_API_PORT", 21212),
		Domain:                           normalizeHost(os.Getenv("SB_DOMAIN")),
		PublicHost:                       normalizeHost(getEnv("SB_PUBLIC_HOST", "127.0.0.1")),
		CaddyAdminURL:                    getEnv("SB_CADDY_ADMIN_URL", "http://127.0.0.1:2019"),
		CaddyServerID:                    getEnv("SB_CADDY_SERVER_ID", "srv0"),
		DBPath:                           getEnv("SB_DB_PATH", "/var/lib/sandboxd/state.db"),
		DockerNetwork:                    getEnv("SB_DOCKER_NETWORK", "bridge"),
		ToolboxBinaryPath:                getEnv("SB_TOOLBOX_BINARY_PATH", defaultToolboxPath),
		ToolboxMountPath:                 getEnv("SB_TOOLBOX_MOUNT_PATH", "/usr/local/bin/toolboxd"),
		ToolboxPort:                      getEnvInt("SB_TOOLBOX_PORT", defaultToolboxPort),
		IdleTimeoutMinutes:               getEnvInt("SB_IDLE_TIMEOUT_MIN", 0),
		ContainerPrivileged:              getEnvBool("SB_CONTAINER_PRIVILEGED", false),
		ResourceLimitsOff:                getEnvBool("SB_RESOURCE_LIMITS_DISABLED", false),
		Runtime:                          getEnv("SB_CONTAINER_RUNTIME", models.RuntimeDocker),
		AutoReconcile:                    getEnvBool("SB_AUTO_RECONCILE", true),
		EnableCaddy:                      getEnvBool("SB_ENABLE_CADDY", true),
		EnableNetworkRules:               getEnvBool("SB_ENABLE_NETWORK_RULES", true),
		EnableEventMonitor:               getEnvBool("SB_ENABLE_EVENT_MONITOR", true),
		EnableSSHGateway:                 getEnvBool("SB_ENABLE_SSH_GATEWAY", true),
		EnableServerless:                 getEnvBool("SB_ENABLE_SERVERLESS", true),
		EnableCustomDomains:              getEnvBool("SB_ENABLE_CUSTOM_DOMAINS", false),
		CustomDomainsMaxPerSandbox:       getEnvInt("SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX", models.MaxCustomDomainsPerSandbox),
		TLSOnDemandBurst:                 getEnvInt("SB_TLS_ON_DEMAND_BURST", 5),
		TLSOnDemandInterval:              getEnvDuration("SB_TLS_ON_DEMAND_INTERVAL", time.Minute),
		ACMEDaemonBudgetFraction:         getEnvFloat("SB_ACME_DAEMON_BUDGET_FRACTION", 0.8),
		ACMEDaemonBudgetWindow:           getEnvDuration("SB_ACME_DAEMON_BUDGET_WINDOW", 3*time.Hour),
		ACMEDaemonBudgetCapacity:         getEnvInt("SB_ACME_DAEMON_BUDGET_CAPACITY", 300),
		InternalIngressAddr:              getEnv("SB_INTERNAL_INGRESS_ADDR", "127.0.0.1:21213"),
		InternalL4WakeAddr:               getEnv("SB_INTERNAL_L4_WAKE_ADDR", "127.0.0.1:21214"),
		InternalL4WakeDir:                getEnv("SB_INTERNAL_L4_WAKE_DIR", "/run/sandboxd/l4wake"),
		L4WakeMaxPendingPerSandbox:       getEnvInt("SB_L4_WAKE_MAX_PENDING_PER_SANDBOX", 256),
		L4WakeMaxPendingGlobal:           getEnvInt("SB_L4_WAKE_MAX_PENDING_GLOBAL", 4096),
		L4WakeMaxActivePerSandbox:        getEnvInt("SB_L4_WAKE_MAX_ACTIVE_PER_SANDBOX", 4096),
		L4WakeMaxActiveGlobal:            getEnvInt("SB_L4_WAKE_MAX_ACTIVE_GLOBAL", 65536),
		HTTPWakeMaxBuffer:                int64(getEnvInt("SB_HTTP_WAKE_MAX_BUFFER", 8*1024*1024)),
		HTTPWakeUpstreamReadyTimeout:     getEnvDuration("SB_HTTP_WAKE_UPSTREAM_READY_TIMEOUT", 30*time.Second),
		HTTPWakeMaxPendingPerSandbox:     getEnvInt("SB_HTTP_WAKE_MAX_PENDING_PER_SANDBOX", 256),
		HTTPWakeMaxPendingGlobal:         getEnvInt("SB_HTTP_WAKE_MAX_PENDING_GLOBAL", 4096),
		HTTPWakeMaxBufferBytesGlobal:     int64(getEnvInt("SB_HTTP_WAKE_MAX_BUFFER_GLOBAL", 1024*1024*1024)),
		WakeStartConcurrency:             getEnvInt("SB_WAKE_START_CONCURRENCY", 64),
		HTTPWakeDirectBypassEnabled:      getEnvBool("SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED", false),
		HTTPWakeDirectRouteRetryDuration: getEnvDuration("SB_HTTP_WAKE_DIRECT_ROUTE_RETRY_DURATION", 2*time.Second),
		CaddyCoalesceInterval:            getEnvDuration("SB_CADDY_COALESCE_INTERVAL", 250*time.Millisecond),
		L4WakeDirectBypassEnabled:        getEnvBool("SB_L4_WAKE_DIRECT_BYPASS_ENABLED", false),
		TLSWakeListenerCloseDelay:        getEnvDuration("SB_TLS_WAKE_LISTENER_CLOSE_DELAY", 5*time.Second),
		SSHListenAddr:                    getEnv("SB_SSH_LISTEN_ADDR", "0.0.0.0:2220"),
		SSHHostKeyPath:                   getEnv("SB_SSH_HOST_KEY_PATH", "/var/lib/sandboxd/ssh_host_ed25519_key"),
		CredentialEncryptionKey:          strings.TrimSpace(os.Getenv("SB_CREDENTIAL_ENCRYPTION_KEY")),
		CredentialEncryptionKeyPath:      getEnv("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", "/var/lib/sandboxd/credential_encryption.key"),
		MountsRootPath:                   getEnv("SB_MOUNTS_ROOT", "/var/lib/sandboxd/mounts"),
		MountsCredentialsRuntimeDir:      getEnv("SB_MOUNTS_CRED_DIR", "/run/sandboxd"),
		MountWaitTimeout:                 getEnvDuration("SB_MOUNT_WAIT_TIMEOUT", 30*time.Second),
		LogLevel:                         strings.ToLower(getEnv("SB_LOG_LEVEL", "info")),
		ShutdownTimeout:                  getEnvDuration("SB_SHUTDOWN_TIMEOUT", 10*time.Second),
		HTTPClientTimeout:                getEnvDuration("SB_HTTP_CLIENT_TIMEOUT", 180*time.Second),
		DockerRuntimeWaitTimeout:         getEnvDuration("SB_DOCKER_WAIT_TIMEOUT", 30*time.Second),
		ToolboxWaitTimeout:               getEnvDuration("SB_TOOLBOX_WAIT_TIMEOUT", 30*time.Second),
		ReconcileInterval:                getEnvDuration("SB_RECONCILE_INTERVAL", 5*time.Minute),
		NetstatsPollInterval:             getEnvDuration("SB_NETSTATS_POLL_INTERVAL", 10*time.Second),
		UploadMaxBytes:                   int64(getEnvInt("SB_UPLOAD_MAX_BYTES", 256*1024*1024)),
		OTELMetricsEnabled:               getEnvBool("SB_OTEL_METRICS_ENABLED", false),
		OTELMetricsEndpoint:              firstNonEmpty(os.Getenv("SB_OTEL_METRICS_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")),
		OTELMetricsInterval:              getEnvDuration("SB_OTEL_METRICS_INTERVAL", 30*time.Second),
		OTELTracesEnabled:                getEnvBool("SB_OTEL_TRACES_ENABLED", false),
		OTELTracesEndpoint:               firstNonEmpty(os.Getenv("SB_OTEL_TRACES_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")),
		OTELTracesSampleRatio:            getEnvFloat("SB_OTEL_TRACES_SAMPLE_RATIO", 0.05),
		OTELServiceName:                  getEnv("OTEL_SERVICE_NAME", "sandboxd"),

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
	}

	if cfg.ToolboxMountPath == "" || !strings.HasPrefix(cfg.ToolboxMountPath, "/") {
		return Config{}, fmt.Errorf("SB_TOOLBOX_MOUNT_PATH must be an absolute path")
	}

	if cfg.Domain == "" && cfg.PublicHost == "" {
		return Config{}, errors.New("SB_PUBLIC_HOST is required when SB_DOMAIN is empty")
	}

	// SB_CONTAINER_RUNTIME must be one of the runtimes we know how to drive.
	// We reject "" here too: the caller substitutes the host default when a
	// per-sandbox value is empty, but the host default itself must always be
	// explicit. "kata" is a valid identifier but not implemented yet — we
	// allow it as the host default so operators can pre-stage config, and
	// reject individual create requests until the runtime is wired up.
	if _, err := models.ValidRuntime(cfg.Runtime); err != nil || cfg.Runtime == "" {
		return Config{}, fmt.Errorf("invalid SB_CONTAINER_RUNTIME=%q (allowed: %s, %s, %s)", cfg.Runtime, models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeKata)
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
