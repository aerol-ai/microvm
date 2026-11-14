package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/createpolicy"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/failpoint"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/internal/netsplice"
	"github.com/aerol-ai/microvm/internal/runtime"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/scaleobs"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/internal/usagemetrics"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netstats"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"golang.org/x/crypto/ssh"
)

// allocatorRandomAttempts caps the random-first phase of host-port allocation.
// With a 10k-port pool and a few hundred allocations live, collisions are
// rare; the linear-scan fallback only runs when the pool is genuinely
// near-full, so this keeps p95 low without spinning forever in tight pools.
const allocatorRandomAttempts = 16

// ErrPreferredHostPortUnavailable is returned by exposePort when a TCP replay
// supplied a specific preferredHostPort that's already reserved (cluster-wide
// or on this node) and so cannot be re-bound. The allocator deliberately does
// NOT silently fall through to a fresh random port: cluster-stable TCP
// endpoints are the entire point of B6 — clients addressing host:40123 must
// not be invisibly rerouted to host:55555 after a failover-recreate. Park is
// the policy; the FSM record (with the original HostPort) stays intact and
// the watcher / operator surfaces the parked state instead of mutating the
// contract behind the client's back.
var ErrPreferredHostPortUnavailable = errors.New("preferred host port unavailable on this node; exposure parked")

// ErrPublicTrafficDisabled is returned when a still-private sandbox
// (allow_public_traffic=false) is asked for a custom-domain route. It is NOT
// returned by expose_port — expose is the opt-in lever that flips the
// sandbox public (enableSandboxPublicTraffic); custom domains alone stay
// refused so that attaching a domain never silently publishes a sandbox the
// caller kept private. The sandbox stays reachable through the toolbox proxy
// and SSH gateway.
var ErrPublicTrafficDisabled = errors.New("public traffic is disabled for this sandbox; pass allow_public_traffic=true at create or expose a port to opt in")

// ErrClusterFinalizationUnavailable means local runtime teardown completed but
// the owner+incarnation-fenced placement could not be durably removed. The
// local sandbox row is intentionally retained as a retry/reconcile anchor.
var ErrClusterFinalizationUnavailable = errors.New("cluster placement finalization temporarily unavailable")

const clusterIngressReconcileInterval = 5 * time.Second

// clusterIngressTransientRetryDelay is the first retry delay after a pass
// could not reach Caddy's admin API at all (EOF, refused, reset). It doubles
// on each consecutive such failure, up to clusterIngressReconcileInterval.
// The failed write may or may not have landed and repeating it is safe;
// waiting a full interval left a just-exposed URL unroutable 5s longer.
const clusterIngressTransientRetryDelay = 500 * time.Millisecond

type Service struct {
	cfg    config.Config
	logger *slog.Logger
	store  *store.Store
	// docker holds the dockerd lifecycle driver. The field name stays
	// "docker" because every existing call site is shaped around it;
	// the type is runtime.Runtime so a non-Docker driver can be slotted in
	// without touching service code.
	docker runtime.Runtime
	// containerd holds the native containerd lifecycle driver when
	// SB_CONTAINER_ENGINE=containerd. Nil on docker-only hosts. Existing
	// rows with engine=docker keep routing through s.docker during migration.
	containerd runtime.Runtime
	// firecracker is the second registered runtime (native Firecracker, per
	// plans/snapshot-clone-fast-boot.md). Nil unless main.go has called
	// SetFirecrackerRuntime — which only happens when cfg.EnableFirecracker
	// is true. The CreateSandbox dispatch checks this field for
	// runtime="firecracker" requests; nil here falls back to the
	// "SB_ENABLE_FIRECRACKER required" operator-facing error.
	//
	// Kept as a separate field rather than a runtime-by-name map because
	// (a) we have exactly two runtimes and a map adds indirection without
	// type-system payoff, and (b) the docker field stays the unconditional
	// Default-runtime fast path for the >>99% docker case.
	firecracker runtime.Runtime
	// wasm is the third registered runtime (plans/wasm-runtime.md). Nil
	// unless pkg/daemon has called SetWasmRuntime when cfg.EnableWasm is
	// true.
	wasm runtime.Runtime
	// isolate is the fifth registered runtime — V8 isolates, Workers model
	// (plans/isolate-runtime.md). Nil unless pkg/daemon has called
	// SetIsolateRuntime when cfg.EnableIsolate is true. Host-mediated like
	// wasm: satisfies Runtime only, never ContainerRuntime.
	isolate runtime.Runtime
	// ipv6Fence answers the create gate: whether the node's IPv6 fence
	// covers a runtime's sandboxes (ipv6_fence.go). Nil until pkg/daemon
	// wires it (tests, non-Linux, nodes that own no sandboxes).
	ipv6Fence IPv6Fence
	// isolateBundles is the content-addressed JS/TS bundle store behind
	// POST /v1/js-bundles and the owner-scoped name→digest resolution on an
	// isolate create. Nil unless pkg/daemon wired it (EnableIsolate).
	isolateBundles *jsbundle.Store
	// isolateStaging refcounts content digests staged by an in-flight isolate
	// create but not yet pinned by a persisted store row, so the bundle GC does
	// not reap them mid-create (pinStagingDigest / stagingDigests).
	isolateStagingMu sync.Mutex
	isolateStaging   map[string]int
	// wasmModuleResolver resolves module_ref for POST /v1/wasm-modules.
	wasmModuleResolver WasmModuleResolver
	// wasmWarmPool receives registration-time NoteModule calls so the warm
	// pool pre-compiles a module before its first create. Nil when the pool
	// is disabled — registration then stays a pure catalogue write.
	wasmWarmPool WasmWarmPoolNotifier
	// templateBuilder is the Phase 2 OCI→ext4 builder used by the
	// template lifecycle (internal/service/template.go). Nil unless main
	// has called SetTemplateBuilder — which only happens when
	// cfg.EnableFirecracker is true. CreateTemplate rejects with a
	// not-configured error when this is nil so the handler can return
	// 503 rather than panicking.
	templateBuilder TemplateBuilder
	// templateSnapshotter is the Phase 3 snapshot-capture seam. Nil
	// disables the second build phase: rootfs builds still complete and
	// templates end in status=ready_no_snapshot (cold-boot only). Wired
	// from main.go to an adapter around *firecracker.Driver.
	templateSnapshotter TemplateSnapshotter
	// templateCIDAllocator reserves the per-template host-side AF_VSOCK
	// CID that gets baked into the snapshot.state file at build time and
	// re-used by every clone load. Wired to the same TapPool used for
	// sandbox slot allocation via the "template:" + id synthetic sandbox
	// id (the pool's per-id uniqueness gate gives us idempotent
	// reservation). Nil here also disables the snapshot phase.
	templateCIDAllocator TemplateCIDAllocator
	// events is the engine-agnostic event + PID lookup surface for the
	// daemon event monitor and netstats poller. On docker-only hosts this
	// is the *docker.Client; under containerd it may be a mux across both
	// engines during migration.
	events docker.EventsSource
	// dockerAux is the concrete docker client for APIs that remain dockerd-
	// shaped during containerd migration (built-image GC, live stats). Always
	// set on hosts that run dockerd; nil only in trimmed unit tests.
	dockerAux *docker.Client
	caddy     *caddy.Client
	cipher    *secrets.Cipher
	// imageBuilder compiles Dockerfiles (SetImageBuilder); nil on a daemon
	// without one.
	imageBuilderMu sync.RWMutex
	imageBuilder   ImageBuilder
	// secretProvider owns cluster-secret Put/Open/Delete (ref → plaintext).
	// Lazily built from cipher+store when tests construct &Service{...}
	// without New; mount/registry seal paths still use cipher directly.
	secretProvider secrets.Provider
	// secretWrapBackend replaces the key-store client ConfigureSecretProvider
	// builds (tests inject a fake KMS so no call leaves the process). It is
	// still routed and limited.
	secretWrapBackend secrets.DataKeyWrapper
	// pkcs11Helper is the running PKCS#11 helper client, set by pkg/daemon
	// before ConfigureSecretProvider; nil when no PKCS#11 settings are set.
	pkcs11Helper secrets.DataKeyWrapper
	// keyStoreWrapper is the key-store client the daemon built before it
	// opened the server key (SetKeyStoreWrapper); nil for local, or when a
	// test builds the service directly.
	keyStoreWrapper secrets.DataKeyWrapper
	// keyCustody is the server key's lifecycle under wrapped custody:
	// re-check, revoke, recover (plans/customer-key-custody.md §10).
	keyCustody keyCustodyState
	// secretAudit records every secret decrypt/open (cluster provider,
	// UnsealRegistry, loadMounts). Lazily wired to {Dir(DBPath)}/audit/secrets.jsonl
	// unless tests inject a sink. Writes are async/buffered — never on the
	// StartSandbox / create hot path.
	secretAudit     SecretAuditSink
	secretAuditFile *fileAuditSink // non-nil when the sink is the file writer
	// secretAuditIndex is the per-sandbox read index over secretAuditFile
	// (nil when disabled or storeless); reads fall back to a scan without it.
	secretAuditIndex *secretAuditIndexer
	// secretAuditChainBroken latches a failed full verification (the boot
	// background pass); local audit reads refuse until restart.
	secretAuditChainBroken atomic.Bool
	secretAuditBootVerify  sync.WaitGroup
	secretAuditInitErr     error // retained so daemon boot can fail closed
	secretAuditOnce        sync.Once
	// apiFlood is the api record flood control and its shared-node
	// evaluator (api_audit.go, api_audit_flood.go).
	apiFlood               apiFloodState
	secretAuditPruneStop   chan struct{}
	secretAuditPruneDone   sync.WaitGroup
	auditWitnessMu         sync.Mutex
	auditWitness           controlplane.Witness
	auditWitnessShipMu     sync.Mutex // serializes ship + receipt rewrite
	secretAuditWitnessOnce sync.Once
	secretAuditWitnessStop chan struct{}
	secretAuditWitnessDone sync.WaitGroup
	// witnessBootPending is armed by SetWitness and cleared only when
	// ValidateSecretAuditWitness passes; until then nothing ships to the
	// external witness. witnessValidated is closed at that moment so the
	// ship loop can make its first ship without waiting out an interval.
	// storageObligationReport dedupes this owner's UC-160 reports
	// (storage_obligations.go).
	storageObligationReport storageObligationReporterState
	witnessBootPending      atomic.Bool
	witnessValidatedOnce    sync.Once
	witnessValidated        chan struct{}
	auditIngestMu           sync.Mutex
	auditIngest             *auditIngestServer
	// auditIngestKey caches the resolved capability signing key (see
	// auditIngestSigningKey); guarded by auditIngestMu.
	auditIngestKey string
	// auditLeases answers the per-event egress audit binding check from a
	// short-lived, lifecycle-fenced lease instead of a control-plane read per
	// record. See internal/service/audit_ownership_lease.go.
	auditLeaseOnce sync.Once
	// artifactCatalog tracks, per artifact kind, what the local inventory has
	// reached and what the replicated catalogue has accepted. See
	// artifact_catalog.go.
	artifactCatalog         artifactCatalogState
	auditLeases             *auditOwnershipLeases
	auditIncarnationMu      sync.RWMutex
	pendingAuditIncarnation map[string]string
	// auditIdentityCache memoizes each sandbox's resolved (incarnation,
	// owner_ref). Both are immutable for a lifecycle, and egress audit stamps
	// every event with them — without this, one event per sandbox per second
	// is one control-plane placement read per event on every worker, ahead of
	// the sink's rate limiter. Evicted whenever a lifecycle starts or ends so
	// a recreated deterministic sandbox ID can never inherit the previous
	// lifetime's identity. Guarded by auditIncarnationMu.
	auditIdentityCache map[string]auditIdentity
	auditExportMu      sync.Mutex
	auditExportRunMu   sync.Mutex // serializes cursor/read/export/prune reset
	auditExporter      controlplane.AuditExporter
	// auditBackend is the env-configured connector behind auditExporter (nil
	// when a managed build injected its own exporter or none is configured).
	auditBackend auditexport.Backend
	// auditExportBackoff / auditExportNotBefore pace retries after a failed
	// export; guarded by auditExportRunMu.
	auditExportBackoff    auditexport.Backoff
	auditExportNotBefore  time.Time
	secretAuditExportOnce sync.Once
	secretAuditExportStop chan struct{}
	secretAuditExportDone sync.WaitGroup
	secretRefanoutMu      sync.Mutex
	secretRefanoutRunning bool
	// secretHolderCursor resumes the holder-refresh page. One tick captures at
	// most secretHolderRefreshScan holder keys — the batch placement endpoint
	// refuses more ids than cluster.MaxPlacementPageLimit, and its failure
	// makes the whole tick skip — so a node holding more than that must walk
	// its holders across ticks instead of losing all of them. Guarded by
	// secretHolderCursorMu.
	secretHolderCursorMu sync.Mutex
	secretHolderCursor   string
	// testAuditFetcher overrides peer audit fan-out in tests.
	// templateRebuildWG tracks in-flight snapshot rebuilds so their filesystem
	// work can be joined before the templates directory is torn down.
	templateRebuildWG sync.WaitGroup
	testAuditFetcher  cluster.AuditPeerFetcher
	// nodeRetirements caches the operator storage-destruction attestations
	// consulted by the delete-outbox pass. See node_storage_retirement.go.
	nodeRetirementMu sync.Mutex
	nodeRetirements  *nodeStorageRetirementCache
	mounts           *mounts.Manager
	admitter         *capacity.Admitter
	images           ImageDistributionProvider
	// volumeReclaimer deletes the backing bytes (S3 prefix / NFS dir) of deleted
	// platform volumes. Non-nil only when the daemon wired a backend reclaimer;
	// nil leaves the pending_volume_deletions ledger for an external reconciler.
	volumeReclaimer VolumeReclaimer
	// snapshotPusher + snapshotPushReconciler are non-nil only when
	// cfg.SnapshotPushEnabled is true. The snapshot-create path checks
	// snapshotPusher for nil to decide whether to mark a new row as
	// "pending" vs straight-to-"active", and kicks the reconciler once
	// (best-effort, in a goroutine) so callers don't always wait for the
	// next reconciler tick.
	snapshotPusher         *SnapshotPusher
	snapshotPushReconciler *SnapshotPushReconciler
	// wasmCheckpointPusher uploads durable WASM checkpoints to AOCR (§4.8).
	wasmCheckpointPusher WasmCheckpointStore
	// templateArtifactPusher + templateArtifactPushReconciler are non-nil
	// only when cfg.SnapshotPushEnabled is true AND a templates dir is
	// configured. Mirror the snapshot push wiring: the build success path
	// checks templateArtifactPusher for nil to decide whether to mark a
	// new row as "pending" vs straight-to-"active", and kicks the
	// reconciler once (best-effort, in a goroutine) so callers don't
	// always wait for the next reconciler tick.
	templateArtifactPusher         *TemplateArtifactPusher
	templateArtifactPushReconciler *TemplateArtifactPushReconciler
	// templateArtifactPuller is the consumer-side pair to the pusher
	// (Phase 6 PR 6-B.2). Non-nil iff cmd/sandboxd called
	// AttachTemplateArtifactPuller — in single-node deployments and on
	// nodes without AOCR configured it stays nil, and EnsureTemplateLocal
	// degrades to a fast no-op. The per-template ready latch +
	// single-flight mutex (templateLocalReady) live next to it; same
	// shape as l4Ready/l4Mu but keyed by template ID so concurrent first
	// creates against the same not-yet-local template collapse to one
	// pull.
	templateArtifactPuller *TemplateArtifactPuller
	templateLocalReadyMu   sync.Mutex
	templateLocalReady     map[string]*templateLocalReadyEntry
	// localReadyTemplateIDsCache is the Phase 6 PR-D capacity-heartbeat
	// payload cached for ~5s so the cluster-wide gossip cadence does not
	// hammer SQLite (single-writer; MaxOpenConns=1). Same TTL window the
	// capacity-lease loop uses, so a stale-by-one-tick reading is the
	// worst case. Lazily populated on first Capacity() call.
	localReadyTemplateIDsMu        sync.Mutex
	localReadyTemplateIDsCache     []string
	localTemplateCatalogIDsCache   []string
	localReadyTemplateIDsKnown     bool
	localReadyTemplateIDsExpires   time.Time
	localReadyWasmModuleIDsMu      sync.Mutex
	localReadyWasmModuleIDsCache   []string
	localReadyWasmModuleIDsKnown   bool
	localReadyWasmModuleIDsExpires time.Time
	// slotPools caches LocalSlotPools (slot_pools.go) for the capacity
	// heartbeat, so placement's per-create self refresh does not read SQLite.
	slotPools slotPoolCache
	// Reserved standard-module aliases that actually resolve on this host,
	// computed once: each resolve hashes a staged file up to 256MiB, so it must
	// not run on every 5s inventory refresh (hard rule 2). Staged modules are
	// immutable fleet-wide, so a single probe at first use is authoritative.
	reservedModuleRefsOnce sync.Once
	reservedModuleRefs     []string
	// l4Ready latches true once caddy.EnsureLayer4 has succeeded — either at
	// boot or lazily on the first TCP/TLS expose call. Boot bootstrap is
	// best-effort (caddy may not be reachable yet on a cold start), so the
	// expose path retries under l4Mu when the latch is still false. atomic
	// load gives a lock-free fast path on the steady-state hot path.
	l4Mu       sync.Mutex
	l4Ready    atomic.Bool
	snapshotMu sync.Mutex
	l4WakeMu   sync.Mutex
	l4WakeTCP  net.Listener
	l4WakeTLS  map[string]net.Listener
	// pendingTLSClose holds the in-flight delayed-close timers for TLS
	// wake sockets keyed by (id, port). D2 of warm-direct-route-bypass:
	// on warm→cold (Started → wake-shape PATCH), the listener stays alive
	// for cfg.TLSWakeListenerCloseDelay so a TLS handshake started against
	// the wake-aware route can complete before the socket goes away.
	// ensureTLSWakeListener cancels any pending timer on its key so a
	// rapid cold→warm→cold flip doesn't tear down a socket that the new
	// wake route depends on.
	pendingTLSClose map[string]*time.Timer
	// l4Pending counts L4 connections waiting for wake/target resolution;
	// l4Active counts connections already admitted to proxy bytes. Keeping
	// both lets cold-start bursts shed excess work without blocking
	// unrelated warm traffic accounting. See l4Limiters (lazy) and
	// netsplice.Limiter.
	// routeWriter, when set, replaces s.caddy for every per-sandbox route
	// write (publicRoutes, eng review 4A). nil means the concrete client.
	// Written only through setRouteWriter (routing mode switches at boot,
	// while other goroutines already route).
	routeWriter   publicRouteWriter
	routeWriterMu sync.RWMutex

	l4LimitersOnce sync.Once
	l4Pending      *netsplice.Limiter
	l4Active       *netsplice.Limiter
	// l4ActivityGenerations / l4ActivitySeq are guarded by l4Active's lock
	// (netsplice.Limiter hooks), so a generation changes atomically with the
	// count.
	l4ActivityGenerations map[string]uint64
	l4ActivitySeq         uint64

	// Egress gateway (plans/egress-domain-filtering.md §5.3). egressWired
	// holds the UDS client to the separate egress-gateway process and the
	// sandbox bridge discovery (sandboxd has the docker socket; the gateway
	// does not, S5); nil = feature off, and egressGateway() returns
	// egress.Noop then. It is atomic because in cluster mode the capacity
	// loop already polls EgressGatewayReady when the daemon wires it.
	// egressReady/egressMu are the EnsureLayer4Ready-shaped lazy bootstrap:
	// connect, hand over the bridges, full Sync.
	egressWired atomic.Pointer[egressWiring]
	egressMu    sync.Mutex
	egressReady atomic.Bool
	// egressSyncMu makes a full Sync exclusive against attaches and detaches
	// (shared), and egressInflight carries the attaches the store doesn't
	// show yet into it (review finding 1).
	egressSyncMu   sync.RWMutex
	egressInflight egressInflight
	// egressCreateHolds counts the creates holding an early gateway attach
	// per sandbox, and egressCreateLocks orders an undo's check-and-detach
	// against a duplicate create's attach (egress_early.go).
	egressCreateHolds egressCreateHolds
	egressCreateLocks egressPolicyLocks
	// egressHoldLocks serializes each sandbox's hold record with the
	// enforcement derived from it (egress_blocks.go).
	egressHoldLocks egressPolicyLocks
	// destroyLocks serializes an API destroy with the runtime's destroy
	// event for the same sandbox. Removing the container fires the event
	// while DestroySandbox is still finalizing; unserialized, the event
	// handler raced it through the cluster placement delete and failed on
	// the placement the API path had just removed, once per destroy.
	destroyLocks egressPolicyLocks
	// lifecycleLocks is the lifecycle boundary (lifecycle_boundary.go): one
	// lock per sandbox around every start, stop, pause, resume, destroy,
	// restart on failure, wake, timed stop or delete, die/stop/destroy event,
	// and the read-modify-write of its Lifecycle timers (D7). Without it two
	// facade calls that each read the Lifecycle, patch one field and write the
	// whole struct back race, and an automatic restart already inside the
	// runtime start undoes a stop that succeeded (review 2 finding 9).
	lifecycleLocks keyedLocks[string]
	// programExitRotation and lifecycleRotation keep the lifecycle sweep's
	// exit probes and its stops and deletes fair across passes
	// (sweep_rotation.go; review 2 finding 11).
	programExitRotation sweepRotation
	lifecycleRotation   sweepRotation
	// Restart on failure (restart_on_failure.go): one timer per sandbox
	// waiting to restart, the daemon context they run under, and test seams
	// for the clock and the timer.
	restartMu        sync.Mutex
	restartTimers    map[string]restartTimerEntry
	restartGen       uint64
	restartBase      context.Context
	restartClock     func() time.Time
	restartAfterFunc func(time.Duration, func()) restartTimer
	// programExitHTTP is a test seam for the destroy-after-exit probe of
	// toolboxd's /health (program_exit.go); nil uses the toolbox client.
	programExitHTTP *http.Client
	// egressBlocksPending holds sandboxes whose last gateway block write
	// failed; they are re-applied from the store until one succeeds.
	egressBlocksPending egressBlockPending
	// egressDetachPending holds terminal detaches that failed; the
	// supervisor retries them (egress_gateway.go).
	egressDetachPending egressDetachPending
	// egressAttachSeq numbers successful attaches; egressAttached holds each
	// sandbox's newest, which a terminal detach intent compares against.
	egressAttachSeq atomic.Uint64
	egressAttached  sync.Map
	// egressRuleClears is the working set of the durable ledger of host
	// egress rules sandboxes left at an address (egress_rule_clears.go);
	// egressIPLocks serializes each address's entry. Lock order: policy,
	// then address, then hold.
	egressRuleClears egressRuleClears
	egressIPLocks    egressPolicyLocks
	egressClears     egressClearLog
	// createsInFlight is the sandbox IDs whose create is running, which the
	// reconcile orphan sweep skips (create_inflight.go).
	createsInFlight createsInFlight
	// createLeases holds, per sandbox ID, the one create of it running on
	// this node; a second create of the ID waits for it (create_lease.go).
	createLeases createLeases
	// reconcileUnknown tracks sandboxes whose runtime could not say whether
	// they exist, pass after pass (reconcile_unknown.go).
	reconcileUnknown reconcileUnknownTracker
	// egressApplyIdle is true once a pass found no apply_failed hold left;
	// recording one clears it. Zero (false) at start, so the first pass
	// after a restart reads the store (review 3 finding 8).
	egressApplyIdle atomic.Bool
	// egressRecovering single-flights the table-loss recovery, and
	// egressGaugeBatch/egressGaugeDirty defer the held gauge's refresh to
	// the end of a batch (review finding 12).
	egressRecovering atomic.Bool
	// egressRetainedAt is when the gateway last got the recording
	// inventory (unix nanos).
	egressRetainedAt atomic.Int64
	// egressPids remembers each per-binary sandbox's init pid by container,
	// for the gateway's executable lookups (sandbox id → egressPidEntry).
	egressPids       sync.Map
	egressGaugeBatch atomic.Int32
	egressGaugeDirty atomic.Bool
	// egressCA is the node's TLS inspection CA once loaded or made (P3-1);
	// egressCAMu single-flights its creation, and egressCAPushed records
	// that the connected gateway has it. egressCAPushMu orders the CA's
	// pushes against a revoke's clear at the gateway, and
	// egressCAClearOwed is set while that clear has not reached it.
	egressCA          atomic.Pointer[egress.InspectCA]
	egressCAMu        sync.Mutex
	egressCAPushed    atomic.Bool
	egressCAPushMu    sync.Mutex
	egressCAClearOwed atomic.Bool
	egressSubOnce     sync.Once
	egressStats       egressCounters
	// egressSelfTest is the per-bridge self-test (T41); nil skips it. Atomic
	// for the same reason as egressWired: readiness reads it.
	egressSelfTest atomic.Pointer[egressSelfTest]
	// egressOperatorWatcher holds the private-cloud operator file (§5.10);
	// nil = no file, today's behavior.
	egressOperatorWatcher *operator.Watcher
	// createPolicyWatcher holds the operator's create policy
	// (SB_CREATE_POLICY_FILE); nil = no file, today's behavior.
	createPolicyWatcher *createpolicy.Watcher
	// blockPrivateDefault is SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT's state, set
	// once at boot (egress_private_default.go); nil = off.
	blockPrivateDefault atomic.Pointer[privateDefault]
	// egressControlPushed is the control-port guard list last pushed to the
	// gateway; nil after a full sync, so a restarted gateway gets it again.
	egressControlPushed atomic.Pointer[string]
	// nodeGuard is the node guard's state: what each runtime got, and the
	// per-runtime result the create gate reads (node_guard.go).
	nodeGuard nodeGuardState
	// egressFloor is the host-firewall deny floor's state: the floor each
	// runtime got, and the per-runtime result the create gate reads
	// (egress_floor.go).
	egressFloor egressFloorState
	// egressPolicyLocks serializes live policy updates per sandbox (§5.8).
	egressPolicyLocks egressPolicyLocks
	// egressProfileKick wakes SuperviseEgressProfiles after a profile change
	// (profileKick creates it).
	egressProfileKick     chan struct{}
	egressProfileKickOnce sync.Once
	// egressProfiles stores named egress profiles; nil is the local store
	// (single node). A cluster swaps in its Raft-backed store.
	egressProfiles egressProfileBackend
	// teamQuotas is the single-node team-quota ledger (team_quotas.go). A
	// cluster decides quotas on its Raft leader and never uses it.
	teamQuotas teamQuotaLedger
	// resizeLocks runs one resize of a sandbox at a time, from its read
	// through the runtime change and the store write to the quota settle
	// (ResizeSandbox). Resizes of different sandboxes still run together.
	resizeLocks keyedLocks[string]
	// specLocks serializes this node's read-modify-writes of one sandbox's
	// replicated spec (replicateSpecPatch, commitPolicySpec, a resize's quota
	// write and its undo), so one writer cannot put back a field, such as the
	// size a team is charged for, that another has just changed. A sandbox's
	// mutations run on its owner, so one node's lock covers them.
	specLocks keyedLocks[string]
	// specFloors is, per sandbox, the oldest spec version a read may return
	// after this node's last spec write (writeReplicatedSpec): the lock
	// orders the writes, and this keeps the next one from reading a copy
	// from before the last.
	specFloors specReadFloors
	// identity is the cloud-identity issuer state: signing keys, the lazy
	// bootstrap latch and in-flight token pushes (identity.go).
	identity identityState

	// Warm-pool entries (warm_pools.go). warmPoolStore replaces the backend
	// in tests; nil picks the store or the cluster. warmPoolTargets are this
	// node's pools; the sync loop's cursor and failure state sit beside them
	// under warmPoolMu.
	warmPoolStore       warmPoolBackend
	warmPoolMu          sync.Mutex
	warmPoolTargets     []registeredWarmPool
	warmPoolSyncVersion uint64
	warmPoolSyncBehind  int
	warmPoolSyncFailing bool
	// warmPoolApplied is what the last warm-pool sync applied, so a sync
	// that applies the same again logs nothing.
	warmPoolApplied  string
	warmPoolKick     chan struct{}
	warmPoolKickOnce sync.Once

	// API tokens (api_tokens.go). apiTokenSet is the single-node in-memory
	// index the request path reads; apiTokenMirror is the token copy on a
	// cluster node without Raft state (nil elsewhere). apiTokenEntropy and
	// apiTokenClock are nil in production (crypto/rand, time.Now).
	apiTokenSet     identity.TokenSet
	apiTokenMirror  *identity.TokenMirror
	apiTokenEntropy io.Reader
	apiTokenClock   func() time.Time

	// netstatsReady latches the lazy bootstrap of the per-sandbox network
	// byte-counter poller. Same pattern as l4Ready: atomic fast-path on the
	// hot side, single-flight Mutex on the cold-start side. The poller is
	// kicked off either at daemon boot (best-effort) or on the first request
	// that needs network usage data — whichever happens first.
	netstatsMu       sync.Mutex
	netstatsReady    atomic.Bool
	netstatsPoller   *netstats.Poller
	netstatsLastTick atomic.Int64 // unix nanos; last successful tick for /usage staleness reporting

	// usageReporter ships neutral usage samples toward the managed control
	// plane. nil on the open-source build (set only by the managed daemon via
	// SetUsageReporter), so emitUsage is a no-op there and adds zero work. It is
	// read on background loops (reconcile / event monitor / netstats / live
	// sampler), never on the request hot path.
	//
	// usageCursor tracks, per sandbox, the end of the last reserved-usage window
	// emitted. The reconcile sweep and the lifecycle event edges both advance it,
	// so the two sources tile each sandbox's timeline without gaps or overlaps —
	// a sandbox that starts and dies between heartbeats still gets its tail
	// emitted from the stop edge. In-memory only; lost on restart (the server
	// reconciles via window bounds + idempotent EventIDs).
	usageReporter controlplane.Reporter
	usageMu       sync.Mutex
	usageCursor   map[string]time.Time

	// liveCursor holds, per sandbox, the previous live-sampler observation (its
	// cumulative CPU counter and the time it was read), so the next tick can
	// difference the CPU counter into vcpu-seconds for the window. Separate from
	// usageMu so the opt-in live sampler never contends with the reserved-usage
	// cursor on the reconcile/event paths. nil/empty unless the live sampler runs.
	liveMu     sync.Mutex
	liveCursor map[string]liveSamplePoint

	// usageMeter holds the per-owner usage counters /v1/metrics exports
	// (usage_metrics.go, C20). nil unless SB_USAGE_METRICS_ENABLED, so the
	// row-delete hook is one atomic load when the exporter is off. Separate
	// from usageReporter: it ships nothing anywhere.
	//
	// usageCgroupRoot is the cgroup mount the exporter reads ("" is
	// usagemetrics.DefaultCgroupRoot), and usageDockerStats replaces the
	// Docker stats call (nil is dockerAux.ContainerStats). Both are for tests.
	usageMeter       atomic.Pointer[usagemetrics.Meter]
	usageCgroupRoot  string
	usageDockerStats liveStatFunc

	// fleetAdmitter is the managed create-gate: consulted in createSandbox for
	// owner-scoped (user-token) creates before any capacity is reserved. nil on
	// the open-source build (set only by the managed daemon via
	// SetFleetAdmitter), so the gate is skipped entirely there. Its Admit must be
	// a fast in-memory check — it sits on the create request path.
	fleetAdmitter controlplane.Admitter

	// netstatsActivity is the per-sandbox "last observed network activity"
	// timestamp (unix nanos), populated by the netstats poller sink from
	// non-zero byte deltas and established TCP sockets. The idle sweep uses it
	// as the activity floor under direct-route bypass so warm traffic that
	// never reaches sandboxd (Caddy → container direct) still keeps the sweep
	// from stopping a busy sandbox. RWMutex because the sweep reads more often
	// than the poller writes (default 60s vs 10s). See
	// plans/warm-direct-route-bypass.md C2.
	netstatsActivityMu sync.RWMutex
	netstatsActivity   map[string]int64

	// Poll-failure detection is derived from netstatsLastTick
	// staleness in netstatsPollIsStale; the poller does not expose an
	// error-reporting path to the sink, and absence-of-a-recent-tick
	// is the operationally meaningful signal (whether the cause was
	// docker-stats hiccup, namespace teardown, or anything else).

	// cluster is the cluster.Client used by the API layer for owner lookup
	// and cross-node forwarding. Defaults to a Noop in single-node mode so
	// callsites (and the API wrapper) can stay unconditional.
	cluster      cluster.Client
	clusterMu    sync.Mutex
	clusterReady atomic.Bool
	// ownership is the worker's ownership lease and fence
	// (ownership_lease.go). Zero value: not begun, fences nothing.
	ownership ownershipLease
	// moves holds the sandboxes released for a decommission move (C9,
	// decommission.go); OwnershipFenced folds them in.
	moves moveFences
	// moveTargets names, per sandbox released for a snapshot move, the
	// node that may pull its bundle; movesIn holds sandboxes imported here
	// by one until the placement names this node (snapshot_move.go).
	moveTargets moveTargets
	movesIn     moveFences
	movedRows   checkpointRows
	// ownershipFile writes that lease for the runtime supervisor
	// (ownership_lease_file.go).
	ownershipFile ownershipLeaseFile

	// expectedStops tracks sandboxes whose stop was issued by sandboxd
	// itself (manual API call or lifecycle sweep). The Docker /events
	// stream surfaces every "die"/"stop" the same way regardless of who
	// asked for it, so without this side-channel the event handler cannot
	// tell whether a stop was the operator's intent (no wake) or an
	// involuntary exit (arm wake on serverless sandboxes). Entries are
	// consumed by markSandboxStopped; whatever is left at sweep time is
	// implicitly involuntary (timeout cleanup runs from a janitor).
	expectedStopsMu sync.Mutex
	expectedStops   map[string]expectedStopRecord

	// wakeFlights holds the per-sandbox single-flight + circuit-breaker
	// state used by EnsureSandboxAwakeForHTTP. Same pattern as l4Ready,
	// but per-sandbox: a wave of HTTP requests targeting a sleeping
	// sandbox must collapse to one StartSandbox call, and a cold-start
	// that keeps failing (admission rejected, image fetch fails) must
	// not retry on every request indefinitely. Entries are created
	// lazily on first wake; they live for the daemon lifetime to keep
	// the breaker state stable across the 60s windows the policy uses.
	wakeFlightsMu sync.Mutex
	wakeFlights   map[string]*wakeFlight

	// wakeStartSem caps concurrent wake-driven StartSandbox calls
	// across all sandboxes on this node. Per-sandbox single-flight
	// (wakeFlights) already collapses same-id duplicates; this protects
	// against cross-id storms — without it, the pending caps still admit
	// up to ~8k different sandboxes into their cold-start window at once,
	// and they all hit Docker create / start and Caddy admin in lockstep.
	// Buffered chan; capacity = cfg.WakeStartConcurrency at init. Lazily
	// created via wakeStartSemOnce so test harnesses building &Service{}
	// directly need no rewiring. Operator-initiated StartSandbox (API
	// surface) bypasses this — only the wake helper acquires.
	wakeStartSem     chan struct{}
	wakeStartSemOnce sync.Once

	// warmCache is the short-TTL in-memory cache fronting IsSandboxStarted.
	// Every warm serverless HTTP request currently pays a SQLite read here,
	// and SQLite is single-writer in this process (MaxOpenConns=1), so at
	// 100k QPS those reads serialize through one connection and become the
	// bottleneck. The cache stores (id -> expiresAtUnixNano) for hits that
	// were observed as Started; cold (Stopped/Destroyed/Error) results are
	// NOT cached — only the hot path is optimized, and a cold sandbox
	// always falls through to the source of truth. TTL is intentionally
	// short (2s) so even an entirely missed invalidation self-heals
	// quickly; we still install explicit invalidation hooks on every
	// stop/destroy path to keep the staleness window sub-second under
	// normal conditions. The worst-case failure of a stale-true hit is
	// the proxy connecting to a not-yet-warm upstream and returning
	// 503+Retry-After, which is identical to the cold-start race the
	// readiness probe already handles.
	warmCacheMu sync.RWMutex
	warmCache   map[string]warmEntry
	// warmGen counts invalidateWarm calls. A setter reads it before its
	// row read and stores nothing if it moved, so a row read from before
	// a stop or a port-gate change is never cached after the invalidation
	// that change made (the entry also carries the port gate, A2).
	warmGen atomic.Uint64

	// portLocks serializes expose and unexpose on one sandbox port
	// (lockExposedPort). Entries live only while a call holds or waits.
	portLocks keyedLocks[portLockKey]

	// The locks every writer of one way into a port shares while it reads
	// the port's gate from the store and writes from it, so no writer acts
	// on a copy from before a change to "token" (route_gate.go).
	httpRouteLocks         keyedLocks[portLockKey]
	customDomainRouteLocks keyedLocks[string]
	// rootRouteLocks: every writer of a sandbox's root (toolbox) route and
	// custom-domain routes takes it and reads the ownership fence under it,
	// as applyHTTPPortRoute does with httpRouteLocks, so the last write
	// always matches the fence. Innermost: taken after customDomainRouteLocks.
	rootRouteLocks keyedLocks[string]
	// l4RouteLocks is the same rule for a TCP or TLS exposure's route.
	l4RouteLocks   keyedLocks[portLockKey]
	allowlistLocks keyedLocks[string]
	// testAfterRouteGateRead runs inside those locks, right after the read.
	// Nil in production.
	testAfterRouteGateRead func(stage string)

	// toolboxCalls holds every in-flight network toolbox request by
	// sandbox, so the stop and destroy paths can end them at once instead
	// of leaving them to wait on a sandbox that is gone (toolbox_calls.go).
	toolboxCalls toolboxCallRegistry

	// sandboxOOMs remembers recent oom events, so the die that follows an
	// init's OOM kill is recorded as one (sandbox_oom.go). An oom event is
	// not a stop.
	sandboxOOMs sandboxOOMTracker

	// runStarts holds when each sandbox's current run started, on the
	// engine's clock, so a die or stop event of an earlier run changes
	// nothing (run_starts.go).
	runStarts sandboxRunStarts

	// touchCoalescer debounces last_active_at flushes per sandbox so a
	// burst of HTTP requests (wake-aware ingress proxy, toolbox/session/
	// runtime proxies, SSH gateway) does not become one SQLite UPDATE
	// per request. Without this, a single sandbox at 1000 RPS would
	// queue 1000 UPDATEs/sec behind every other store write — a single
	// hot serverless sandbox could starve the create/start/stop path
	// across the rest of the node. See touch_coalescer.go.
	//
	// Lazily initialized via touchCoalescerOnce so test harnesses that
	// build &Service{...} literals (newCapacityHarness, the cluster
	// fixtures, etc.) don't need updating.
	touchCoalescer     *touchCoalescer
	touchCoalescerOnce sync.Once

	// caddyCoalescer batches Caddy admin writes for the same (id, port)
	// so a rapid wake→stop→wake sequence collapses to one admin call.
	// installHTTPPortRoute routes through Flush so callers still observe
	// synchronous errors, while concurrent callers for the same key
	// coalesce into a single admin write per drain. The periodic Run
	// goroutine (started from cmd/sandboxd/main.go) drains any
	// fire-and-forget Enqueues left over after the daemon idles. Same
	// lazy-init pattern as touchCoalescer so &Service{...} literals in
	// tests still work — see plans/warm-direct-route-bypass.md D6/D12.
	caddyCoalescer        *caddyCoalescer
	caddyCoalescerOnce    sync.Once
	caddyCoalescerStarted atomic.Bool

	// ingressLastHash is the hash of the placement view that the last
	// successful cluster-ingress reconcile installed. The reconciler hashes
	// the next view and skips work when unchanged — this is the cheap idle
	// path that keeps a 10K-placement steady state from hammering Caddy's
	// admin API every 5 seconds. Set to 0 on error so the next tick retries.
	ingressLastHash atomic.Uint64
	// ingressRouteCache is the last route-intent set successfully applied to
	// local Caddy by ReconcileClusterIngress. The reconciler diffs against it
	// so a one-sandbox placement mutation does not rewrite the full shard.
	ingressRouteMu          sync.Mutex
	ingressShardFilterCache cluster.IngressShardFilterCache
	ingressRouteCache       map[string]ingressRouteIntent
	ingressLastFullGCUnix   atomic.Int64
	dnsResolver             DNSResolver

	// probeContainerPortFn is the function used by exposePort to verify a
	// container port is accepting connections before installing the Caddy route.
	// nil falls back to the package-level probeContainerPort. Overridden in
	// tests to avoid real TCP dials against non-routable container IPs.
	probeContainerPortFn func(ctx context.Context, containerIP string, port int) error

	// testSealedMountsOverride, when non-nil, replaces sealedMounts after
	// sealMounts on create paths so PutMounts rollback can be exercised
	// offline without FUSE MountAll. Nil in production.
	testSealedMountsOverride []byte
	// testForcePlatformAttachments, when non-nil, is appended after store.Create
	// so PutAttachments rollback can be forced offline without MountAll.
	// Nil in production.
	testForcePlatformAttachments []models.VolumeAttachment
	// testAfterStoreCreate runs after a successful store.Create on docker/wasm
	// create paths. Tests close the DB here so PutMounts / custom-domain
	// persist failure arms run without a store wrapper. Nil in production.
	testAfterStoreCreate func()
	// testAttachStage, when set, sees each gateway-attach sub-stage's
	// duration (egress_attach_stages.go); the attach benchmark reads the
	// split from it. Nil in production.
	testAttachStage func(stage string, d time.Duration)
	// testAfterCustomDomainsOnCreate runs after persistCustomDomainsOnCreate
	// succeeds on the wasm create path so the subsequent Get/sync failure
	// rollbacks can be forced. Nil in production.
	testAfterCustomDomainsOnCreate func()
	// testAfterHTTPPortInstall runs after installHTTPPortRoute succeeds in
	// exposePort's HTTP path so UpsertPort / recordClusterExposedPort
	// rollback arms can be forced (e.g. by closing the store). Nil in production.
	testAfterHTTPPortInstall func()
	// testAfterRuntimeDestroy runs after rt.Destroy succeeds in DestroySandbox
	// so store.Delete / UnmountAll failure arms can be forced. Nil in production.
	testAfterRuntimeDestroy func()
	// testAfterStoreDeleteOnDestroy runs after a successful store.Delete in
	// DestroySandbox so attachment / wasm-cleanup / cluster-secret failure
	// arms can be forced (e.g. by closing the store). Nil in production.
	testAfterStoreDeleteOnDestroy func()
	// testDuringSandboxRowDelete runs between the pre-delete audit fences and
	// the row removal, which is the window a concurrent audit resolve lands
	// in. See deleteSandboxRowAndFenceAudit.
	testDuringSandboxRowDelete func()
	// testAfterTemplateGCList runs after ListGCEligibleTemplates succeeds in
	// runTemplateGC so IsTemplateReferenced / VMM-ref failure arms can be
	// forced. Nil in production.
	testAfterTemplateGCList func()
	// testAfterTemplateGCSandboxRefCheck runs after IsTemplateReferenced
	// succeeds with referenced=false so the VMM-ref / delete failure arms
	// can be forced by closing the store. Nil in production.
	testAfterTemplateGCSandboxRefCheck func()
	// testAfterTemplateGCVMMRefCheck runs after IsTemplateReferencedByVMM
	// succeeds with referenced=false so DeleteTemplate failure can be forced
	// without skipping via the VMM-check warn arm. Nil in production.
	testAfterTemplateGCVMMRefCheck func()
	// testAfterPendingImageGCList runs after ListPendingImageGCDue succeeds
	// so per-entry HasActiveImageRef / row-clear failure arms can be forced.
	// Nil in production.
	testAfterPendingImageGCList func()
	// testL4ActivityInterval, when >0, overrides l4WakeActivityInterval in
	// touchDuringL4Activity so unit tests don't wait 30s. Zero in production.
	testL4ActivityInterval time.Duration
	// testOriginalDstPort, when set, replaces the SO_ORIGINAL_DST read on
	// REDIRECTed host-port connections (the kernel can't be faked in tests).
	testOriginalDstPort func(net.Conn) (int, error)
	// testAfterLifecycleScopedGet runs after UpdateLifecycle's scopedGet
	// succeeds so store.UpdateLifecycle failure can be forced. Nil in production.
	testAfterLifecycleScopedGet func()
	// testForceUnmountErr, when non-nil, replaces the UnmountAll result in
	// DestroySandbox so the warn arm is reachable offline. Nil in production.
	testForceUnmountErr error
	// testCreateLeaseWait, when >0, replaces createLeaseWait so a test can
	// reach a waiter's ErrCreateInProgress without waiting out the create
	// timeout. Zero in production.
	testCreateLeaseWait time.Duration
	// testBeforeRollbackSweepDestroy runs in reconcileRollbackPending after
	// the pending ids were listed and before each one is acted on, so a test
	// can land a create retry inside that window. Nil in production.
	testBeforeRollbackSweepDestroy func(id string)
	// testSecretPeerPusher overrides cluster secret fan-out in tests. Nil in
	// production (SealAndDistribute type-asserts the live Cluster/Agent).
	testSecretPeerPusher cluster.SecretPeerPusher
	// testBeforeStoreCreateSnapshot runs after normalize/initial push state and
	// before store.CreateSnapshot so conflict / GetSnapshot arms can be forced
	// under the snapshotMu lock. Nil in production.
	testBeforeStoreCreateSnapshot func(*models.SandboxSnapshot)
	// testNormalizeSnapshotErr, when non-nil, is returned from
	// normalizeSnapshotImageDistribution so CreateSnapshotWithOwnership's
	// normalize failure arm is reachable. Nil in production.
	testNormalizeSnapshotErr error
	// testVolumeMeta, when non-nil, replaces volumeMeta() so reclaim / attach
	// failure arms can be forced without a store wrapper. Nil in production.
	testVolumeMeta volumeMetaStore
	// testForceFleetSuspendErr, when non-nil, replaces SetFleetSuspended's
	// result in StopByOwner so the non-NotFound error arm is reachable.
	// Nil in production.
	testForceFleetSuspendErr error
	// testAfterNetstatsUpdate runs in handleNetworkSamples once per sandbox
	// whose counters were applied, before the quota re-read, so the re-read's
	// failure arms can be forced. Nil in production.
	testAfterNetstatsUpdate func()

	// idempotencySweepAt is the unix-nano time the next request_idempotency
	// expiry sweep may run (idempotency_ledger.go). Claims trigger it, so
	// the table is pruned without a dedicated background loop.
	idempotencySweepAt atomic.Int64

	// nodeUpgrades is the single-node upgrade API's state (node_upgrade.go).
	nodeUpgrades nodeUpgradeState
}

func New(cfg config.Config, logger *slog.Logger, db *store.Store, runtimeDriver runtime.Runtime, eventsClient docker.EventsSource, caddyClient *caddy.Client, cipher *secrets.Cipher, mountManager *mounts.Manager, admitter *capacity.Admitter) *Service {
	if db != nil {
		db.SetSecretCipher(cipher)
	}
	s := &Service{
		cfg:      cfg,
		logger:   logger,
		store:    db,
		docker:   runtimeDriver,
		events:   eventsClient,
		caddy:    caddyClient,
		cipher:   cipher,
		mounts:   mountManager,
		admitter: admitter,
		images:   newDefaultImageDistributionProvider(cfg.ImageDistributionAOCRHost),
		// Default to Noop so callers don't have to nil-check the cluster
		// reference. AttachCluster swaps in the real implementation when
		// cluster mode is enabled at boot. EffectivePublicHost() feeds the
		// DNS-helper API (Noop.IngressTargets) — single-node deployments
		// can answer "what should DNS point at" without any extra wiring.
		cluster:     cluster.NewNoop("standalone", "", cfg.EffectivePublicHost()),
		dnsResolver: &DefaultDNSResolver{},
	}
	// Default to local provider when cipher+store are present. Non-local
	// backends (awskms) are wired by ConfigureSecretProvider at daemon boot
	// so AWS client construction / boot canary stay off the New() path used
	// by unit tests.
	if cipher != nil && db != nil && secrets.NormalizeProviderName(cfg.SecretProvider) == secrets.ProviderLocal {
		s.secretProvider = secrets.NewLocalProvider(cipher, newSecretBlobStore(db))
	}
	s.ensureSecretAuditSink()
	s.ensureTouchCoalescer()
	s.ensureCaddyCoalescer()
	return s
}

// ConfigureSecretProvider selects the secrets.Provider from cfg.SecretProvider.
// For an external provider it builds the key-store client behind the per-node
// limiter, runs a wrap/unwrap canary (E4 lite), and fails open unless
// cfg.SecretProviderStrictBoot. Safe to call when the provider is already
// local — it is a no-op refresh for that case.
func (s *Service) ConfigureSecretProvider(ctx context.Context) error {
	if s == nil || s.store == nil {
		return nil
	}
	name := secrets.NormalizeProviderName(s.cfg.SecretProvider)
	ctx = bootContext(ctx)
	wrapper := s.keyStoreWrapper
	switch {
	case wrapper != nil:
	case secrets.IsExternalProvider(name):
		opts := KeyStoreOptions(s.cfg, s.keyStoreNodeID(), s.pkcs11Helper)
		opts.Wrapper = s.secretWrapBackend
		w, err := secrets.NewWrapper(ctx, opts)
		if err != nil {
			return err
		}
		wrapper = w
	default:
		// Still sealing local, maybe with a key store's settings already
		// added: step 1 of the two-step switch (§12, eng D8).
		w, err := secrets.NewOpenWrapper(ctx, KeyStoreOptions(s.cfg, s.keyStoreNodeID(), s.pkcs11Helper))
		if err != nil {
			return err
		}
		wrapper = w
	}
	p, wrapper, err := secrets.NewProvider(ctx, secrets.ProviderOptions{
		Name: name, Cipher: s.cipher, Store: newSecretBlobStore(s.store), Prebuilt: wrapper,
	})
	if err != nil {
		return err
	}
	s.secretProvider = p
	if !secrets.IsExternalProvider(name) || wrapper == nil {
		return nil
	}
	if s.cfg.CredentialKeyCustody == secrets.CustodyWrapped && s.keyStoreWrapper != nil {
		// The daemon unwrapped the server key through this same client at
		// boot: real data already proved the key store (§3 step 5).
		recordSecretProviderCanary(true)
		if s.logger != nil {
			s.logger.Info("secret provider ok: the server key unwrapped through it at boot", "provider", name)
		}
		return nil
	}
	if err := secrets.CanaryWrapUnwrap(ctx, wrapper); err != nil {
		recordSecretProviderCanary(false)
		if s.cfg.SecretProviderStrictBoot {
			return fmt.Errorf("secret provider boot canary failed (SB_SECRET_PROVIDER_STRICT_BOOT=true): %w", err)
		}
		if s.logger != nil {
			s.logger.Warn("secret provider boot canary failed; continuing (set SB_SECRET_PROVIDER_STRICT_BOOT=true to fail closed)",
				"provider", name, "err", err)
		}
		return nil
	}
	recordSecretProviderCanary(true)
	if s.logger != nil {
		s.logger.Info("secret provider boot canary ok", "provider", name)
	}
	return nil
}

// SetPKCS11Helper hands ConfigureSecretProvider the running PKCS#11 helper
// (pkg/daemon starts it: the vendor library never loads into sandboxd).
func (s *Service) SetPKCS11Helper(w secrets.DataKeyWrapper) {
	if s != nil {
		s.pkcs11Helper = w
	}
}

// keyStoreNodeID names this node in the key store's audit log: the cluster
// id when there is one, else the configured node id, else "standalone".
func (s *Service) keyStoreNodeID() string {
	if id := s.selfNodeID(); id != "" {
		return id
	}
	if id := strings.TrimSpace(s.cfg.NodeID); id != "" {
		return id
	}
	return "standalone"
}

// ensureTouchCoalescer is the lazy init path TouchSandbox uses. Direct
// &Service{...} literals in test harnesses skip New(), so the coalescer
// has to come up on first use. The flush closure dereferences s.store
// at call time so harnesses that swap the store after construction
// (e.g. newServerlessHarness) still route through the right writer.
func (s *Service) ensureTouchCoalescer() {
	s.touchCoalescerOnce.Do(func() {
		s.touchCoalescer = newTouchCoalescer(touchDebounceInterval, func(ctx context.Context, id string, at time.Time) error {
			return s.store.Touch(ctx, id, at)
		})
	})
}

// ensureCaddyCoalescer lazily constructs the per-(id,port) Caddy write
// batcher. Same rationale as ensureTouchCoalescer: &Service{...} test
// literals skip New(), so installHTTPPortRoute initializes on demand.
// Tick falls back to the 250ms default when cfg.CaddyCoalesceInterval
// is zero — that covers test harnesses that don't populate cfg.
func (s *Service) ensureCaddyCoalescer() {
	s.caddyCoalescerOnce.Do(func() {
		s.caddyCoalescer = newCaddyCoalescer(s.logger, s.cfg.CaddyCoalesceInterval)
	})
}

// StartCaddyCoalescer starts the periodic-drain goroutine. Called once
// from cmd/sandboxd/main.go after svc.New on worker nodes. Flush-only
// callers (installHTTPPortRoute today) don't strictly need this — Flush
// drives its own drain — but the ticker is the safety net for any
// future Enqueue (fire-and-forget) callsites and for ops that get
// stranded when a Flush caller's ctx cancels mid-drain.
func (s *Service) StartCaddyCoalescer(ctx context.Context) {
	s.ensureCaddyCoalescer()
	if !s.caddyCoalescerStarted.CompareAndSwap(false, true) {
		return
	}
	go s.caddyCoalescer.Run(ctx)
}

// StopCaddyCoalescer drains any pending op and exits the Run goroutine.
// No-op when StartCaddyCoalescer was never called — caddyCoalescer.Stop
// blocks on c.done which is only closed by Run, so calling it without
// a prior Start would hang shutdown.
func (s *Service) StopCaddyCoalescer() {
	if !s.caddyCoalescerStarted.CompareAndSwap(true, false) {
		return
	}
	s.caddyCoalescer.Stop()
}

// AttachCluster swaps in a cluster.Client. Called from cmd/sandboxd/main after
// service.New when SB_ENABLE_CLUSTER=true. Idempotent.
func (s *Service) AttachCluster(c cluster.Client) {
	if c == nil {
		return
	}
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()
	s.cluster = c
}

// ClearClusterForTest drops the attached cluster client so API handlers can
// exercise their "cluster disabled" branches. Production always has at least
// cluster.Noop from New().
func (s *Service) ClearClusterForTest() {
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()
	s.cluster = nil
}

// SetFirecrackerRuntime registers the second runtime driver. Called by
// main.go after construction, only when cfg.EnableFirecracker is true.
// Passing nil clears the registration (used by tests). Once set, the
// CreateSandbox dispatch routes runtime="firecracker" requests through
// this driver instead of returning a "not enabled" error.
//
// Why a setter rather than a New() parameter: the existing service.New
// signature is consumed by ~20 test files, and growing it to carry a
// nil-able second runtime would force a fan-out edit across every one.
// A setter keeps the constructor stable and confines the wire-up to
// main.go where the daemon-config flag actually lives.
func (s *Service) SetFirecrackerRuntime(r runtime.Runtime) {
	s.firecracker = r
}

// SetWasmRuntime registers the WASM driver. Called from pkg/daemon when
// cfg.EnableWasm is true.
func (s *Service) SetWasmRuntime(r runtime.Runtime) {
	s.wasm = r
}

// SetIsolateRuntime registers the V8-isolate driver. Called from pkg/daemon
// when cfg.EnableIsolate is true.
func (s *Service) SetIsolateRuntime(r runtime.Runtime) {
	s.isolate = r
}

// SetContainerdRuntime registers the containerd engine driver. Called from
// pkg/daemon when SB_CONTAINER_ENGINE=containerd.
func (s *Service) SetContainerdRuntime(r runtime.Runtime) {
	s.containerd = r
}

// SetEventsSource wires the daemon event monitor + netstats PID lookup seam.
func (s *Service) SetEventsSource(src docker.EventsSource) {
	s.events = src
}

// SetDockerAuxClient wires docker-only auxiliary APIs (built-image GC, live
// stats) that are not part of the EventsSource seam.
func (s *Service) SetDockerAuxClient(c *docker.Client) {
	s.dockerAux = c
}

// ociEngineForSandbox resolves the container engine (dockerd vs native
// containerd) that owns an OCI-runtime sandbox row. It is terminal: the sole
// caller (runtimeForSandbox) has already peeled off firecracker/wasm, so any
// runtime that reaches here — including an unrecognized value written by a
// newer binary or a hand-edited row — resolves to a concrete engine and never
// calls back into runtimeForSandbox (a recursive fallback here would stack
// overflow the daemon on an unknown runtime; pre-engine-column code was total
// and returned s.docker for everything non-fc/wasm).
func (s *Service) ociEngineForSandbox(sandbox *models.Sandbox) (runtime.Runtime, error) {
	engine := models.SandboxEngine(sandbox)
	if engine == models.ContainerEngineContainerd {
		if s.containerd == nil {
			return nil, fmt.Errorf("sandbox engine %q: %w", engine, models.ErrContainerEngineNotRegistered)
		}
		return s.containerd, nil
	}
	if s.docker == nil {
		return nil, fmt.Errorf("sandbox engine %q: %w", engine, models.ErrContainerEngineNotRegistered)
	}
	return s.docker, nil
}

// imageRemoverForEngine resolves the driver that holds an image copy. An empty
// engine is a ledger row written before the ledger became engine-aware (or by
// a runtime with no engine of its own) and resolves to the host's configured
// engine, which is what those rows always implicitly meant.
func (s *Service) imageRemoverForEngine(engine string) (runtime.Runtime, error) {
	switch strings.TrimSpace(engine) {
	case models.ContainerEngineContainerd:
		if s.containerd == nil {
			return nil, fmt.Errorf("engine %q: %w", engine, models.ErrContainerEngineNotRegistered)
		}
		return s.containerd, nil
	case models.ContainerEngineDocker:
		if s.docker == nil {
			return nil, fmt.Errorf("engine %q: %w", engine, models.ErrContainerEngineNotRegistered)
		}
		return s.docker, nil
	default:
		return s.ociEngineForNewCreate()
	}
}

func (s *Service) ociEngineForNewCreate() (runtime.Runtime, error) {
	if s.cfg.ContainerEngine == models.ContainerEngineContainerd {
		if s.containerd == nil {
			return nil, fmt.Errorf("host engine %q: %w", s.cfg.ContainerEngine, models.ErrContainerEngineNotRegistered)
		}
		return s.containerd, nil
	}
	return s.docker, nil
}

func (s *Service) isFirecrackerSandbox(sandbox *models.Sandbox) bool {
	return sandbox != nil && sandbox.Runtime == models.RuntimeFirecracker
}

func (s *Service) runtimeForSandbox(sandbox *models.Sandbox) (runtime.Runtime, error) {
	if s.isFirecrackerSandbox(sandbox) {
		if s.firecracker == nil {
			return nil, fmt.Errorf("runtime %q: driver not registered: %w",
				models.RuntimeFirecracker, models.ErrRuntimeNotImplemented)
		}
		return s.firecracker, nil
	}
	if s.isWasmSandbox(sandbox) {
		if s.wasm == nil {
			return nil, fmt.Errorf("runtime %q: driver not registered: %w",
				models.RuntimeWasm, models.ErrRuntimeNotImplemented)
		}
		return s.wasm, nil
	}
	if s.isIsolateSandbox(sandbox) {
		if s.isolate == nil {
			return nil, fmt.Errorf("runtime %q: driver not registered: %w",
				models.RuntimeIsolate, models.ErrRuntimeNotImplemented)
		}
		return s.isolate, nil
	}
	return s.ociEngineForSandbox(sandbox)
}

func (s *Service) runtimeRef(sandbox *models.Sandbox) string {
	// Host-mediated runtimes have no container: the sandbox ID is the
	// end-to-end runtime reference.
	if s.isFirecrackerSandbox(sandbox) || s.isWasmSandbox(sandbox) || s.isIsolateSandbox(sandbox) {
		return sandbox.ID
	}
	return sandboxContainerRef(sandbox)
}

func (s *Service) containerRuntimeForSandbox(sandbox *models.Sandbox) (runtime.ContainerRuntime, error) {
	rt, err := s.runtimeForSandbox(sandbox)
	if err != nil {
		return nil, err
	}
	cr, ok := runtime.AsContainerRuntime(rt)
	if !ok {
		return nil, fmt.Errorf("runtime %q does not support container network rules", sandbox.Runtime)
	}
	return cr, nil
}

// runtimeListings holds one reconcile pass's listing from each runtime
// driver on this node.
type runtimeListings struct {
	docker, containerd, firecracker, wasm, isolate map[string]*models.SandboxRuntimeState
}

// forSandbox is the listing a row is checked against: the one from the
// driver that runs its runtime. Every non-OCI runtime is named here. One that
// was not used to fall through to Docker's listing: an isolate row was
// skipped whenever Docker was off or could not be listed, so a gone isolate
// kept its row, its capacity and its routes for good. inDocker reports a
// Docker-engine row, the only listing a pass can fail to read.
func (l runtimeListings) forSandbox(sandbox *models.Sandbox) (listing map[string]*models.SandboxRuntimeState, inDocker bool) {
	switch sandbox.Runtime {
	case models.RuntimeFirecracker:
		return l.firecracker, false
	case models.RuntimeWasm:
		return l.wasm, false
	case models.RuntimeIsolate:
		return l.isolate, false
	}
	if models.SandboxEngine(sandbox) == models.ContainerEngineContainerd {
		return l.containerd, false
	}
	return l.docker, true
}

func mergeManagedRuntimes(maps ...map[string]*models.SandboxRuntimeState) map[string]*models.SandboxRuntimeState {
	total := 0
	for _, m := range maps {
		total += len(m)
	}
	out := make(map[string]*models.SandboxRuntimeState, total)
	for _, m := range maps {
		for id, state := range m {
			out[id] = state
		}
	}
	return out
}

// AttachSnapshotPusher wires in the optional AOCR snapshot-push pipeline.
// pusher must be non-nil to activate the feature; a nil pusher is a no-op
// and leaves the service in legacy local-only snapshot mode. reconciler may
// be nil — when nil, kick-after-create is disabled (useful in tests that
// assert on the initial persisted state before any reconcile runs). Called
// once from main() after cfg.SnapshotPushEnabled validation.
func (s *Service) AttachSnapshotPusher(pusher *SnapshotPusher, reconciler *SnapshotPushReconciler) {
	if pusher == nil {
		return
	}
	s.snapshotPusher = pusher
	s.snapshotPushReconciler = reconciler
	if reconciler != nil {
		// Before the daemon starts the worker (go r.Run), so no race.
		reconciler.onPushed = s.forgetSnapshotLocalOnly
	}
}

// AttachWasmCheckpointPusher wires AOCR push for durable WASM checkpoints.
// Called from main when SnapshotPushEnabled is true.
func (s *Service) AttachWasmCheckpointPusher(pusher WasmCheckpointStore) {
	if pusher == nil {
		return
	}
	s.wasmCheckpointPusher = pusher
}

// SnapshotPushReconciler exposes the reconciler so main.go can drive it
// from a ticker. Returns nil when snapshot push is disabled — the ticker
// wrapper should no-op cleanly in that case.
func (s *Service) SnapshotPushReconciler() *SnapshotPushReconciler {
	return s.snapshotPushReconciler
}

// AttachTemplateArtifactPusher wires in the optional AOCR template push
// pipeline (Phase 6 PR 6-B.1). pusher must be non-nil to activate the
// feature; a nil pusher leaves new template rows in push_state='active'
// forever (the reconciler only picks 'pending'/'error') — backward-
// compatible with single-node deployments and with cfg.EnableCluster=false.
// reconciler may be nil for tests that assert on initial persisted state.
// Called once from main() after cfg.SnapshotPushEnabled validation.
func (s *Service) AttachTemplateArtifactPusher(pusher *TemplateArtifactPusher, reconciler *TemplateArtifactPushReconciler) {
	if pusher == nil {
		return
	}
	s.templateArtifactPusher = pusher
	s.templateArtifactPushReconciler = reconciler
}

// TemplateArtifactPushReconciler exposes the reconciler so main.go can
// drive it from a ticker. Returns nil when template push is disabled.
func (s *Service) TemplateArtifactPushReconciler() *TemplateArtifactPushReconciler {
	return s.templateArtifactPushReconciler
}

// Cluster returns the attached cluster.Client. Always non-nil.
func (s *Service) Cluster() cluster.Client {
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()
	return s.cluster
}

// ClusterEnabled distinguishes a configured cluster from the single-node Noop
// client, which intentionally implements the same interface.
func (s *Service) ClusterEnabled() bool {
	return s != nil && s.cfg.EnableCluster
}

// ClusterTopologyError returns a production-topology violation for the current
// live member set. It is intentionally a runtime check so rolling membership,
// old nodes that still gossip empty roles, and explicit hybrid roles are all
// evaluated from the same source of truth the scheduler uses.
func (s *Service) ClusterTopologyError() error {
	if !s.cfg.EnableCluster {
		return nil
	}
	c := s.Cluster()
	if c == nil {
		return nil
	}
	// Roles and liveness only — no capacity or inventory needed.
	return s.clusterTopologyErrorFor(cluster.IdentityMembers(c))
}

// clusterTopologyErrorFor evaluates the production-topology contract against a
// caller-supplied member snapshot. Extracted so Health() and the reconcile
// loop can run the same shard-aware-ingress check without re-fetching members
// or duplicating the threshold logic.
func (s *Service) clusterTopologyErrorFor(members []cluster.Member) error {
	err := s.evaluateClusterTopology(members)
	if err != nil {
		clusterTopologyOK.Set(0)
	} else {
		clusterTopologyOK.Set(1)
	}
	return err
}

func (s *Service) evaluateClusterTopology(members []cluster.Member) error {
	if err := cluster.LargeClusterTopologyError(members); err != nil {
		return err
	}
	if !s.cfg.ClusterShardAwareIngress {
		ingress := 0
		for _, m := range members {
			if m.Alive && strings.TrimSpace(m.NodeID) != "" && cluster.CanServeIngressRole(m.Role) {
				ingress++
			}
		}
		if ingress > cluster.MaxReplicatedIngressRouteNodes {
			return fmt.Errorf("%w: clusters with more than %d live ingress nodes shard public routes; set SB_CLUSTER_SHARD_AWARE_INGRESS=true only when the upstream router uses /v1/cluster/ingress-route/{id} or an equivalent shard-aware routing path",
				cluster.ErrInvalidTopology, cluster.MaxReplicatedIngressRouteNodes)
		}
	}
	return nil
}

func (s *Service) validateLifecycle(l models.Lifecycle) error {
	if s.anyBypassEnabled() {
		return l.ValidateWithBypassFloor(s.cfg.NetstatsPollInterval, s.cfg.ReconcileInterval)
	}
	return l.Validate()
}

// EnsureClusterReady blocks until the cluster has elected a leader, mirroring
// the EnsureLayer4Ready single-flight latch shape. Single-node mode latches
// immediately. The API wrapper calls this before any RecordPlacement so a
// just-booted node doesn't 503 a CreateSandbox while raft is still catching up.
func (s *Service) EnsureClusterReady(ctx context.Context) error {
	if s.clusterReady.Load() {
		return nil
	}
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()
	if s.clusterReady.Load() {
		return nil
	}
	c := s.cluster
	if c == nil {
		return errors.New("cluster: not initialized")
	}
	// In single-node mode Leader() is always the standalone ID; latch immediately.
	if c.Leader() == "" {
		// One short retry — give raft a beat to elect on cold start.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		if c.Leader() == "" {
			return errors.New("cluster: no leader yet")
		}
	}
	s.clusterReady.Store(true)
	return nil
}

func (s *Service) CreateSandbox(ctx context.Context, req models.CreateSandboxRequest) (*models.CreateSandboxResponse, error) {
	resp, err := s.createSandbox(ctx, req, "")
	s.noteSandboxCreated(ctx, resp)
	return resp, err
}

// noteSandboxCreated tells the API edge's record which sandbox the create
// made (its route has no id), with the lifecycle and owner the record is
// stamped with, so the create record names the sandbox, its creator can be
// found from it, and writing it needs no lookup; and nudges the api
// flood-mode evaluator, since the node may now host a second owner. Both are
// in-memory: a context lookup under a mutex and a non-blocking send.
func (s *Service) noteSandboxCreated(ctx context.Context, resp *models.CreateSandboxResponse) {
	if resp == nil {
		return
	}
	auditlog.NoteSandboxIdentity(ctx, resp.Sandbox.ID, resp.Sandbox.AuditIncarnationID, resp.Sandbox.OwnerRef)
	s.NoteLocalOwnersChanged()
}

// CreateSandboxWithID is the failover-recreate entry point: it behaves like
// CreateSandbox but uses the supplied ID instead of generating a fresh one.
// Idempotent at the cluster boundary — if a sandbox with this ID already
// exists locally we return the existing record without touching docker. Used
// by the cluster owner watcher to re-materialize a sandbox after its previous
// owner died, and by every create that derives its ID (Idempotency-Key, E2B,
// Runloop).
//
// It holds the ID's create lease (create_lease.go) from before it looks for
// the row until the create's rollback has run, so a second create of the ID
// on this node waits for this one and then replays its sandbox, or creates
// afresh when this one failed, instead of running a second create whose
// failure would undo this one's reservation and mounts.
func (s *Service) CreateSandboxWithID(ctx context.Context, req models.CreateSandboxRequest, id string) (*models.CreateSandboxResponse, error) {
	if id == "" {
		return nil, errors.New("CreateSandboxWithID: id required")
	}
	// An Idempotency-Key create replays only the request it was made with
	// (keyed_create.go): a different one is refused here, before anything is
	// created, when a create of the ID is running, and below when the
	// sandbox exists.
	ctx, release, err := s.beginCreateLease(ctx, id, req.CreateRequestDigests)
	if err != nil {
		return nil, err
	}
	defer release()
	if existing, getErr := s.store.Get(ctx, id); getErr == nil && existing != nil {
		// The fast path returns a fully-hydrated row — toolbox token included
		// — so it must never answer a caller that does not own it. A facade
		// deriving the ID from request content (E2B) would otherwise let any
		// tenant reclaim another tenant's ID and be handed its credentials.
		// enforceOwner passes for the owner-watcher / internal recreate path,
		// which carries no Access and legitimately re-materializes any row.
		// It answers before the digest check, so a digest says nothing about
		// another tenant's sandbox.
		if err := enforceOwner(ctx, existing); err != nil {
			return nil, fmt.Errorf("%w: sandbox id is already in use", models.ErrSandboxExists)
		}
		if err := s.checkStoredCreateDigest(ctx, id); err != nil {
			return nil, err
		}
		if !existing.RollbackPending {
			// Already present locally — recreate is a no-op. The watcher tick
			// that noticed the FSM-only entry must have raced with a local
			// create.
			auditlog.NoteSandboxIdentity(ctx, id, existing.AuditIncarnationID, existing.OwnerRef)
			return &models.CreateSandboxResponse{Sandbox: *existing, Replayed: true}, nil
		}
		// A create of this id was reported failed and its rollback has not
		// finished (rollback_pending.go): not a sandbox to hand back. Finish
		// the rollback now, once; then this retry creates afresh below, or
		// answers ErrCreateRollbackPending (503) and reconcile keeps trying.
		if err := s.FinishRollbackPending(ctx, id); err != nil {
			return nil, err
		}
	}
	resp, err := s.createSandbox(ctx, req, id)
	// A failed earlier create of this ID can leave its runtime instance
	// behind (create_leftover.go). Its own rollback has run by now, and the
	// lease is still held: remove the leftover and create once more.
	var leftover *leftoverInstanceError
	if errors.As(err, &leftover) {
		if rmErr := s.removeLeftoverInstance(ctx, id, leftover); rmErr != nil {
			if s.logger != nil {
				s.logger.Warn("create: leftover instance not removed", "sandbox_id", id, "error", rmErr)
			}
		} else {
			resp, err = s.createSandbox(ctx, req, id)
		}
	}
	s.noteSandboxCreated(ctx, resp)
	return resp, err
}

// reconcileStaleOwnership destroys local materializations whose authoritative
// cluster placement no longer points to self. Reads are batched so a worker
// with thousands of local rows makes O(pages), not O(sandboxes), control-plane
// calls. Errors are logged and swallowed; the next reconcile tick retries.
func (s *Service) reconcileStaleOwnership(ctx context.Context) {
	c := s.Cluster()
	if c == nil {
		return
	}
	self := c.SelfNodeID()
	if self == "" {
		return
	}
	known, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("cluster: stale-ownership list failed", "err", err)
		return
	}
	ids := make([]string, 0, len(known))
	for _, sb := range known {
		if sb == nil || sb.ID == "" {
			continue
		}
		ids = append(ids, sb.ID)
	}
	placements := make(map[string]cluster.Placement, len(ids))
	for start := 0; start < len(ids); start += cluster.MaxPlacementPageLimit {
		end := min(start+cluster.MaxPlacementPageLimit, len(ids))
		batch, err := c.AuthoritativePlacementsByIDs(ctx, ids[start:end])
		if err != nil {
			s.logger.Warn("cluster: stale-ownership authoritative read failed", "err", err)
			return
		}
		for id, placement := range batch {
			placements[id] = placement
		}
	}
	for _, sb := range known {
		if sb == nil || sb.ID == "" {
			continue
		}
		placement, ok := placements[sb.ID]
		// A sandbox imported here by a snapshot move still names its
		// source until the leader's swap, moments later (snapshot_move.go).
		if s.movesIn.held(sb.ID, time.Now()) {
			continue
		}
		// No placement can be a fresh local create awaiting ownership replay;
		// an orphan has no replacement owner yet. Neither is proof that this
		// node's runtime is stale. A row with no placement is the ownership
		// replay's to settle (settleUnplacedRow): it destroys a deleted or
		// unproven one after an authoritative read.
		if !ok || placement.IsOrphaned() || strings.TrimSpace(placement.OwnerNodeID) == self {
			continue
		}
		if strings.TrimSpace(placement.IncarnationID) == "" {
			s.logger.Warn("cluster: stale-ownership placement missing lifecycle; refusing local teardown",
				"sandbox_id", sb.ID, "current_owner", placement.OwnerNodeID)
			continue
		}
		s.logger.Warn("cluster: destroying stale local sandbox; ownership reassigned",
			"sandbox_id", sb.ID, "current_owner", placement.OwnerNodeID)
		if err := s.destroyStaleLocalSandbox(ctx, sb, placement); err != nil {
			s.logger.Warn("cluster: stale-destroy failed; will retry next reconcile",
				"sandbox_id", sb.ID, "err", err)
		}
	}
}

// destroyStaleLocalSandbox removes only this node's obsolete materialization.
// The authoritative placement now belongs to another node, so the lifecycle's
// replicated volume attachments, peer secrets, and external WASM checkpoints
// must remain intact for that owner. The local row is removed before runtime
// Destroy so the resulting Docker event cannot enter the normal lifecycle-wide
// destroy finalizer and fan out credential deletion.
func (s *Service) destroyStaleLocalSandbox(ctx context.Context, sandbox *models.Sandbox, placement cluster.Placement) error {
	return s.finalizeStaleLocalSandbox(ctx, sandbox, placement, false)
}

func (s *Service) finalizeStaleLocalSandbox(ctx context.Context, sandbox *models.Sandbox, placement cluster.Placement, runtimeAlreadyGone bool) error {
	if s == nil || sandbox == nil || strings.TrimSpace(sandbox.ID) == "" {
		return nil
	}
	self := ""
	if c := s.Cluster(); c != nil {
		self = strings.TrimSpace(c.SelfNodeID())
	}
	localIncarnation := strings.TrimSpace(sandbox.AuditIncarnationID)
	placementIncarnation := strings.TrimSpace(placement.IncarnationID)
	if placement.SandboxID != sandbox.ID || localIncarnation == "" || placementIncarnation == "" {
		return errors.New("stale local sandbox lifecycle identity is missing")
	}
	if placementIncarnation == localIncarnation && strings.TrimSpace(placement.OwnerNodeID) == self && !placement.IsOrphaned() {
		return nil
	}
	if err := s.retainSandboxAuditACL(ctx, sandbox); err != nil {
		return err
	}
	var rt runtime.Runtime
	if !runtimeAlreadyGone {
		var err error
		rt, err = s.runtimeForSandbox(sandbox)
		if err != nil {
			return err
		}
	}
	for _, port := range sandbox.ExposedPorts {
		_ = s.deleteExposedPortRoute(ctx, sandbox, port)
	}
	_ = s.deleteSandboxPublicRoutes(ctx, sandbox)
	if s.mounts != nil {
		if err := s.mounts.UnmountAll(sandbox.ID); err != nil && s.logger != nil {
			s.logger.Warn("unmount stale local sandbox failed", "sandbox_id", sandbox.ID, "error", err)
		}
	}

	if localIncarnation != placementIncarnation && s.store != nil {
		// This is an ID-reused old local lifecycle, not merely the old owner of
		// the current lifecycle. Tomb its local ciphertext without contacting
		// any peer belonging to either lifecycle.
		if _, err := s.store.DeleteClusterSecretsOriginatorWithOutbox(ctx, sandbox.ID, localIncarnation, nil); err != nil {
			return fmt.Errorf("delete stale-lifecycle local secrets: %w", err)
		}
	}
	if s.isWasmSandbox(sandbox) && s.store != nil {
		// Forget local tracking only. cleanupWasmSandboxArtifacts intentionally
		// deletes external manifests and is therefore lifecycle-wide, not valid
		// for an obsolete owner materialization.
		if err := s.store.DeleteAllWasmStateKV(ctx, sandbox.ID); err != nil {
			return err
		}
		if err := s.store.DeleteAllWasmCheckpointPushes(ctx, sandbox.ID); err != nil {
			return err
		}
	}
	if err := s.deleteSandboxRowAndFenceAudit(ctx, sandbox.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if !runtimeAlreadyGone {
		// The gateway lets go once the workload is gone and before the
		// runtime frees the address (gatewayReleaser).
		if err := rt.Destroy(s.gatewayReleaserCtx(ctx, sandbox, false), sandbox); err != nil {
			// With the row gone, the ordinary orphan-runtime sweep owns retries and
			// cannot mistake this for a lifecycle-wide delete.
			return err
		}
	}
	// This node's copy is gone (the row first, then the runtime): its
	// toolbox requests end; a retry is routed to the owner.
	s.endToolboxCalls(sandbox.ID, toolboxEndMoved, "moved to another node")
	s.forgetWakeFlight(sandbox.ID)
	s.invalidateWarm(sandbox.ID)
	s.forgetNetstatsActivity(sandbox.ID)
	s.runStarts.forget(sandbox.ID)
	if s.admitter != nil {
		s.admitter.Release(sandbox.ID)
	}
	if !s.isWasmSandbox(sandbox) {
		s.schedulePendingImageGC(ctx, models.SandboxEngine(sandbox), sandbox.Image)
	}
	return nil
}

// obsoleteLocalPlacement returns an authoritative proof that sandbox is only
// an obsolete local materialization. Missing placements are not proof: a
// freshly-created local row may still be awaiting ownership replay.
func (s *Service) obsoleteLocalPlacement(ctx context.Context, sandbox *models.Sandbox) (cluster.Placement, bool, error) {
	if s == nil || sandbox == nil || !s.cfg.EnableCluster {
		return cluster.Placement{}, false, nil
	}
	c := s.Cluster()
	if c == nil {
		return cluster.Placement{}, false, fmt.Errorf("%w: placement client unavailable", ErrClusterFinalizationUnavailable)
	}
	placements, err := c.AuthoritativePlacementsByIDs(ctx, []string{sandbox.ID})
	if err != nil {
		return cluster.Placement{}, false, fmt.Errorf("%w: resolve authoritative placement: %v", ErrClusterFinalizationUnavailable, err)
	}
	placement, ok := placements[sandbox.ID]
	if !ok {
		return cluster.Placement{}, false, nil
	}
	localIncarnation := strings.TrimSpace(sandbox.AuditIncarnationID)
	placementIncarnation := strings.TrimSpace(placement.IncarnationID)
	if localIncarnation == "" || placementIncarnation == "" {
		return cluster.Placement{}, false, fmt.Errorf("%w: sandbox or placement incarnation_id is missing", ErrClusterFinalizationUnavailable)
	}
	self := strings.TrimSpace(c.SelfNodeID())
	obsolete := placementIncarnation != localIncarnation || placement.IsOrphaned() || strings.TrimSpace(placement.OwnerNodeID) != self
	return placement, obsolete, nil
}

// placementIncarnation is the lifetime the placement being recreated belongs
// to: what the owner watcher handed over, else the placement itself.
func (s *Service) placementIncarnation(id string, secrets cluster.PlacementSecrets) string {
	if inc := strings.TrimSpace(secrets.IncarnationID); inc != "" {
		return inc
	}
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(id); ok {
			return strings.TrimSpace(p.IncarnationID)
		}
	}
	return ""
}

// RecreateSandbox satisfies cluster.SandboxRecreator. The cluster owner
// watcher invokes this for any FSM placement that points to self. If the
// sandbox already exists locally, we still replay the replicated port intents:
// a previous recreate attempt may have created the container and then failed
// while restoring Caddy/L4 ingress.
//
// secrets is the provider handle that can rehydrate the redacted spec; we
// resolve and re-merge it here via OpenClusterSecretsForNode so the recreated
// container can pull from the same private registry / mount the same external
// storage. Two walls historically blocked cross-node open: the sealed
// cluster_secrets row lived only on the sealing node, and the envelope was
// recipient-bound to that node alone. Recipient-set sealing plus mandatory
// peer fan-out fix both. A decrypt failure is
// fatal to this attempt; ErrRecipientDenied is permanent for this node (the
// owner watcher must not reassign-churn the fleet).
//
// Port replay tries every port but returns an error when any replay failed so
// the owner watcher keeps retrying and can eventually reassign the placement.
// ExposePort is idempotent, so a partial replay is safe to resume.
//
// Only placements whose create spec opted into failover.policy=recreate reach
// this path; default sandboxes remain non-HA and are orphaned on owner death.
//
// It knows no takeover time (the owner watcher calls RecreateSandboxReport),
// so a reused local row keeps its tokens_not_before.
func (s *Service) RecreateSandbox(ctx context.Context, id string, spec models.CreateSandboxRequest, secrets cluster.PlacementSecrets, exposedPorts map[int]cluster.ExposedPortRoute) error {
	_, err := s.RecreateSandboxReport(ctx, id, spec, secrets, exposedPorts, 0)
	return err
}

// RecreateSandboxReport implements cluster.SandboxRecreateReporter. attempted
// is false when a watcher tick finds an already-materialized sandbox and all
// idempotent route replay work is already healthy. This keeps the failover
// recreate counter from becoming a constant five-second polling rate.
//
// ownerSinceUnixNano is the placement's OwnerSinceUnixNano (0: no takeover
// known). A local row this node kept from an earlier ownership is reused,
// not recreated, so it does not get a new row's not-before; its
// tokens_not_before is raised to the takeover instead
// (raiseTokensNotBeforeToTakeover).
func (s *Service) RecreateSandboxReport(ctx context.Context, id string, spec models.CreateSandboxRequest, secrets cluster.PlacementSecrets, exposedPorts map[int]cluster.ExposedPortRoute, ownerSinceUnixNano int64) (bool, error) {
	// The owner watcher calls this for a placement that failed over to us;
	// no request is behind it. A gVisor move's target calls it too, after
	// the swap (C21), and is logged as the move it is.
	moved := movedIdentityFrom(ctx) != nil
	if moved {
		ctx = withAuditSubsystem(ctx, auditSubsystemMove)
	} else {
		ctx = withAuditSubsystem(ctx, auditSubsystemFailover)
	}
	// The replicated spec holds the owner-qualified name key; the local row
	// gets the user's name back (names are unique per owner in the store).
	// A malformed legacy "owner:" name decodes to itself and never fails.
	spec = cluster.DecodeSpecName(spec)
	// Nothing local yet: this call would create the sandbox. Take the id's
	// create lease first, the one a placement-only DELETE also takes
	// (destroy_unmaterialized.go), and confirm under it that the placement
	// the watcher read is still this node's to create: a DELETE may have
	// committed since the watcher's tick began. A materialized sandbox skips
	// this, so a steady-state tick adds no control-plane read.
	if _, err := s.store.Get(ctx, id); errors.Is(err, store.ErrNotFound) {
		var release func()
		var leaseErr error
		ctx, release, leaseErr = s.beginCreateLease(ctx, id, spec.CreateRequestDigests)
		if leaseErr != nil {
			return true, leaseErr
		}
		defer release()
		owned, firstCreated, err := s.failoverRecreateStillOwned(ctx, id, secrets)
		if err != nil {
			return true, err
		}
		if !owned {
			return false, nil
		}
		ctx = contextWithFailoverCreatedAt(ctx, firstCreated)
	}
	if strings.TrimSpace(spec.Runtime) == models.RuntimeWasm && spec.Durability == models.DurabilityDurable {
		nodeID := ""
		if c := s.Cluster(); c != nil {
			nodeID = c.SelfNodeID()
		}
		merged, err := s.OpenClusterSecretsForNode(ctx, id, spec, secrets, nodeID)
		if err != nil {
			return true, fmt.Errorf("recreate %s: %w", id, err)
		}
		attempted, err := s.recreateWasmDurableSandbox(ctx, id, s.placementIncarnation(id, secrets), merged, exposedPorts, ownerSinceUnixNano)
		if err != nil {
			return true, err
		}
		if attempted {
			s.restoreCompatStateAfterRecreate(ctx, id, spec.CompatState)
			s.recordFailoverReason(ctx, id)
			s.logger.Info("cluster: recreated durable wasm sandbox after failover",
				"sandbox_id", id, "replayed_ports", len(exposedPorts))
		}
		return attempted, nil
	}
	if existing, err := s.store.Get(ctx, id); err == nil && existing != nil {
		// First, so a failed replay below cannot leave the revoked tokens
		// working until a later tick.
		if err := s.raiseTokensNotBeforeToTakeover(ctx, existing, ownerSinceUnixNano); err != nil {
			return true, fmt.Errorf("recreate %s: %w", id, err)
		}
		attempted := false
		if s.isWasmSandbox(existing) && existing.Durability == models.DurabilityDurable &&
			existing.Status == models.SandboxStatusPassivated {
			attempted = true
			// Sealed env only: this branch never opened the cluster secret bag,
			// and the replicated spec it was given is the redacted one.
			if err := s.hydrateSandboxEnvForRestore(ctx, existing, nil); err != nil {
				return true, fmt.Errorf("recreate %s: %w", id, err)
			}
			if _, err := s.rehydrateWasmIfNeeded(ctx, existing, nil); err != nil {
				return true, fmt.Errorf("recreate %s: rehydrate wasm: %w", id, err)
			}
		}
		// D1 reconstruction: on owner change, a Serverless && stopped row
		// without wake_armed is the new owner's first chance to install
		// wake routes and arm the bit. Done before port replay so the
		// wake-aware route shape is in place when replayClusterExposedPorts
		// touches HTTP exposures.
		s.ReconstructWakeArmedIfNeeded(ctx, existing)
		if err := s.replayClusterExposedPorts(ctx, id, exposedPorts); err != nil {
			return true, err
		}
		return attempted, nil
	}
	nodeID := ""
	if c := s.Cluster(); c != nil {
		nodeID = c.SelfNodeID()
	}
	merged, err := s.OpenClusterSecretsForNode(ctx, id, spec, secrets, nodeID)
	if err != nil {
		return true, fmt.Errorf("recreate %s: %w", id, err)
	}
	if _, err := s.CreateSandboxWithID(contextWithStoredSpecReplay(ctx), merged, id); err != nil {
		return true, err
	}
	s.restoreCompatStateAfterRecreate(ctx, id, spec.CompatState)
	if moved {
		s.recordMovedIn(ctx, id)
	} else {
		s.recordFailoverReason(ctx, id)
	}
	if err := s.replayClusterExposedPorts(ctx, id, exposedPorts); err != nil {
		return true, err
	}
	msg := "cluster: recreated sandbox after failover"
	if moved {
		msg = "cluster: a sandbox moved here with its memory"
	}
	s.logger.Info(msg, "sandbox_id", id, "replayed_ports", len(exposedPorts))
	return true, nil
}

// rowStillStarted reports whether the stored row still says started.
func (s *Service) rowStillStarted(ctx context.Context, id string) bool {
	cur, err := s.store.Get(ctx, id)
	return err == nil && cur.Status == models.SandboxStatusStarted
}

// recordFailoverReason marks a sandbox the owner watcher just recreated
// here: it is started, but as a fresh copy of its spec, so its programs and
// anything outside a volume did not survive. A separate write after the
// create rather than a field on the create's row, so the ordinary create path
// is unchanged. Best effort: a lost reason costs a hint, not the sandbox.
func (s *Service) recordFailoverReason(ctx context.Context, id string) {
	err := s.store.SetStatusReason(ctx, id, models.StatusReasonFailover, nil)
	if err != nil && s.logger != nil {
		s.logger.Warn("cluster: record failover status reason failed", "sandbox_id", id, "err", err)
	}
	recordSandboxStart(startKindFailover)
	// The recreate is an automatic start the log should show (L3); ctx
	// names system:failover.
	s.beginSystemActionReason(ctx, id, systemActionFailoverRecreated, models.StatusReasonFailover)(nil)
}

// restoreCompatStateAfterRecreate re-materializes the facade compat-state rows a
// failover recreate inherited from the replicated spec (B11). The rows are
// node-local, so the new owner rewrites them from spec.CompatState; a failure
// only means a facade falls back to defaults until the next edit, so it logs
// rather than failing the recreate.
func (s *Service) restoreCompatStateAfterRecreate(ctx context.Context, id string, compat map[string]string) {
	for facade, stateJSON := range compat {
		if err := s.store.UpsertCompatState(ctx, id, facade, stateJSON); err != nil && s.logger != nil {
			s.logger.Warn("cluster: restore facade compat state after recreate failed",
				"sandbox_id", id, "facade", facade, "err", err)
		}
	}
}

func (s *Service) replayClusterExposedPorts(ctx context.Context, id string, exposedPorts map[int]cluster.ExposedPortRoute) error {
	var firstErr error
	for port, route := range exposedPorts {
		if _, err := s.exposePort(ctx, id, port, route.Protocol, route.Visibility, route.HostPort); err != nil {
			s.logger.Warn("cluster: re-expose after recreate failed; owner watcher will retry",
				"sandbox_id", id, "port", port, "protocol", route.Protocol, "host_port", route.HostPort, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("replay exposed port %d: %w", port, err)
			}
		}
	}
	return firstErr
}

const wasmWorkerOverheadMB = 8

func capacityRequestFromCreate(req models.CreateSandboxRequest) capacity.Request {
	out := capacity.Request{
		CPU:        req.CPU,
		MemoryMB:   req.MemoryMB,
		DiskGB:     diskGBForCapacity(req.DiskGB, req.Runtime, req.OverlaySizeGB),
		Runtime:    req.Runtime,
		GPUs:       gpuCountForCapacity(req.GPUs),
		GPUVendor:  gpuVendorForCapacity(req.GPUs),
		TemplateID: req.TemplateID,
		ModuleRef:  models.ModuleRefForCreate(req),
	}
	if req.Runtime == models.RuntimeWasm {
		out.MemoryMB += wasmWorkerOverheadMB
	}
	return out
}

func capacityRequestFromSandbox(sandbox *models.Sandbox) capacity.Request {
	if sandbox == nil {
		return capacity.Request{}
	}
	out := capacity.Request{
		CPU:        sandbox.CPU,
		MemoryMB:   sandbox.MemoryMB,
		DiskGB:     diskGBForCapacity(sandbox.DiskGB, sandbox.Runtime, sandbox.OverlaySizeGB),
		Runtime:    sandbox.Runtime,
		GPUs:       gpuCountForCapacity(sandbox.GPUs),
		GPUVendor:  gpuVendorForCapacity(sandbox.GPUs),
		TemplateID: sandbox.TemplateID,
		ModuleRef:  sandbox.ModuleRef,
	}
	if sandbox.Runtime == models.RuntimeWasm {
		out.MemoryMB += wasmWorkerOverheadMB
	}
	return out
}

func diskGBForCapacity(base int, runtimeName string, overlaySizeGB int) int {
	if runtimeName == models.RuntimeFirecracker && overlaySizeGB > 0 {
		return base + overlaySizeGB
	}
	return base
}

// storedSpecReplayKey marks a context in which createSandbox is replaying a
// spec the cluster already holds (failover recreate) rather than admitting a
// new request. Intake-only rules — ones whose purpose is to keep something out
// of the replicated spec — are downgraded to a warning there: the spec is
// already replicated, and refusing the recreate would only lose the sandbox.
type storedSpecReplayKey struct{}

func contextWithStoredSpecReplay(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, storedSpecReplayKey{}, true)
}

func isStoredSpecReplay(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	replay, _ := ctx.Value(storedSpecReplayKey{}).(bool)
	return replay
}

// failoverCreatedAtKey carries into a failover recreate the time the cluster
// first placed the sandbox, which persistSandboxCreate keeps as the new row's
// created_at.
type failoverCreatedAtKey struct{}

func contextWithFailoverCreatedAt(ctx context.Context, at time.Time) context.Context {
	if at.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, failoverCreatedAtKey{}, at)
}

func failoverCreatedAtFrom(ctx context.Context) time.Time {
	if ctx == nil {
		return time.Time{}
	}
	at, _ := ctx.Value(failoverCreatedAtKey{}).(time.Time)
	return at
}

// validateCreateMounts applies the mount policy to a create request. The
// placement rule (credentials must be in Credentials, never in Source or
// Options, which are replicated in the clear) is enforced on new requests and
// only logged on a stored-spec replay — see storedSpecReplayKey.
func (s *Service) validateCreateMounts(ctx context.Context, mounts []models.MountSpec, sandboxID string) error {
	if len(mounts) > models.MaxMountsPerSandbox {
		return fmt.Errorf("too many mounts: max %d", models.MaxMountsPerSandbox)
	}
	// Raw mounts run host-side as the daemon user, OUTSIDE the microVM
	// isolation boundary: Source, NFS opts and S3 extra_args are passed
	// verbatim into mount commands, and a credential-less network mount uses
	// the host's ambient (instance-role) identity. pr-review.md §5 treats
	// these inputs as trusted only because "PAT holder == host operator". A
	// validated user token is NOT an operator, so for an owner-scoped caller a
	// raw mount is a host attack surface (reach another tenant's export root,
	// borrow the host S3 role, inject mount flags). Until the mount helper is
	// isolated (§5: low-priv user, scoped netns, seccomp) raw mounts stay an
	// operator-only capability; tenants use owner-namespaced platform volumes.
	// Operator/PAT, admin and internal replay/failover callers pass. A runner
	// bound to every team is unscoped but not a host operator, so it is
	// refused like a tenant (hostCapable, eng review D3).
	if !hostCapable(ctx) && len(mounts) > 0 {
		return models.ErrMountOperatorOnly
	}
	for i := range mounts {
		if err := mounts[i].Validate(s.cfg.ToolboxMountPath); err != nil {
			return fmt.Errorf("mount %d: %w", i, err)
		}
		if err := mounts[i].ValidateSecretsPlacement(); err != nil {
			if !isStoredSpecReplay(ctx) {
				return fmt.Errorf("mount %d: %w", i, err)
			}
			if s.logger != nil {
				s.logger.Warn("cluster: recreating a sandbox whose stored mount spec carries a credential outside credentials; it is replicated in the clear — recreate the sandbox with the credential in credentials",
					"sandbox_id", sandboxID, "mount", i, "target", mounts[i].Target, "err", err)
			}
		}
	}
	return validateUniqueMountTargets(mounts)
}

func validateUniqueMountTargets(mounts []models.MountSpec) error {
	seen := make(map[string]int, len(mounts))
	for i, m := range mounts {
		target := strings.TrimSpace(m.Target)
		if target == "" {
			continue
		}
		cleaned := path.Clean(target)
		if prev, ok := seen[cleaned]; ok {
			return fmt.Errorf("duplicate mount target %q at mounts %d and %d", cleaned, prev, i)
		}
		seen[cleaned] = i
	}
	return nil
}

func gpuCountForCapacity(req *models.GPURequest) int {
	if req == nil {
		return 0
	}
	if req.Count <= 0 {
		return 1
	}
	return req.Count
}

func gpuVendorForCapacity(req *models.GPURequest) string {
	if req == nil {
		return ""
	}
	return string(req.Vendor)
}

func (s *Service) createSandbox(ctx context.Context, req models.CreateSandboxRequest, idOverride string) (resp *models.CreateSandboxResponse, err error) {
	// The work before the runtime driver, as back-to-back Server-Timing
	// stages (svc_validate, svc_quota, svc_policy, then on the container
	// path svc_keygen, svc_admit, svc_pre_driver), so none of it is time no
	// stage covers. Boot-path (pr-review §2): a timer read and a RecordStage
	// per mark on a timed create; nil, and free, when nothing times it.
	clock := createtiming.StartClock(ctx)
	// The runtime that serves this create from something already running
	// (a warm pool slot, a parked container) marks it warm (O1).
	ctx, warm := scaleobs.WithWarmStart(ctx)
	done := beginSandboxCreateMetric(warm)
	defer func() { done(err) }()
	// A caller-supplied id (CreateSandboxWithID / the X-Cluster-Create-ID
	// forward header) becomes a host path component in the mount manager and the
	// per-sandbox state dirs, so it must be delimiter-safe before any runtime
	// dispatch. An empty id is generated downstream and is always safe. This is
	// a pure in-memory check: no effect on boot latency or the generated-id path.
	if idOverride != "" {
		if err := models.ValidateSandboxID(idOverride); err != nil {
			return nil, err
		}
		// Every per-ID side effect below (admission, mounts, the runtime's
		// names, routes, rows) assumes it is the only create of this ID:
		// hold the ID's create lease (create_lease.go) before the first of
		// them and until the last rollback has run. CreateSandboxWithID
		// already holds it, so this take joins it; it is here so no caller
		// can reach the side effects without it. A generated ID cannot
		// collide and needs no lease.
		var release func()
		ctx, release, err = s.beginCreateLease(ctx, idOverride, req.CreateRequestDigests)
		if err != nil {
			return nil, err
		}
		defer release()
	}
	// Bound the entire create operation so a stalled image pull or a slow
	// registry cannot block a goroutine forever. 0 disables the guard.
	if t := s.cfg.CreateSandboxTimeout(); t > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	// Rollback is detached from the createSandbox timeout so that rollback
	// calls (docker.Destroy, caddy.DeleteSandboxRoute) are not immediately
	// cancelled when the timeout fires mid-operation. Without this, orphaned
	// containers are left running with no store row when the timeout fires
	// after docker.Create has returned but before the store row is written.
	// Its budget starts when a rollback begins — see rollbackBudget.
	var rollback rollbackBudget
	defer rollback.Release()
	if err := s.ClusterTopologyError(); err != nil {
		return nil, err
	}
	if s.cfg.EnableCluster && !s.cfg.IsWorker() {
		return nil, cluster.ErrNoPlacementTarget
	}

	memoryWasOmitted := req.MemoryMB <= 0
	req = normalizeCreateRequest(req)
	if err := s.NormalizeCreateImageDistribution(ctx, &req); err != nil {
		return nil, err
	}
	// An owner-scoped (validated user-token) caller must not be able to start
	// another tenant's private image just because it is already in the shared
	// local image cache: tell the runtime to authorize the image against its
	// registry even on a cache hit. Operator/PAT and internal/failover callers
	// are unscoped and keep the fast cache-trusting path.
	if _, scoped := ownerScope(ctx); scoped {
		req.VerifyRegistryAccess = true
	}
	if err := NormalizeCreateFailover(&req); err != nil {
		return nil, err
	}
	// Private-by-default: a create that doesn't opt in with
	// allow_public_traffic=true gets no public ingress route (and ExposePort
	// refuses). Normalize to explicit false so persisted and replicated state
	// remains unambiguous. This applies equally to failover recreation.
	if req.AllowPublicTraffic == nil {
		private := false
		req.AllowPublicTraffic = &private
	}
	if req.Image == "" && strings.TrimSpace(req.ModuleRef) == "" {
		return nil, errors.New("image is required")
	}
	// Name rules are intake-only: a failover recreate replays whatever name
	// the replicated spec holds, including legacy names that predate them.
	if !isStoredSpecReplay(ctx) {
		if err := models.ValidateSandboxName(req.Name); err != nil {
			return nil, err
		}
	}
	// Placement rule (plans/placement-rules.md): this node refuses a create
	// its own labels do not satisfy. In single-node mode that is the whole
	// check (P1.6); in a cluster the router already filtered, and this
	// catches a router on an older build or labels changed by a restart. An
	// in-memory map compare, so no boot-path cost.
	if err := s.checkPlacementRule(&req); err != nil {
		return nil, err
	}
	clock.Mark("svc_validate")

	// Owner attribution: a validated user token stamps its account onto the
	// new sandbox; operator/PAT and internal creates are owner-less (""). The
	// value is resolved once here and applied to whichever runtime path builds
	// the row below. The account mapping is refreshed here (one write per
	// create, not per request) so the auth hot path stays write-free; it is
	// best-effort because attribution on the sandbox row is the source of
	// truth, and a noop store/owner-less create has nothing to record.
	ownerRef := s.ownerRefForCreateOrRecreate(ctx, idOverride)
	if ownerRef != "" {
		access, _ := controlplane.AccessFromContext(ctx)
		if err := s.store.UpsertAccountMapping(ctx, ownerRef, access.Identity.ExternalID); err != nil {
			s.logger.Warn("fleet: account mapping upsert failed; attribution still on the sandbox row",
				"owner_ref", ownerRef, "error", err)
		}
		// Fleet create-gate. Owner-scoped creates consult the managed admitter
		// before any capacity is reserved or Docker/Firecracker is touched, so a
		// refused create costs nothing. Placed ahead of the runtime branch below
		// so both the Docker and Firecracker paths are gated by the one check.
		// Operator/PAT and internal creates (ownerRef == "") skip the gate — the
		// open-source admitter admits everything anyway. The error is returned
		// verbatim so apihttp maps ErrAdmissionDenied→403 and
		// ErrAdmissionUnavailable→503.
		if s.fleetAdmitter != nil {
			if err := s.fleetAdmitter.Admit(ctx, ownerRef); err != nil {
				return nil, err
			}
		}
	}
	// Team quota (plan item P2): one node claims room in the team's quota
	// here, in memory and under one lock, so two creates for the last slot
	// cannot both pass; a failed create gives the claim back. A cluster's
	// leader decided this at reservation time instead (team_quotas.go).
	quotaTicket, err := s.admitTeamQuotaCreate(ctx, ownerRef, req)
	if err != nil {
		return nil, err
	}
	defer func() { quotaTicket.settle(resp, err) }()
	clock.Mark("svc_quota")
	// Custom-domain validation runs early so an invalid or unsupported
	// payload fails before admission/mounts/docker.Create burn resources.
	// On success req.CustomDomains is rewritten with the canonical slice.
	if err := s.validateCreateCustomDomains(&req); err != nil {
		return nil, err
	}
	// Named egress profiles (D21): validate the inline lists, then expand
	// the references so the operator's ceiling and everything after it see
	// the effective allow list. The replicated spec, built by the caller from
	// its own copy of req, keeps the references.
	// Learn mode (P2-7) rides the same side state as the references.
	// The operator default goes first: its org profiles are references too.
	// The cluster create paths already applied it to the spec they promote.
	if !isStoredSpecReplay(ctx) {
		s.NormalizeCreateEgressDefault(&req)
	}
	if len(req.EgressProfiles) > 0 || req.NetworkEgressMode != "" || len(req.NetworkEgressRules) > 0 || len(req.EgressWithheldEnv) > 0 {
		if _, cerr := compileCreateEgress(&req); cerr != nil {
			return nil, cerr
		}
		// An inject rule's key must be in the env the sandbox is created
		// with (P3-2).
		if ierr := requireInjectKeys(req.Env, injectKeys(req.NetworkEgressRules)); ierr != nil {
			return nil, ierr
		}
		if !isStoredSpecReplay(ctx) {
			if rerr := s.refuseDisabledBuiltins(req.EgressProfiles); rerr != nil {
				return nil, rerr
			}
		}
		// rerr, not err: the deferred record must see and set the named
		// result, or a failed record would undo the create and still
		// report success.
		resolved, held, rerr := s.resolveCreateEgress(ctx, ownerRef, &req)
		if rerr != nil {
			return nil, rerr
		}
		if mode, rules, withheld := req.NetworkEgressMode, req.NetworkEgressRules, withheldKeys(&req); len(resolved.Refs) > 0 || mode != "" || len(rules) > 0 || len(withheld) > 0 {
			defer func() {
				if err == nil && resp != nil {
					err = s.recordCreateEgressState(ctx, &resp.Sandbox, resolved, mode, rules, withheld, held)
				}
			}()
		}
	}
	// Operator default policy and ceiling (§5.10 PC-2): in memory, before
	// any runtime is chosen, so native and facade creates of every runtime
	// get the same answer and the stored spec carries the result.
	if err := s.applyEgressOperatorPolicy(&req, isStoredSpecReplay(ctx)); err != nil {
		return nil, err
	}

	// Validate the requested runtime and resolve "" to the host default. We
	// write the resolved value back into req so the runtime layer sees an
	// explicit choice and the persisted sandbox row records what was actually
	// used — empty stays empty only on pre-migration rows.
	chosenRuntime, err := models.ValidRuntime(req.Runtime)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.TemplateID) != "" {
		req.TemplateID = strings.TrimSpace(req.TemplateID)
		if chosenRuntime != "" && chosenRuntime != models.RuntimeFirecracker {
			return nil, fmt.Errorf("template_id requires runtime %q (got %q)",
				models.RuntimeFirecracker, chosenRuntime)
		}
		chosenRuntime = models.RuntimeFirecracker
	}
	if chosenRuntime == "" {
		chosenRuntime = s.cfg.Runtime
	}
	// "kata" is reserved as a future runtime. Accept it through validation
	// (so operators can pre-stage the host default) but reject individual
	// create requests until the runtime is wired up. Surfaced as a clear
	// 4xx-shaped error so clients see "not implemented" rather than a
	// generic Docker failure 30s later.
	if chosenRuntime == models.RuntimeKata {
		return nil, fmt.Errorf("runtime %q: %w", chosenRuntime, models.ErrRuntimeNotImplemented)
	}
	// destroy_at becomes destroy_at_age from now (L6), before the defaults
	// look at whether the create set timers of its own. In memory only.
	if err := NormalizeCreateLifecycle(&req, time.Now().UTC()); err != nil {
		return nil, err
	}
	// The server's default destroy timers (L4) for a create with no timers
	// of its own. In memory only: it fills the request's lifecycle.
	req.Lifecycle = s.withDefaultLifecycle(req.Lifecycle)
	// Lifecycle options a runtime cannot honour are refused before any work
	// (restart_on_failure needs die events). A field check, nothing more.
	if req.Lifecycle != nil {
		if err := validateLifecycleRuntime(*req.Lifecycle, chosenRuntime); err != nil {
			return nil, err
		}
	}
	// Operator create policy (SB_CREATE_POLICY_FILE, create_policy.go): in
	// memory, once the runtime and the image are settled and before any
	// work, so every create path gets the same 403. Failover replays are
	// exempt. require_non_root is enforced by the container runtime once it
	// has read the image; its refusal is counted on the way out.
	if err := s.applyCreatePolicy(&req, chosenRuntime, memoryWasOmitted, isStoredSpecReplay(ctx)); err != nil {
		return nil, err
	}
	if req.RequireNonRootUser {
		defer noteNonRootRefusal(&err)
	}
	// Fail closed: no sandbox on a runtime whose node guard failed to
	// install, since it could reach every service on the node. One atomic
	// map read (node_guard.go).
	if err := s.requireNodeGuard(chosenRuntime); err != nil {
		return nil, err
	}
	// Fail closed: no sandbox on a runtime whose egress deny floor is not
	// installed, since it could reach the cloud metadata endpoints and the
	// node's credentials. One atomic map read (egress_floor.go).
	if err := s.requireEgressFloor(chosenRuntime); err != nil {
		return nil, err
	}
	if hasBinariesRule(req.NetworkEgressRules) && chosenRuntime == models.RuntimeGvisor {
		return nil, unsupportedBinaries(chosenRuntime)
	}
	durability, err := models.NormalizeCreateDurability(req.Durability, chosenRuntime)
	if err != nil {
		return nil, err
	}
	req.Durability = durability
	// Fail closed: no container or Firecracker sandbox while the node's
	// IPv6 fence is not installed for its runtime. One atomic map read
	// (ipv6_fence.go).
	if err := s.requireIPv6Fence(chosenRuntime); err != nil {
		return nil, err
	}
	if err := validateMaskRequestHost(req.MaskRequestHost); err != nil {
		return nil, err
	}
	// Cloud identity (plans/sandbox-cloud-identity.md): checked before any
	// runtime is touched, recorded once the row exists, first token pushed
	// off the response path. Every runtime path below returns through here.
	if req.Identity != nil {
		if err := s.prepareCreateIdentity(ctx, &req, ownerRef, chosenRuntime); err != nil {
			return nil, err
		}
		identityReq := *req.Identity
		defer func() {
			if err == nil && resp != nil {
				err = s.recordCreateIdentity(ctx, &resp.Sandbox, &identityReq)
			}
		}()
	}
	// Translate named platform volumes into synthesized, tenant-scoped mounts
	// appended to req.Mounts. Runs before the firecracker/wasm dispatch so the
	// runtime gate applies uniformly, and before mount validation/seal/MountAll
	// so the synthesized specs ride the existing mount pipeline.
	platformAttachments, err := s.resolvePlatformVolumes(ctx, &req, chosenRuntime)
	if err != nil {
		return nil, err
	}
	platformVolumesCommitted := false
	defer func() {
		if !platformVolumesCommitted {
			s.cleanupPlatformVolumeAttachments(rollback.Context(), platformAttachments)
			s.cleanupCreatedPlatformVolumes(rollback.Context(), platformAttachments)
		}
	}()
	// "firecracker" is the second runtime, dispatched to the native
	// Firecracker driver per plans/snapshot-clone-fast-boot.md.
	//
	// Two operator-troubleshooting shapes for the gate:
	//   - SB_ENABLE_FIRECRACKER=false: the host has not opted in. Tell
	//     them which env var to flip and which plan describes the path.
	//   - SB_ENABLE_FIRECRACKER=true but firecracker==nil: the driver
	//     was not registered. This is a daemon-configuration bug
	//     rather than an operator misconfiguration — main.go must
	//     always register the driver when the env var is set. The
	//     distinct message lets the operator tell the two apart.
	if chosenRuntime == models.RuntimeFirecracker {
		if !s.cfg.EnableFirecracker {
			return nil, fmt.Errorf("runtime %q requires SB_ENABLE_FIRECRACKER=true on this host (see plans/snapshot-clone-fast-boot.md): %w",
				chosenRuntime, models.ErrRuntimeNotImplemented)
		}
		if s.firecracker == nil {
			return nil, fmt.Errorf("runtime %q: driver not registered (SB_ENABLE_FIRECRACKER=true but main.go did not call SetFirecrackerRuntime): %w",
				chosenRuntime, models.ErrRuntimeNotImplemented)
		}
		req.Runtime = chosenRuntime
		clock.Mark("svc_policy")
		return s.createFirecrackerSandbox(ctx, req, idOverride)
	}
	if chosenRuntime == models.RuntimeWasm {
		if !s.cfg.EnableWasm {
			return nil, fmt.Errorf("runtime %q requires SB_ENABLE_WASM=true on this host (see plans/wasm-runtime.md): %w",
				chosenRuntime, models.ErrRuntimeNotImplemented)
		}
		if s.wasm == nil {
			return nil, fmt.Errorf("runtime %q: driver not registered (SB_ENABLE_WASM=true but daemon did not call SetWasmRuntime): %w",
				chosenRuntime, models.ErrRuntimeNotImplemented)
		}
		if memoryWasOmitted {
			req.MemoryMB = 0
		}
		req.Runtime = chosenRuntime
		clock.Mark("svc_policy")
		return s.createWasmSandbox(ctx, req, idOverride)
	}
	// "isolate" is the fifth runtime (V8 isolates, Workers model), dispatched
	// to internal/runtime/isolate per plans/isolate-runtime.md. Same two
	// operator-troubleshooting shapes as the firecracker/wasm gates: flag off
	// vs driver-not-registered.
	if chosenRuntime == models.RuntimeIsolate {
		if !s.cfg.EnableIsolate {
			return nil, fmt.Errorf("runtime %q requires SB_ENABLE_ISOLATE=true on this host (see plans/isolate-runtime.md): %w",
				chosenRuntime, models.ErrRuntimeNotImplemented)
		}
		if s.isolate == nil {
			return nil, fmt.Errorf("runtime %q: driver not registered (SB_ENABLE_ISOLATE=true but daemon did not call SetIsolateRuntime): %w",
				chosenRuntime, models.ErrRuntimeNotImplemented)
		}
		req.Runtime = chosenRuntime
		clock.Mark("svc_policy")
		return s.createIsolateSandbox(ctx, req, idOverride)
	}
	req.Runtime = chosenRuntime

	// Block-all, the address lists, hostname rules and byte caps are host
	// firewall rules on a container: on a node whose firewall is off, refuse
	// them before any work rather than create a sandbox whose GET claims a
	// policy nothing enforces. Checked on the effective request, so an
	// operator default and a failover replay are held to it too.
	if ociRt, rerr := s.ociEngineForNewCreate(); rerr == nil {
		fields := firewallPolicyFields(&req)
		unenforced, ferr := s.requireNetRules(ociRt, chosenRuntime, fields)
		if ferr != nil {
			return nil, ferr
		}
		if unenforced {
			defer func() {
				if err == nil && resp != nil {
					s.warnUnenforced(resp.ID, chosenRuntime, "create", fields)
				}
			}()
		}
	}

	if err := s.validateCreateMounts(ctx, req.Mounts, idOverride); err != nil {
		return nil, err
	}

	var lifecycle models.Lifecycle
	if req.Lifecycle != nil {
		if err := s.validateLifecycle(*req.Lifecycle); err != nil {
			return nil, fmt.Errorf("invalid lifecycle: %w", err)
		}
		lifecycle = *req.Lifecycle
	}

	if req.GPUs != nil {
		if err := req.GPUs.Validate(); err != nil {
			return nil, fmt.Errorf("invalid gpu request: %w", err)
		}
	}

	// Mirror SetNetworkLimits: enforcement uses `limit > 0`, so a negative
	// value would silently behave as unlimited and bypass the quota.
	if req.NetworkBytesInLimit < 0 || req.NetworkBytesOutLimit < 0 {
		return nil, errors.New("network byte limits must be >= 0")
	}

	sealedMounts, err := s.sealMounts(req.Mounts)
	if err != nil {
		return nil, err
	}
	if s.testSealedMountsOverride != nil {
		sealedMounts = s.testSealedMountsOverride
	}
	clock.Mark("svc_policy")

	toolboxToken, err := generateToolboxToken()
	if err != nil {
		return nil, fmt.Errorf("generate toolbox token: %w", err)
	}

	authorizedKey, privateKeyPEM, err := generateSandboxSSHKeys()
	if err != nil {
		return nil, fmt.Errorf("generate ssh keypair: %w", err)
	}
	// A sandbox moving here with its memory (C21) keeps what its programs
	// and its users already hold: the token its running toolbox checks and
	// the SSH key its users log in with. A context read, nothing more, on
	// every other create.
	moved := movedIdentityFrom(ctx)
	if moved != nil {
		toolboxToken, authorizedKey, privateKeyPEM = moved.ToolboxToken, moved.Sandbox.SSHPublicKey, ""
	}

	// Choose the sandbox ID up-front so we have stable host paths to bind
	// before docker.Create runs. The ID also becomes the container's name.
	// idOverride is non-empty only on the cluster owner watcher's recreate
	// path — preserving the original ID is what makes failover transparent
	// to clients holding the sandbox URL.
	sandboxID := idOverride
	if sandboxID == "" {
		var err error
		sandboxID, err = s.NewSandboxID()
		if err != nil {
			return nil, fmt.Errorf("generate sandbox id: %w", err)
		}
	}
	clock.Mark("svc_keygen")

	// Cluster mode carries the redacted spec inside the placement's raft log
	// entry, which is size-capped (cluster.ValidateRecoveryPayloadSize) — there
	// is no oversize fallback path. Reject here, before admission and container
	// work, so the caller gets a clean 400 instead of a placement failure after
	// the sandbox half-exists. The check includes this sandbox's deterministic
	// secret ref even when the request carries no credentials: a later
	// credential rotation attaches the handle via UpsertSpec and must not be
	// blocked by a spec that barely fit without it. Cost: one JSON encode +
	// SHA-256 of ≤4KiB (~µs), cluster mode only.
	if s.cfg.EnableCluster {
		redacted := RedactClusterSecrets(req)
		// The replicated spec carries the owner-qualified name key, which is
		// longer than the user's name; size what will actually be encoded.
		redacted.Name = cluster.QualifiedSandboxName(ownerRef, redacted.Name)
		incarnationID := ""
		if c := s.Cluster(); c != nil {
			if p, ok := c.PlacementOf(sandboxID); ok {
				incarnationID = p.IncarnationID
			}
		}
		if incarnationID == "" {
			// Size validation runs before an unreserved placement receives its
			// real random incarnation. Use an equal-width placeholder so this
			// preflight cannot undercount the canonical current-format handle.
			incarnationID = strings.Repeat("0", 32)
		}
		handle := cluster.PlacementSecrets{
			Ref:           secrets.FormatRef(sandboxID, incarnationID, secrets.RefVersion),
			Version:       secrets.RefVersion,
			IncarnationID: incarnationID,
		}
		if err := cluster.ValidateRecoveryPayloadSize(sandboxID, &redacted, handle); err != nil {
			return nil, fmt.Errorf("sandbox spec too large to replicate across the cluster (image, env, labels, and mount definitions all count): %w", err)
		}
	}

	// Admission check uses normalized values (req.CPU/MemoryMB are guaranteed
	// > 0 by normalizeCreateRequest above), so a default-sized request still
	// counts against the host budget. Reservation happens here; every failure
	// path below must release it.
	releaseAdmission, err := s.admitCreate(sandboxID, req)
	if err != nil {
		return nil, err
	}
	clock.Mark("svc_admit")

	prepareStart := time.Now()
	egressPol, err := compileCreateEgressEffective(&req)
	if err != nil {
		releaseAdmission()
		return nil, err
	}
	// Hostname rules (gateway mode) need the egress gateway. The driver gets
	// a driver-facing copy: block-all and no lists, so its existing create,
	// warm-adopt and park paths stay fail-closed unchanged and hostnames
	// never reach netrules. The gateway attach then lifts the block
	// (plans/egress-domain-filtering.md §5.7).
	gatewayMode := egressPol.GatewayMode()
	driverReq := req
	if gatewayMode {
		if err := s.requireEgressGateway(); err != nil {
			releaseAdmission()
			return nil, err
		}
		driverReq.NetworkBlockAll = true
		driverReq.NetworkAllowOut, driverReq.NetworkDenyOut = nil, nil
		createtiming.From(ctx).RecordStage("svc_egress_prepare", time.Since(prepareStart))
	}
	// Inspect rules (P3-1): the gateway gets the node CA before any traffic,
	// and the sandbox the CA file, the bundle's tmpfs and the environment.
	// Mounts and env keep this create off the warm pools (§8.2's one
	// known regression).
	var inspectBinds []mounts.ContainerBind
	if hasInspectRule(req.NetworkEgressRules) {
		inspectBinds, driverReq.Env, err = s.prepareInspect(ctx, req.Env, req.NetworkEgressRules)
		if err != nil {
			releaseAdmission()
			return nil, err
		}
	}
	// Credentials the gateway injects, or ever injected for this sandbox,
	// are placeholders inside it (P3-2), with or without inspect rules now.
	withheld := withheldKeys(&req)
	driverReq.Env = withholdEnv(driverReq.Env, withheld)

	binds, err := s.mounts.MountAll(ctx, sandboxID, req.Mounts)
	if err != nil {
		releaseAdmission()
		return nil, fmt.Errorf("mount external storage: %w", err)
	}
	// The ID's mount set is this create's only if it made one: MountAll
	// refuses an ID whose mounts are established, and a create without
	// mounts made none. Tearing down rootDir/<id> otherwise would unmount
	// the storage of whatever holds the ID.
	mountedHere := len(req.Mounts) > 0
	cleanupMounts := func() {
		if s.mounts == nil || !mountedHere {
			return
		}
		err := s.mounts.UnmountAll(sandboxID)
		if s.testForceUnmountErr != nil {
			err = s.testForceUnmountErr
		}
		if err != nil {
			s.logger.Warn("cleanup unmount failed", "sandbox_id", sandboxID, "error", err)
		}
	}

	ociRt, err := s.ociEngineForNewCreate()
	if err != nil {
		cleanupMounts()
		releaseAdmission()
		return nil, err
	}
	chosenEngine := s.cfg.ContainerEngine
	if chosenEngine == "" {
		chosenEngine = models.ContainerEngineDocker
	}
	// egressDone carries the gateway attach, which runs alongside sealing and
	// the row persist (latency amendment §8.2). waitEgress joins it; every
	// exit after the runtime create joins first, so the attach never races a
	// rollback.
	var egressDone chan error
	waitEgress := func() error {
		if egressDone == nil {
			return nil
		}
		joinStart := time.Now()
		err := <-egressDone
		egressDone = nil
		createtiming.From(ctx).RecordStage("svc_egress_join", time.Since(joinStart))
		return err
	}
	// early is the gateway attach this create starts as soon as the runtime
	// reports the sandbox's address, so it overlaps the runtime create
	// (egress_early.go). Per-binary rules keep the late attach: the gateway
	// traces them from the container's init pid, which only the started
	// container has.
	var early *earlyEgressAttach
	createCtx := ctx
	if gatewayMode && !hasBinariesRule(req.NetworkEgressRules) {
		if cr, ok := runtime.AsContainerRuntime(ociRt); ok {
			early = s.newEarlyEgressAttach(ctx, cr, models.Sandbox{ID: sandboxID, Runtime: chosenRuntime, Engine: chosenEngine,
				NetworkAllowOut: req.NetworkAllowOut, NetworkDenyOut: req.NetworkDenyOut, NetworkEgressMode: req.NetworkEgressMode,
				NetworkEgressRules: req.NetworkEgressRules, Env: req.Env})
			createCtx = runtime.WithAddressObserver(ctx, early)
		}
	}
	rollbackDestroy := func(partial *models.Sandbox) {
		if partial == nil {
			return
		}
		_ = waitEgress()
		partial.Runtime = chosenRuntime
		partial.Engine = chosenEngine
		// Destroy first: a container that outlives a failed rollback stays
		// filtered (attached, or still behind the driver's block-all). The
		// runtime tells the observer once the workload is gone and before
		// its address is free, so the gateway lets go first: an early attach
		// undoes itself (unless a duplicate create holds it), any other
		// attach detaches.
		_, reported := early.reported()
		destroyCtx := s.gatewayReleaserCtx(rollback.Context(), partial, false)
		if reported {
			destroyCtx = runtime.WithAddressObserver(rollback.Context(), early)
		}
		destroyErr := ociRt.Destroy(destroyCtx, partial)
		switch {
		case !gatewayMode:
		case reported && destroyErr != nil:
			// It may still run: it keeps the attach, and the orphan sweep's
			// removal detaches it.
			early.commit()
		case reported:
			early.undo()
		case destroyErr == nil:
			s.detachSandboxEgress(rollback.Context(), partial, partial.ContainerIP)
		}
	}

	// The driver installs the sandbox's rules before its row carries the
	// address: settleEnforcedEgress checks for a clear in between.
	// The runtime instance exists before the row: reconcile's orphan sweep
	// must not take it for a leak until this create has returned.
	defer s.createsInFlight.begin(sandboxID)()
	// Settles the early attach on every exit, before the in-flight mark
	// goes: once the row is stored with the attach joined it owns the
	// attach; any other exit undoes it (a no-op once a rollback has).
	egressCommitted := false
	defer func() { early.end(egressCommitted) }()
	clearGen := s.egressClears.now()
	// svc_pre_driver: egress compile, mounts and the runtime pick. A
	// gateway create's svc_egress_prepare is a part of it.
	clock.Mark("svc_pre_driver")
	state, err := ociRt.Create(createCtx, driverReq, sandboxID, toolboxToken, append(binds, inspectBinds...))
	if err != nil {
		// A driver that reported the address and failed let it go through
		// ReleasingAddress; this covers one that didn't.
		early.undo()
		// A name collision (ErrSandboxContainerExists) means another
		// instance holds the ID. This create still releases only what it
		// made: releaseAdmission and cleanupMounts are no-ops for a
		// reservation or a mount set it found in place (admitCreate,
		// mountedHere), on the replay exit as on every other.
		cleanupMounts()
		if resp, dupErr := s.handleDuplicateCreateAfterRuntime(ctx, sandboxID, err); dupErr == nil {
			releaseAdmission()
			return resp, nil
		} else if !errors.Is(dupErr, err) {
			releaseAdmission()
			return nil, s.asLeftoverInstance(ctx, dupErr, ociRt, sandboxID, chosenRuntime, chosenEngine)
		}
		releaseAdmission()
		// A bridge or subnet that filled past the counted pool (a port
		// taken without a reservation) is still capacity, not a fault: the
		// driver removed what it created, and the API answers 503.
		return nil, capacity.AsNetworkSlotExhausted(networkSlotPool(chosenEngine), err)
	}
	s.releaseAdoptedParkReservation(state)
	if state.AdoptedParkID != "" {
		scaleobs.MarkWarmStart(ctx)
	}
	if gatewayMode {
		cr, ok := runtime.AsContainerRuntime(ociRt)
		attachSB := &models.Sandbox{ID: sandboxID, ContainerID: state.ContainerID, ContainerIP: state.ContainerIP, Runtime: chosenRuntime, Engine: chosenEngine,
			NetworkAllowOut: req.NetworkAllowOut, NetworkDenyOut: req.NetworkDenyOut, NetworkEgressMode: req.NetworkEgressMode,
			NetworkEgressRules: req.NetworkEgressRules, Env: req.Env}
		egressDone = make(chan error, 1)
		s.startCreateAttach(ctx, early, attachSB, cr, ok, egressDone)
	}

	// Seal the registry creds (if any) BEFORE building the row so a marshal
	// or encrypt error doesn't leave a half-created sandbox: we already passed
	// runtime Create at this point, so failure here goes through the same
	// rollback chain as any later store error below.
	sealedRegistry, err := s.sealRegistry(req.Registry)
	if err != nil {
		rollbackDestroy(&models.Sandbox{ID: state.SandboxID, ContainerID: state.ContainerID, Runtime: chosenRuntime, Engine: chosenEngine, ContainerIP: state.ContainerIP, NetworkAllowOut: req.NetworkAllowOut, NetworkDenyOut: req.NetworkDenyOut, NetworkEgressMode: req.NetworkEgressMode})
		cleanupMounts()
		releaseAdmission()
		return nil, err
	}

	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID:                   state.SandboxID,
		Image:                req.Image,
		Status:               state.Status,
		PublicURL:            s.sandboxPublicURL(state.SandboxID, req.AllowPublicTraffic),
		ContainerID:          state.ContainerID,
		ContainerIP:          state.ContainerIP,
		CPU:                  req.CPU,
		MemoryMB:             req.MemoryMB,
		DiskGB:               req.DiskGB,
		OSUser:               req.OSUser,
		Env:                  req.Env,
		NetworkBlockAll:      req.NetworkBlockAll,
		NetworkAllowOut:      req.NetworkAllowOut,
		NetworkDenyOut:       req.NetworkDenyOut,
		NetworkEgressMode:    req.NetworkEgressMode,
		NetworkEgressRules:   req.NetworkEgressRules,
		AllowPublicTraffic:   req.AllowPublicTraffic,
		MaskRequestHost:      strings.TrimSpace(req.MaskRequestHost),
		ToolboxEnabled:       true,
		ToolboxToken:         toolboxToken,
		SSHPublicKey:         authorizedKey,
		Name:                 strings.TrimSpace(req.Name),
		Tags:                 req.Tags,
		CreatedAt:            now,
		UpdatedAt:            now,
		LastActiveAt:         now,
		ContainerCommand:     req.ContainerCommand,
		Lifecycle:            lifecycle,
		Failover:             req.Failover,
		Runtime:              chosenRuntime,
		Engine:               chosenEngine,
		GPUs:                 req.GPUs,
		RegistryAuthSealed:   sealedRegistry,
		NetworkBytesInLimit:  req.NetworkBytesInLimit,
		NetworkBytesOutLimit: req.NetworkBytesOutLimit,
		Durability:           req.Durability,
	}
	if moved != nil {
		// Tokens issued for it before the move stay good; those revoked
		// on the source stay revoked (persistSandboxCreate keeps it).
		sandbox.TokensNotBefore = moved.TokensNotBefore
	}
	// Populate the in-memory CustomDomains slice so the initial route
	// matcher sees the full hostname union. Status is pending_dns until
	// the first ACME ask flips it; the per-row store inserts happen below.
	if len(req.CustomDomains) > 0 {
		sandbox.CustomDomains = make([]models.CustomDomain, 0, len(req.CustomDomains))
		for _, h := range req.CustomDomains {
			sandbox.CustomDomains = append(sandbox.CustomDomains, models.CustomDomain{
				Hostname:  h,
				Status:    models.CustomDomainPendingDNS,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}

	// Private sandboxes skip caddy entirely on the boot path: a fresh create
	// has no route to install, and the defensive delete inside
	// syncSandboxPublicRoute is redundant here — crash residue is swept by
	// the reconcile pass (cleanupPublicTrafficDisabledIngressState).
	if sandboxAllowsPublicTraffic(sandbox) {
		caddyStart := time.Now()
		if err := s.syncSandboxPublicRoute(ctx, sandbox); err != nil {
			// UpsertSandboxRoute is non-atomic in domain mode: it installs the
			// main route and then a per-custom-domain leaf route in a loop, so a
			// failure on a later leaf can leave the main route + earlier leaves
			// installed. deleteSandboxPublicRoutes (not DeleteSandboxRoute) tears
			// down the main route AND every custom-domain leaf — 404 per leaf is
			// a no-op, so it's safe on a partial install.
			_ = s.deleteSandboxPublicRoutes(rollback.Context(), sandbox)
			rollbackDestroy(sandbox)
			cleanupMounts()
			releaseAdmission()
			return nil, err
		}
		createtiming.From(ctx).RecordStage("svc_caddy", time.Since(caddyStart))
	}

	// UC-480's crash window: the container runs, its route and network slot
	// are held, and no row records any of it. Last before the store write so
	// the crash leaves everything a restart has to clean up. Compiled to
	// nothing outside itest builds (internal/failpoint).
	failpoint.Hit(failpoint.CreateBeforePersist, sandbox.Name)

	persistStart := time.Now()
	sandbox.OwnerRef = ownerRef
	if err := s.persistSandboxCreate(ctx, sandbox); err != nil {
		// ErrSandboxExists: a row holds the ID, and with it the ID's public
		// route, reservation and mounts. This create releases only what it
		// made (admitCreate, mountedHere) and puts the route back.
		s.rollbackCreatePublicRoutes(rollback.Context(), sandbox, errors.Is(err, models.ErrSandboxExists))
		rollbackDestroy(sandbox)
		cleanupMounts()
		if resp, dupErr := s.handleDuplicateStoreCreate(ctx, sandbox.ID, err); dupErr == nil {
			releaseAdmission()
			return resp, nil
		} else if !errors.Is(dupErr, err) {
			releaseAdmission()
			return nil, dupErr
		}
		releaseAdmission()
		return nil, err
	}
	if s.testAfterStoreCreate != nil {
		s.testAfterStoreCreate()
	}
	if len(s.testForcePlatformAttachments) > 0 {
		platformAttachments = append(platformAttachments, s.testForcePlatformAttachments...)
	}

	if len(platformAttachments) > 0 {
		for i := range platformAttachments {
			platformAttachments[i].SandboxID = sandbox.ID
			platformAttachments[i].IncarnationID = sandbox.AuditIncarnationID
		}
		if err := s.volumeMeta().PutAttachments(ctx, platformAttachments); err != nil {
			_ = s.store.RollbackSandboxCreate(rollback.Context(), sandbox.ID, sandbox.AuditIncarnationID)
			_ = s.deleteSandboxPublicRoutes(rollback.Context(), sandbox)
			rollbackDestroy(sandbox)
			cleanupMounts()
			releaseAdmission()
			return nil, fmt.Errorf("persist platform volume attachments: %w", err)
		}
	}

	// Push any pending GC deadline for this image forward — a fresh
	// create proves the image is back in active use, so the next
	// destroy should restart the full TTL clock instead of inheriting
	// the previous destroy's old timestamp. Deferred off the response
	// path: the helper is best-effort by design, and on the
	// single-writer SQLite connection an inline UPDATE would queue the
	// response behind unrelated writes. WithoutCancel because the
	// request ctx dies when the response is written, and aborting the
	// UPDATE there would turn "best-effort" into "never" on a busy
	// host; the timeout keeps the detached write bounded.
	go func(image string) {
		gcCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		s.refreshPendingImageGCOnUse(gcCtx, image)
	}(sandbox.Image)

	if len(sealedMounts) > 0 {
		if err := s.store.PutMounts(ctx, sandbox.ID, sealedMounts); err != nil {
			_ = s.store.RollbackSandboxCreate(rollback.Context(), sandbox.ID, sandbox.AuditIncarnationID)
			_ = s.deleteSandboxPublicRoutes(rollback.Context(), sandbox)
			rollbackDestroy(sandbox)
			cleanupMounts()
			releaseAdmission()
			return nil, fmt.Errorf("persist sandbox mounts: %w", err)
		}
	}

	if err := s.persistCustomDomainsOnCreate(ctx, sandbox.ID, req.CustomDomains); err != nil {
		// Same rollback chain as a mount-persist failure. ErrCustomDomainConflict
		// flows through unchanged so the API layer can map it to 409.
		_ = s.store.RollbackSandboxCreate(rollback.Context(), sandbox.ID, sandbox.AuditIncarnationID)
		_ = s.deleteSandboxPublicRoutes(rollback.Context(), sandbox)
		rollbackDestroy(sandbox)
		cleanupMounts()
		releaseAdmission()
		return nil, err
	}

	s.logger.Info("audit sandbox created",
		"sandbox_id", sandbox.ID,
		"image", sandbox.Image,
		"cpu", sandbox.CPU,
		"memory_mb", sandbox.MemoryMB,
		"disk_gb", sandbox.DiskGB,
		"network_block_all", sandbox.NetworkBlockAll,
		"mount_count", len(req.Mounts),
	)
	if err := waitEgress(); err != nil {
		if isStoredSpecReplay(ctx) {
			// A failover recreate never refuses its stored spec: the sandbox
			// comes up held (driver block-all stays, hold recorded) and
			// reconcile retries the attach (CEO D16).
			if cr, ok := runtime.AsContainerRuntime(ociRt); ok {
				s.holdSandboxEgress(ctx, sandbox, cr, egressHoldUnavailable)
			}
		} else {
			// Same rollback chain as a mount-persist failure; 2xx would claim
			// a live policy the gateway never applied.
			_ = s.store.RollbackSandboxCreate(rollback.Context(), sandbox.ID, sandbox.AuditIncarnationID)
			_ = s.deleteSandboxPublicRoutes(rollback.Context(), sandbox)
			rollbackDestroy(sandbox)
			cleanupMounts()
			releaseAdmission()
			return nil, fmt.Errorf("%w: %v", ErrEgressGatewayUnavailable, err)
		}
	}
	platformVolumesCommitted = true
	egressCommitted = true
	s.settleEgressAttach(sandbox.ID)
	s.settleEnforcedEgress(ctx, sandbox, clearGen)
	stored, err := s.store.Get(ctx, sandbox.ID)
	if err != nil {
		return nil, err
	}
	stored.AuditIncarnationID = sandbox.AuditIncarnationID
	createtiming.From(ctx).RecordStage("svc_persist", time.Since(persistStart))
	return &models.CreateSandboxResponse{
		Sandbox:       *stored,
		SSHPrivateKey: privateKeyPEM,
	}, nil
}

// createFirecrackerSandbox is the post-Create scaffolding for the
// native Firecracker runtime. Mirrors the docker path's flow in
// createSandbox above — keep them in lockstep when the docker path
// grows new steps. The differences are deliberate and short:
//
//   - No mount sealing: Phase 1 doesn't pass binds to the firecracker
//     driver (the host's bind-mount story is Docker-shaped; the
//     firecracker guest will use virtio-fs or per-snapshot rootfs
//     hard-links in a later phase).
//   - No GPU normalize: GPU passthrough on Firecracker requires PCI
//     passthrough setup that's out of Phase 1 scope.
//   - The "registry auth seal" step still runs because the firecracker
//     driver may pull from private registries via skopeo, but the
//     sealed bytes are persisted onto the sandbox row in case Phase 2's
//     template builder needs to re-pull.
//   - Caddy still gets UpsertSandboxRoute called with the guest IP —
//     the caddy upstream doesn't care whether the IP is a docker veth
//     peer or a firecracker TAP guest, so the public URL routing works
//     uniformly across runtimes.
//
// Cleanup contract — pr-review.md §4: every post-driver failure path
// unwinds the driver-side state via firecracker.Destroy, mirroring the
// docker path's _ = s.docker.Destroy(...) calls. The driver's own
// cleanup contract (TAP slot release, runDir teardown) sits inside
// Destroy, so we don't have to know the driver's internals here.
func (s *Service) createFirecrackerSandbox(ctx context.Context, req models.CreateSandboxRequest, idOverride string) (*models.CreateSandboxResponse, error) {
	// Rollback is independent of ctx so that rollback calls succeed even when
	// ctx was cancelled by the outer createSandbox timeout guard, and its
	// budget starts when a rollback begins — a Firecracker cold boot can
	// outlast one taken here. See rollbackBudget.
	var rollback rollbackBudget
	defer rollback.Release()

	if len(req.Mounts) > models.MaxMountsPerSandbox {
		return nil, fmt.Errorf("too many mounts: max %d", models.MaxMountsPerSandbox)
	}
	if len(req.Mounts) > 0 {
		// Phase 1 explicitly rejects mounts on the firecracker path
		// rather than silently dropping them. When virtio-fs support
		// lands, this branch becomes a call into a new mount adapter.
		return nil, fmt.Errorf("runtime %q does not yet support mounts (see plans/snapshot-clone-fast-boot.md): %w",
			req.Runtime, models.ErrRuntimeNotImplemented)
	}

	var lifecycle models.Lifecycle
	if req.Lifecycle != nil {
		if err := s.validateLifecycle(*req.Lifecycle); err != nil {
			return nil, fmt.Errorf("invalid lifecycle: %w", err)
		}
		lifecycle = *req.Lifecycle
	}

	// GPU on firecracker is a future axis; reject explicitly so users
	// don't think a silent drop happened. Same shape as the mounts
	// rejection above.
	if req.GPUs != nil {
		return nil, fmt.Errorf("runtime %q does not yet support GPUs (see plans/snapshot-clone-fast-boot.md): %w",
			req.Runtime, models.ErrRuntimeNotImplemented)
	}
	if req.NetworkBytesInLimit < 0 || req.NetworkBytesOutLimit < 0 {
		return nil, errors.New("network byte limits must be >= 0")
	}
	if err := s.checkFirecrackerEgress(&req); err != nil {
		return nil, err
	}
	// Hostname entries, profiles and learn mode go through the egress
	// gateway, as on the container runtimes: the driver gets a block-all
	// copy, so the guest boots shut, and the attach lifts it (§5.7).
	prepareStart := time.Now()
	egressPol, err := compileCreateEgressEffective(&req)
	if err != nil {
		return nil, err
	}
	gatewayMode := egressPol.GatewayMode()
	driverReq := req
	if gatewayMode {
		if err := s.requireEgressGateway(); err != nil {
			return nil, err
		}
		driverReq.NetworkBlockAll = true
		driverReq.NetworkAllowOut, driverReq.NetworkDenyOut = nil, nil
		// The same stage as the container path, so a Firecracker create's
		// Server-Timing splits its egress work the same way (UC-185).
		createtiming.From(ctx).RecordStage("svc_egress_prepare", time.Since(prepareStart))
	}
	if req.NetworkBytesInLimit > 0 || req.NetworkBytesOutLimit > 0 {
		return nil, unsupportedFirecrackerOption("network byte limits")
	}
	// The driver delivers the env into the guest, so a key the egress
	// gateway injects (or ever injected) stays a placeholder there, as on
	// the container path (P3-2). The row keeps the real value, sealed.
	driverReq.Env = withholdEnv(driverReq.Env, withheldKeys(&req))

	toolboxToken, err := generateToolboxToken()
	if err != nil {
		return nil, fmt.Errorf("generate toolbox token: %w", err)
	}
	authorizedKey, privateKeyPEM, err := generateSandboxSSHKeys()
	if err != nil {
		return nil, fmt.Errorf("generate ssh keypair: %w", err)
	}

	sandboxID := idOverride
	if sandboxID == "" {
		sandboxID, err = s.NewSandboxID()
		if err != nil {
			return nil, fmt.Errorf("generate sandbox id: %w", err)
		}
	}

	// Admission check mirrors the docker path. The capacity model is
	// runtime-agnostic — a firecracker VMM's vCPU/memory footprint
	// is counted the same way as a docker container's.
	releaseAdmission, err := s.admitCreate(sandboxID, req)
	if err != nil {
		return nil, err
	}

	// Dispatch into the firecracker driver. The driver's Create owns
	// TAP slot allocation, host TAP creation, rootfs build, VMM spawn,
	// REST orchestration, and the vsock handshake. On error, the
	// driver releases everything it acquired before returning.
	//
	// The gateway attach starts as soon as the driver has the guest's TAP
	// slot shut and reports its address, so it overlaps the boot
	// (egress_early.go); a warm-pool hit reports nothing and attaches late.
	gwSB := models.Sandbox{ID: sandboxID, Runtime: req.Runtime,
		NetworkAllowOut: req.NetworkAllowOut, NetworkDenyOut: req.NetworkDenyOut, NetworkEgressMode: req.NetworkEgressMode}
	var early *earlyEgressAttach
	createCtx := ctx
	if gatewayMode && !hasBinariesRule(req.NetworkEgressRules) {
		if cr, ok := runtime.AsContainerRuntime(s.firecracker); ok {
			early = s.newEarlyEgressAttach(ctx, cr, gwSB)
			createCtx = runtime.WithAddressObserver(ctx, early)
		}
	}
	committed := false
	// The runtime instance exists before the row: reconcile's orphan sweep
	// must not take it for a leak until this create has returned.
	defer s.createsInFlight.begin(sandboxID)()
	// Settles the early attach on every exit, before the in-flight mark
	// goes (see the container path).
	defer func() { early.end(committed) }()
	clearGen := s.egressClears.now()
	state, err := s.firecracker.Create(createCtx, driverReq, sandboxID, toolboxToken, nil)
	if err != nil {
		early.undo()
		// Phase 6 PR-A: cold-load corruption intercept. The driver's
		// configureVMMForLoad path verifies the snapshot checksum and
		// returns ErrSnapshotCorrupt-wrapping errors on mismatch; surface
		// that to the template-health code so the row transitions out of
		// ready and the rebuild kicks. Best-effort (MarkSnapshotCorrupt is
		// idempotent and swallows its own errors after logging); the
		// caller still gets the original Create failure.
		if errors.Is(err, models.ErrSnapshotCorrupt) && strings.TrimSpace(req.TemplateID) != "" {
			_ = s.MarkSnapshotCorrupt(ctx, req.TemplateID, err.Error())
		}
		releaseAdmission()
		return nil, err
	}
	// The gateway attach runs alongside the persist, as on the docker path;
	// destroyVM joins it first, so it never races a rollback.
	var egressDone chan error
	waitEgress := func() error {
		if egressDone == nil {
			return nil
		}
		joinStart := time.Now()
		err := <-egressDone
		egressDone = nil
		createtiming.From(ctx).RecordStage("svc_egress_join", time.Since(joinStart))
		return err
	}
	gwSB.ContainerIP = state.ContainerIP
	destroyVM := func(partial *models.Sandbox) {
		_ = waitEgress()
		// As on the docker path: a VM that outlives a failed rollback stays
		// filtered, and the gateway lets go once the VM is down and before
		// the TAP slot is free.
		_, reported := early.reported()
		destroyCtx := s.gatewayReleaserCtx(rollback.Context(), &gwSB, false)
		if reported {
			destroyCtx = runtime.WithAddressObserver(rollback.Context(), early)
		}
		err := s.firecracker.Destroy(destroyCtx, partial)
		switch {
		case !gatewayMode:
		case reported && err != nil:
			early.commit()
		case reported:
			early.undo()
		case err == nil:
			s.detachSandboxEgress(rollback.Context(), partial, state.ContainerIP)
		}
	}
	if gatewayMode {
		cr, ok := runtime.AsContainerRuntime(s.firecracker)
		attachSB := gwSB
		attachSB.ID = state.SandboxID
		egressDone = make(chan error, 1)
		s.startCreateAttach(ctx, early, &attachSB, cr, ok, egressDone)
	}

	sealedRegistry, err := s.sealRegistry(req.Registry)
	if err != nil {
		destroyVM(&models.Sandbox{ID: state.SandboxID, Runtime: req.Runtime})
		releaseAdmission()
		return nil, err
	}

	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID:                   state.SandboxID,
		Image:                req.Image,
		Status:               state.Status,
		PublicURL:            s.sandboxPublicURL(state.SandboxID, req.AllowPublicTraffic),
		ContainerID:          state.ContainerID,
		ContainerIP:          state.ContainerIP,
		CPU:                  req.CPU,
		MemoryMB:             req.MemoryMB,
		DiskGB:               req.DiskGB,
		OSUser:               req.OSUser,
		Env:                  req.Env,
		NetworkBlockAll:      req.NetworkBlockAll,
		NetworkAllowOut:      req.NetworkAllowOut,
		NetworkDenyOut:       req.NetworkDenyOut,
		NetworkEgressMode:    req.NetworkEgressMode,
		NetworkEgressRules:   req.NetworkEgressRules,
		AllowPublicTraffic:   req.AllowPublicTraffic,
		MaskRequestHost:      strings.TrimSpace(req.MaskRequestHost),
		ToolboxEnabled:       true,
		ToolboxToken:         toolboxToken,
		SSHPublicKey:         authorizedKey,
		Name:                 strings.TrimSpace(req.Name),
		Tags:                 req.Tags,
		CreatedAt:            now,
		UpdatedAt:            now,
		LastActiveAt:         now,
		ContainerCommand:     req.ContainerCommand,
		Lifecycle:            lifecycle,
		Failover:             req.Failover,
		Runtime:              req.Runtime,
		RegistryAuthSealed:   sealedRegistry,
		NetworkBytesInLimit:  req.NetworkBytesInLimit,
		NetworkBytesOutLimit: req.NetworkBytesOutLimit,
		// TemplateID is persisted so the GC's IsTemplateReferenced probe
		// finds this row and so failover re-creates the sandbox from the
		// same template rather than re-resolving from the request.
		TemplateID:    strings.TrimSpace(req.TemplateID),
		OverlaySizeGB: req.OverlaySizeGB,
		Durability:    req.Durability,
	}
	if len(req.CustomDomains) > 0 {
		sandbox.CustomDomains = make([]models.CustomDomain, 0, len(req.CustomDomains))
		for _, h := range req.CustomDomains {
			sandbox.CustomDomains = append(sandbox.CustomDomains, models.CustomDomain{
				Hostname:  h,
				Status:    models.CustomDomainPendingDNS,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}

	// Private sandboxes skip caddy on the boot path; see the docker path.
	if sandboxAllowsPublicTraffic(sandbox) {
		if err := s.syncSandboxPublicRoute(ctx, sandbox); err != nil {
			// deleteSandboxPublicRoutes (not DeleteSandboxRoute) so a non-atomic
			// partial UpsertSandboxRoute — main route + per-custom-domain leaves —
			// is fully torn down. See the docker path for the rationale.
			_ = s.deleteSandboxPublicRoutes(rollback.Context(), sandbox)
			destroyVM(sandbox)
			releaseAdmission()
			return nil, err
		}
	}

	sandbox.OwnerRef = s.ownerRefForCreateOrRecreate(ctx, idOverride)
	if err := s.persistSandboxCreate(ctx, sandbox); err != nil {
		_ = s.deleteSandboxPublicRoutes(rollback.Context(), sandbox)
		destroyVM(sandbox)
		releaseAdmission()
		return nil, err
	}

	if err := s.persistCustomDomainsOnCreate(ctx, sandbox.ID, req.CustomDomains); err != nil {
		_ = s.store.RollbackSandboxCreate(rollback.Context(), sandbox.ID, sandbox.AuditIncarnationID)
		_ = s.deleteSandboxPublicRoutes(rollback.Context(), sandbox)
		destroyVM(sandbox)
		releaseAdmission()
		return nil, err
	}

	if err := waitEgress(); err != nil {
		if isStoredSpecReplay(ctx) {
			// A failover recreate never refuses its stored spec: the guest
			// comes up shut and held, and reconcile retries the attach
			// (CEO D16).
			if cr, ok := runtime.AsContainerRuntime(s.firecracker); ok {
				s.holdSandboxEgress(ctx, sandbox, cr, egressHoldUnavailable)
			}
		} else {
			// 2xx would claim a live policy the gateway never applied.
			_ = s.store.RollbackSandboxCreate(rollback.Context(), sandbox.ID, sandbox.AuditIncarnationID)
			_ = s.deleteSandboxPublicRoutes(rollback.Context(), sandbox)
			destroyVM(sandbox)
			releaseAdmission()
			return nil, fmt.Errorf("%w: %v", ErrEgressGatewayUnavailable, err)
		}
	}
	committed = true
	s.settleEgressAttach(sandbox.ID)
	s.settleEnforcedEgress(ctx, sandbox, clearGen)

	s.logger.Info("audit sandbox created",
		"sandbox_id", sandbox.ID,
		"image", sandbox.Image,
		"cpu", sandbox.CPU,
		"memory_mb", sandbox.MemoryMB,
		"disk_gb", sandbox.DiskGB,
		"runtime", sandbox.Runtime,
	)
	stored, err := s.store.Get(ctx, sandbox.ID)
	if err != nil {
		return nil, err
	}
	stored.AuditIncarnationID = sandbox.AuditIncarnationID
	return &models.CreateSandboxResponse{
		Sandbox:       *stored,
		SSHPrivateKey: privateKeyPEM,
	}, nil
}

// sealRegistry encrypts the user-supplied RegistryAuth so it can ride on the
// sandbox row without exposing credentials at rest. Returns nil for the
// no-credentials case (public registry, or a partially-zero RegistryAuth) so
// the column stays the empty-blob default for sandboxes that don't need it.
func (s *Service) sealRegistry(auth *models.RegistryAuth) ([]byte, error) {
	if auth == nil || (auth.Server == "" && auth.Username == "" && auth.Password == "") {
		return nil, nil
	}
	plain, err := json.Marshal(auth)
	if err != nil {
		return nil, fmt.Errorf("marshal registry auth: %w", err)
	}
	sealed, err := s.cipher.Encrypt(plain)
	if err != nil {
		return nil, fmt.Errorf("encrypt registry auth: %w", err)
	}
	return sealed, nil
}

// UnsealRegistry decrypts a previously sealed RegistryAuth. Returns nil/nil
// when the input is empty (no credentials persisted). Exported for the
// boot-time backfill in cmd/sandboxd that rebuilds CreateSandboxRequest from
// the persisted Sandbox row. sandboxID is audit-only (ref registry:{id}).
func (s *Service) UnsealRegistry(ctx context.Context, sandboxID string, sealed []byte) (auth *models.RegistryAuth, err error) {
	if len(sealed) == 0 {
		return nil, nil
	}
	auditIncarnationID, auditOwnerRef := s.auditIdentityFor(sandboxID)
	done := s.beginSecretAuditFor(ctx, sandboxID, registryAuditRef(sandboxID), s.auditActor(), auditIncarnationID, auditOwnerRef)
	defer func() { done(err) }()
	if s == nil || s.cipher == nil {
		return nil, fmt.Errorf("%w: registry auth cipher is not configured", secrets.ErrDecryptFailed)
	}
	plain, decErr := s.cipher.Decrypt(sealed)
	if decErr != nil {
		return nil, sealedOpenError("decrypt registry auth", decErr)
	}
	var out models.RegistryAuth
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, fmt.Errorf("%w: unmarshal registry auth: %v", secrets.ErrDecryptFailed, err)
	}
	return &out, nil
}

// attachWasmRegistryAuth unseals the sandbox's persisted registry creds into
// its transient RegistryAuth field, so the WASM runtime can re-pull a private
// oci:// module under the tenant's identity on a node that lacks it (codex C4).
// Fail closed when persisted credentials cannot be opened. Falling through to
// the node's ambient registry identity would cross the tenant authorization
// boundary and make credential revocation ineffective.
func (s *Service) attachWasmRegistryAuth(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil || len(sandbox.RegistryAuthSealed) == 0 {
		return nil
	}
	auth, err := s.UnsealRegistry(ctx, sandbox.ID, sandbox.RegistryAuthSealed)
	if err != nil {
		return fmt.Errorf("wasm: unseal registry auth for %s: %w", sandbox.ID, err)
	}
	sandbox.RegistryAuth = auth
	return nil
}

// persistSandboxCreate writes the sandbox row and its sealed environment in
// the same transaction.
func (s *Service) persistSandboxCreate(ctx context.Context, sandbox *models.Sandbox) error {
	if s == nil || s.store == nil {
		return errors.New("store is not configured")
	}
	if digests := createRequestDigestsFrom(ctx); sandbox.CreateRequestDigest == "" && len(digests) > 0 {
		sandbox.CreateRequestDigest = digests[0]
	}
	// A failover recreate is the same sandbox on another node, so its row
	// keeps the time the sandbox was first created. The age timers
	// (StopAtAge, DestroyAtAge, and the E2B timeout, which is stored as an
	// age) count from created_at and come back unchanged in the replicated
	// spec, so a row stamped with the recreate time moved every deadline out
	// by the sandbox's age. Billing still starts now: the usage cursor gets
	// the time this node made the row, which the created_at fallback gave
	// before (reconcileFallbackWindowStart).
	madeAt := sandbox.CreatedAt
	first := failoverCreatedAtFrom(ctx)
	keepFirstCreated := !first.IsZero() && first.Before(madeAt)
	if keepFirstCreated {
		sandbox.CreatedAt = first.UTC()
	}
	// Every new row refuses the sandbox tokens issued before it. The
	// not-before lives only in the owner's row, so a failover recreate (or
	// a WASM recreate or migration) onto another node would otherwise come
	// back with none and revive tokens revoked on the old owner; the same
	// holds for an id reused after a delete. Set in the INSERT itself, so
	// no request ever sees the row without it. A clock read, no I/O.
	// A sandbox moved here with its memory (C21) keeps its source row's
	// not-before instead: the move is planned and its bundle authenticated,
	// so the tokens that row refuses are exactly the ones to refuse.
	if notBefore := sandboxtoken.NotBeforeAt(sandboxTokenNow()); sandbox.TokensNotBefore < notBefore && movedIdentityFrom(ctx) == nil {
		sandbox.TokensNotBefore = notBefore
	}
	if strings.TrimSpace(sandbox.AuditIncarnationID) == "" {
		incarnationID, err := s.prepareAuditIncarnation(ctx, sandbox.ID, sandbox.ToolboxToken)
		if err != nil {
			return err
		}
		defer s.clearPendingAuditIncarnation(sandbox.ID, incarnationID)
		sandbox.AuditIncarnationID = incarnationID
	}
	sealed, err := s.sealEnv(sandbox.ID, sandbox.AuditIncarnationID, sandbox.Env)
	if err != nil {
		return err
	}
	if err := s.store.CreateWithSealedEnv(ctx, sandbox, sealed); err != nil {
		return err
	}
	// A recreate-policy sandbox is in the lease file's fence before its
	// create is answered (T3, R9): the answer lets the cluster recreate it
	// elsewhere, so the runtime supervisor must already know to freeze it
	// here if sandboxd dies. With SB_OWNERSHIP_LEASE_FILE only: one listing
	// of this node's rows and one small file write, plus one ownership read
	// on the first such create after a start. A fence that cannot be written
	// fails the create, and its row goes with it.
	if sandbox.Failover != nil && sandbox.Failover.ShouldRecreate() {
		if err := s.publishOwnershipFence(ctx); err != nil {
			if rbErr := s.store.RollbackSandboxCreate(context.WithoutCancel(ctx), sandbox.ID, sandbox.AuditIncarnationID); rbErr != nil && s.logger != nil {
				s.logger.Error("create: could not remove the row of a sandbox whose fence failed", "sandbox_id", sandbox.ID, "error", rbErr)
			}
			return err
		}
	}
	if keepFirstCreated && s.usageEnabled() {
		s.advanceUsageCursor(sandbox.ID, madeAt)
	}
	// The row is the authority from here on. Complete the lifecycle identity
	// so audit stamps carry the tenant owner instead of the blank one the
	// pre-persist nonce necessarily resolves to.
	s.finalizeAuditIdentity(sandbox.ID, sandbox.AuditIncarnationID, sandbox.OwnerRef)
	// A lifetime STARTING is a lifecycle boundary too. Anything that resolved
	// the binding before this row existed — a capability probe, a retry of the
	// previous lifetime under a reused deterministic id — left a negative
	// lease that would reject this lifetime's own valid capability until it
	// expired. Two map writes under a mutex; no I/O on the boot path.
	s.invalidateAuditOwnershipLease(sandbox.ID)
	return nil
}

// sealEnv marshals env and encrypts it for at-rest storage. Returns nil when
// env is empty (no sandbox_env row).
func (s *Service) sealEnv(sandboxID, incarnationID string, env map[string]string) ([]byte, error) {
	if len(env) == 0 {
		return nil, nil
	}
	if sandboxID == "" || incarnationID == "" {
		return nil, errors.New("seal env: sandbox id and incarnation id are required")
	}
	plain, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal env: %w", err)
	}
	if s.cipher == nil {
		return nil, fmt.Errorf("env cipher is not configured")
	}
	sealed, err := s.cipher.EncryptWithAAD(plain, secrets.EnvAAD(sandboxID, incarnationID))
	if err != nil {
		return nil, fmt.Errorf("encrypt env: %w", err)
	}
	return sealed, nil
}

// loadEnv reads the sealed sandbox_env row. Explicit loads are audited (D9 / T6).
func (s *Service) loadEnv(ctx context.Context, sandboxID, incarnationID string) (env map[string]string, err error) {
	sealed, envPresent, auditIncarnationID, auditOwnerRef, getErr := s.store.GetEnvWithIdentity(ctx, sandboxID)
	done := s.beginSecretAuditFor(ctx, sandboxID, envAuditRef(sandboxID), s.auditActor(), auditIncarnationID, auditOwnerRef)
	defer func() { done(err) }()

	if getErr == nil {
		if auditIncarnationID != incarnationID {
			return nil, fmt.Errorf("%w: sandbox lifecycle changed before env read", secrets.ErrDecryptFailed)
		}
		if owner, scoped := ownerScope(ctx); scoped && owner != auditOwnerRef {
			return nil, store.ErrNotFound
		}
	}
	if getErr == nil && len(sealed) > 0 {
		if s.cipher == nil {
			return nil, fmt.Errorf("%w: env cipher is not configured", secrets.ErrDecryptFailed)
		}
		plain, decErr := s.cipher.DecryptWithAAD(sealed, secrets.EnvAAD(sandboxID, auditIncarnationID))
		if decErr != nil {
			return nil, sealedOpenError("decrypt env", decErr)
		}
		var out map[string]string
		if umErr := json.Unmarshal(plain, &out); umErr != nil {
			return nil, fmt.Errorf("%w: unmarshal env: %v", secrets.ErrDecryptFailed, umErr)
		}
		if out == nil {
			out = map[string]string{}
		}
		return out, nil
	}
	if getErr == nil && !envPresent {
		// The sandbox row exists but its sealed env row does not. Every create
		// writes one (empty when the sandbox has no environment) and warm
		// upgrades are backfilled, so absence is loss — not "no env". Mapping
		// it to an empty map is how a start/wake without a replicated spec
		// used to boot a sandbox stripped of its credentials; fail loud
		// instead so the operator sees it.
		return nil, fmt.Errorf("%w: sealed env row is missing for sandbox %s", secrets.ErrDecryptFailed, sandboxID)
	}
	if errors.Is(getErr, store.ErrNotFound) || (getErr == nil && len(sealed) == 0) {
		return map[string]string{}, nil
	}
	return nil, getErr
}

// hydrateSandboxEnvForRestore materialises a sandbox's environment before a
// runtime restore hands the row to a driver.
//
// The hardened schema has no env_json column — sealed sandbox_env is the only
// source — so a row read back with store.Get always has Env nil. The WASM
// driver builds an instance's baseEnv from exactly that field, so restoring
// from an unhydrated row brings the sandbox back with an empty environment and
// every later exec silently loses its credentials. StartSandbox loads env for
// this reason; the failover-recreate paths must too, and a retry after a
// failed restore is precisely where the row is read back instead of built.
//
// specEnv is the decrypted create spec's environment when the caller has one
// (failover recreate opens the cluster secret bag). It is the fallback for a
// row whose sealed env is missing, and the seal is repaired from it so the
// next restore on this node does not depend on the spec being available again.
func (s *Service) hydrateSandboxEnvForRestore(ctx context.Context, sandbox *models.Sandbox, specEnv map[string]string) error {
	if s == nil || sandbox == nil || len(sandbox.Env) > 0 {
		return nil
	}
	env, err := s.loadEnv(ctx, sandbox.ID, sandbox.AuditIncarnationID)
	if err != nil {
		if len(specEnv) == 0 {
			return fmt.Errorf("load sealed env for %s: %w", sandbox.ID, err)
		}
		// The authenticated cluster-secret bag carries the same credentials the
		// local seal was written from, so an unreadable seal is worth a warning
		// and a repair, not a sandbox that never comes back.
		if s.logger != nil {
			s.logger.Warn("sealed env unreadable on restore; falling back to the placement spec",
				"sandbox_id", sandbox.ID, "error", err)
		}
		env = nil
	}
	if len(env) > 0 {
		sandbox.Env = env
		return nil
	}
	if len(specEnv) == 0 {
		return nil
	}
	sandbox.Env = specEnv
	return s.repairSealedEnv(ctx, sandbox)
}

// repairSealedEnv writes the sealed row for an environment recovered from the
// placement spec. Failure is returned rather than logged: the restore has not
// started yet, so the caller can retry a whole attempt instead of running a
// sandbox whose next wake would lose its environment again.
func (s *Service) repairSealedEnv(ctx context.Context, sandbox *models.Sandbox) error {
	if s == nil || s.store == nil || sandbox == nil {
		return nil
	}
	incarnationID := strings.TrimSpace(sandbox.AuditIncarnationID)
	if incarnationID == "" {
		return nil
	}
	sealed, err := s.sealEnv(sandbox.ID, incarnationID, sandbox.Env)
	if err != nil {
		return fmt.Errorf("seal recovered env for %s: %w", sandbox.ID, err)
	}
	if len(sealed) == 0 {
		return nil
	}
	return s.store.PutEnv(ctx, sandbox.ID, sealed)
}

// sealMounts marshals the user's mount specs and encrypts the JSON for
// at-rest storage. Returns nil when there are no mounts.
func (s *Service) sealMounts(specs []models.MountSpec) ([]byte, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	plain, err := json.Marshal(models.MountSpecFile{Mounts: specs})
	if err != nil {
		return nil, fmt.Errorf("marshal mounts: %w", err)
	}
	sealed, err := s.cipher.Encrypt(plain)
	if err != nil {
		return nil, fmt.Errorf("encrypt mounts: %w", err)
	}
	return sealed, nil
}

// loadMounts reads, decrypts, and unmarshals a sandbox's stored mount specs.
// Returns nil, nil when the sandbox has no mounts. Decrypt attempts are
// audited under ref mounts:{sandboxID}.
func (s *Service) loadMounts(ctx context.Context, sandboxID string) (specs []models.MountSpec, err error) {
	sealed, getErr := s.store.GetMounts(ctx, sandboxID)
	if getErr != nil {
		if errors.Is(getErr, store.ErrNotFound) {
			return nil, nil
		}
		return nil, getErr
	}
	if len(sealed) == 0 {
		return nil, nil
	}
	auditIncarnationID, auditOwnerRef := s.auditIdentityFor(sandboxID)
	done := s.beginSecretAuditFor(ctx, sandboxID, mountsAuditRef(sandboxID), s.auditActor(), auditIncarnationID, auditOwnerRef)
	defer func() { done(err) }()
	if s.cipher == nil {
		return nil, fmt.Errorf("%w: mounts cipher is not configured", secrets.ErrDecryptFailed)
	}
	plain, decErr := s.cipher.Decrypt(sealed)
	if decErr != nil {
		return nil, sealedOpenError("decrypt mounts", decErr)
	}
	var file models.MountSpecFile
	if umErr := json.Unmarshal(plain, &file); umErr != nil {
		return nil, fmt.Errorf("%w: unmarshal mounts: %v", secrets.ErrDecryptFailed, umErr)
	}
	return file.Mounts, nil
}

// ListMounts returns the redacted mount config for a sandbox. Credentials are
// never included in the response — they are write-only via CreateSandbox.
func (s *Service) ListMounts(ctx context.Context, sandboxID string) ([]models.MountSpecRedacted, error) {
	if _, err := s.scopedGet(ctx, sandboxID); err != nil {
		return nil, err
	}
	specs, err := s.loadMounts(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	return models.RedactMounts(specs), nil
}

// generateSandboxSSHKeys produces an ed25519 keypair scoped to a single
// sandbox. The OpenSSH-format authorized public key is what the gateway will
// store on the sandbox record; the PEM-encoded private key is returned to the
// caller exactly once and never persisted.
func generateSandboxSSHKeys() (authorizedKey, privateKeyPEM string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("derive signer: %w", err)
	}
	authorizedKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	block, err := ssh.MarshalPrivateKey(priv, "AerolVM sandbox key")
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	privateKeyPEM = string(pem.EncodeToMemory(block))
	return authorizedKey, privateKeyPEM, nil
}

// GetSandboxOptions controls public Get/List env materialization (D9).
type GetSandboxOptions struct {
	IncludeEnv bool
	// CorrelationID is attached to the audited include_env load when set
	// (typically from X-Correlation-ID / X-Request-ID).
	CorrelationID string
}

func (s *Service) GetSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	return s.GetSandboxWithOptions(ctx, id, GetSandboxOptions{})
}

// HasLocalSandbox reports whether this node's store holds a row for id,
// unscoped (the handler that serves the row applies owner scoping). Only a
// definite miss is false: any other store error is true, so the caller serves
// locally and the handler surfaces that error instead of a guessed absence.
// The cluster router asks it only while the placement view is catching up.
func (s *Service) HasLocalSandbox(ctx context.Context, id string) bool {
	if s == nil || s.store == nil || strings.TrimSpace(id) == "" {
		return false
	}
	_, err := s.store.Get(ctx, id)
	return !errors.Is(err, store.ErrNotFound)
}

// GetSandboxWithOptions returns a sandbox. Env is omitted unless IncludeEnv
// is set; that opt-in path loads via loadEnv and is audited.
func (s *Service) GetSandboxWithOptions(ctx context.Context, id string, opts GetSandboxOptions) (*models.Sandbox, error) {
	sb, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	s.attachFailoverReady(ctx, sb)
	sb.EgressStatus = s.EgressStatus(ctx, sb)
	s.showEgressProfiles(ctx, sb)
	if opts.IncludeEnv {
		env, loadErr := s.loadEnv(ContextWithSecretAuditCorrelation(ctx, opts.CorrelationID), id, sb.AuditIncarnationID)
		if loadErr != nil {
			return nil, loadErr
		}
		sb.Env = env
	} else {
		sb.Env = nil
	}
	return sb, nil
}

// ListSandboxes returns sandboxes whose Tags match every entry in tagFilter.
// A nil or empty filter returns every sandbox on this node. Filtering happens
// in-memory after the store read because Tags is JSON-encoded; pushing the
// filter into SQL via json_extract is a follow-up once row counts make the
// extra hop worth it. The filter exists so an external control plane can ask
// "give me the sandboxes belonging to user X" without round-tripping every
// sandbox in the cluster (see plans/multi-tenancy-via-control-plane.md).
// Env is always omitted (D9); use ListSandboxesWithOptions to opt in.
func (s *Service) ListSandboxes(ctx context.Context, tagFilter map[string]string) ([]*models.Sandbox, error) {
	return s.ListSandboxesWithOptions(ctx, tagFilter, GetSandboxOptions{})
}

// ListSandboxesWithOptions is ListSandboxes with optional IncludeEnv (audited).
func (s *Service) ListSandboxesWithOptions(ctx context.Context, tagFilter map[string]string, opts GetSandboxOptions) ([]*models.Sandbox, error) {
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	// Owner scoping first: a user token sees only its own sandboxes; operator
	// and internal callers see all. Applied before the tag filter so a tenant
	// can't tag-probe across owners.
	sandboxes = filterByOwnerScope(ctx, sandboxes)
	if len(tagFilter) == 0 {
		s.attachFailoverReadyAll(ctx, sandboxes)
		if err := s.applyListEnvOptions(ctx, sandboxes, opts); err != nil {
			return nil, err
		}
		return sandboxes, nil
	}
	filtered := sandboxes[:0]
	for _, sb := range sandboxes {
		if sandboxMatchesTags(sb, tagFilter) {
			filtered = append(filtered, sb)
		}
	}
	s.attachFailoverReadyAll(ctx, filtered)
	if err := s.applyListEnvOptions(ctx, filtered, opts); err != nil {
		return nil, err
	}
	return filtered, nil
}

func (s *Service) applyListEnvOptions(ctx context.Context, sandboxes []*models.Sandbox, opts GetSandboxOptions) error {
	s.showEgressProfiles(ctx, sandboxes...)
	if opts.IncludeEnv {
		loadCtx := ContextWithSecretAuditCorrelation(ctx, opts.CorrelationID)
		for _, sb := range sandboxes {
			if sb == nil {
				continue
			}
			env, err := s.loadEnv(loadCtx, sb.ID, sb.AuditIncarnationID)
			if err != nil {
				return err
			}
			sb.Env = env
		}
		return nil
	}
	for _, sb := range sandboxes {
		if sb != nil {
			sb.Env = nil
		}
	}
	return nil
}

// sandboxMatchesTags returns true iff every key in want is present on sb.Tags
// with the same value. An empty want matches everything (caller short-circuits).
// ListSandboxesByName returns the caller's sandbox called name as a list of
// zero or one, so a lookup by name and a list share one wire shape (the v1
// GET /sandboxes?name= filter). Names are unique per owner and the lookup runs
// in the caller's namespace (ResolveSandboxIDByName), so another tenant's
// name reads as an empty list rather than revealing that it exists. A tag
// filter still applies to the one row.
func (s *Service) ListSandboxesByName(ctx context.Context, name string, tagFilter map[string]string, opts GetSandboxOptions) ([]*models.Sandbox, error) {
	empty := []*models.Sandbox{}
	id, err := s.ResolveSandboxIDByName(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return empty, nil
	}
	if err != nil {
		return nil, err
	}
	sb, err := s.GetSandboxWithOptions(ctx, id, opts)
	if errors.Is(err, store.ErrNotFound) {
		return empty, nil
	}
	if err != nil {
		return nil, err
	}
	if !sandboxMatchesTags(sb, tagFilter) {
		return empty, nil
	}
	return []*models.Sandbox{sb}, nil
}

func sandboxMatchesTags(sb *models.Sandbox, want map[string]string) bool {
	for k, v := range want {
		if sb.Tags[k] != v {
			return false
		}
	}
	return true
}

// StartSandbox starts a sandbox inside the lifecycle boundary
// (lifecycle_boundary.go): it waits for any start, stop or restart of the
// same sandbox already in flight, and a stop that comes during it waits for
// it in turn.
func (s *Service) StartSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.startSandboxLocked(ctx, id, startRequested)
}

// startCause says who starts a sandbox: a call (API, facade, wake, fleet
// restore) or a restart on failure.
type startCause int

const (
	startRequested startCause = iota
	// startForRestart keeps LastActiveAt: a restart is not activity, so a
	// sandbox that keeps crashing still reaches its idle timer.
	startForRestart
)

// startSandboxLocked is the start itself. The caller holds the lifecycle
// boundary for id.
func (s *Service) startSandboxLocked(ctx context.Context, id string, cause startCause) (_ *models.Sandbox, err error) {
	// A fenced sandbox may be running on another node by now: no start of
	// any kind (API, wake, restart on failure) until ownership is confirmed
	// (ownership_lease.go).
	if s.OwnershipFenced(id) {
		return nil, ErrOwnershipFenced
	}
	// A started sandbox gets a fresh identity token at once, a restart on
	// failure included (no-op for one without an identity, or a deployment
	// that is not an issuer).
	defer func() {
		if err == nil {
			s.kickIdentityPush(id)
		}
	}()
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	// A row a move release fenced, which this process never saw (it
	// restarted since): refused like any fenced sandbox until the fence in
	// the row lapses (R11).
	if err := s.refuseMovedRowStart(sandbox); err != nil {
		return nil, err
	}
	// Sealed-env mode omits Env from store scans. Runtime paths (especially
	// WASM reconstruct / passivate rehydrate) need the materialised map —
	// public Get/List redaction must not starve internal start.
	if env, loadErr := s.loadEnv(ctx, id, sandbox.AuditIncarnationID); loadErr != nil {
		return nil, loadErr
	} else if len(env) > 0 {
		sandbox.Env = env
	}
	wasmPassivated := s.isWasmSandbox(sandbox) && sandbox.Status == models.SandboxStatusPassivated
	var wasmRehydrateBinds []mounts.ContainerBind
	if wasmPassivated {
		specs, loadErr := s.loadMounts(ctx, id)
		if loadErr != nil {
			return nil, loadErr
		}
		if len(specs) > 0 {
			if err := s.mounts.Reestablish(ctx, id, specs); err != nil {
				return nil, fmt.Errorf("reestablish mounts: %w", err)
			}
			wasmRehydrateBinds = s.mounts.HostBindsFor(id)
		}
		sandbox, err = s.rehydrateWasmIfNeeded(ctx, sandbox, wasmRehydrateBinds)
		if err != nil {
			return nil, err
		}
	}

	// A sandbox created with a firewall policy, on a node whose firewall has
	// since been turned off, stays stopped: starting it would run it open
	// while GET still shows the policy. Nothing has been touched yet.
	if err := s.checkSandboxNetRules(sandbox, "start", sandboxFirewallFields(sandbox)); err != nil {
		return nil, err
	}

	// A team over its quota (an admin lowered it) does not bring stopped
	// sandboxes back; a start adds nothing to usage otherwise (P2).
	if err := s.checkTeamQuotaForStart(ctx, sandbox); err != nil {
		return nil, err
	}
	// Re-Admit against the host budget before touching Docker. StopSandbox
	// (and the die/stop/oom event handler) releases the reservation, so a
	// stopped sandbox does not hold capacity. Admit is idempotent per ID:
	// already-running sandboxes computed against the same footprint succeed
	// without double-counting. A failed admission must not mutate any state.
	if s.admitter != nil {
		if err := s.admitter.Admit(id, capacityRequestFromSandbox(sandbox)); err != nil {
			return nil, err
		}
	}
	releaseAdmission := func() {
		if s.admitter != nil {
			s.admitter.Release(id)
		}
	}

	specs, err := s.loadMounts(ctx, id)
	if err != nil {
		releaseAdmission()
		return nil, err
	}
	if len(specs) > 0 {
		if err := s.mounts.Reestablish(ctx, id, specs); err != nil {
			releaseAdmission()
			return nil, fmt.Errorf("reestablish mounts: %w", err)
		}
	}

	rt, err := s.runtimeForSandbox(sandbox)
	if err != nil {
		releaseAdmission()
		return nil, err
	}
	var state *models.SandboxRuntimeState
	if s.isWasmSandbox(sandbox) {
		if host, ok := s.wasm.(wasmruntime.StartHost); ok {
			hostBinds := s.mounts.HostBindsFor(id)
			// Unseal per-tenant registry creds so a private oci:// module
			// re-pulls under the tenant's identity if this node lacks it
			// (codex C4). Transient: never persisted or serialized.
			if err := s.attachWasmRegistryAuth(ctx, sandbox); err != nil {
				_ = s.mounts.UnmountAll(id)
				releaseAdmission()
				_ = s.store.UpdateStatus(ctx, id, models.SandboxStatusError, err.Error())
				return nil, err
			}
			state, err = host.StartSandbox(ctx, sandbox, hostBinds)
			if err != nil {
				_ = s.mounts.UnmountAll(id)
				releaseAdmission()
				_ = s.store.UpdateStatus(ctx, id, models.SandboxStatusError, err.Error())
				s.invalidateWarm(id)
				return nil, err
			}
		}
	}
	if state == nil {
		if es, ok := runtime.AsEnvIdentityStarter(rt); ok {
			state, err = es.StartWithIdentityEnv(ctx, s.runtimeRef(sandbox), sandbox.ID, sandbox.ToolboxToken, s.adoptEnvLoader(sandbox))
		} else if is, ok := runtime.AsIdentityStarter(rt); ok {
			state, err = is.StartWithIdentity(ctx, s.runtimeRef(sandbox), sandbox.ID, sandbox.ToolboxToken)
		} else {
			state, err = rt.Start(ctx, s.runtimeRef(sandbox))
		}
		if err != nil {
			_ = s.mounts.UnmountAll(id)
			releaseAdmission()
			if capacity.IsNetworkExhaustion(err) {
				// A full bridge refused the start the way admission
				// would have: the sandbox is still stopped and a retry
				// can start it, so it is not marked error.
				s.invalidateWarm(id)
				return nil, capacity.AsNetworkSlotExhausted(networkSlotPool(models.SandboxEngine(sandbox)), err)
			}
			_ = s.store.UpdateStatus(ctx, id, models.SandboxStatusError, err.Error())
			s.invalidateWarm(id)
			return nil, err
		}
	}
	// The runtime has a new run from here, whatever fails below: an exit
	// event of an earlier run, queued behind this start, is told apart from
	// now on (run_starts.go).
	s.noteRunStart(id, state.StartedAt)
	sandbox.ContainerID = state.ContainerID
	sandbox.ContainerIP = state.ContainerIP
	sandbox.Status = state.Status
	sandbox.WakeArmed = false
	// A start answers whatever stopped the sandbox. The store writes these
	// only with the status change, so a start racing its own start event
	// still lands one clean record.
	sandbox.StatusReason = ""
	sandbox.ExitCode = nil
	sandbox.UpdatedAt = time.Now().UTC()
	if cause != startForRestart {
		sandbox.LastActiveAt = time.Now().UTC()
	}
	// Put the stored egress policy back before the start reports success or
	// publishes a route: the stop event cleared it, since the IP can be
	// reassigned to another container. Fail closed: a sandbox whose isolation
	// can't be restored is stopped. A gateway-mode sandbox whose attach fails
	// starts shut and held instead (plans/egress-domain-filtering.md §5.7,
	// CEO D16). An unfinished transition, or rules another sandbox left at
	// the new address, are rebuilt first (review 6 findings 1 and 2).
	clearGen := s.egressClears.now()
	if cr, ok := runtime.AsContainerRuntime(rt); ok {
		if err := s.enforceEgressOnStart(ctx, cr, sandbox); err != nil {
			_ = rt.Stop(ctx, s.runtimeRef(sandbox))
			_ = s.mounts.UnmountAll(id)
			releaseAdmission()
			_ = s.store.UpdateStatus(ctx, id, models.SandboxStatusError, err.Error())
			return nil, err
		}
	} else if err := egressUnsupportedOnStart(sandbox); err != nil {
		_ = rt.Stop(ctx, s.runtimeRef(sandbox))
		_ = s.mounts.UnmountAll(id)
		releaseAdmission()
		return nil, err
	}

	if err := s.syncSandboxPublicRoute(ctx, sandbox); err != nil {
		return nil, err
	}
	for _, port := range sandbox.ExposedPorts {
		if err := s.syncExposedPortRoute(ctx, sandbox, port); err != nil {
			return nil, err
		}
	}

	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return nil, err
	}
	// A start by a call answers a crash too: a restart still waiting for
	// its backoff would only start it a second time.
	if cause == startRequested && sandbox.RestartAt != nil {
		// Logged inside; a running sandbox is not restarted, and its next
		// stop cancels again.
		_ = s.cancelPendingRestart(ctx, sandbox, "")
	}
	if cause == startForRestart {
		recordSandboxStart(startKindRestarted)
	} else {
		recordSandboxStart(startKindRequested)
	}
	s.settleEgressAttach(id)
	s.settleEnforcedEgress(ctx, sandbox, clearGen)
	warmGen := s.warmGen.Load()
	refreshed, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	s.syncAllowedPorts(ctx, refreshed)
	// Populate the warm-preflight cache so the convoy of HTTP requests
	// released by this wake skips the SQLite preflight on the way to
	// the now-warm upstream. invalidateWarm fires from every stop /
	// destroy path so a later transition out of Started invalidates.
	if refreshed.Status == models.SandboxStatusStarted {
		s.warmCacheSetSandbox(refreshed, warmGen)
	}
	return refreshed, nil
}

// egressUnsupportedOnStart refuses a start on a runtime without host rules
// when the sandbox has egress enforcement for them to carry.
func egressUnsupportedOnStart(sb *models.Sandbox) error {
	switch {
	case sb.NetworkBlockAll:
		return fmt.Errorf("apply network block on start: runtime %q does not support network_block_all", sb.Runtime)
	case isGatewayMode(sb):
		return fmt.Errorf("apply egress on start: runtime %q does not support egress filtering", sb.Runtime)
	case len(sb.NetworkAllowOut) > 0 || len(sb.NetworkDenyOut) > 0:
		return fmt.Errorf("apply egress policy on start: runtime %q does not support selective egress", sb.Runtime)
	}
	return nil
}

// StopSandbox is the operator-initiated stop (API surface, manual). It is a
// thin wrapper over stopSandboxInternal that pins the stop mode to manual:
// wake_armed is always cleared, so a serverless sandbox stopped via this
// path stays down until the operator explicitly starts it again.
// See serverless.go for the full wake-arming policy. It runs inside the
// lifecycle boundary: a restart on failure already starting the sandbox
// finishes first, and this stop then stops it.
func (s *Service) StopSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	return s.stopSandboxInternal(ctx, id, stopModeManual)
}

// DestroySandbox deletes a sandbox inside the lifecycle boundary, so a start
// or a restart on failure in flight cannot write the row back after the
// delete (Upsert inserts a missing row).
//
// With no local row, a cluster node may still own the sandbox's placement:
// one reassigned to it by a failover that its owner watcher has not recreated
// yet. destroyUnmaterializedPlacement deletes that placement instead of
// answering 404. It runs after the lifecycle lock is released, because it
// takes the create lease, and the lock order is create lease, then lifecycle
// lock (a create's rollback destroys under its lease).
func (s *Service) DestroySandbox(ctx context.Context, id string) error {
	err := s.destroySandboxUnderLifecycleLock(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return s.destroyUnmaterializedPlacement(ctx, id, err)
	}
	return err
}

// destroySandboxUnderLifecycleLock runs the local destroy inside the
// lifecycle boundary for id.
func (s *Service) destroySandboxUnderLifecycleLock(ctx context.Context, id string) error {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	return s.destroySandboxLocked(ctx, id)
}

// destroySandboxLocked is the destroy itself. The caller holds the lifecycle
// boundary for id.
func (s *Service) destroySandboxLocked(ctx context.Context, id string) error {
	// A pending restart on failure is for a sandbox that is going away.
	s.cancelRestartTimer(id)
	unlock := s.destroyLocks.lock(id)
	defer unlock()
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return err
	}
	// Establish retained authorization before any runtime or route teardown.
	// Failure leaves both the sandbox row and its runtime intact for retry.
	if err := s.retainSandboxAuditACL(ctx, sandbox); err != nil {
		return err
	}
	if placement, obsolete, err := s.obsoleteLocalPlacement(ctx, sandbox); err != nil {
		return err
	} else if obsolete {
		return s.destroyStaleLocalSandbox(ctx, sandbox, placement)
	}
	// Commit the exact owner/incarnation deleting fence BEFORE any destructive
	// local work. Routes and the runtime are not recoverable once torn down,
	// so tearing them down while the placement is still recreate-eligible
	// leaves a window where Raft is unavailable (or ownership moves) and the
	// cluster re-materializes a sandbox whose local materialization is already
	// gone. Fencing first inverts that: a Raft outage fails the destroy with
	// nothing torn down, and every step after this point is a retry from a
	// durable deleting state (opBeginDelete is a no-op on an already-deleting
	// placement, and the fence's TTL only expires once its owner is gone).
	if err := s.beginSelfOwnedClusterPlacementDeleteStrict(ctx, sandbox); err != nil {
		return err
	}
	// delete_with_sandbox volumes (platform_volumes_lifetime.go): recorded
	// now, while the attachments still say which; deleted once they are gone.
	dwsVolumes := s.recordSandboxVolumeDeletes(ctx, sandbox)
	for _, port := range sandbox.ExposedPorts {
		_ = s.deleteExposedPortRoute(ctx, sandbox, port)
	}
	// deleteSandboxPublicRoutes (not DeleteSandboxRoute) so the per-custom-domain
	// leaf routes installed by UpsertSandboxRoute are torn down too. store.Delete
	// below cascades the custom_domain DB rows, but the caddy routes are separate
	// state and would otherwise be orphaned on every destroy. nil-caddy safe.
	_ = s.deleteSandboxPublicRoutes(ctx, sandbox)
	rt, err := s.runtimeForSandbox(sandbox)
	if err != nil {
		return err
	}
	// Leave the egress gateway only once the workload is gone: a destroy
	// that fails leaves the sandbox running, and still filtered, for the
	// retry (review finding 3). And leave it before the address is free:
	// the runtime calls the releaser between the two (containerd, a pause
	// netns, Firecracker), so no other sandbox ever meets this one's
	// gateway state. A runtime whose address goes with the container
	// (Docker's IPAM) can't, and the teardown below detaches right after;
	// there the gateway's IP ownership check (D5) and a new gateway-mode
	// owner's own Attach purge cover the reuse.
	if err := rt.Destroy(s.gatewayReleaserCtx(ctx, sandbox, false), sandbox); err != nil {
		return err
	}
	// The runtime is gone: end its toolbox requests now, and again on the
	// way out for one that read the row meanwhile (toolbox_calls.go).
	s.endToolboxCalls(id, toolboxEndDestroyed, "destroyed")
	defer s.endToolboxCalls(id, toolboxEndDestroyed, "destroyed")
	// Everything the installed record names goes: a transition that didn't
	// finish may have left a gateway attachment and CIDR rules at once. The
	// row is the retry anchor until those are recorded against the address
	// (review 6 finding 3); a retried destroy finds the runtime gone.
	if err := s.teardownSandboxEgress(ctx, sandbox, sandbox.ContainerIP); err != nil {
		return err
	}
	s.egressPids.Delete(id)
	s.forgetLearned(ctx, sandbox)
	if s.testAfterRuntimeDestroy != nil {
		s.testAfterRuntimeDestroy()
	}
	if s.mounts != nil {
		err := s.mounts.UnmountAll(id)
		if s.testForceUnmountErr != nil {
			err = s.testForceUnmountErr
		}
		if err != nil {
			s.logger.Warn("unmount on destroy failed", "sandbox_id", id, "error", err)
		}
	} else if s.testForceUnmountErr != nil {
		s.logger.Warn("unmount on destroy failed", "sandbox_id", id, "error", s.testForceUnmountErr)
	}
	// Defence in depth. The deleting fence above blocks reassignment, so this
	// should no longer be reachable in cluster mode; it stays because a
	// pre-fence placement (or a non-cluster path that reaches here) must still
	// preserve an active lifecycle rather than delete its secrets.
	if placement, obsolete, err := s.obsoleteLocalPlacement(ctx, sandbox); err != nil {
		return err
	} else if obsolete {
		return s.finalizeStaleLocalSandbox(ctx, sandbox, placement, true)
	}
	// Tomb/outbox secret cleanup must succeed before the irreversible sandbox
	// delete. cluster_secrets has no FK, so a post-delete failure leaves
	// retries with ErrNotFound while ciphertext and peer copies remain.
	// Shared with docker-destroy and reconcile-destroyed paths.
	if err := s.DeleteClusterSecrets(ctx, id, sandbox.AuditIncarnationID); err != nil {
		return err
	}
	if err := s.cleanupWasmSandboxArtifacts(ctx, sandbox); err != nil {
		return err
	}
	// Placement deletion is part of the durable destroy boundary. Removing the
	// local row first would leave no retry anchor if Raft were unavailable, and
	// a recreate-enabled ghost placement could then resurrect a sandbox the
	// client was told was deleted. Owner+incarnation CAS protects a concurrent
	// failover or ID reuse. The FSM releases replicated volume attachments in
	// the same apply, so there is no second Raft cleanup window.
	if err := s.deleteSelfOwnedClusterPlacementStrict(ctx, sandbox); err != nil {
		return err
	}
	// ErrNotFound is benign here and must not fail the destroy: rt.Destroy above
	// makes Docker emit die+destroy, and handleDestroyEvent removes the row for
	// the same sandbox concurrently (events.go, which tolerates the mirror-image
	// race for exactly this reason). Everything between the two — secret tomb,
	// wasm cleanup, placement delete — widened that window enough that the event
	// watcher wins essentially every time, so an unguarded error here turned
	// every successful DELETE /v1/sandboxes/{id} into a 404 while the sandbox
	// was in fact fully deleted (observed 3/3 on single-node, 2026-09-23).
	//
	// The helper keeps returning the error on purpose — audit_ownership_lease_test
	// asserts that, and the fence must still run — so tolerance belongs at the
	// call site, matching the other callers of this helper.
	if err := s.deleteSandboxRowAndFenceAudit(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	s.finishSandboxVolumeDeletes(ctx, id, dwsVolumes)
	if s.testAfterStoreDeleteOnDestroy != nil {
		s.testAfterStoreDeleteOnDestroy()
	}
	s.forgetWakeFlight(id)
	s.invalidateWarm(id)
	s.forgetNetstatsActivity(id)
	s.runStarts.forget(id)
	if s.admitter != nil {
		s.admitter.Release(id)
	}
	s.releaseTeamQuota(sandbox)
	if s.logger != nil {
		s.logger.Info("audit sandbox destroyed", "sandbox_id", id, "image", sandbox.Image)
	}
	s.NoteLocalOwnersChanged()
	if !s.isWasmSandbox(sandbox) {
		s.schedulePendingImageGC(ctx, models.SandboxEngine(sandbox), sandbox.Image)
	}
	return nil
}

// deleteSandboxRowAndFenceAudit removes the authoritative local row and
// brackets it with the audit lifecycle fences.
//
// Invalidating only BEFORE the removal leaves a window: a resolve that starts
// after the invalidation still finds the row, and installs a POSITIVE
// identity and binding lease under the current epoch. Nothing retires those
// once the row is gone, so a capability for the destroyed lifetime keeps
// being accepted until the TTL expires. The second invalidation closes the
// window from both ends — it retires anything installed during the removal,
// and it bumps the epoch again, which fences a resolve still in flight from
// installing its answer at all.
//
// Every path that removes the row goes through here so the ordering cannot
// drift apart again.
func (s *Service) deleteSandboxRowAndFenceAudit(ctx context.Context, sandboxID string) error {
	s.invalidateAuditIdentity(sandboxID)
	s.invalidateAuditOwnershipLease(sandboxID)
	if s.testDuringSandboxRowDelete != nil {
		s.testDuringSandboxRowDelete()
	}
	err := s.store.Delete(ctx, sandboxID)
	// Fence after the transition whatever the outcome: a delete that failed
	// part way must not leave a lease minted from the window either.
	s.invalidateAuditIdentity(sandboxID)
	s.invalidateAuditOwnershipLease(sandboxID)
	if err == nil || errors.Is(err, store.ErrNotFound) {
		s.closeUsageMetrics(sandboxID)
	}
	return err
}

func (s *Service) deleteSelfOwnedClusterPlacement(ctx context.Context, placement cluster.Placement, reason string) {
	id := strings.TrimSpace(placement.SandboxID)
	if !s.cfg.EnableCluster || id == "" {
		return
	}
	c := s.Cluster()
	if c == nil {
		return
	}
	ownerID := strings.TrimSpace(placement.OwnerNodeID)
	incarnationID := strings.TrimSpace(placement.IncarnationID)
	if ownerID == "" || ownerID != strings.TrimSpace(c.SelfNodeID()) || incarnationID == "" {
		return
	}
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.DeletePlacementExact(commitCtx, id, ownerID, incarnationID); err != nil {
		s.logger.Warn("cluster placement delete after local destroy failed",
			"sandbox_id", id, "reason", reason, "error", err)
	}
}

func (s *Service) beginSelfOwnedClusterPlacementDeleteStrict(ctx context.Context, sandbox *models.Sandbox) error {
	if s == nil || sandbox == nil || !s.cfg.EnableCluster || strings.TrimSpace(sandbox.ID) == "" {
		return nil
	}
	c := s.Cluster()
	if c == nil {
		return fmt.Errorf("%w: placement client unavailable", ErrClusterFinalizationUnavailable)
	}
	incarnationID := strings.TrimSpace(sandbox.AuditIncarnationID)
	if incarnationID == "" {
		return fmt.Errorf("%w: sandbox incarnation_id is missing", ErrClusterFinalizationUnavailable)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	placements, err := c.AuthoritativePlacementsByIDs(lookupCtx, []string{sandbox.ID})
	cancel()
	if err != nil {
		return fmt.Errorf("%w: resolve authoritative placement before delete fence: %v", ErrClusterFinalizationUnavailable, err)
	}
	placement, ok := placements[sandbox.ID]
	if !ok {
		// Retry after an earlier final opDelete: the local row remains the
		// cleanup anchor and exact-incarnation secret cleanup is still safe.
		return nil
	}
	selfID := strings.TrimSpace(c.SelfNodeID())
	if strings.TrimSpace(placement.IncarnationID) != incarnationID || strings.TrimSpace(placement.OwnerNodeID) != selfID || placement.IsOrphaned() {
		return fmt.Errorf("%w: authoritative ownership changed before delete fence", ErrClusterFinalizationUnavailable)
	}
	commitCtx, commitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer commitCancel()
	if err := c.BeginDeletePlacementExact(commitCtx, sandbox.ID, selfID, incarnationID); err != nil {
		return fmt.Errorf("%w: begin authoritative placement delete: %v", ErrClusterFinalizationUnavailable, err)
	}
	return nil
}

func (s *Service) deleteSelfOwnedClusterPlacementStrict(ctx context.Context, sandbox *models.Sandbox) error {
	if s == nil || sandbox == nil || !s.cfg.EnableCluster || strings.TrimSpace(sandbox.ID) == "" {
		return nil
	}
	c := s.Cluster()
	if c == nil {
		return fmt.Errorf("%w: placement client unavailable", ErrClusterFinalizationUnavailable)
	}
	incarnationID := strings.TrimSpace(sandbox.AuditIncarnationID)
	if incarnationID == "" {
		return fmt.Errorf("%w: sandbox incarnation_id is missing", ErrClusterFinalizationUnavailable)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	placements, err := c.AuthoritativePlacementsByIDs(lookupCtx, []string{sandbox.ID})
	cancel()
	if err != nil {
		return fmt.Errorf("%w: resolve authoritative placement: %v", ErrClusterFinalizationUnavailable, err)
	}
	placement, ok := placements[sandbox.ID]
	if !ok {
		return nil
	}
	if strings.TrimSpace(placement.IncarnationID) != incarnationID {
		return fmt.Errorf("%w: local sandbox and authoritative placement lifecycles differ: %v",
			ErrClusterFinalizationUnavailable, cluster.ErrIncarnationConflict)
	}
	selfID := strings.TrimSpace(c.SelfNodeID())
	ownerID := strings.TrimSpace(placement.OwnerNodeID)
	if ownerID == "" || ownerID != selfID {
		// A stale-ownership reconcile destroys only local state. The current
		// owner's placement must remain intact.
		return nil
	}
	commitCtx, commitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer commitCancel()
	if err := c.DeletePlacementExact(commitCtx, sandbox.ID, ownerID, incarnationID); err != nil {
		return fmt.Errorf("%w: delete authoritative placement: %v", ErrClusterFinalizationUnavailable, err)
	}
	return nil
}

// CreateSnapshot commits the sandbox container into a reusable local image.
// Idempotency is by snapshot name: repeated requests for the same sandbox +
// name return the stored snapshot metadata, while a different sandbox trying
// to claim the same name is rejected with a conflict.
func (s *Service) CreateSnapshot(ctx context.Context, sandboxID string, req models.CreateSandboxSnapshotRequest) (*models.SandboxSnapshot, error) {
	snapshot, _, err := s.CreateSnapshotWithOwnership(ctx, sandboxID, req)
	return snapshot, err
}

// errReservedSnapshotName refuses a snapshot name in a namespace the daemon
// keeps its own images under (committed snapshots, builds): a catalog name
// there could pass for one of those images.
var errReservedSnapshotName = errors.New("snapshot names may not start with \"" + docker.SnapshotImageNamespace + "/\" or \"" + docker.BuiltImageNamespace + "/\"")

// validateSnapshotName checks a new snapshot's name.
func validateSnapshotName(name string) error {
	if name == "" {
		return errors.New("snapshot name is required")
	}
	if docker.IsSnapshotImageRef(name) || docker.IsBuiltImageRef(name) {
		return fmt.Errorf("%w: %q", errReservedSnapshotName, name)
	}
	return nil
}

// RegisterSnapshot persists a snapshot row whose Image was resolved out-of-band
// — either a pre-existing registry image the caller supplied by name, or a
// freshly built local tag produced by the image builder (e.g. the daytona
// facade's buildInfo path). It does NOT call docker.CreateSnapshot; the image
// is assumed to already be runnable. Idempotency is by snapshot name; a
// re-register with matching image is treated as a no-op so SDK retries don't
// fail. A different image under the same name is a conflict.
//
// The image is authorized as the caller now, the same way a create from it
// would be: a user token cannot record a pointer to an image it could not
// start, such as another tenant's snapshot named directly or through
// registered names of its own.
func (s *Service) RegisterSnapshot(ctx context.Context, snapshot *models.SandboxSnapshot) (*models.SandboxSnapshot, error) {
	if snapshot == nil {
		return nil, errors.New("snapshot is required")
	}
	name := strings.TrimSpace(snapshot.Name)
	if err := validateSnapshotName(name); err != nil {
		return nil, err
	}
	if strings.TrimSpace(snapshot.Image) == "" {
		return nil, errors.New("snapshot image is required")
	}
	if err := s.normalizeSnapshotImageDistribution(ctx, snapshot, false); err != nil {
		return nil, err
	}

	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()

	if existing, err := s.getSnapshotAnySpelling(ctx, name); err == nil {
		// Retry semantics: same name + same image → echo back the existing
		// row. Different image under the same name is a conflict, and so is
		// another tenant's row: names are global, but its contents are not
		// the caller's to read back. Another spelling of an existing name
		// conflicts too: the engine would treat the two as one image.
		if existing.Name == name && snapshotVisible(ctx, existing) && strings.TrimSpace(existing.Image) == strings.TrimSpace(snapshot.Image) {
			return existing, nil
		}
		return nil, store.ErrSnapshotNameConflict
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if slices.Contains(docker.EquivalentImageNames(name), strings.TrimSpace(snapshot.Image)) {
		// Named after its own image: there is no catalog row behind it
		// (none has this name), so only the reference form is checked.
		if owner, scoped := ownerScope(ctx); scoped {
			if err := authorizeTenantImageRef(owner, snapshot.Image); err != nil {
				return nil, err
			}
		}
	} else if _, _, err := s.resolveSnapshotChain(ctx, snapshot.Image, name); err != nil {
		return nil, err
	}

	if snapshot.CreatedAt.IsZero() {
		snapshot.CreatedAt = time.Now().UTC()
	}
	snapshot.Name = name
	snapshot.OwnerRef = ownerRefForCreate(ctx)
	// Only a commit has a source sandbox; that is how a delete tells an
	// image the snapshot owns from one it only names.
	snapshot.SourceSandboxID = ""
	snapshot.PushState = s.initialSnapshotPushState(snapshot)
	if err := s.store.CreateSnapshot(ctx, snapshot); err != nil {
		return nil, err
	}
	s.kickSnapshotPushReconciler(snapshot)
	s.registerSnapshotHome(ctx, snapshot)
	return snapshot, nil
}

// CreateSnapshotWithOwnership commits a sandbox image and reports whether this
// call created the native snapshot row. Callers that add companion metadata can
// use the flag to avoid rolling back a snapshot that already existed.
func (s *Service) CreateSnapshotWithOwnership(ctx context.Context, sandboxID string, req models.CreateSandboxSnapshotRequest) (*models.SandboxSnapshot, bool, error) {
	name := strings.TrimSpace(req.Name)
	if err := validateSnapshotName(name); err != nil {
		return nil, false, err
	}

	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()

	// Every spelling of the name, not just this one: the runtime commits to
	// the name as an image tag, and "snap" and "snap:latest" are one tag, so
	// a second owner committing to either would replace the first owner's
	// image under its catalog row.
	if existing, err := s.getSnapshotAnySpelling(ctx, name); err == nil {
		return replayExistingSnapshot(ctx, existing, sandboxID)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}

	sandbox, err := s.scopedGet(ctx, sandboxID)
	if err != nil {
		return nil, false, err
	}
	if err := snapshotPauseAllowed(sandbox, req.AllowPause); err != nil {
		return nil, false, err
	}

	rt, err := s.runtimeForSandbox(sandbox)
	if err != nil {
		return nil, false, err
	}
	// The image goes under a tag of the snapshot's own, never under its
	// name: a name is the caller's choice, and as a tag it would replace
	// whatever image already had it on this node — "python" for everyone.
	// The tag is scoped to the snapshot's owner so two tenants committing a
	// same-named snapshot on one node do not collide on one local image.
	image := docker.SnapshotImageTagForOwner(sandbox.OwnerRef, name)
	// Rollback rule (pr-review §4): the image exists from the moment the
	// commit returns, the catalogue row that owns it only from the insert
	// below. A failure or a crash between the two would leave an image
	// nothing names, so the cleanup is recorded durably BEFORE the commit
	// and cleared only once the row is in. Any exit in between leaves the
	// intent for runPendingImageGC; a failure after the commit also removes
	// the image right away (rollbackSnapshotCommit). snapshotMu, held from
	// before the commit until after the insert, keeps the janitor off a tag
	// whose create is in flight.
	engine, engineImage := snapshotCommitEngine(sandbox)
	if engineImage {
		if err := s.recordSnapshotCommitIntent(ctx, engine, image); err != nil {
			return nil, false, err
		}
	}
	imageID, err := rt.CreateSnapshot(ctx, s.runtimeRef(sandbox), image)
	if err != nil {
		// The intent stays: a commit that failed here can still land its
		// tag (an engine finishing after the caller gave up), and the
		// janitor removes whatever is there once no row names it.
		return nil, false, err
	}

	snapshot := &models.SandboxSnapshot{
		Name:            name,
		Image:           image,
		ImageID:         imageID,
		SourceSandboxID: sandboxID,
		CreatedAt:       time.Now().UTC(),
		// The source sandbox's owner, not the caller's: an operator
		// snapshotting a tenant's sandbox produces that tenant's snapshot.
		OwnerRef: sandbox.OwnerRef,
	}
	if err := s.normalizeSnapshotImageDistribution(ctx, snapshot, true); err != nil {
		s.rollbackSnapshotCommit(ctx, engineImage, engine, image)
		return nil, false, err
	}
	snapshot.PushState = s.initialSnapshotPushState(snapshot)
	if s.testBeforeStoreCreateSnapshot != nil {
		s.testBeforeStoreCreateSnapshot(snapshot)
	}
	if err := s.store.CreateSnapshot(ctx, snapshot); err != nil {
		if errors.Is(err, store.ErrSnapshotNameConflict) {
			// A commit's snapshot belongs to the SANDBOX's owner, which may
			// differ from the caller (an operator/internal caller committing a
			// tenant's sandbox). Resolve the conflicting row in that owner's
			// namespace, not the caller's, so a legitimate retry replays.
			//
			// The tag may be that row's image now, so it is not removed
			// here: the intent stays for the janitor, which drops it while
			// any row names the tag and removes the tag once none does.
			if existing, getErr := s.store.GetSnapshotByNames(ctx, snapshot.OwnerRef, docker.EquivalentImageNames(name)); getErr == nil {
				return replayExistingSnapshot(ctx, existing, sandboxID)
			}
		}
		s.rollbackSnapshotCommit(ctx, engineImage, engine, image)
		return nil, false, err
	}
	if engineImage {
		// The row owns the image now. A failed delete is harmless: the
		// janitor sees the row (HasActiveImageRef) and drops the intent.
		s.clearSnapshotCommitIntent(ctx, engine, image)
	}
	s.kickSnapshotPushReconciler(snapshot)
	s.registerSnapshotHome(ctx, snapshot)
	return snapshot, true, nil
}

// snapshotCommitEngine reports which engine's image store a sandbox's
// snapshot commit writes its tag into, and whether it writes one at all. A
// container sandbox commits through its own engine; a Firecracker one imports
// its disk into the node's configured engine ("" resolves to it). A WASM
// checkpoint is a file, not an image, so it has no tag to clean up.
func snapshotCommitEngine(sandbox *models.Sandbox) (engine string, ok bool) {
	switch sandbox.Runtime {
	case models.RuntimeFirecracker:
		return "", true
	case models.RuntimeWasm, models.RuntimeIsolate:
		return "", false
	}
	return models.SandboxEngine(sandbox), true
}

// recordSnapshotCommitIntent durably schedules a snapshot tag for removal
// before the commit that creates it, so a crash between the commit and the
// catalogue insert leaves the tag to the janitor instead of to nobody. An
// upsert: a retry resets the TTL rather than adding a row. Gated like
// schedulePendingImageGC — with image GC off no janitor would ever drain the
// row — but unlike it, a failed write fails the create: committing without
// the intent is exactly the leak this exists to close.
func (s *Service) recordSnapshotCommitIntent(ctx context.Context, engine, image string) error {
	if !s.cfg.ImageBuildGCEnabled || s.imageGCWhitelisted(image) {
		return nil
	}
	if err := s.store.SchedulePendingImageGC(ctx, engine, image, time.Now().UTC()); err != nil {
		return fmt.Errorf("record snapshot cleanup intent: %w", err)
	}
	return nil
}

// clearSnapshotCommitIntent drops the cleanup intent once nothing is left to
// clean up: the catalogue row owns the image, or the image is gone. Failure
// only delays the janitor's own decision, so it is logged, not returned.
func (s *Service) clearSnapshotCommitIntent(ctx context.Context, engine, image string) {
	if !s.cfg.ImageBuildGCEnabled {
		return
	}
	if err := s.store.DeletePendingImageGC(ctx, engine, image); err != nil {
		s.logger.Warn("snapshot cleanup intent clear failed; image gc will drop it", "engine", engine, "image", image, "error", err)
	}
}

// rollbackSnapshotCommit removes the image a commit produced when its
// catalogue row could not be written, instead of waiting a TTL for the
// janitor. It applies the janitor's own rule — never remove a tag a row or a
// live sandbox still names — and keeps the intent unless the tag is really
// gone, so anything it cannot finish stays the janitor's. Runs detached from
// the request: the failure being rolled back may be that the caller left.
func (s *Service) rollbackSnapshotCommit(ctx context.Context, engineImage bool, engine, image string) {
	if !engineImage {
		return
	}
	ctx = context.WithoutCancel(ctx)
	referenced, err := s.store.HasActiveImageRef(ctx, image)
	if err != nil || referenced {
		if err != nil {
			s.logger.Warn("snapshot commit rollback: image ref check failed; left to image gc", "image", image, "error", err)
		}
		return
	}
	if err := s.removeSnapshotImage(ctx, image); err != nil {
		s.logger.Warn("snapshot commit rollback: image remove failed; left to image gc", "image", image, "error", err)
		return
	}
	s.clearSnapshotCommitIntent(ctx, engine, image)
}

// CreateSnapshotWithAlias commits a snapshot and records the facade alias that
// addresses it, in one call — the create-then-alias sequence E2B and Runloop
// each used to re-implement, each with its own compensating delete (D8). The
// alias's SnapshotName is filled in from the committed snapshot, so a caller
// passes only its own Alias / Facade / ExtraNames / StateJSON. The alias is
// part of the snapshot: an id that resolves to nothing is useless, so a failed
// alias write rolls the commit back — but only when this call created it (a
// replayed retry leaves the existing row alone and just re-asserts the alias,
// which is idempotent). Snapshot creation stays serialized by the service's
// snapshotMu inside CreateSnapshotWithOwnership.
func (s *Service) CreateSnapshotWithAlias(ctx context.Context, sandboxID string, req models.CreateSandboxSnapshotRequest, alias models.SnapshotAlias) (*models.SandboxSnapshot, bool, error) {
	snapshot, created, err := s.CreateSnapshotWithOwnership(ctx, sandboxID, req)
	if err != nil {
		return nil, false, err
	}
	alias.SnapshotName = snapshot.Name
	if err := s.UpsertSnapshotAlias(ctx, alias); err != nil {
		if created {
			if delErr := s.DeleteSnapshot(context.WithoutCancel(ctx), snapshot.Name); delErr != nil && s.logger != nil {
				s.logger.Warn("snapshot alias rollback failed", "snapshot", snapshot.Name, "error", delErr)
			}
		}
		return nil, false, err
	}
	return snapshot, created, nil
}

// snapshotPauseAllowed refuses a snapshot that would pause a sandbox whose
// caller said it must not be paused (allow_pause: false). Every runtime
// pauses a running sandbox for its snapshot, so only a stopped (or, for
// WASM, passivated) sandbox passes. Checked here, before any runtime work,
// so the answer is the same on every runtime. A retry of a snapshot that
// already exists never gets here: it pauses nothing.
func snapshotPauseAllowed(sandbox *models.Sandbox, allowPause *bool) error {
	if allowPause == nil || *allowPause {
		return nil
	}
	switch sandbox.Status {
	case models.SandboxStatusStopped, models.SandboxStatusPassivated:
		return nil
	}
	return fmt.Errorf("sandbox %s is %s and allow_pause is false; stop it first, or allow the snapshot to pause it briefly: %w",
		sandbox.ID, sandbox.Status, models.ErrSnapshotSourceNotReady)
}

// replayExistingSnapshot answers a snapshot create whose name is taken. The
// same source sandbox makes it a retry, answered with the stored row — but
// only to a caller who may see it: the name check runs before the source
// sandbox is loaded, so without this a user token naming another tenant's
// sandbox would be handed that tenant's snapshot. A different source is a
// name conflict.
func replayExistingSnapshot(ctx context.Context, existing *models.SandboxSnapshot, sandboxID string) (*models.SandboxSnapshot, bool, error) {
	if existing.SourceSandboxID != sandboxID {
		return nil, false, store.ErrSnapshotNameConflict
	}
	if !snapshotVisible(ctx, existing) {
		return nil, false, store.ErrNotFound
	}
	return existing, false, nil
}

// getSnapshotAnySpelling returns the snapshot whose name is name in any
// spelling the engine treats as the same image ("snap", "snap:latest",
// "docker.io/library/snap", ...), the literal spelling first. Creating,
// reading and deleting a snapshot all go through it, as resolving one for a
// create does, so no spelling reaches a snapshot the others would not.
func (s *Service) getSnapshotAnySpelling(ctx context.Context, name string) (*models.SandboxSnapshot, error) {
	// Snapshot names are per-owner, so look within the caller's namespace: a
	// user token in its own account, operator/internal ("") in the operator
	// namespace. This scopes the register-conflict check and by-name resolution
	// so one tenant can neither see nor collide with another's names.
	return s.store.GetSnapshotByNames(ctx, ownerRefForCreate(ctx), docker.EquivalentImageNames(name))
}

// initialSnapshotPushState picks the push_state value to write for a
// newly-created snapshot row. When the feature is off (or the image is
// already remote), the value is "active" — identical to pre-feature
// behavior. When the feature is on and the image is local_only, the
// row starts as "pending" so the reconciler picks it up.
func (s *Service) initialSnapshotPushState(snapshot *models.SandboxSnapshot) string {
	if s.snapshotPusher == nil {
		return models.SnapshotPushStateActive
	}
	if !SnapshotNeedsPush(snapshot) {
		return models.SnapshotPushStateActive
	}
	return models.SnapshotPushStatePending
}

// kickSnapshotPushReconciler wakes the node's snapshot push worker after a
// snapshot was just inserted in 'pending' state, so its push starts now
// rather than on the next tick. A non-blocking wake-up, not a sweep of its
// own: a burst of creates used to start one full sweep each, every one with
// its own fan-out, all listing the same rows.
func (s *Service) kickSnapshotPushReconciler(snapshot *models.SandboxSnapshot) {
	if s.snapshotPushReconciler == nil || snapshot == nil {
		return
	}
	if snapshot.PushState != models.SnapshotPushStatePending {
		return
	}
	s.snapshotPushReconciler.Kick()
}

// markTemplateForPush is the kickTemplateBuild success-path seam for
// Phase 6 PR 6-B.1. Best-effort: when the pusher isn't wired (cluster
// off / push disabled) the call is a no-op so the build path stays
// byte-identical to today. The store helper is state-guarded — a row
// already in pending/pushing/error is left alone.
func (s *Service) markTemplateForPush(ctx context.Context, templateID string) bool {
	if s.templateArtifactPusher == nil {
		return false
	}
	changed, err := s.store.MarkTemplatePushPending(ctx, templateID)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("template push: mark pending failed",
				"template", templateID, "error", err)
		}
		return false
	}
	return changed
}

// kickTemplateArtifactPushReconciler wakes the node's template push worker
// after the build path flipped a template row to push_state=pending, so the
// AOCR push starts without waiting a tick. A wake-up, not a sweep of its own
// (see kickSnapshotPushReconciler).
func (s *Service) kickTemplateArtifactPushReconciler(templateID string) {
	if s.templateArtifactPushReconciler == nil {
		return
	}
	s.templateArtifactPushReconciler.Kick()
}

// GetSnapshot resolves a snapshot by name or image ID. Another tenant's
// snapshot reads as store.ErrNotFound for a user token, the same 404 a
// cross-owner sandbox id gets.
func (s *Service) GetSnapshot(ctx context.Context, idOrName string) (*models.SandboxSnapshot, error) {
	needle := strings.TrimSpace(idOrName)
	if needle == "" {
		return nil, store.ErrNotFound
	}
	snapshot, err := s.getSnapshotAnySpelling(ctx, needle)
	if err == nil {
		if snapshotVisible(ctx, snapshot) {
			return snapshot, nil
		}
		return nil, store.ErrNotFound
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	snapshots, err := s.store.ListSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	for _, snapshot := range snapshots {
		if snapshot != nil && strings.TrimSpace(snapshot.ImageID) == needle && snapshotVisible(ctx, snapshot) {
			return snapshot, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListSnapshots returns the snapshots the caller may see: every row for
// operator and internal callers, the caller's own account's for a user token.
func (s *Service) ListSnapshots(ctx context.Context) ([]*models.SandboxSnapshot, error) {
	snapshots, err := s.store.ListSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	if _, scoped := ownerScope(ctx); !scoped {
		return snapshots, nil
	}
	visible := make([]*models.SandboxSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshotVisible(ctx, snapshot) {
			visible = append(visible, snapshot)
		}
	}
	return visible, nil
}

// ListSnapshotPage returns one name-ordered page of the snapshots the caller
// may see, optionally narrowed to one source sandbox and joined with one
// facade's alias rows. It pages in the store, so a list costs one bounded
// range scan however large the catalogue is.
func (s *Service) ListSnapshotPage(ctx context.Context, sourceSandboxID, aliasFacade, afterName string, limit int) ([]store.SnapshotPageRow, error) {
	owner, scoped := ownerScope(ctx)
	return s.store.ListSnapshotPage(ctx, store.SnapshotPageQuery{
		OwnerRef:        owner,
		Scoped:          scoped,
		SourceSandboxID: sourceSandboxID,
		AliasFacade:     aliasFacade,
		AfterName:       afterName,
		Limit:           limit,
	})
}

// snapshotOwnedScanBatch is the page size ListOwnedSnapshots reads per store
// round trip. It is well under maxSnapshotPageRows (1000) so one owner's
// catalogue comes back in a few bounded scans rather than one unbounded read.
const snapshotOwnedScanBatch = 200

// ListOwnedSnapshots returns every snapshot the caller may see — optionally
// narrowed to one source sandbox and joined with one facade's alias rows — by
// paging the store's owner-scoped range scan. It exists so a facade that needs
// its own sort order or page-number pagination (Daytona, E2B) can materialize
// just the caller's snapshots instead of calling ListSnapshots, which reads
// every tenant's rows and filters in Go (D9). Rows come back in the store's
// keyset order (name ASC); the caller re-sorts as its wire API requires. Pass
// aliasFacade "" when the caller does not join aliases.
func (s *Service) ListOwnedSnapshots(ctx context.Context, sourceSandboxID, aliasFacade string) ([]store.SnapshotPageRow, error) {
	var out []store.SnapshotPageRow
	after := ""
	for {
		rows, err := s.ListSnapshotPage(ctx, sourceSandboxID, aliasFacade, after, snapshotOwnedScanBatch)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		if len(rows) < snapshotOwnedScanBatch {
			return out, nil
		}
		after = rows[len(rows)-1].Snapshot.Name
	}
}

// CountSnapshots counts the snapshots ListSnapshotPage would walk for the
// caller with the same source filter.
func (s *Service) CountSnapshots(ctx context.Context, sourceSandboxID string) (int, error) {
	owner, scoped := ownerScope(ctx)
	return s.store.CountSnapshots(ctx, owner, scoped, sourceSandboxID)
}

// registerSnapshotHome records, best-effort, that this node holds the snapshot's
// image, so a snapshot-by-id GET/DELETE that lands on another node can be routed
// here (B6), and so can a create that names the snapshot's committed tag. A
// snapshot lives in per-node SQLite with no node column, so the replicated
// index is the only cluster-wide home lookup. A failure costs only routing —
// the snapshot is still usable locally and a re-register would fix it — so it
// never fails the create. It is a no-op single-node (the Noop client). The
// write detaches from the request context so a client that disconnected right
// after the commit still gets the snapshot registered.
//
// A snapshot whose image is only here (not, or not yet, pushed to the
// registry) also gets the local-only key, so a create by its name that lands
// on another node runs here instead of pulling a copy that does not exist
// (UC-459). The push worker drops that key when the push lands
// (forgetSnapshotLocalOnly).
func (s *Service) registerSnapshotHome(ctx context.Context, snapshot *models.SandboxSnapshot) {
	c := s.Cluster()
	if c == nil {
		return
	}
	self := c.SelfNodeID()
	if self == "" {
		return
	}
	keys := snapshotHomeKeys(snapshot)
	if SnapshotNeedsPush(snapshot) {
		keys = append(keys, cluster.SnapshotLocalOnlyKey(snapshot.OwnerRef, snapshot.Name))
	}
	for _, key := range keys {
		if err := c.RegisterSnapshotNode(context.WithoutCancel(ctx), key, self); err != nil && s.logger != nil {
			s.logger.Warn("snapshot home-node register failed", "snapshot", snapshot.Name, "error", err)
		}
	}
}

// forgetSnapshotHome drops the snapshot's home entries after it is deleted.
// Best-effort: a stale entry is also swept when its node leaves the cluster.
// The local-only key goes too, whatever the row's push state: a push whose
// own forget failed left it behind, and it would keep sending creates by this
// name to a node that no longer has the snapshot.
func (s *Service) forgetSnapshotHome(ctx context.Context, snapshot *models.SandboxSnapshot) {
	c := s.Cluster()
	if c == nil {
		return
	}
	keys := append(snapshotHomeKeys(snapshot), cluster.SnapshotLocalOnlyKey(snapshot.OwnerRef, snapshot.Name))
	for _, key := range keys {
		if err := c.ForgetSnapshotNode(context.WithoutCancel(ctx), key); err != nil && s.logger != nil {
			s.logger.Warn("snapshot home-node forget failed", "snapshot", snapshot.Name, "error", err)
		}
	}
}

// forgetSnapshotLocalOnly drops a snapshot's local-only key once its push has
// landed: the registry copy exists now, so a create by its name may run on any
// node again. The push worker calls it (SnapshotPushReconciler.onPushed).
// Best-effort: a failed forget only keeps those creates on this node, where
// the snapshot still runs, until the snapshot is deleted.
func (s *Service) forgetSnapshotLocalOnly(ctx context.Context, snapshot *models.SandboxSnapshot) {
	c := s.Cluster()
	if c == nil || snapshot == nil {
		return
	}
	if err := c.ForgetSnapshotNode(context.WithoutCancel(ctx), cluster.SnapshotLocalOnlyKey(snapshot.OwnerRef, snapshot.Name)); err != nil && s.logger != nil {
		s.logger.Warn("snapshot local-only key forget failed; creates by its name stay on this node", "snapshot", snapshot.Name, "error", err)
	}
}

// snapshotHomeKeys lists the index keys a snapshot's home is recorded under.
// The (owner, name) key stops a tenant overwriting another tenant's same-named
// entry and hijacking its routing (#11). A snapshot that owns its committed tag
// is also keyed by that tag, so a create naming the tag (the SDK hands a
// caller snap.Image) reaches this node from any other; the tag is the one
// NormalizeCreateImageDistribution resolves through this row (snapshotCommittedAs),
// so a registered alias that merely points at someone's tag adds no tag key.
func snapshotHomeKeys(snapshot *models.SandboxSnapshot) []string {
	keys := []string{cluster.SnapshotHomeKey(snapshot.OwnerRef, snapshot.Name)}
	if snapshotImageIsOwnedTag(snapshot) {
		if key := cluster.SnapshotImageHomeKey(snapshot.Image); key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func (s *Service) DeleteSnapshot(ctx context.Context, idOrName string) error {
	if strings.TrimSpace(idOrName) == "" {
		return store.ErrNotFound
	}

	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()

	snapshot, err := s.GetSnapshot(ctx, idOrName)
	if err != nil {
		return err
	}
	// Only a snapshot's own committed image is the snapshot's to remove,
	// and only once no other snapshot holds it. A registered snapshot names
	// an image that exists without it — a registry image, a build, someone
	// else's snapshot — so deleting the name leaves that image to the image
	// janitors, which remove it once nothing uses it.
	holders, err := s.store.GetSnapshotsByImage(ctx, []string{snapshot.Image})
	if err != nil {
		return err
	}
	shared := slices.ContainsFunc(holders, func(other *models.SandboxSnapshot) bool { return other.Name != snapshot.Name })
	switch {
	case shared:
	case snapshotOwnsImage(snapshot):
		if err := s.removeSnapshotImage(ctx, snapshot.Image); err != nil {
			return err
		}
	default:
		s.schedulePendingImageGC(ctx, "", snapshot.Image)
	}
	// The row and the obligation to retire its registry copy go in one
	// transaction, so a deleted snapshot never leaves a copy nothing will
	// remove. Only the copy this node's pusher made for this snapshot is
	// retired (the ref it would push to; "" without a registry, so no
	// obligation); the push worker removes it by digest.
	if err := s.store.DeleteSnapshotRetiringRegistryCopy(ctx, snapshot.OwnerRef, snapshot.Name,
		s.snapshotPusher.DestRefFor(snapshot.OwnerRef, snapshot.Name)); err != nil {
		return err
	}
	s.forgetSnapshotHome(ctx, snapshot)
	if s.snapshotPushReconciler != nil {
		s.snapshotPushReconciler.Kick()
	}
	return nil
}

// removeSnapshotImage deletes a snapshot's own image from every container
// engine on this node. A snapshot taken on a containerd node (from a
// containerd sandbox, or a Firecracker one, whose image goes into the node's
// engine) is in containerd's store, not Docker's; removing it from Docker
// alone found nothing and left it there. The tag is the snapshot's own, and
// both engines treat a missing image as removed, so this touches nothing else.
func (s *Service) removeSnapshotImage(ctx context.Context, image string) error {
	if err := s.docker.RemoveImage(ctx, image); err != nil {
		return err
	}
	if s.containerd != nil {
		if err := s.containerd.RemoveImage(ctx, image); err != nil {
			return err
		}
	}
	return nil
}

// snapshotOwnsImage reports a snapshot whose image was committed for it:
// one taken from a sandbox (only a commit records its source, see
// RegisterSnapshot), or one under its own tag.
func snapshotOwnsImage(snapshot *models.SandboxSnapshot) bool {
	return snapshot.SourceSandboxID != "" || snapshotImageIsOwnedTag(snapshot)
}

// snapshotImageIsOwnedTag reports whether a snapshot's image is its own
// committed tag. It accepts both the owner-scoped tag (new commits) and the
// legacy owner-agnostic tag so snapshots committed before the tag was scoped
// still classify as owning their image.
func snapshotImageIsOwnedTag(snapshot *models.SandboxSnapshot) bool {
	if snapshot == nil {
		return false
	}
	img := strings.TrimSpace(snapshot.Image)
	return img == docker.SnapshotImageTagForOwner(snapshot.OwnerRef, snapshot.Name) ||
		img == docker.SnapshotImageTag(snapshot.Name)
}

// ResizeSandbox changes a sandbox's CPU, memory or disk.
//
// One resize of a sandbox runs at a time, from the read below to the quota
// settle at the end (resizeLocks); resizes of different sandboxes still run
// together. Before, two resizes of one sandbox each read the old size, the
// later one replaced the earlier one's quota claim while the earlier one was
// still changing the runtime, and a create could be admitted into room the
// earlier one then used: a 4-CPU team ended up holding 5.
//
// The team quota is held for the whole resize at the larger of the old and
// new size (admitTeamQuotaResize) and settled at the size the store shows
// at the end, so a downsize frees its room and a failed resize gives back
// only what it took. If the runtime changed but the store write failed, the
// runtime is put back first: only then is the hold undone. If that fails
// too the hold stays at the larger size, so the team is never charged less
// than the sandbox may hold.
func (s *Service) ResizeSandbox(ctx context.Context, id string, req models.ResizeSandboxRequest) (*models.Sandbox, error) {
	// A caller that already left starts no resize, even on a free lock.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	unlock, err := s.resizeLocks.lockCtx(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	// The create policy's size limits hold for a resize too, or a sandbox
	// could be made small and then grown past them.
	if err := s.checkResizePolicy(req); err != nil {
		return nil, err
	}

	// A team's quota is checked before host capacity and before anything
	// changes: resize used to re-admit against the host only, so a team
	// could grow past its quota one resize at a time (plan item P2).
	hold, err := s.admitTeamQuotaResize(ctx, sandbox, req)
	if err != nil {
		return nil, err
	}
	settled := false
	defer func() {
		if !settled {
			hold.undo()
		}
	}()

	// Decide what the post-resize footprint will be and re-admit against it
	// before mutating Docker. Admit is idempotent per ID — it computes the
	// delta against the existing reservation, so a downsize will free budget
	// and an upsize that exceeds the budget is rejected with no changes.
	if s.admitter != nil {
		next := capacityRequestFromSandbox(sandbox)
		if req.CPU > 0 {
			next.CPU = req.CPU
		}
		if req.MemoryMB > 0 {
			next.MemoryMB = req.MemoryMB
		}
		if req.DiskGB > 0 {
			next.DiskGB = req.DiskGB
		}
		if next.CPU != sandbox.CPU || next.MemoryMB != sandbox.MemoryMB || next.DiskGB != sandbox.DiskGB {
			if err := s.admitter.Admit(id, next); err != nil {
				return nil, err
			}
		}
	}

	rt, err := s.runtimeForSandbox(sandbox)
	if err != nil {
		if s.admitter != nil {
			s.admitter.Reserve(id, capacityRequestFromSandbox(sandbox))
		}
		return nil, err
	}
	if err := rt.Resize(ctx, s.runtimeRef(sandbox), req); err != nil {
		// Restore the prior reservation; the resize did not actually take
		// effect on the container, so accounting must reflect the unchanged
		// footprint.
		if s.admitter != nil {
			s.admitter.Reserve(id, capacityRequestFromSandbox(sandbox))
		}
		return nil, err
	}
	before := *sandbox
	if req.CPU > 0 {
		sandbox.CPU = req.CPU
	}
	if req.MemoryMB > 0 {
		sandbox.MemoryMB = req.MemoryMB
	}
	if req.DiskGB > 0 {
		sandbox.DiskGB = req.DiskGB
	}
	sandbox.UpdatedAt = time.Now().UTC()
	if err := s.store.Upsert(ctx, sandbox); err != nil {
		settled = !s.revertResizeAfterStoreFailure(ctx, rt, &before, req, err)
		return nil, err
	}
	settled = true
	hold.settle(sandbox.CPU, sandbox.MemoryMB)
	if hold.specHolds(req) {
		// The quota admission already recorded the new size in the
		// replicated spec; writing it again would only cost a Raft entry.
		return s.store.Get(ctx, id)
	}
	// Mirror the resize into the FSM-replicated spec so a future failover
	// recreate uses the post-resize footprint, not the create-time one. Lives
	// in the service layer so v1, Daytona, and E2B all inherit the write-
	// through; previously this was duplicated in the v1 handler and silently
	// missing from the facades. For a team's sandbox it is also where a
	// cluster records a shrink: until it lands the team counts the larger
	// size admission wrote, an overcharge, never an undercharge.
	s.replicateSpecPatch(ctx, id, func(spec *models.CreateSandboxRequest) {
		if req.CPU > 0 {
			spec.CPU = req.CPU
		}
		if req.MemoryMB > 0 {
			spec.MemoryMB = req.MemoryMB
		}
		if req.DiskGB > 0 {
			spec.DiskGB = req.DiskGB
		}
	})
	return s.store.Get(ctx, id)
}

// revertResizeAfterStoreFailure handles a resize whose runtime change took
// but whose store write did not. Giving the quota back while the sandbox may
// hold the new size would undercharge a resource that grew, so it first puts
// the runtime back to the size the store still shows. It reports whether
// that worked: then nothing changed and the caller undoes the quota hold.
// If not, the sandbox's real size is unknown, so the hold stays at the
// larger of the two sizes (a pending ledger entry a recount keeps, or the
// spec admission wrote) and host capacity stays at the new size, and the
// error is logged for an operator to resize the sandbox again.
func (s *Service) revertResizeAfterStoreFailure(ctx context.Context, rt runtime.Runtime, before *models.Sandbox, req models.ResizeSandboxRequest, storeErr error) bool {
	back := models.ResizeSandboxRequest{}
	if req.CPU > 0 {
		back.CPU = before.CPU
	}
	if req.MemoryMB > 0 {
		back.MemoryMB = before.MemoryMB
	}
	if req.DiskGB > 0 {
		back.DiskGB = before.DiskGB
	}
	// A size the row never recorded cannot be put back.
	canRevert := (req.CPU <= 0 || back.CPU > 0) && (req.MemoryMB <= 0 || back.MemoryMB > 0) && (req.DiskGB <= 0 || back.DiskGB > 0)
	var revertErr error
	if canRevert {
		// The request may be what ended (a cancelled context fails the
		// store write too), so the revert gets its own deadline.
		revertCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		revertErr = rt.Resize(revertCtx, s.runtimeRef(before), back)
		cancel()
		if revertErr == nil {
			if s.admitter != nil {
				s.admitter.Reserve(before.ID, capacityRequestFromSandbox(before))
			}
			return true
		}
	}
	if s.logger != nil {
		s.logger.Error("resize: the runtime changed but the store write failed and the runtime could not be put back; the team quota keeps the larger size, resize the sandbox again",
			"sandbox_id", before.ID, "store_err", storeErr, "revert_err", revertErr)
	}
	return false
}

// UpdateLifecycle replaces the lifecycle timers on an existing sandbox.
// Full-replacement semantics: pass zero in any field to clear that timer.
// The sweep picks up the new values on its next tick (within ~1 minute),
// so a tightened deadline can fire as soon as the next sweep runs.
func (s *Service) UpdateLifecycle(ctx context.Context, id string, l models.Lifecycle) (*models.Sandbox, error) {
	// A destroy_at needs the sandbox's creation time, so it is checked
	// after the read; everything else fails before the lock as before.
	if l.DestroyAt == nil {
		if err := s.validateLifecycle(l); err != nil {
			return nil, fmt.Errorf("invalid lifecycle: %w", err)
		}
	}
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	priorSandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	if l.DestroyAt != nil {
		if err := resolveLifecycleUpdate(&l, priorSandbox); err != nil {
			return nil, err
		}
		if err := s.validateLifecycle(l); err != nil {
			return nil, fmt.Errorf("invalid lifecycle: %w", err)
		}
	}
	if err := validateLifecycleRuntime(l, s.sandboxRuntime(priorSandbox)); err != nil {
		return nil, err
	}
	updated, _, err := s.writeLifecycleLocked(ctx, id, l, priorSandbox)
	return updated, err
}

// sandboxRuntime is the runtime a sandbox runs on; a pre-migration row with
// none runs on the host default.
func (s *Service) sandboxRuntime(sb *models.Sandbox) string {
	if sb.Runtime != "" {
		return sb.Runtime
	}
	return s.cfg.Runtime
}

// writeLifecycleLocked persists lifecycle l for id and replays the resulting
// serverless route transition. The caller holds the lifecycle boundary for id and
// passes the scoped prior read so the whole read→write is one critical section
// (D7); l is already validated. It reports whether the write ran (always true
// here; the bool lets ApplyLifecyclePatch tell a no-op apart).
func (s *Service) writeLifecycleLocked(ctx context.Context, id string, l models.Lifecycle, priorSandbox *models.Sandbox) (*models.Sandbox, bool, error) {
	if s.testAfterLifecycleScopedGet != nil {
		s.testAfterLifecycleScopedGet()
	}
	if err := s.store.UpdateLifecycle(ctx, id, l); err != nil {
		return nil, false, err
	}
	// Only a failover recreate reads the replicated lifecycle back; a
	// keep-alive (E2B setTimeout) on any other sandbox costs no Raft write,
	// and on a failover sandbox about one a minute.
	s.replicateRecoveryLifecycle(ctx, id, priorSandbox, l)
	updated, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, false, err
	}
	// If Serverless flipped on a running sandbox, re-install exposed port
	// routes in the matching shape. The install helpers own cleanup of the
	// previous direct/wake shape, so this is the entire transition. We only do
	// the work when something actually changed AND when the gate is on
	// — gate-off keeps the legacy direct routes regardless.
	if s.cfg.EnableServerless && priorSandbox != nil && updated != nil &&
		priorSandbox.Lifecycle.Serverless != updated.Lifecycle.Serverless &&
		updated.Status == models.SandboxStatusStarted {
		for _, port := range updated.ExposedPorts {
			if err := s.syncExposedPortRoute(ctx, updated, port); err != nil {
				if s.logger != nil {
					s.logger.Warn("re-install port route after lifecycle change failed",
						"sandbox_id", id, "port", port.Port, "err", err)
				}
			}
		}
	}
	return updated, true, nil
}

// ExposePort publishes a sandbox container port through one of three caddy
// surfaces, selected by protocol:
//   - "" / "http": existing Caddy HTTP reverse-proxy route, returns
//     https://<id>-<port>.<domain> (or the path-mode equivalent).
//   - "tcp": allocates a parent-host TCP port from the [SB_L4_PORT_RANGE_START,
//     SB_L4_PORT_RANGE_END] pool, points caddy-l4 at it, and returns
//     tcp://<public-host>:<host-port>. This is what unblocks native Postgres /
//     Redis / MySQL DSNs in the spawn-postgres docs.
//   - "tls": adds a TLS-SNI route to the shared layer4 server. Requires
//     --domain (so the SNI hostname has a place to resolve) and a non-empty
//     SB_L4_TLS_LISTEN. Returns tls://<id>-<port>.<domain>:<l4-port>.
func (s *Service) ExposePort(ctx context.Context, id string, port int, protocol string) (models.ExposePortResponse, error) {
	return s.exposePort(ctx, id, port, protocol, "", 0)
}

// ExposePortWithVisibility is ExposePort with a visibility (A2): "public",
// "token" (the public URL needs a sandbox token for this port), or "" (a new
// exposure is public; a re-expose keeps what it has). Only an explicit
// value changes a port's visibility, so a retry from a client that does not
// know about visibility can never open a gated port.
func (s *Service) ExposePortWithVisibility(ctx context.Context, id string, port int, protocol, visibility string) (models.ExposePortResponse, error) {
	return s.exposePort(ctx, id, port, protocol, visibility, 0)
}

func (s *Service) exposePort(ctx context.Context, id string, port int, protocol, visibility string, preferredHostPort int) (models.ExposePortResponse, error) {
	// From the row read below to the last write: the visibility this call
	// writes depends on the row it read, so two calls on one port must not
	// interleave (lockExposedPort says what goes wrong if they do).
	unlock := s.lockExposedPort(id, port)
	defer unlock()
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return models.ExposePortResponse{}, err
	}
	if port <= 0 || port > 65535 {
		return models.ExposePortResponse{}, errors.New("invalid port")
	}
	canonicalProto, err := models.ValidExposedPortProtocol(protocol)
	if err != nil {
		return models.ExposePortResponse{}, err
	}
	requestedVisibility, err := models.ValidExposedPortVisibility(visibility)
	if err != nil {
		return models.ExposePortResponse{}, fmt.Errorf("%w: %v", ErrTokenVisibilityInvalid, err)
	}
	// IRON RULE (plans/custom-domains.md): a sandbox with custom domains
	// cannot also publish protocol=tcp/tls exposures. The L4 listener is
	// SNI/port-routed only, with no way to honor a host-based match — a
	// shared :443 listener would steer custom-domain traffic to the wrong
	// container. Reject at the entry point rather than letting the L4 path
	// install a half-broken route.
	if (canonicalProto == models.ExposedPortProtocolTCP || canonicalProto == models.ExposedPortProtocolTLS) && hasCustomDomains(sandbox) {
		return models.ExposePortResponse{}, ErrCustomDomainProtocolConflict
	}
	if s.isWasmSandbox(sandbox) && canonicalProto != models.ExposedPortProtocolHTTP {
		return models.ExposePortResponse{}, unsupportedWasmOption("expose_port protocol " + canonicalProto)
	}
	if s.isIsolateSandbox(sandbox) && canonicalProto != models.ExposedPortProtocolHTTP {
		return models.ExposePortResponse{}, fmt.Errorf("runtime %q only supports expose_port protocol http (host-mediated): %w",
			models.RuntimeIsolate, models.ErrRuntimeNotImplemented)
	}

	now := time.Now().UTC()
	existingBefore := findExposure(sandbox, port)
	if existingBefore != nil {
		existingProto := existingBefore.Protocol
		if existingProto == "" {
			existingProto = models.ExposedPortProtocolHTTP
		}
		if existingProto != canonicalProto {
			return models.ExposePortResponse{}, fmt.Errorf("port %d already exposed as %s; unexpose it first", port, existingProto)
		}
	}
	gated := requestedVisibility == models.ExposedPortVisibilityToken ||
		(requestedVisibility == "" && existingBefore != nil && existingBefore.TokenGated())
	if gated {
		if err := s.checkTokenVisibility(sandbox, port, canonicalProto); err != nil {
			return models.ExposePortResponse{}, err
		}
	}
	// expose_port is the opt-in lever for a sandbox created private: there is
	// no standalone flag-update endpoint, so asking for a public port IS the
	// consent to public exposure. The flip runs after every reject path above
	// (a call that fails validation must not mutate the sandbox) and before
	// the port route goes in, so a successful expose always leaves a fully
	// public sandbox: flag, public_url, and root route. Deliberately not
	// rolled back if a later port-route step fails — the flip is an
	// idempotent prerequisite and the expose retry completes it, same stance
	// as EnsureLayer4Ready rather than un-publishing on a transient error.
	if !sandboxAllowsPublicTraffic(sandbox) {
		if err := s.enableSandboxPublicTraffic(ctx, sandbox); err != nil {
			return models.ExposePortResponse{}, err
		}
	}
	// Probe the container port before routing traffic to it. Skipped on
	// re-expose (existingBefore != nil — port was already reachable) and on
	// WASM sandboxes (no direct container IP). Non-fatal: if the process has
	// not yet bound we warn and proceed rather than holding the caller until
	// it does; the operator can retry expose_port or the client can retry
	// the request once the process is up.
	if existingBefore == nil && sandbox.ContainerIP != "" && sandbox.Status == models.SandboxStatusStarted && !skipPortProbe(ctx) {
		probeFn := s.probeContainerPortFn
		if probeFn == nil {
			probeFn = probeContainerPort
		}
		if err := probeFn(ctx, sandbox.ContainerIP, port); err != nil {
			s.logger.Warn("expose_port: container port not yet accepting connections; route installed anyway",
				"sandbox_id", id, "port", port, "error", err)
		}
	}
	switch canonicalProto {
	case models.ExposedPortProtocolHTTP:
		publicURL := s.caddy.PortPublicURL(id, port)
		exposure := models.ExposedPort{
			SandboxID: id,
			Port:      port,
			Protocol:  canonicalProto,
			PublicURL: publicURL,
			CreatedAt: now,
		}
		if gated {
			exposure.Visibility = models.ExposedPortVisibilityToken
		}
		// existingBefore points into sandbox.ExposedPorts, which setExposure
		// overwrites: keep a copy of the row as it was, for the rollback.
		var previous *models.ExposedPort
		if existingBefore != nil {
			cp := *existingBefore
			previous = &cp
		}
		// The route installer reads the port's visibility from the row it
		// is handed: give it the exposure this call is about to store.
		setExposure(sandbox, exposure)
		wasGated := previous != nil && previous.TokenGated()
		if gated || wasGated {
			// A gate change writes the row first and the route second: from
			// the row write on, every request through the sandboxd ingress
			// is checked, and until the route moves onto it the port is as
			// public as it already was. A failed route write puts the old
			// row back, so the store never says "token" while the route is
			// still the open one.
			if err := s.exposeGatedHTTPPort(ctx, sandbox, exposure, previous); err != nil {
				return models.ExposePortResponse{}, err
			}
		} else {
			if err := s.installHTTPPortRoute(ctx, sandbox, port); err != nil {
				return models.ExposePortResponse{}, err
			}
			if s.testAfterHTTPPortInstall != nil {
				s.testAfterHTTPPortInstall()
			}
			if err := s.store.UpsertPort(ctx, exposure); err != nil {
				_ = s.removeHTTPPortRoute(ctx, id, port)
				return models.ExposePortResponse{}, err
			}
		}
		if err := s.recordClusterExposedPort(ctx, id, port, cluster.ExposedPortRoute{Protocol: canonicalProto, PublicURL: publicURL, Visibility: exposure.Visibility}); err != nil {
			if existingBefore == nil {
				_ = s.removeHTTPPortRoute(ctx, id, port)
				_ = s.store.DeletePort(ctx, id, port)
				s.invalidateWarm(id)
			}
			return models.ExposePortResponse{}, err
		}
		s.touchAllowedPorts(ctx, id)
		return models.ExposePortResponse{Protocol: canonicalProto, PublicURL: publicURL, Visibility: exposure.Visibility}, nil

	case models.ExposedPortProtocolTCP:
		// Lazy bootstrap: boot's EnsureLayer4 is best-effort, so retry here
		// in case caddy was not reachable at start-up. Idempotent and cheap
		// after the first success (atomic load).
		if err := s.EnsureLayer4Ready(ctx); err != nil {
			return models.ExposePortResponse{}, err
		}
		// Fast-path idempotency: a re-expose for an already-TCP port reuses
		// the existing host_port reservation. Without this, the allocator
		// would loop on PK collisions in TryReserveHostPort and exhaust the
		// pool. A different protocol on the same (id, port) is rejected
		// outright — the caller must unexpose first to switch protocols.
		if existing := existingBefore; existing != nil {
			if existing.HostPort > 0 {
				if err := s.installTCPPortRoute(ctx, sandbox, port, existing.HostPort); err != nil {
					return models.ExposePortResponse{}, err
				}
				if err := s.recordClusterExposedPort(ctx, id, port, cluster.ExposedPortRoute{Protocol: canonicalProto, HostPort: existing.HostPort, PublicURL: existing.PublicURL}); err != nil {
					return models.ExposePortResponse{}, err
				}
				s.touchAllowedPorts(ctx, id)
				return models.ExposePortResponse{
					Protocol:  canonicalProto,
					PublicURL: existing.PublicURL,
					Host:      s.caddy.PublicHost(),
					HostPort:  existing.HostPort,
				}, nil
			}
		}
		hostPort, publicURL, reused, err := s.allocateHostPort(ctx, id, port, now, preferredHostPort)
		if err != nil {
			return models.ExposePortResponse{}, err
		}
		if err := s.installTCPPortRoute(ctx, sandbox, port, hostPort); err != nil {
			// Only roll back rows we ourselves inserted. A reused row was
			// installed by a concurrent caller and is not ours to delete.
			if !reused {
				_ = s.store.DeletePort(ctx, id, port)
				if preferredHostPort == 0 {
					_ = s.removeClusterExposedPort(ctx, id, port)
				}
			}
			return models.ExposePortResponse{}, err
		}
		if err := s.recordClusterExposedPort(ctx, id, port, cluster.ExposedPortRoute{Protocol: canonicalProto, HostPort: hostPort, PublicURL: publicURL}); err != nil {
			_ = s.publicRoutes().DeleteTCPRoute(ctx, hostPort)
			if !reused {
				_ = s.store.DeletePort(ctx, id, port)
				if preferredHostPort == 0 {
					_ = s.removeClusterExposedPort(ctx, id, port)
				}
			}
			return models.ExposePortResponse{}, err
		}
		s.touchAllowedPorts(ctx, id)
		return models.ExposePortResponse{
			Protocol:  canonicalProto,
			PublicURL: publicURL,
			Host:      s.caddy.PublicHost(),
			HostPort:  hostPort,
		}, nil

	case models.ExposedPortProtocolTLS:
		sniHost := s.caddy.SNIHost(id, port)
		if sniHost == "" {
			return models.ExposePortResponse{}, errors.New("TLS-SNI exposure requires --domain to be configured")
		}
		if s.caddy.L4TLSListen() == "" {
			return models.ExposePortResponse{}, errors.New("TLS-SNI exposure requires SB_L4_TLS_LISTEN to be set")
		}
		// Lazy bootstrap: retry here so a failed boot doesn't break the
		// first TLS-SNI exposure. The shared SNI mux server lives inside
		// the layer4 app, so this is the gate before any UpsertTLSSNIRoute.
		if err := s.EnsureLayer4Ready(ctx); err != nil {
			return models.ExposePortResponse{}, err
		}
		publicURL := s.caddy.TLSPublicEndpoint(id, port, s.caddy.L4TLSListen())
		if err := s.installTLSPortRoute(ctx, sandbox, port); err != nil {
			return models.ExposePortResponse{}, err
		}
		exposure := models.ExposedPort{
			SandboxID: id,
			Port:      port,
			Protocol:  canonicalProto,
			PublicURL: publicURL,
			CreatedAt: now,
		}
		if err := s.store.UpsertPort(ctx, exposure); err != nil {
			_ = s.deleteTLSPortRoute(ctx, id, port)
			return models.ExposePortResponse{}, err
		}
		if err := s.recordClusterExposedPort(ctx, id, port, cluster.ExposedPortRoute{Protocol: canonicalProto, PublicURL: publicURL}); err != nil {
			if existingBefore == nil {
				_ = s.deleteTLSPortRoute(ctx, id, port)
				_ = s.store.DeletePort(ctx, id, port)
			}
			return models.ExposePortResponse{}, err
		}
		s.touchAllowedPorts(ctx, id)
		return models.ExposePortResponse{Protocol: canonicalProto, PublicURL: publicURL}, nil
	}
	return models.ExposePortResponse{}, fmt.Errorf("unhandled protocol %q", canonicalProto)
}

// EnsureLayer4Ready bootstraps the caddy-l4 app under a single-flight
// mutex and latches success. Safe to call from boot AND from each L4
// exposure path: the atomic fast-path turns it into a single load on the
// steady state, and a failed boot is recovered by the very next TCP/TLS
// expose call instead of surfacing as a confusing "layer4 app missing"
// error from caddy.
func (s *Service) EnsureLayer4Ready(ctx context.Context) error {
	return s.ensureLayer4Ready(ctx, false)
}

func (s *Service) RepairLayer4Ready(ctx context.Context) error {
	return s.ensureLayer4Ready(ctx, true)
}

func (s *Service) ensureLayer4Ready(ctx context.Context, force bool) error {
	if !force && s.l4Ready.Load() {
		return nil
	}
	s.l4Mu.Lock()
	defer s.l4Mu.Unlock()
	if !force && s.l4Ready.Load() {
		return nil
	}
	if err := s.caddy.EnsureLayer4(ctx, s.cfg.L4TLSListen, s.cfg.L4TLSFallback); err != nil {
		return fmt.Errorf("bootstrap caddy layer4: %w", err)
	}
	s.l4Ready.Store(true)
	return nil
}

// allocateHostPort reserves a parent-host port for a raw-TCP exposure. In
// cluster mode it first reserves the candidate in the Raft placement FSM so
// cross-node collisions are rejected before local Caddy state is changed. The
// local SQLite reservation still runs afterward to catch per-node bind
// conflicts and same-sandbox idempotent retries.
//
// The random-first phase tries up to allocatorRandomAttempts candidates from
// the configured pool. When randoms collide enough times we fall back to a
// deterministic linear scan, which guarantees we exhaust the pool before
// giving up.
//
// Returns reused=true when a concurrent caller installed the (sandbox_id,
// port) row first; the returned host_port and public URL come from that
// existing row. The flag lets the caller skip rollback on caddy failures so
// it doesn't delete a row it didn't create.
func (s *Service) allocateHostPort(ctx context.Context, sandboxID string, containerPort int, now time.Time, preferredHostPort int) (hostPort int, publicURL string, reused bool, err error) {
	if s.cfg.L4PortRangeEnd <= s.cfg.L4PortRangeStart {
		return 0, "", false, errors.New("L4 port pool is misconfigured")
	}
	span := s.cfg.L4PortRangeEnd - s.cfg.L4PortRangeStart + 1

	tryCandidate := func(candidate int, preserveClusterRouteOnLocalConflict bool) (int, string, bool, bool, error) {
		candidateURL := s.caddy.TCPPublicEndpoint(candidate)
		candidateRoute := cluster.ExposedPortRoute{
			Protocol:  models.ExposedPortProtocolTCP,
			HostPort:  candidate,
			PublicURL: candidateURL,
		}
		clusterRecorded := false
		if s.cfg.EnableCluster {
			if err := s.recordClusterExposedPort(ctx, sandboxID, containerPort, candidateRoute); err != nil {
				if errors.Is(err, cluster.ErrHostPortReserved) {
					return 0, "", false, false, nil
				}
				return 0, "", false, false, err
			}
			clusterRecorded = true
		}
		result, err := s.store.TryReserveHostPort(ctx, sandboxID, containerPort, candidate, models.ExposedPortProtocolTCP, candidateURL, now)
		if err != nil {
			if clusterRecorded {
				_ = s.removeClusterExposedPort(ctx, sandboxID, containerPort)
			}
			return 0, "", false, false, err
		}
		if result.Reserved {
			return candidate, candidateURL, false, true, nil
		}
		if result.Existing != nil {
			// Race: a concurrent ExposePort installed the row first. Reuse
			// when protocols match; otherwise refuse (avoids the pool walk
			// AND prevents silently leaking the prior route).
			if result.Existing.Protocol != models.ExposedPortProtocolTCP {
				if clusterRecorded {
					route := cluster.ExposedPortRoute{
						Protocol:  result.Existing.Protocol,
						HostPort:  result.Existing.HostPort,
						PublicURL: result.Existing.PublicURL,
					}
					if route.Protocol == "" {
						route.Protocol = models.ExposedPortProtocolHTTP
					}
					_ = s.recordClusterExposedPort(ctx, sandboxID, containerPort, route)
				}
				return 0, "", false, false, fmt.Errorf("port %d already exposed as %s; unexpose it first", containerPort, result.Existing.Protocol)
			}
			if result.Existing.HostPort > 0 {
				if clusterRecorded && result.Existing.HostPort != candidate {
					if err := s.recordClusterExposedPort(ctx, sandboxID, containerPort, cluster.ExposedPortRoute{
						Protocol:  models.ExposedPortProtocolTCP,
						HostPort:  result.Existing.HostPort,
						PublicURL: result.Existing.PublicURL,
					}); err != nil {
						return 0, "", false, false, err
					}
				}
				return result.Existing.HostPort, result.Existing.PublicURL, true, true, nil
			}
		}
		if clusterRecorded && !preserveClusterRouteOnLocalConflict {
			_ = s.removeClusterExposedPort(ctx, sandboxID, containerPort)
		}
		return 0, "", false, false, nil
	}

	if preferredHostPort > 0 {
		if preferredHostPort < s.cfg.L4PortRangeStart || preferredHostPort > s.cfg.L4PortRangeEnd {
			return 0, "", false, fmt.Errorf("preferred host port %d is outside configured L4 range", preferredHostPort)
		}
		hp, url, r, done, terr := tryCandidate(preferredHostPort, true)
		if terr != nil {
			return 0, "", false, terr
		}
		if done {
			return hp, url, r, nil
		}
		// Park, don't reallocate. Falling through to the random-then-linear
		// pool walk would mint a new public endpoint and silently break every
		// client that had memorized the original host:port. See
		// ErrPreferredHostPortUnavailable for the policy rationale.
		return 0, "", false, fmt.Errorf("%w: %d", ErrPreferredHostPortUnavailable, preferredHostPort)
	}

	for i := 0; i < allocatorRandomAttempts; i++ {
		candidate := s.cfg.L4PortRangeStart + mathrand.Intn(span)
		hp, url, r, done, terr := tryCandidate(candidate, false)
		if terr != nil {
			return 0, "", false, terr
		}
		if done {
			return hp, url, r, nil
		}
	}

	for candidate := s.cfg.L4PortRangeStart; candidate <= s.cfg.L4PortRangeEnd; candidate++ {
		hp, url, r, done, terr := tryCandidate(candidate, false)
		if terr != nil {
			return 0, "", false, terr
		}
		if done {
			return hp, url, r, nil
		}
	}
	return 0, "", false, errors.New("L4 port pool exhausted")
}

func (s *Service) recordClusterExposedPort(ctx context.Context, sandboxID string, port int, route cluster.ExposedPortRoute) error {
	c := s.Cluster()
	if c == nil {
		return nil
	}
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.AddExposedPort(commitCtx, sandboxID, port, route); err != nil {
		return fmt.Errorf("cluster: record exposed port: %w", err)
	}
	return nil
}

func (s *Service) removeClusterExposedPort(ctx context.Context, sandboxID string, port int) error {
	c := s.Cluster()
	if c == nil {
		return nil
	}
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.RemoveExposedPort(commitCtx, sandboxID, port); err != nil {
		return fmt.Errorf("cluster: remove exposed port: %w", err)
	}
	return nil
}

func (s *Service) UnexposePort(ctx context.Context, id string, port int) error {
	unlock := s.lockExposedPort(id, port)
	defer unlock()
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return err
	}
	exposure := findExposure(sandbox, port)
	// Best-effort tear-down of every caddy surface the exposure could be on.
	// We dispatch on the recorded protocol when it's known, but also fall
	// back to the legacy HTTP path so old rows that pre-date the protocol
	// column are still cleaned up correctly.
	if exposure == nil {
		_ = s.publicRoutes().DeletePortRoute(ctx, id, port)
	} else {
		if err := s.deleteExposedPortRoute(ctx, sandbox, *exposure); err != nil {
			return err
		}
	}
	if err := s.store.DeletePort(ctx, id, port); err != nil {
		return err
	}
	// The ingress proxy's cached port gates come from the row just deleted.
	s.invalidateWarm(id)
	s.touchAllowedPorts(ctx, id)
	return nil
}

// findExposure returns the exposure matching port, or nil. Linear scan is
// fine because ExposedPorts is bounded by the host port pool size and in
// practice rarely exceeds a handful per sandbox.
func findExposure(sandbox *models.Sandbox, port int) *models.ExposedPort {
	if sandbox == nil {
		return nil
	}
	for i := range sandbox.ExposedPorts {
		if sandbox.ExposedPorts[i].Port == port {
			return &sandbox.ExposedPorts[i]
		}
	}
	return nil
}

// upsertExposedPortRoute republishes one exposure to caddy based on its
// stored protocol. Used everywhere a sandbox transitions to running
// (StartSandbox, Reconcile when a container is back, docker start events).
//
// For HTTP exposures, the route shape depends on whether the sandbox
// opted into serverless wake (Lifecycle.Serverless + EnableServerless
// rollout gate). Serverless sandboxes get the wake-aware route that
// targets the loopback ingress proxy; everything else gets the legacy
// direct-dial route. installHTTPPortRoute owns the transition logic so
// the two shapes never coexist for the same (id, port).
func (s *Service) upsertExposedPortRoute(ctx context.Context, sandbox *models.Sandbox, port models.ExposedPort) error {
	switch port.Protocol {
	case "", models.ExposedPortProtocolHTTP:
		return s.installHTTPPortRoute(ctx, sandbox, port.Port)
	case models.ExposedPortProtocolTCP:
		return s.installTCPPortRoute(ctx, sandbox, port.Port, port.HostPort)
	case models.ExposedPortProtocolTLS:
		return s.installTLSPortRoute(ctx, sandbox, port.Port)
	default:
		return fmt.Errorf("unknown protocol %q on exposed port %d", port.Protocol, port.Port)
	}
}

// deleteExposedPortRoute drops one exposure's caddy entity. Used everywhere
// a sandbox transitions out of running (StopSandbox, DestroySandbox, exit
// events, reconcile destroyed pass).
//
// For HTTP exposures we delete BOTH route shapes (direct + wake) because
// either may exist depending on the sandbox's current serverless mode
// — and for a wake-armed serverless sandbox transitioning to stopped,
// removeHTTPPortRoute is also the right cleanup when the lifecycle
// callsite is a destroy, not just a stop. Stop-but-armed callers must
// skip this path entirely (see stopSandboxInternal).
func (s *Service) deleteExposedPortRoute(ctx context.Context, sandbox *models.Sandbox, port models.ExposedPort) error {
	switch port.Protocol {
	case "", models.ExposedPortProtocolHTTP:
		return s.removeHTTPPortRoute(ctx, sandbox.ID, port.Port)
	case models.ExposedPortProtocolTCP:
		return s.publicRoutes().DeleteTCPRoute(ctx, port.HostPort)
	case models.ExposedPortProtocolTLS:
		return s.deleteTLSPortRoute(ctx, sandbox.ID, port.Port)
	default:
		return fmt.Errorf("unknown protocol %q on exposed port %d", port.Protocol, port.Port)
	}
}

// installHTTPPortRoute writes the HTTP port route in the shape that
// matches the sandbox's current serverless mode AND current status,
// then removes any other shape. Install-then-delete ordering means
// there is never a window where neither shape exists, so a request
// landing mid-flip always hits one valid route.
//
// Shape selection is delegated to chooseRouteShape so reconcile,
// lifecycle, and event paths share one source of truth — see
// plans/warm-direct-route-bypass.md D7/D8.
//
// Routed through caddyCoalescer.Flush so concurrent callers targeting
// the same (id, port) collapse into one admin write. Flush preserves
// the synchronous error contract callers (ExposePort, reconcile, the
// rollback path) depend on; an op superseded by a later Enqueue/Flush
// for the same key returns nil to the prior waiter, which is correct
// because the newer intent represents the same converged state the
// caller wanted. See plans/warm-direct-route-bypass.md D6/D12.
func (s *Service) installHTTPPortRoute(ctx context.Context, sandbox *models.Sandbox, port int) error {
	s.ensureCaddyCoalescer()
	// Snapshot the sandbox row by value so a concurrent mutation
	// (Status flip, ContainerIP rebind) between Flush enqueue and the
	// drain's invocation of `do` cannot change the intent the caller
	// asked for. The closure must operate on a stable view.
	snapshot := *sandbox
	return s.caddyCoalescer.Flush(ctx, sandbox.ID, port, func() error {
		return s.applyHTTPPortRoute(ctx, &snapshot, port)
	})
}

// applyHTTPPortRoute performs the actual Caddy admin writes for one
// (sandbox, port) install intent. Extracted from installHTTPPortRoute
// so the coalescer's drain can invoke it with a stable sandbox
// snapshot. Not called directly outside the coalescer path.
//
// The snapshot decides the shape except for the port's token gate, which
// is read from the store under httpRouteLocks (route_gate.go): two drains
// can run ops for one key at once, and the coalescer cannot tell an old
// intent from a new one, so only the lock plus a fresh read keep an old
// public intent from replacing a newer gated route.
func (s *Service) applyHTTPPortRoute(ctx context.Context, sandbox *models.Sandbox, port int) error {
	// Every shape takes the lock, not just the direct one: a writer that
	// read the gate before an expose stored "token" must finish before
	// that expose's wake write starts, or its direct write lands last. The
	// ownership fence is read under it for the same reason: the fence and
	// the confirm that lifts it each rewrite the route after changing the
	// fence, so the last write for a port always matches the fence.
	unlock := s.httpRouteLocks.lock(portLockKey{id: sandbox.ID, port: port})
	defer unlock()
	if s.OwnershipFenced(sandbox.ID) {
		return s.applyFencedHTTPPortRoute(ctx, sandbox.ID, port)
	}
	if s.isWasmSandbox(sandbox) {
		return s.installWasmHTTPPortRoute(ctx, sandbox, port)
	}
	if s.isIsolateSandbox(sandbox) {
		return s.installIsolateHTTPPortRoute(ctx, sandbox, port)
	}
	// The direct route is where DIRECT-path Host masking is enforced; the
	// serverless wake route can't carry it (the loopback ingress proxy
	// overwrites Host on re-dial), so that path masks in the proxy instead.
	routeOpts := caddy.HTTPRouteOptions{MaskRequestHost: sandbox.MaskRequestHost}
	shape := s.chooseRouteShape(sandbox, RouteKindHTTP)
	if shape == RouteShapeDirect {
		// A token-gated port (A2) never gets the route that dials the
		// container: only the ingress-proxy shape passes the token check.
		// The gate is read from the store here, not from sandbox, which
		// reconcile or a start may have read before an expose changed it.
		gated, err := s.portGatedNow(ctx, sandbox, port)
		if err != nil {
			return err
		}
		s.afterRouteGateRead(gateReadPortRoute)
		if gated {
			shape = RouteShapeWake
		}
	}
	switch shape {
	case RouteShapeDirect:
		// Non-serverless callers (and serverless-bypass-off callers)
		// fall through to UpsertPortRoute byte-for-byte (empty mask emits no
		// headers block), so the non-serverless JSON regression test stays
		// valid. Only the warm-bypass path adopts the retry window.
		if s.serverlessWakeEnabled(sandbox) && s.cfg.HTTPWakeDirectBypassEnabled {
			if err := s.publicRoutes().UpsertPortRouteWithRetry(ctx, sandbox.ID, sandbox.ContainerIP, port, s.cfg.HTTPWakeDirectRouteRetryDuration, routeOpts); err != nil {
				return err
			}
		} else {
			if err := s.publicRoutes().UpsertPortRoute(ctx, sandbox.ID, sandbox.ContainerIP, port, routeOpts); err != nil {
				return err
			}
		}
		// Best-effort: any leftover wake route from a prior
		// Stopped+armed state (or a flag flip back to bypass-on) must
		// go so Caddy doesn't keep two routes matching the same host.
		// DeleteWakeHTTPPortRoute treats 404 as success.
		_ = s.publicRoutes().DeleteWakeHTTPPortRoute(ctx, sandbox.ID, port)
		return nil
	case RouteShapeWake:
		if err := s.publicRoutes().UpsertWakeHTTPPortRoute(ctx, sandbox.ID, s.cfg.InternalIngressAddr, port); err != nil {
			return err
		}
		_ = s.publicRoutes().DeletePortRoute(ctx, sandbox.ID, port)
		return nil
	case RouteShapeNone:
		// Destroyed sandboxes or stopped-unarmed serverless sandboxes
		// publish neither route. Idempotent deletes; either or both
		// may already be absent.
		_ = s.publicRoutes().DeletePortRoute(ctx, sandbox.ID, port)
		_ = s.publicRoutes().DeleteWakeHTTPPortRoute(ctx, sandbox.ID, port)
		return nil
	}
	return nil
}

// installTCPPortRoute publishes the correct L4-TCP server config for
// the (sandbox, port, hostPort) tuple based on chooseRouteShape. Today
// (bypass off) every serverless sandbox still gets the wake-aware
// shape — chooseRouteShape short-circuits to Wake when
// L4WakeDirectBypassEnabled=false, preserving pre-Phase-2 behavior.
// With the flag on, warm serverless TCP exposures publish a direct
// upstream and stopped-unarmed sandboxes drop the L4 server entirely.
func (s *Service) installTCPPortRoute(ctx context.Context, sandbox *models.Sandbox, port, hostPort int) error {
	if err := s.EnsureLayer4Ready(ctx); err != nil {
		return err
	}
	// The fence is read under the port's l4RouteLocks, as applyHTTPPortRoute
	// reads it under httpRouteLocks: the last write always matches it.
	unlock := s.l4RouteLocks.lock(portLockKey{id: sandbox.ID, port: port})
	defer unlock()
	if s.OwnershipFenced(sandbox.ID) {
		return s.publicRoutes().UpsertFencedTCPRoute(ctx, sandbox.ID, port, hostPort)
	}
	switch s.chooseRouteShape(sandbox, RouteKindL4) {
	case RouteShapeDirect:
		return s.publicRoutes().UpsertTCPRoute(ctx, sandbox.ID, sandbox.ContainerIP, port, hostPort)
	case RouteShapeWake:
		return s.publicRoutes().UpsertWakeTCPRoute(ctx, sandbox.ID, port, hostPort, s.cfg.InternalL4WakeAddr)
	case RouteShapeNone:
		return s.publicRoutes().DeleteTCPRoute(ctx, hostPort)
	}
	return nil
}

// installTLSPortRoute publishes the correct TLS-SNI route for the
// (sandbox, port) tuple based on chooseRouteShape. The Unix-socket
// lifecycle is intertwined with the route shape:
//
//   - Direct shape: PATCH first, then schedule a delayed close on the
//     wake listener (D2 — a TLS handshake started against the prior
//     wake route may still be in flight when PATCH lands; closing the
//     socket immediately drops that handshake).
//   - Wake shape: create the socket first so the upstream is reachable
//     the instant Caddy PATCHes the route to point at it; roll back the
//     socket on PATCH failure to avoid leaking a listener with no live
//     route.
//   - None: delete the route then close the socket; both are
//     idempotent.
func (s *Service) installTLSPortRoute(ctx context.Context, sandbox *models.Sandbox, port int) error {
	if err := s.EnsureLayer4Ready(ctx); err != nil {
		return err
	}
	sniHost := s.caddy.SNIHost(sandbox.ID, port)
	unlock := s.l4RouteLocks.lock(portLockKey{id: sandbox.ID, port: port})
	defer unlock()
	if s.OwnershipFenced(sandbox.ID) {
		// A wake listener, if any, stays: the swap back re-points the
		// route at it (ensureTLSWakeListener is idempotent).
		return s.caddy.UpsertFencedTLSSNIRoute(ctx, sandbox.ID, sniHost, port)
	}
	switch s.chooseRouteShape(sandbox, RouteKindL4) {
	case RouteShapeDirect:
		if err := s.caddy.UpsertTLSSNIRoute(ctx, sandbox.ID, sniHost, sandbox.ContainerIP, port); err != nil {
			return err
		}
		s.scheduleTLSWakeListenerClose(sandbox.ID, port, s.cfg.TLSWakeListenerCloseDelay)
		return nil
	case RouteShapeWake:
		socketPath, err := s.ensureTLSWakeListener(sandbox.ID, port)
		if err != nil {
			return err
		}
		if err := s.caddy.UpsertWakeTLSSNIRoute(ctx, sandbox.ID, sniHost, socketPath, port); err != nil {
			s.closeTLSWakeListener(sandbox.ID, port)
			return err
		}
		return nil
	case RouteShapeNone:
		if err := s.caddy.DeleteTLSSNIRoute(ctx, sandbox.ID, port); err != nil {
			return err
		}
		s.closeTLSWakeListener(sandbox.ID, port)
		return nil
	}
	return nil
}

func (s *Service) deleteTLSPortRoute(ctx context.Context, id string, port int) error {
	if err := s.caddy.DeleteTLSSNIRoute(ctx, id, port); err != nil {
		return err
	}
	s.closeTLSWakeListener(id, port)
	return nil
}

func (s *Service) serverlessWakeEnabled(sandbox *models.Sandbox) bool {
	return sandbox != nil && s.cfg.EnableServerless && sandbox.Lifecycle.Serverless
}

// removeHTTPPortRoute drops both HTTP route shapes for a (sandbox, port).
// Both calls are idempotent and treat 404 as success, so calling this
// without knowing which shape is currently live is safe and cheap.
func (s *Service) removeHTTPPortRoute(ctx context.Context, id string, port int) error {
	s.releaseWasmHTTPListener(id, port)
	s.releaseIsolateHTTPListener(id, port)
	if err := s.publicRoutes().DeletePortRoute(ctx, id, port); err != nil {
		return err
	}
	if err := s.publicRoutes().DeleteWakeHTTPPortRoute(ctx, id, port); err != nil {
		return err
	}
	return nil
}

// touchAllowedPorts is a small wrapper that refreshes the toolbox's allowlist
// after a port-table mutation. The store round-trip gets the current status,
// address and token; syncAllowedPorts reads the ports under its own lock.
func (s *Service) touchAllowedPorts(ctx context.Context, id string) {
	if updated, err := s.store.Get(ctx, id); err == nil {
		s.syncAllowedPorts(ctx, updated)
	}
}

type ToolboxEndpoint struct {
	URL   string
	Token string
}

func (s *Service) ToolboxTarget(ctx context.Context, id string) (ToolboxEndpoint, error) {
	if err := s.TouchSandbox(ctx, id); err != nil {
		return ToolboxEndpoint{}, err
	}
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return ToolboxEndpoint{}, err
	}
	return s.toolboxEndpointForSandbox(ctx, sandbox)
}

// toolboxEndpointForSandbox builds the toolbox endpoint from an already-fetched,
// owner-scoped sandbox. The toolbox dispatchers pass the sandbox the wake helper
// already read, so the network path avoids re-reading the row (D15); it does not
// touch the sandbox (ToolboxTarget and the dispatchers' TouchSandbox own that).
func (s *Service) toolboxEndpointForSandbox(ctx context.Context, sandbox *models.Sandbox) (ToolboxEndpoint, error) {
	// A stopped sandbox has no live toolbox. Only Firecracker clears ContainerIP
	// on stop, so for Docker/containerd a stale ContainerIP would otherwise be
	// dialed — and that address may have been reassigned to another container,
	// which would then receive this sandbox's toolbox token (S12). Gate on the
	// running state, which every caller has already ensured via
	// EnsureSandboxAwakeForHTTP (a serverless sandbox is woken first; a
	// manually-stopped one errors there). ErrSandboxNotRunning classifies to 409.
	if sandbox.Status != models.SandboxStatusStarted {
		return ToolboxEndpoint{}, ErrSandboxNotRunning
	}
	if sandbox.ContainerIP == "" {
		return ToolboxEndpoint{}, errors.New("sandbox container IP is not available")
	}
	addr, err := s.toolboxAddress(ctx, sandbox)
	if err != nil {
		return ToolboxEndpoint{}, err
	}
	return ToolboxEndpoint{
		URL:   "http://" + addr,
		Token: sandbox.ToolboxToken,
	}, nil
}

// toolboxEndpointForActiveCall is the dispatcher entry: it touches the sandbox
// (coalesced last-active write) and builds the endpoint from the sandbox the
// dispatcher already read, skipping ToolboxTarget's re-read (D15).
func (s *Service) toolboxEndpointForActiveCall(ctx context.Context, sandbox *models.Sandbox) (ToolboxEndpoint, error) {
	if err := s.TouchSandbox(ctx, sandbox.ID); err != nil {
		return ToolboxEndpoint{}, err
	}
	return s.toolboxEndpointForSandbox(ctx, sandbox)
}

// toolboxAddress is the host:port sandboxd dials for the sandbox's toolboxd:
// the runtime's answer when it has one (Docker under
// SB_DOCKER_TOOLBOX_LOOPBACK reads the live 127.0.0.1 binding — one inspect
// per call, since the port changes on every start), else
// ContainerIP:ToolboxPort.
func (s *Service) toolboxAddress(ctx context.Context, sandbox *models.Sandbox) (string, error) {
	if rt, err := s.runtimeForSandbox(sandbox); err == nil {
		if a, ok := runtime.AsToolboxAddresser(rt); ok {
			return a.ToolboxAddress(ctx, sandbox)
		}
	}
	return fmt.Sprintf("%s:%d", sandbox.ContainerIP, s.cfg.ToolboxPort), nil
}

// WakeAwareToolboxTarget is the entry point every control-plane HTTP
// proxy (v1 toolbox/sessions, daytona toolbox, e2b runtime) calls in
// place of ToolboxTarget. It funnels every request through the wake
// helper so a stopped serverless sandbox with wake_armed=true is
// resurrected before the proxy attempts to dial the toolbox.
//
// Behavior is exactly ToolboxTarget for: running sandboxes, stopped
// non-serverless sandboxes, and any case where cfg.EnableServerless
// is off (rollout-gate contract). The two new sentinels
// (ErrSandboxManuallyStopped, ErrWakeCircuitOpen) are surfaced
// upstream so apihttp can map them to 409 and 503+Retry-After:60
// respectively.
func (s *Service) WakeAwareToolboxTarget(ctx context.Context, id string) (ToolboxEndpoint, error) {
	if _, err := s.EnsureSandboxAwakeForHTTP(ctx, id); err != nil {
		return ToolboxEndpoint{}, err
	}
	return s.ToolboxTarget(ctx, id)
}

// PortEndpoint is the upstream the ingress proxy dials for a wake-aware
// exposed-port request. URL has the form http://{containerIP}:{port}.
type PortEndpoint struct {
	URL string
	// MaskRequestHost is the value the loopback ingress proxy must rewrite the
	// upstream Host header to before re-dialing the container. Empty = keep the
	// proxy's default (the upstream URL host). This is the serverless wake-path
	// enforcement point for E2B network.maskRequestHost; the direct Caddy route
	// enforces the same value via caddy.HTTPRouteOptions. Both read the one
	// sandbox row, so they can't disagree.
	MaskRequestHost string
}

// WakeAwarePortTarget resolves a sandbox's exposed-port upstream URL,
// ensuring the sandbox is awake first. Used by the loopback ingress proxy
// when Caddy forwards a wake-aware HTTP port route. The same sentinels
// EnsureSandboxAwakeForHTTP returns flow through here unchanged.
func (s *Service) WakeAwarePortTarget(ctx context.Context, id string, port int) (PortEndpoint, error) {
	sandbox, err := s.EnsureSandboxAwakeForHTTP(ctx, id)
	if err != nil {
		return PortEndpoint{}, err
	}
	if sandbox == nil || sandbox.ContainerIP == "" {
		// Re-read in case the wake path returned a stale snapshot from
		// before StartSandbox attached the new container IP.
		fresh, getErr := s.store.Get(ctx, id)
		if getErr != nil {
			return PortEndpoint{}, getErr
		}
		sandbox = fresh
	}
	exposure := findExposure(sandbox, port)
	if exposure == nil || (exposure.Protocol != "" && exposure.Protocol != models.ExposedPortProtocolHTTP) {
		return PortEndpoint{}, fmt.Errorf("sandbox %s does not expose HTTP port %d", id, port)
	}
	mask := strings.TrimSpace(sandbox.MaskRequestHost)
	if s.isWasmSandbox(sandbox) {
		url, err := s.wasmHTTPUpstreamURL(ctx, id, port)
		if err != nil {
			return PortEndpoint{}, err
		}
		return PortEndpoint{URL: url, MaskRequestHost: mask}, nil
	}
	if s.isIsolateSandbox(sandbox) {
		url, err := s.isolateHTTPUpstreamURL(ctx, id, port)
		if err != nil {
			return PortEndpoint{}, err
		}
		return PortEndpoint{URL: url, MaskRequestHost: mask}, nil
	}
	if sandbox.ContainerIP == "" {
		return PortEndpoint{}, errors.New("sandbox container IP is not available")
	}
	return PortEndpoint{URL: fmt.Sprintf("http://%s:%d", sandbox.ContainerIP, port), MaskRequestHost: mask}, nil
}

// TouchSandbox bumps last_active_at for id with per-sandbox debounce.
// The wake-aware ingress proxy and the toolbox/session/runtime proxies
// call this on every request, so it must be cheap under high
// per-sandbox RPS — see touch_coalescer.go for the rationale and the
// debounce window. Callers that need a guaranteed immediate flush
// (lifecycle transitions, tests) should drop to s.store.Touch directly.
func (s *Service) TouchSandbox(ctx context.Context, id string) error {
	s.ensureTouchCoalescer()
	return s.touchCoalescer.Touch(ctx, id)
}

// IsSandboxStarted is the preflight check the wake-aware ingress proxy
// uses to skip request-body buffering for warm sandboxes. It returns
// (true, nil) only when the sandbox row exists and its status is
// Started; any other status (Stopped, Destroyed, in-flight create)
// returns (false, nil). store.ErrNotFound is returned unwrapped so the
// proxy can map it to 404 without a second store hit.
//
// Hot path: a short-TTL cache (warmCache) lets repeated warm requests
// to the same sandbox skip the SQLite read. The cache holds positives
// only ("seen Started in the last warmCacheTTL"); a miss always falls
// through to s.store.Get so cold/stopped/destroyed sandboxes never
// short-circuit. Lifecycle transitions (StartSandbox success, every
// stop path, every destroy path) explicitly invalidate the entry.
func (s *Service) IsSandboxStarted(ctx context.Context, id string) (bool, error) {
	if s.warmCacheHit(id) {
		return true, nil
	}
	warmGen := s.warmGen.Load()
	sb, err := s.scopedGet(ctx, id)
	if err != nil {
		return false, err
	}
	started := sb.Status == models.SandboxStatusStarted
	if started {
		s.warmCacheSetSandbox(sb, warmGen)
	}
	return started, nil
}

// warmCacheTTL is intentionally short (2s) so an entirely-missed
// invalidation self-heals fast. The explicit invalidation hooks below
// keep the normal staleness window sub-second; the TTL is the backstop
// for the pathological case where an invalidation never fires.
const warmCacheTTL = 2 * time.Second

func (s *Service) warmCacheHit(id string) bool {
	_, ok := s.warmEntryFor(id)
	return ok
}

// warmCacheSet caches id as warm without its port list (tests). The port
// gate never trusts such an entry (PortAccess re-reads the row); production
// paths have the row and use warmCacheSetSandbox.
func (s *Service) warmCacheSet(id string) {
	s.warmCacheMu.Lock()
	if s.warmCache == nil {
		s.warmCache = make(map[string]warmEntry)
	}
	s.warmCache[id] = warmEntry{exp: time.Now().Add(warmCacheTTL).UnixNano()}
	s.warmCacheMu.Unlock()
}

// invalidateWarm drops id from the warm cache. Called from every state
// transition that takes a sandbox out of Started: StartSandbox failure
// paths, every stop path (manual, lifecycle, involuntary die/oom), and
// every destroy path. Safe on a missing key.
func (s *Service) invalidateWarm(id string) {
	s.warmCacheMu.Lock()
	delete(s.warmCache, id)
	s.warmGen.Add(1)
	s.warmCacheMu.Unlock()
}

// acquireWakeStartSlot caps concurrent wake-driven StartSandbox
// invocations across the node. Returns a release closure on success;
// returns ctx.Err() if the caller's context is cancelled before a slot
// becomes available. Lazily sized from cfg.WakeStartConcurrency on
// first use so test harnesses (newCapacityHarness, cluster fixtures)
// that build &Service{} directly don't have to thread the value
// through. A zero or negative cfg value disables the cap entirely
// (unbounded chan via nil send branch) to preserve pre-feature
// behavior for tests.
func (s *Service) acquireWakeStartSlot(ctx context.Context) (func(), error) {
	s.wakeStartSemOnce.Do(func() {
		cap := s.cfg.WakeStartConcurrency
		if cap > 0 {
			s.wakeStartSem = make(chan struct{}, cap)
		}
	})
	if s.wakeStartSem == nil {
		return func() {}, nil
	}
	select {
	case s.wakeStartSem <- struct{}{}:
		return func() { <-s.wakeStartSem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Service) Health(ctx context.Context) (models.HealthStatus, error) {
	live, err := s.store.CountLive(ctx)
	if err != nil {
		return models.HealthStatus{}, err
	}

	// A containerd host with no Docker (SB_DOCKER_ENABLED=false, C2) is not
	// degraded by its absence.
	dockerStatus := "disabled"
	if !s.cfg.DockerDisabled {
		dockerStatus = "ok"
		if err := s.docker.Ping(ctx); err != nil {
			dockerStatus = err.Error()
		}
	}

	caddyStatus := "ok"
	if err := s.caddy.Ping(ctx); err != nil {
		caddyStatus = err.Error()
	}

	// "disabled" is distinct from "ok" / failure — it tells the operator
	// "we didn't probe this on purpose" rather than masking a real fault.
	// A node whose role does not run the gateway (a server-only node in a
	// role-split cluster) reports "disabled" too, even with
	// SB_ENABLE_SSH_GATEWAY on: the daemon never starts one there
	// (Config.RunsSSHGateway), so probing it could only fail. The wording is
	// the existing one on purpose: the dashboard, the SDKs and every other
	// reader of ssh_gateway already treat "disabled" as "not run here".
	sshStatus := "disabled"
	if s.cfg.RunsSSHGateway() {
		if err := probeSSHGateway(ctx, s.cfg.SSHListenAddr); err != nil {
			sshStatus = err.Error()
		} else {
			sshStatus = "ok"
		}
	}

	firecrackerStatus := "disabled"
	if s.cfg.EnableFirecracker {
		switch rt := s.firecracker.(type) {
		case interface{ RuntimeHealth(context.Context) string }:
			firecrackerStatus = rt.RuntimeHealth(ctx)
		case nil:
			firecrackerStatus = fmt.Sprintf("runtime %q: driver not registered", models.RuntimeFirecracker)
		default:
			if err := rt.Ping(ctx); err != nil {
				firecrackerStatus = err.Error()
			} else {
				firecrackerStatus = "ok"
			}
		}
	}

	wasmStatus := "disabled"
	if s.cfg.EnableWasm {
		if !s.cfg.IsWorker() {
			wasmStatus = "skipped on non-worker node"
		} else {
			switch rt := s.wasm.(type) {
			case nil:
				wasmStatus = fmt.Sprintf("runtime %q: driver not registered", models.RuntimeWasm)
			default:
				if err := rt.Ping(ctx); err != nil {
					wasmStatus = err.Error()
				} else {
					wasmStatus = "ok"
				}
			}
		}
	}

	// Isolate health mirrors wasm: Ping stats the workerd binary so a
	// missing/broken binary surfaces as degraded here rather than only as
	// failed creates. Non-worker nodes never host isolates, so they report
	// "skipped" and do not degrade.
	isolateStatus := "disabled"
	if s.cfg.EnableIsolate {
		if !s.cfg.IsWorker() {
			isolateStatus = "skipped on non-worker node"
		} else {
			switch rt := s.isolate.(type) {
			case nil:
				isolateStatus = fmt.Sprintf("runtime %q: driver not registered", models.RuntimeIsolate)
			default:
				if err := rt.Ping(ctx); err != nil {
					isolateStatus = err.Error()
				} else {
					isolateStatus = "ok"
				}
			}
		}
	}

	status := "ok"
	if (!s.cfg.DockerDisabled && dockerStatus != "ok") || caddyStatus != "ok" {
		status = "degraded"
	}
	if s.cfg.EnableFirecracker && firecrackerStatus != "ok" {
		status = "degraded"
	}
	if s.cfg.EnableWasm && s.cfg.IsWorker() && wasmStatus != "ok" {
		status = "degraded"
	}
	if s.cfg.EnableIsolate && s.cfg.IsWorker() && isolateStatus != "ok" {
		status = "degraded"
	}
	// SSH gateway being down only degrades health when it's expected to be up.
	if s.cfg.RunsSSHGateway() && sshStatus != "ok" {
		status = "degraded"
	}
	// A revoked key stops the node's work on sealed data (§10). Health still
	// answers, so the docs do not promise the ingress stops routing here.
	keyCustody := ""
	if s.KeyRevoked() {
		keyCustody = "revoked"
		status = "degraded"
	}

	clusterTopology := ""
	clusterNodes := 0
	if s.cfg.EnableCluster {
		clusterTopology = "ok"
		if c := s.Cluster(); c != nil {
			// Health reports node counts and the topology contract, both
			// of which are identity/role facts.
			members := cluster.IdentityMembers(c)
			clusterNodes = cluster.LiveMemberCount(members)
			if err := s.clusterTopologyErrorFor(members); err != nil {
				clusterTopology = err.Error()
				status = "degraded"
			}
		}
	}

	return models.HealthStatus{
		Status:          status,
		Sandboxes:       live,
		Docker:          dockerStatus,
		Caddy:           caddyStatus,
		Firecracker:     firecrackerStatus,
		Wasm:            wasmStatus,
		Isolate:         isolateStatus,
		SSHGateway:      sshStatus,
		ClusterTopology: clusterTopology,
		ClusterNodes:    clusterNodes,
		KeyCustody:      keyCustody,
		Version:         version.Version,
	}, nil
}

// sealedOpenError reports a failed open of a sealed value. A key-store class
// (a revoke) stays visible, so the API answers 503 key_revoked instead of a
// decrypt failure; anything else is ErrDecryptFailed as before.
func sealedOpenError(what string, err error) error {
	if secrets.IsKeyStoreError(err) {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%w: %s: %v", secrets.ErrDecryptFailed, what, err)
}

// Capacity returns the admitter's current snapshot. Returns the zero value
// when no admitter is configured (e.g. in tests).
//
// Phase 6 PR-D: overlays LocalTemplateIDs from a 5s-TTL cache so peers
// fetching /v1/capacity see which Firecracker templates this node can
// already serve without paying a remote AOCR pull. The cache shields
// SQLite from the gossip cadence (single-writer; MaxOpenConns=1).
func (s *Service) Capacity() capacity.Snapshot {
	var snap capacity.Snapshot
	if s.admitter == nil {
		snap = capacity.Snapshot{CanAdmit: true}
	} else {
		snap = s.admitter.Snapshot()
	}
	if ids, known := s.LocalReadyTemplateInventory(context.Background()); known {
		snap.LocalTemplateInventoryKnown = true
		snap.LocalTemplateIDs = ids
	}
	if ids, known := s.LocalTemplateCatalogInventory(context.Background()); known {
		snap.LocalTemplateCatalogInventoryKnown = true
		snap.LocalTemplateCatalogIDs = ids
	}
	if refs, known := s.LocalReadyWasmModuleInventory(context.Background()); known {
		snap.LocalWasmModuleInventoryKnown = true
		snap.LocalWasmModuleIDs = refs
	}
	snap.EgressGatewayReady = s.EgressGatewayReady()
	snap.OwnershipLeaseFile = s.cfg.EnableCluster && s.cfg.OwnershipLeaseFile != ""
	// Warm-pool entry status: how GET /v1/warm-pools on any node reports
	// this one, with no fan-out (W1).
	snap.WarmPools = s.localWarmPoolStatus()
	// Network-slot pools: a peer with CPU and memory to spare can still be
	// full for a runtime, and placement can only skip it if we say so.
	snap.SlotPools = s.LocalSlotPools(context.Background())
	// Observability-only engine tag (not a placement attribute).
	if s.cfg.ContainerEngine != "" {
		snap.ContainerEngine = s.cfg.ContainerEngine
	}
	return snap
}

// LocalReadyTemplateInventory returns the IDs of Firecracker templates
// whose artifacts are usable on this host plus whether that inventory
// is authoritative. Cached for 5s — peers gossip /v1/capacity at this
// cadence and a per-tick SQLite hit would starve the create path's
// writes (single-writer DB). On error the cache is left untouched and
// the previous value is returned, matching the "stale is better than
// wrong" contract the rest of the heartbeat path uses.
func (s *Service) LocalReadyTemplateInventory(ctx context.Context) ([]string, bool) {
	if s == nil || s.store == nil {
		return nil, false
	}
	now := time.Now()
	s.localReadyTemplateIDsMu.Lock()
	if now.Before(s.localReadyTemplateIDsExpires) {
		// Defensive copy: callers might mutate (placement wraps it in a
		// snapshot that crosses goroutine boundaries) and we don't want
		// to hand out the cache's backing array.
		out := append([]string(nil), s.localReadyTemplateIDsCache...)
		known := s.localReadyTemplateIDsKnown
		s.localReadyTemplateIDsMu.Unlock()
		return out, known
	}
	s.localReadyTemplateIDsMu.Unlock()

	ids, catalogIDs, err := s.store.ListTemplateInventoryIDs(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("local ready template ids: list failed",
				"error", err)
		}
		// Return the stale cache rather than nil so a one-tick SQLite
		// hiccup doesn't trick peers into thinking we lost all our
		// templates.
		s.localReadyTemplateIDsMu.Lock()
		out := append([]string(nil), s.localReadyTemplateIDsCache...)
		known := s.localReadyTemplateIDsKnown
		s.localReadyTemplateIDsMu.Unlock()
		return out, known
	}
	s.localReadyTemplateIDsMu.Lock()
	s.localReadyTemplateIDsCache = ids
	s.localTemplateCatalogIDsCache = catalogIDs
	s.localReadyTemplateIDsKnown = true
	s.localReadyTemplateIDsExpires = now.Add(5 * time.Second)
	out := append([]string(nil), ids...)
	s.localReadyTemplateIDsMu.Unlock()
	return out, true
}

// LocalTemplateCatalogInventory returns every template row on this worker,
// including pending and failed rows. It shares the ready-inventory refresh so
// capacity heartbeats still perform only one small SQLite query per TTL.
func (s *Service) LocalTemplateCatalogInventory(ctx context.Context) ([]string, bool) {
	if s == nil || s.store == nil {
		return nil, false
	}
	// Refreshes both cache slices when expired.
	_, known := s.LocalReadyTemplateInventory(ctx)
	s.localReadyTemplateIDsMu.Lock()
	out := append([]string(nil), s.localTemplateCatalogIDsCache...)
	s.localReadyTemplateIDsMu.Unlock()
	return out, known
}

// LocalReadyTemplateIDs returns only the template IDs from
// LocalReadyTemplateInventory. Callers that need to distinguish
// authoritative empty inventory from legacy/unknown should use the
// richer method.
func (s *Service) LocalReadyTemplateIDs(ctx context.Context) []string {
	ids, _ := s.LocalReadyTemplateInventory(ctx)
	return ids
}

// LocalReadyWasmModuleInventory returns module_ref values present in the local
// wasm_modules catalogue plus whether that inventory is authoritative.
func (s *Service) LocalReadyWasmModuleInventory(ctx context.Context) ([]string, bool) {
	if s == nil || s.store == nil || !s.cfg.EnableWasm {
		return nil, false
	}
	now := time.Now()
	s.localReadyWasmModuleIDsMu.Lock()
	if now.Before(s.localReadyWasmModuleIDsExpires) {
		out := append([]string(nil), s.localReadyWasmModuleIDsCache...)
		known := s.localReadyWasmModuleIDsKnown
		s.localReadyWasmModuleIDsMu.Unlock()
		return out, known
	}
	s.localReadyWasmModuleIDsMu.Unlock()

	refs, err := s.store.ListReadyWasmModuleRefs(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("local ready wasm module refs: list failed", "error", err)
		}
		s.localReadyWasmModuleIDsMu.Lock()
		out := append([]string(nil), s.localReadyWasmModuleIDsCache...)
		known := s.localReadyWasmModuleIDsKnown
		s.localReadyWasmModuleIDsMu.Unlock()
		return out, known
	}
	// Reserved-keyword standard modules ("python", …) are filesystem/config
	// backed and deliberately never DB-backed, so they never appear in the
	// catalogue query above. Without folding them into local inventory, a
	// fresh node advertises known-but-empty inventory and cluster placement
	// rejects every `module_ref: "python"` create — yet the only way a row
	// would ever appear is a create that placement just refused (codex P0
	// deadlock). Advertise the staged aliases that actually resolve locally.
	refs = s.appendResolvableReservedModules(ctx, refs)
	s.localReadyWasmModuleIDsMu.Lock()
	s.localReadyWasmModuleIDsCache = refs
	s.localReadyWasmModuleIDsKnown = true
	s.localReadyWasmModuleIDsExpires = now.Add(5 * time.Second)
	out := append([]string(nil), refs...)
	s.localReadyWasmModuleIDsMu.Unlock()
	return out, true
}

// appendResolvableReservedModules unions the reserved standard-module aliases
// that resolve locally into refs (deduped). Resolution is probed once and
// memoized — staged modules are immutable per node, and the resolve hashes a
// large file, so it must not repeat on the inventory hot path.
func (s *Service) appendResolvableReservedModules(ctx context.Context, refs []string) []string {
	s.reservedModuleRefsOnce.Do(func() {
		if s.wasmModuleResolver == nil || len(s.cfg.WasmStandardModules) == 0 {
			return
		}
		for alias := range s.cfg.WasmStandardModules {
			if _, err := s.wasmModuleResolver.Resolve(ctx, alias); err != nil {
				if s.logger != nil {
					s.logger.Warn("reserved wasm module not advertised: did not resolve",
						"alias", alias, "error", err)
				}
				continue
			}
			s.reservedModuleRefs = append(s.reservedModuleRefs, alias)
		}
	})
	if len(s.reservedModuleRefs) == 0 {
		return refs
	}
	seen := make(map[string]struct{}, len(refs))
	for _, r := range refs {
		seen[r] = struct{}{}
	}
	for _, alias := range s.reservedModuleRefs {
		if _, ok := seen[alias]; !ok {
			refs = append(refs, alias)
		}
	}
	return refs
}

// ReplayReservations re-populates the admitter from persistent state. Without
// this, after a daemon restart the admitter sees zero reservations and the
// host can be overcommitted on the first wave of new sandboxes. Destroyed
// AND stopped sandboxes are skipped — neither holds host CPU/RAM (the stop
// path releases the slot, and StartSandbox re-Admits on the way back up), so
// counting them here would re-introduce the overcommit-budget bug we fixed
// when stop began releasing capacity. Best-effort: a store error is logged,
// not returned, since admission control degrading to "unaware" is preferable
// to refusing to boot.
func (s *Service) ReplayReservations(ctx context.Context) {
	if s.admitter == nil {
		return
	}
	ctx = withAuditSubsystem(ctx, auditSubsystemBootRestore)
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("replay reservations: list failed", "error", err)
		return
	}
	replayed := 0
	for _, sandbox := range sandboxes {
		if sandbox.Status == models.SandboxStatusDestroyed || sandbox.Status == models.SandboxStatusStopped {
			continue
		}
		s.admitter.Reserve(sandbox.ID, capacityRequestFromSandbox(sandbox))
		replayed++
	}
	s.logger.Info("capacity reservations replayed", "count", replayed)
}

func (s *Service) Reconcile(ctx context.Context) error {
	// The admin reconcile route keeps its caller: a request's Access wins
	// over the subsystem tag.
	ctx = withAuditSubsystem(ctx, auditSubsystemReconcile)
	// Topology heartbeat: surface a cluster that has crossed the
	// 10-ingress-node sharding threshold without operator opt-in to
	// SB_CLUSTER_SHARD_AWARE_INGRESS. /health also reports this, but the
	// reconcile log line makes it visible to anyone reading sandboxd logs
	// (no metrics scrape required) and repeats on every cycle until fixed,
	// which is the desired loud signal — sharded ingress + naive LB silently
	// black-holes ~(N-1)/N of public traffic.
	if s.cfg.EnableCluster {
		if c := s.Cluster(); c != nil {
			if err := s.clusterTopologyErrorFor(cluster.IdentityMembers(c)); err != nil {
				s.logger.Warn("cluster topology violation", "error", err.Error())
			}
		}
	}

	// Stale-ownership sweep first: if the cluster FSM says another node now
	// owns one of our local sandboxes (typical after a flapped node returns
	// to find its placements were reassigned during the outage), destroy the
	// local copy. This is the converse of the cluster owner watcher — the
	// new owner has already recreated the sandbox; keeping the old copy
	// running would double-bill capacity and serve stale state.
	s.reconcileStaleOwnership(ctx)

	// Creates reported as failed whose rollback did not finish (no leader
	// for the placement fence at the time): finish them before the list
	// below, so a destroyed row is not reconciled as a live one.
	s.reconcileRollbackPending(ctx)

	known, err := s.store.List(ctx)
	if err != nil {
		return err
	}

	// A failed Docker listing must not stop the pass for sandboxes that do
	// not live in Docker. On a containerd-engine host where dockerd is
	// stopped, or was never installed (the Kubernetes worker pod), it fails
	// every time, and returning here left a containerd sandbox the kernel
	// had killed listed as started for good (Kubernetes Phase 0, finding
	// F12). What this pass cannot see, it leaves alone: rows that would be
	// matched against Docker's list, and the stale-mount sweep, which would
	// otherwise read "not listed" as "gone".
	//
	// With Docker off (SB_DOCKER_ENABLED=false, C2) there is nothing to list
	// and no warning to give: Docker-owned rows (there should be none) are
	// left alone, and the mount sweep still runs, since no Docker sandbox
	// can hold a mount here.
	listings := runtimeListings{
		docker:      map[string]*models.SandboxRuntimeState{},
		containerd:  map[string]*models.SandboxRuntimeState{},
		firecracker: map[string]*models.SandboxRuntimeState{},
		wasm:        map[string]*models.SandboxRuntimeState{},
		isolate:     map[string]*models.SandboxRuntimeState{},
	}
	dockerListed := false
	if !s.cfg.DockerDisabled {
		m, dockerErr := s.docker.ListManaged(ctx)
		dockerListed = dockerErr == nil
		if dockerListed {
			listings.docker = m
		} else {
			s.logger.Warn("reconcile: docker listing failed; leaving docker-owned sandboxes and mounts for the next pass", "error", dockerErr)
		}
	}
	if s.containerd != nil {
		listings.containerd, err = s.containerd.ListManaged(ctx)
		if err != nil {
			return err
		}
	}
	if s.firecracker != nil {
		listings.firecracker, err = s.firecracker.ListManaged(ctx)
		if err != nil {
			return err
		}
	}
	if s.wasm != nil {
		listings.wasm, err = s.wasm.ListManaged(ctx)
		if err != nil {
			return err
		}
	}
	if s.isolate != nil {
		listings.isolate, err = s.isolate.ListManaged(ctx)
		if err != nil {
			return err
		}
	}
	managed := mergeManagedRuntimes(listings.docker, listings.containerd, listings.firecracker, listings.wasm, listings.isolate)

	s.reconcileLocalClusterOwnership(ctx, known, managed)

	knownIDs := make(map[string]struct{}, len(known))
	for _, sandbox := range known {
		knownIDs[sandbox.ID] = struct{}{}
	}
	s.reconcileUnknown.retain(knownIDs)
	s.reconcileMissingSelfOwnedPlacements(ctx, knownIDs)

	for _, sandbox := range known {
		runtimeManaged, inDocker := listings.forSandbox(sandbox)
		if inDocker && !dockerListed {
			continue
		}
		state, ok := runtimeManaged[sandbox.ID]
		if !ok {
			// A containerd-owned row on a node whose containerd driver is not
			// wired (operator flipped SB_CONTAINER_ENGINE back to docker, or a
			// config rollback) has no managed entry — but the container may
			// still be live under a containerd we simply aren't driving. Skip
			// it rather than fall through to the delete-row branch below, which
			// would tear down caddy routes, free the host_port, and delete the
			// store row out from under a running task (data loss + leaked
			// container + a freed host_port that can be reallocated while the
			// old bindings persist).
			if models.SandboxEngine(sandbox) == models.ContainerEngineContainerd && s.containerd == nil {
				s.logger.Warn("reconcile: skipping containerd-owned sandbox; containerd driver not registered on this node",
					"sandbox_id", sandbox.ID)
				continue
			}
			if s.isWasmSandbox(sandbox) {
				if s.reconcileWasmOfflineRow(ctx, sandbox) {
					continue
				}
				switch sandbox.Status {
				case models.SandboxStatusPassivated, models.SandboxStatusAwaitingRuntime:
					continue
				case models.SandboxStatusStopped:
					if s.admitter != nil {
						s.admitter.Release(sandbox.ID)
					}
					_ = s.publicRoutes().DeleteSandboxRoute(ctx, sandbox.ID)
					if sandbox.WakeArmed {
						s.ReconstructWakeArmedIfNeeded(ctx, sandbox)
					} else {
						for _, port := range sandbox.ExposedPorts {
							_ = s.deleteExposedPortRoute(ctx, sandbox, port)
						}
					}
					continue
				}
			}
			if s.isFirecrackerSandbox(sandbox) && sandbox.Status == models.SandboxStatusStopped {
				if s.admitter != nil {
					s.admitter.Release(sandbox.ID)
				}
				_ = s.publicRoutes().DeleteSandboxRoute(ctx, sandbox.ID)
				if sandbox.WakeArmed {
					s.ReconstructWakeArmedIfNeeded(ctx, sandbox)
				} else {
					for _, port := range sandbox.ExposedPorts {
						_ = s.deleteExposedPortRoute(ctx, sandbox, port)
					}
				}
				continue
			}
			// The bulk ListManaged snapshot missed this row, but that is one racy
			// read per tick — its per-container Inspect silently skips a
			// container it can't read at that instant (mid-adopt/mid-start).
			// Re-verify with a targeted Inspect before the destructive teardown
			// below, which deletes the row AND the FSM placement
			// (deleteSelfOwnedClusterPlacement): reaping a container that is
			// actually still there turns a transient miss into permanent loss and
			// an intermittent cross-node snapshot 404 on a healthy sandbox
			// (UC-20). Only a definitive not-found reaps; an Inspect that
			// cannot answer keeps the row (reconcile_unknown.go, UC-320).
			if !s.reconcileGoneContainerConfirmed(ctx, sandbox) {
				continue
			}
			// Definitively gone: its toolbox requests will never be
			// answered. (An unknown answer above ends nothing.)
			s.endToolboxCalls(sandbox.ID, toolboxEndGone, "runtime gone")
			// The reap's record (caller system:reconcile) is written once the
			// row is gone; the identity is resolved now, while it exists.
			reaped := s.beginSystemAction(ctx, sandbox.ID, systemActionReap)
			// Container is gone (manual `docker rm`, OOM kill, host reboot,
			// previous reconcile pass already destroyed it via events). Tear
			// down all our state and delete the row outright. Cascades through
			// exposed_ports, immediately freeing any reserved host_port back
			// to the L4 allocator pool — the partial unique index on
			// host_port doesn't filter by sandbox status, so a destroyed-but-
			// retained row would otherwise hold its host_port slot forever.
			//
			// Docker Destroy is intentionally skipped: the container is the
			// reason we're in this branch. Firecracker still gets Destroy so
			// driver-owned bookkeeping (TAP/VMM slot/run dir) is reconciled
			// before the store row disappears. Caddy / mounts / admitter /
			// image cleanup is best-effort and mirrors DestroySandbox's
			// order; failures here are picked up by gcZombieCaddyEntries on
			// a later pass and by the mounts.Sweep at the end of Reconcile.
			if s.caddy != nil {
				_ = s.publicRoutes().DeleteSandboxRoute(ctx, sandbox.ID)
			}
			for _, port := range sandbox.ExposedPorts {
				_ = s.deleteExposedPortRoute(ctx, sandbox, port)
			}
			if s.isFirecrackerSandbox(sandbox) || s.isWasmSandbox(sandbox) || s.isIsolateSandbox(sandbox) {
				rt, err := s.runtimeForSandbox(sandbox)
				if err != nil {
					return err
				}
				if err := rt.Destroy(s.gatewayReleaserCtx(ctx, sandbox, false), sandbox); err != nil {
					return err
				}
			}
			if s.mounts != nil {
				err := s.mounts.UnmountAll(sandbox.ID)
				if s.testForceUnmountErr != nil {
					err = s.testForceUnmountErr
				}
				if err != nil {
					s.logger.Warn("reconcile destroyed unmount failed", "sandbox_id", sandbox.ID, "error", err)
				}
			} else if s.testForceUnmountErr != nil {
				s.logger.Warn("reconcile destroyed unmount failed", "sandbox_id", sandbox.ID, "error", s.testForceUnmountErr)
			}
			// The runtime is gone, so its egress enforcement on this node goes
			// now, before the row and its installed record do; it is local
			// whoever owns the sandbox (review 5 finding 5). The row stays
			// for the next pass until the rules are recorded (review 6
			// finding 3).
			if err := s.teardownSandboxEgress(ctx, sandbox, sandbox.ContainerIP); err != nil {
				s.logger.Warn("reconcile: egress rules of a gone sandbox not recorded; row kept", "sandbox_id", sandbox.ID, "error", err)
				continue
			}
			// Runtime confirmation and teardown can overlap failover. An
			// authoritative recheck prevents this former owner from deleting the
			// active lifecycle's replicated secrets, volume attachments, or
			// external WASM checkpoints after ownership moved elsewhere.
			if placement, obsolete, err := s.obsoleteLocalPlacement(ctx, sandbox); err != nil {
				return err
			} else if obsolete {
				if err := s.finalizeStaleLocalSandbox(ctx, sandbox, placement, true); err != nil {
					return err
				}
				continue
			}
			// Persist retained authorization before the distributed delete lease.
			// An owner crash after the fence can otherwise let leader expiry remove
			// the last authoritative ownership record before audit ACL retention.
			if err := s.retainSandboxAuditACL(ctx, sandbox); err != nil {
				return err
			}
			if err := s.beginSelfOwnedClusterPlacementDeleteStrict(ctx, sandbox); err != nil {
				return err
			}
			dwsVolumes := s.recordSandboxVolumeDeletes(ctx, sandbox)
			// Secret tomb/outbox before store/placement delete (no FK on
			// cluster_secrets). Same finalizer as DestroySandbox / docker events.
			if err := s.DeleteClusterSecrets(ctx, sandbox.ID, sandbox.AuditIncarnationID); err != nil {
				return err
			}
			if err := s.cleanupWasmSandboxArtifacts(ctx, sandbox); err != nil {
				return err
			}
			if err := s.deleteSelfOwnedClusterPlacementStrict(ctx, sandbox); err != nil {
				return err
			}
			// store.Delete must happen BEFORE schedulePendingImageGC. The
			// pending-image janitor uses HasActiveImageRef to decide whether
			// to actually call docker.RemoveImage at sweep time; a stale row
			// with status "started" sitting in sandboxes would make every
			// sweep skip this image, leaking layers across reconcile cycles
			// until something else changed.
			if err := s.deleteSandboxRowAndFenceAudit(ctx, sandbox.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			s.finishSandboxVolumeDeletes(ctx, sandbox.ID, dwsVolumes)
			s.forgetWakeFlight(sandbox.ID)
			s.invalidateWarm(sandbox.ID)
			s.forgetNetstatsActivity(sandbox.ID)
			s.runStarts.forget(sandbox.ID)
			// Again for a request that read the row before it went.
			s.endToolboxCalls(sandbox.ID, toolboxEndGone, "runtime gone")
			if s.admitter != nil {
				s.admitter.Release(sandbox.ID)
			}
			if !s.isWasmSandbox(sandbox) {
				s.schedulePendingImageGC(ctx, models.SandboxEngine(sandbox), sandbox.Image)
			}
			if s.logger != nil {
				s.logger.Info("audit reconcile destroyed",
					"sandbox_id", sandbox.ID,
					"image", sandbox.Image,
				)
			}
			reaped(nil)
			s.NoteLocalOwnersChanged()
			continue
		}

		// The runtime listed it, so any unknown streak is over, and an
		// error this reconcile recorded for it no longer holds.
		s.reconcileUnknown.forget(sandbox.ID)
		if strings.HasPrefix(sandbox.LastError, reconcileUnknownErrorPrefix) {
			sandbox.LastError = ""
		}
		// A lifecycle step (a start, stop, restart, idle stop or destroy)
		// that holds this sandbox is changing it: the runtime is mid-change
		// and the step writes its own status and reason. Reconcile used to
		// see a VM an idle stop had just stopped, record "reconcile" before
		// the stop wrote "idle", and the store kept the first reason (UC-395
		// on single-node-fc, where a VM stop takes seconds). So a change only
		// this pass saw, on a sandbox a step holds, is left to the step; the
		// next pass sees the result. It does not wait: a step can hold the
		// lock for seconds. With no step holding it, a change this pass saw
		// happened outside any step, and "reconcile" is the right reason.
		if state.Status != sandbox.Status && s.lifecycleLocks.held(sandbox.ID) {
			continue
		}
		// A started instance listed without an address or id has not moved;
		// the runtime just did not say this pass (containerd's netns probe
		// failed, firecracker's list never carries them). Keep the row's, so
		// its routes, egress rules and toolbox target stay where they are.
		observedIP := state.ContainerIP
		if observedIP == "" && state.Status == models.SandboxStatusStarted {
			observedIP = sandbox.ContainerIP
		}
		// A row that says started but whose container stopped or moved
		// missed the stop (sandboxd was down, the event stream gapped): what
		// it left at the old address is recorded and cleared now, before
		// the row forgets the address (review 6 finding 4).
		if sandbox.Status == models.SandboxStatusStarted && sandbox.ContainerIP != "" &&
			(state.Status != models.SandboxStatusStarted || observedIP != sandbox.ContainerIP) {
			if err := s.teardownSandboxEgress(ctx, sandbox, sandbox.ContainerIP); err != nil {
				s.logger.Warn("reconcile: egress rules at a moved sandbox's old address not recorded", "sandbox_id", sandbox.ID, "ip", sandbox.ContainerIP, "error", err)
			}
		}
		if state.ContainerID != "" {
			sandbox.ContainerID = state.ContainerID
		}
		sandbox.ContainerIP = observedIP
		// A status change only this pass saw has no event behind it, so
		// reconcile can only say it found the sandbox that way. The store
		// writes the reason only if the row still has the old status, so a
		// stop the event path recorded since this pass read the row keeps
		// its own reason.
		foundStopped := false
		if state.Status != sandbox.Status {
			switch state.Status {
			case models.SandboxStatusStopped:
				sandbox.StatusReason, sandbox.ExitCode = models.StatusReasonReconcile, nil
				foundStopped = sandbox.Status == models.SandboxStatusStarted
			case models.SandboxStatusStarted:
				sandbox.StatusReason, sandbox.ExitCode = "", nil
			}
		}
		sandbox.Status = state.Status
		sandbox.PublicURL = s.sandboxPublicURL(sandbox.ID, sandbox.AllowPublicTraffic)
		sandbox.UpdatedAt = time.Now().UTC()
		// Keep admitter accounting in sync with observed runtime state. The
		// API and event paths handle the common transitions; this branch
		// covers anything those missed — daemon restart with stale Stop
		// events lost, out-of-band `docker stop`/`docker start` outside the
		// event window, or a racy bootstrap. Reserve forces the slot for
		// running containers (we cannot refuse host-side reality), Release
		// frees it for stopped containers. Both helpers are idempotent, so
		// running this every reconcile tick is safe and cheap.
		if s.admitter != nil {
			switch state.Status {
			case models.SandboxStatusStarted:
				s.admitter.Reserve(sandbox.ID, capacityRequestFromSandbox(sandbox))
			case models.SandboxStatusStopped:
				s.admitter.Release(sandbox.ID)
			}
		}
		// D1 reconstruction: a serverless sandbox observed as stopped
		// without wake_armed set is the cross-owner / post-restart case
		// the plan calls out. Reinstall the wake route(s) and flip the
		// bit so the next HTTP request can resurrect it. No-op for
		// non-serverless rows and for sandboxes already armed.
		if state.Status == models.SandboxStatusStopped {
			s.ReconstructWakeArmedIfNeeded(ctx, sandbox)
		}
		if err := s.cleanupPublicTrafficDisabledIngressState(ctx, sandbox); err != nil {
			return err
		}
		if state.Status == models.SandboxStatusStarted {
			sandbox.WakeArmed = false
			// Heal the per-IP egress DROP rule for sandboxes opted into
			// NetworkBlockAll. Idempotent at the netrules layer (Exists check
			// before insert), so this is safe to run on every reconcile pass.
			// Catches host-side state loss: iptables flush, daemon restart
			// rebuilding chains, or a missed Create/Start install.
			if sandbox.NetworkBlockAll {
				cr, err := s.containerRuntimeForSandbox(sandbox)
				if err != nil {
					s.logger.Warn("reconcile reapply network block skipped",
						"sandbox_id", sandbox.ID,
						"error", err,
					)
				} else if inserted, err := reapplyNetworkBlockAll(cr, sandbox.ContainerIP); err != nil {
					networkBlockReapplyErrors.Add(1)
					s.logger.Warn("reconcile reapply network block failed",
						"sandbox_id", sandbox.ID,
						"ip", sandbox.ContainerIP,
						"error", err,
					)
				} else if inserted {
					// Rule was gone and we put it back — the sandbox was
					// un-isolated for at least one reconcile interval.
					networkBlockReapplyTotal.Add(1)
					s.logger.Warn("reconcile reapplied missing network block",
						"sandbox_id", sandbox.ID,
						"ip", sandbox.ContainerIP,
					)
				}
			}
			// Gateway-mode sandboxes are healed through the gateway: a held
			// sandbox gets its attach retried (the hold lifts only on
			// success), and the gateway's own Sync covers the rest. Their
			// hostname lists never go to netrules. A transition that didn't
			// finish is completed instead of healed: adding the stored rules
			// would leave the old enforcement in place beside them (review
			// 5 finding 3). So is an address with rules another sandbox left
			// there (review 6 finding 1). Both rebuild at the address
			// observed now, which the row doesn't have yet.
			if s.transitionUnfinished(ctx, sandbox) || s.rulesPendingAt(ctx, sandbox) {
				if err := s.rebuildEgress(ctx, sandbox.ID, sandbox, false); err != nil {
					s.logger.Warn("reconcile: egress enforcement not rebuilt", "sandbox_id", sandbox.ID, "error", err)
				}
			} else if isGatewayMode(sandbox) {
				s.reconcileSandboxEgress(ctx, sandbox)
			} else if len(sandbox.NetworkAllowOut) > 0 || len(sandbox.NetworkDenyOut) > 0 {
				// Heal the selective-egress policy the same way. Comment-tagged
				// rules survive independently of the blanket block, and the
				// netrules Exists check keeps the reapply idempotent.
				cr, err := s.containerRuntimeForSandbox(sandbox)
				if err != nil {
					s.logger.Warn("reconcile reapply egress policy skipped",
						"sandbox_id", sandbox.ID,
						"error", err,
					)
				} else if err := cr.ApplyEgressPolicy(sandbox.ContainerIP, sandbox.NetworkAllowOut, sandbox.NetworkDenyOut); err != nil {
					s.logger.Warn("reconcile reapply egress policy failed",
						"sandbox_id", sandbox.ID,
						"ip", sandbox.ContainerIP,
						"error", err,
					)
				}
			}
			// Heal quota-driven blocks. The flag is the source of truth for
			// "we previously decided to block"; re-evaluate against the
			// current cumulative counters so a quota raised over the wire
			// while sandboxd was down clears as part of the same pass.
			if sandbox.NetworkQuotaExceeded ||
				(sandbox.NetworkBytesInLimit > 0 && sandbox.NetworkBytesIn >= sandbox.NetworkBytesInLimit) ||
				(sandbox.NetworkBytesOutLimit > 0 && sandbox.NetworkBytesOut >= sandbox.NetworkBytesOutLimit) {
				overIn := sandbox.NetworkBytesInLimit > 0 && sandbox.NetworkBytesIn >= sandbox.NetworkBytesInLimit
				overOut := sandbox.NetworkBytesOutLimit > 0 && sandbox.NetworkBytesOut >= sandbox.NetworkBytesOutLimit
				s.applyNetworkQuotaState(ctx, sandbox, overIn, overOut)
			}
			if err := s.syncSandboxPublicRoute(ctx, sandbox); err != nil {
				return err
			}
			for _, port := range sandbox.ExposedPorts {
				if err := s.syncExposedPortRoute(ctx, sandbox, port); err != nil {
					return err
				}
			}
			s.syncAllowedPorts(ctx, sandbox)
			// Re-establish host-side mounts for running sandboxes after a
			// sandboxd restart. Idempotent — only mounts that aren't already
			// tracked are spawned.
			if specs, err := s.loadMounts(ctx, sandbox.ID); err != nil {
				s.logger.Warn("load mounts during reconcile", "sandbox_id", sandbox.ID, "error", err)
			} else if len(specs) > 0 {
				if err := s.mounts.Reestablish(ctx, sandbox.ID, specs); err != nil {
					s.logger.Warn("reestablish mounts", "sandbox_id", sandbox.ID, "error", err)
				}
			}
		}
		// A stop only this pass saw gets a record (L3). The row is read
		// again first: this pass's read may predate a stop the event path
		// has recorded since, and that stop has its own record.
		recordFound := func(error) {}
		if foundStopped && s.rowStillStarted(ctx, sandbox.ID) {
			recordFound = s.beginSystemActionReason(ctx, sandbox.ID, systemActionFoundStopped, models.StatusReasonReconcile)
			recordSandboxStop(models.StatusReasonReconcile)
		}
		err := s.store.Upsert(ctx, sandbox)
		recordFound(err)
		if err != nil {
			return err
		}
	}

	// Orphan runtime instances: managed by us but no DB row. Remove them so
	// leaked state from a crashed create or a wiped DB doesn't accumulate.
	// Skip warm-pool park-* ids: they are intentional inventory without a
	// sandbox row. ListManaged already filters the park label; this is the
	// defense-in-depth gate for any runtime that still surfaces them.
	removeOrphans := func(rt runtime.Runtime, runtimeName, engine string, items map[string]*models.SandboxRuntimeState) {
		for sandboxID, state := range items {
			if _, ok := knownIDs[sandboxID]; ok {
				continue
			}
			if strings.HasPrefix(sandboxID, "park-") {
				continue
			}
			if !s.confirmedOrphan(ctx, sandboxID) {
				continue
			}
			orphanDone := s.beginSystemAction(ctx, sandboxID, systemActionOrphanReap)
			s.logger.Warn("removing orphan runtime instance",
				"sandbox_id", sandboxID,
				"runtime", runtimeName,
				"engine", engine,
				"container_id", state.ContainerID,
			)
			stub := &models.Sandbox{
				ID:          sandboxID,
				ContainerID: state.ContainerID,
				ContainerIP: state.ContainerIP,
				Runtime:     runtimeName,
				Engine:      engine,
			}
			// An orphan may be a create that died after an early gateway
			// attach (egress_early.go); its stub carries no policy, so the
			// releaser detaches whatever the gateway holds for it before the
			// runtime frees the address (a no-op when it holds nothing).
			err := rt.Destroy(s.gatewayReleaserCtx(ctx, stub, true), stub)
			orphanDone(err)
			if err != nil {
				s.logger.Warn("orphan runtime removal failed",
					"sandbox_id", sandboxID,
					"runtime", runtimeName,
					"engine", engine,
					"error", err,
				)
			}
			if s.caddy != nil {
				_ = s.publicRoutes().DeleteSandboxRoute(ctx, sandboxID)
			}
			if s.mounts != nil {
				_ = s.mounts.UnmountAll(sandboxID)
			}
		}
	}
	if dockerListed {
		removeOrphans(s.docker, models.RuntimeDocker, models.ContainerEngineDocker, listings.docker)
	}
	if s.containerd != nil {
		// containerd is the default engine on clusters. finalizeStaleLocalSandbox
		// deletes the row before runtime Destroy and names this sweep as the
		// retry anchor for a failed Destroy, so an engine missing here leaks
		// its instance forever after one transient failure.
		removeOrphans(s.containerd, models.RuntimeDocker, models.ContainerEngineContainerd, listings.containerd)
	}
	if s.firecracker != nil {
		removeOrphans(s.firecracker, models.RuntimeFirecracker, "", listings.firecracker)
	}
	if s.wasm != nil {
		removeOrphans(s.wasm, models.RuntimeWasm, "", listings.wasm)
	}
	if s.isolate != nil {
		// Isolate leaks more than a process: a jailed group owns a cgroup and a
		// uid-owned chroot tree under SB_ISOLATE_JAIL_CHROOT_BASE, so a skipped
		// sweep strands host state, not just a PID.
		//
		// isolate's ListManaged reads the driver's in-memory byID map
		// (internal/runtime/isolate/driver.go), not the host, so this sweep
		// reclaims groups leaked within one daemon lifetime — the
		// finalizeStaleLocalSandbox case that names this sweep as its retry
		// anchor. Leaks across a restart are swept once at boot, before any
		// spawn (pkg/isolate.SweepLeftovers, after AdoptHosts).
		removeOrphans(s.isolate, models.RuntimeIsolate, "", listings.isolate)
	}

	// Zombie caddy entry sweep. The destroyed-sandbox loop above already
	// drops routes for sandboxes that exist in the DB but lost their
	// container — this catches the orthogonal case where caddy holds an
	// entry for a sandbox row that was deleted out-of-band (DB wipe,
	// manual surgery) and no destroy ran. Without this, caddy accumulates
	// dead routes forever.
	_ = s.gcZombieCaddyEntries(ctx, known) // logged inside; reconcile goes on

	// Stale-mount sweep. Anything under /var/lib/sandboxd/mounts/ that
	// doesn't correspond to a sandbox we're going to keep is a leftover
	// from a crashed create or a previous orphan removal. Kill any FUSE
	// process still attached and remove the directory tree. Mounts the
	// manager already tracks in-process are skipped inside Sweep itself.
	keep := make(map[string]struct{}, len(managed))
	for id, state := range managed {
		if state.Status == models.SandboxStatusStarted {
			keep[id] = struct{}{}
		}
	}
	if dockerListed || s.cfg.DockerDisabled {
		s.mounts.Sweep(keep)
	}

	// Reuse this sweep's already-loaded snapshot to emit one window of reserved
	// usage (uptime + cpu/mem/disk/gpu). No-op on the open-source build (no
	// reporter wired). Last so a reporting hiccup can't affect reconcile.
	s.emitReservedUsage(ctx, known)

	return nil
}

// confirmedOrphan reports whether a runtime instance with no row in this
// sweep's snapshot really has none. The rows were read before the runtime was
// listed, so an instance may belong to a create that is still running (its
// row comes after the instance) or that wrote its row since the snapshot.
// The running check comes first: a create releases it only after writing its
// row, so a release between the two checks still leaves a row to find. A
// lookup error is not an orphan; the next sweep retries.
func (s *Service) confirmedOrphan(ctx context.Context, sandboxID string) bool {
	if s.createsInFlight.running(sandboxID) {
		return false
	}
	switch _, err := s.store.Get(ctx, sandboxID); {
	case err == nil:
		return false
	case !errors.Is(err, store.ErrNotFound):
		if s.logger != nil {
			s.logger.Warn("orphan runtime recheck failed", "sandbox_id", sandboxID, "error", err)
		}
		return false
	}
	return true
}

// maxSelfOwnedReconcilePages bounds one sweep's paging so a control plane that
// keeps handing back a non-advancing cursor can't spin the reconcile goroutine.
// At cluster.DefaultPlacementPageLimit (1000) this covers 1M rows on a single
// owner — the whole 100k-sandbox target fleet on one node, ten times over.
const maxSelfOwnedReconcilePages = 1000

// selfOwnedPlacementsForReconcile returns every materialized placement this
// node owns, paged through the owner-filtered index.
//
// It returns nil — not a partial list — the moment a page comes back
// non-authoritative or the cursor fails to advance. A partial answer here is
// indistinguishable from "these sandboxes have no placement", and the caller
// deletes on exactly that signal, so anything short of a complete view must
// skip the sweep rather than act on a fragment of it.
func (s *Service) selfOwnedPlacementsForReconcile(ctx context.Context, c cluster.Client, self string) []cluster.Placement {
	var (
		out   []cluster.Placement
		token string
	)
	for page := 0; page < maxSelfOwnedReconcilePages; page++ {
		if ctx.Err() != nil {
			return nil
		}
		resp := c.PlacementPage(cluster.PlacementPageRequest{OwnerNodeID: self, PageToken: token})
		if !resp.Authoritative {
			// Control plane unreachable or FSM not ready. Skip this sweep; the
			// next tick retries. Never treat it as "nothing is placed."
			if s.logger != nil {
				s.logger.Warn("cluster placement reconcile skipped: placement view unavailable",
					"node_id", self, "page", page)
			}
			return nil
		}
		out = append(out, resp.Placements...)
		if resp.NextPageToken == "" {
			return out
		}
		if resp.NextPageToken == token {
			if s.logger != nil {
				s.logger.Warn("cluster placement reconcile skipped: page cursor did not advance",
					"node_id", self, "page_token", token)
			}
			return nil
		}
		token = resp.NextPageToken
	}
	if s.logger != nil {
		s.logger.Warn("cluster placement reconcile skipped: exceeded page budget",
			"node_id", self, "max_pages", maxSelfOwnedReconcilePages)
	}
	return nil
}

func (s *Service) reconcileMissingSelfOwnedPlacements(ctx context.Context, knownIDs map[string]struct{}) {
	if !s.cfg.EnableCluster {
		return
	}
	c := s.Cluster()
	if c == nil {
		return
	}
	self := c.SelfNodeID()
	if self == "" {
		return
	}
	// Page this node's own rows instead of pulling the global placement map.
	// At the 100k-sandbox / 2k-worker target the unfiltered view is ~72 MB —
	// past the agent's 16 MiB control-plane response cap — so every worker's
	// sweep failed into an empty cached view and silently reclaimed nothing,
	// stranding placements for sandboxes whose local row was already gone.
	for _, p := range s.selfOwnedPlacementsForReconcile(ctx, c, self) {
		if p.SandboxID == "" || p.OwnerNodeID != self || p.IsReserved() || p.IsOrphaned() {
			continue
		}
		if _, ok := knownIDs[p.SandboxID]; ok {
			continue
		}
		// The initial knownIDs set is a sweep snapshot. A create may commit its
		// local row after that snapshot but before its placement becomes visible.
		// Recheck the point row before destructive cleanup so reconciliation can
		// never erase a concurrently-created sandbox's placement.
		if _, err := s.store.Get(ctx, p.SandboxID); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			if s.logger != nil {
				s.logger.Warn("cluster placement local-row recheck failed",
					"sandbox_id", p.SandboxID, "error", err)
			}
			continue
		}
		// A deleting placement is a durable cleanup anchor, never a candidate for
		// recreation. Once its owner has removed the local row, exact deletion is
		// the only remaining reconciliation step.
		if !p.IsDeleting() {
			if spec := c.SpecOf(p.SandboxID); spec != nil && spec.ShouldRecreateOnFailover() {
				continue
			}
		}
		s.deleteSelfOwnedClusterPlacement(ctx, p, "missing-local-row")
	}
}

// StartLifecycleSweep launches the per-sandbox lifecycle ticker. Every minute
// it evaluates each sandbox's Lifecycle timers (StopIfIdleFor / DestroyIfIdleFor
// / StopAtAge / DestroyAtAge) plus the legacy global SB_IDLE_TIMEOUT_MIN
// fallback for sandboxes that don't declare any per-sandbox timers. Without
// either configured, the sweep still runs but is a no-op — kept on so a
// later UpdateLifecycle call doesn't need to start a goroutine.
// startPeriodic runs sweep on an interval ticker in its own goroutine until ctx
// is cancelled, handing each invocation a fresh timeout-bounded context. It is
// the single home for the daemon's background-sweep skeleton: reconcile, the
// lifecycle sweep, both image janitors, the template janitor, and the wasm
// module/checkpoint sweeps were each an identical copy of this select-loop
// before. Callers keep their own enable/interval guards (the cadence and
// preconditions differ per task); only the loop boilerplate is shared here.
func (s *Service) startPeriodic(ctx context.Context, interval, timeout time.Duration, sweep func(context.Context)) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// select chooses uniformly among ready cases, so a cancelled
				// ctx can lose the coin flip to a ready tick and start one
				// more sweep after shutdown began — against a store the
				// daemon is closing. Re-check before doing any work.
				if ctx.Err() != nil {
					return
				}
				sweepCtx, cancel := context.WithTimeout(ctx, timeout)
				sweep(sweepCtx)
				cancel()
			}
		}
	}()
}

func (s *Service) StartLifecycleSweep(ctx context.Context) {
	s.setRestartBase(ctx)
	s.startPeriodic(withAuditSubsystem(ctx, auditSubsystemLifecycle), time.Minute, 30*time.Second, s.runLifecycleSweep)
}

func (s *Service) runLifecycleSweep(ctx context.Context) {
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("lifecycle sweep failed", "error", err)
		return
	}

	now := time.Now().UTC()
	globalIdle := s.cfg.IdleTimeout()
	// netstatsFallback is checked once per sweep, not per sandbox —
	// the fallback applies to the entire tick (D3). If the most recent
	// successful poll is older than 2 × poll interval, the docker
	// stats subsystem is probably degraded for every sandbox on this
	// node; trusting an absent floor as "idle" would cascade into
	// stopping every warm sandbox. The next successful poll re-arms
	// the netstats signal automatically.
	netstatsFallback := s.netstatsPollIsStale(now)
	if netstatsFallback {
		s.logger.Warn("idle sweep using LastActiveAt fallback",
			"reason", "netstats_poll_failed", "netstats_fallback", true)
	}
	// Main programs that ended, for destroy_after_exit_for: asked first so
	// a short delay can act in this same pass.
	s.probeProgramExits(ctx, sandboxes)
	var due []string
	for _, sandbox := range sandboxes {
		// A restart on failure that lost its timer (the daemon restarted
		// while it waited) gets one now; a due one runs at once.
		if restartPending(sandbox) {
			s.ensureRestartArmed(sandbox)
		}
		floor := s.activityFloorFor(sandbox, netstatsFallback)
		if action, _ := lifecycleDecision(sandbox, now, globalIdle, floor); action != lifecycleNone {
			due = append(due, sandbox.ID)
		}
	}
	// One at a time, least recently tried first (sweep_rotation.go): a
	// delete or stop that keeps failing, slowly or not, cannot use every
	// pass's deadline while the ones behind it wait (review 2 finding 11).
	for _, id := range s.lifecycleRotation.plan(due) {
		if ctx.Err() != nil {
			// The rest are untried, so they go first next pass.
			return
		}
		s.lifecycleRotation.tried(id)
		err := s.runLifecycleAction(ctx, id, now, globalIdle, netstatsFallback)
		if err == nil || ctx.Err() == nil {
			s.lifecycleRotation.done(id, err == nil)
		}
	}
}

// runLifecycleAction carries out one sandbox's timed stop or delete inside the
// lifecycle boundary (lifecycle_boundary.go). It reads the row again there
// and decides again from that read, with the pass's clock: the pass decided
// from a list read before the exit probes and every action ahead of this one,
// and a start, stop, restart or lifecycle update since may have changed the
// answer. A sandbox started again after its main program ended no longer
// carries that exit, so it is not deleted for it (review 2 finding 10). A
// row that is gone, or no longer due, is nothing to do.
func (s *Service) runLifecycleAction(ctx context.Context, id string, now time.Time, globalIdle time.Duration, netstatsFallback bool) error {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	sandbox, err := s.store.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	// A fenced sandbox is frozen, so its idle clock is not real, and stopping
	// or destroying it needs ownership this node has not confirmed
	// (ownership_lease.go). Its timers resume with it.
	if s.OwnershipFenced(id) {
		return nil
	}
	action, reason := lifecycleDecision(sandbox, now, globalIdle, s.activityFloorFor(sandbox, netstatsFallback))
	switch action {
	case lifecycleDestroy:
		done := s.beginSystemActionReason(ctx, id, systemActionAutoDelete, reason)
		err := s.destroySandboxLocked(ctx, id)
		done(err)
		if err != nil {
			s.logger.Warn("auto-destroy failed", "sandbox_id", id, "error", err)
			return err
		}
		recordSandboxExpired(reason)
		s.logger.Info("audit lifecycle auto-destroy", "sandbox_id", id)
	case lifecycleStop:
		// Lifecycle stop: pass mode=stopModeLifecycle so serverless
		// sandboxes arm wake (the next inbound HTTP request will
		// resurrect the sandbox transparently).
		done := s.beginSystemActionReason(ctx, id, systemActionAutoStop, reason)
		_, err := s.stopSandboxLocked(ctx, id, stopModeLifecycle, reason)
		done(err)
		if err != nil {
			s.logger.Warn("auto-stop failed", "sandbox_id", id, "error", err)
			return err
		}
		s.logger.Info("audit lifecycle auto-stop",
			formatStopAuditFields(id, stopModeLifecycle, s.shouldArmWake(sandbox, stopModeLifecycle))...)
	}
	return nil
}

type lifecycleAction int

const (
	lifecycleNone lifecycleAction = iota
	lifecycleStop
	lifecycleDestroy
)

// activityFloorFor computes the timestamp the lifecycle sweep should
// treat as the sandbox's most recent activity. Default is
// sandbox.LastActiveAt; when any warm-direct bypass is enabled (HTTP or
// L4) and the netstats poller has recorded network activity more recent than
// LastActiveAt, the netstats timestamp wins so warm traffic that bypasses
// sandboxd does not get false-idle-stopped.
// Netstats observes container interface bytes regardless of protocol,
// so one floor covers HTTP + L4 with a single mechanism — the OR over
// both flags is what makes Phase 2 (L4 bypass) safe to enable without
// also flipping HTTP. When the most recent netstats poll failed
// (netstatsFallback=true), we fall back to LastActiveAt alone for this
// tick to avoid stopping busy sandboxes on a docker-stats outage (D3).
func (s *Service) activityFloorFor(sandbox *models.Sandbox, netstatsFallback bool) time.Time {
	if sandbox == nil {
		return time.Time{}
	}
	floor := sandbox.LastActiveAt
	if !s.anyBypassEnabled() || netstatsFallback {
		return floor
	}
	if observed := s.netstatsRecentActivityAt(sandbox.ID); !observed.IsZero() && observed.After(floor) {
		return observed
	}
	return floor
}

// netstatsPollIsStale reports whether the most recent successful
// netstats poll is older than 2 × NetstatsPollInterval — the D3
// signal that the docker stats subsystem is degraded and the sweep
// must fall back to LastActiveAt rather than treat an absent floor
// as "idle." Returns false when the bypass is off (the floor is not
// used either way) or when the poller has never recorded a tick (the
// daemon may have just booted; treating that as stale would prematurely
// false-stop warm sandboxes during the first sweep after a restart —
// the start path itself updates LastActiveAt, so falling back is the
// correct conservative answer).
func (s *Service) netstatsPollIsStale(now time.Time) bool {
	if !s.anyBypassEnabled() {
		return false
	}
	if s.cfg.NetstatsPollInterval <= 0 {
		return true
	}
	last := s.netstatsLastTick.Load()
	if last == 0 {
		return true
	}
	return now.Sub(time.Unix(0, last)) > 2*s.cfg.NetstatsPollInterval
}

// netstatsRecentActivityAt returns the unix-nano timestamp of the most recent
// network activity observed for the sandbox, or the zero time if no observation
// has been recorded yet. Cheap read-lock lookup populated by the netstats
// poller sink.
func (s *Service) netstatsRecentActivityAt(id string) time.Time {
	s.netstatsActivityMu.RLock()
	ts, ok := s.netstatsActivity[id]
	s.netstatsActivityMu.RUnlock()
	if !ok || ts == 0 {
		return time.Time{}
	}
	return time.Unix(0, ts).UTC()
}

// recordNetstatsActivity is called by the netstats sink for every
// activity observed by the netstats poller. SampledAt comes from the docker
// stats reader so timestamps are consistent with the rest of the observability
// surface.
func (s *Service) recordNetstatsActivity(id string, sampledAt time.Time) {
	if id == "" || sampledAt.IsZero() {
		return
	}
	s.netstatsActivityMu.Lock()
	if s.netstatsActivity == nil {
		s.netstatsActivity = make(map[string]int64)
	}
	s.netstatsActivity[id] = sampledAt.UnixNano()
	s.netstatsActivityMu.Unlock()
}

// forgetNetstatsActivity drops a sandbox's recorded activity floor.
// Called when a sandbox is destroyed so the map does not leak entries
// for ids the rest of the daemon has forgotten.
func (s *Service) forgetNetstatsActivity(id string) {
	if id == "" {
		return
	}
	s.netstatsActivityMu.Lock()
	delete(s.netstatsActivity, id)
	s.netstatsActivityMu.Unlock()
}

// lifecycleActionFor decides what the sweep should do for one sandbox given
// the current time and the operator's global idle fallback. Pure function:
// no DB, no Docker, easy to exhaustively test.
//
// Priority rules:
//  1. Already destroyed → none. The sweep cannot un-destroy or further
//     destroy something already gone.
//  2. Any destroy timer fired → destroy. Destroy supersedes stop on the
//     same tick to avoid a wasted Stop call followed by Destroy.
//  3. Any stop timer fired AND status is started → stop. Stopping an
//     already-stopped sandbox would be a no-op so we skip it.
//  4. No per-sandbox config and global SB_IDLE_TIMEOUT_MIN would fire →
//     stop. Backwards-compat with the pre-Lifecycle behavior.
//  5. Otherwise → none.
func lifecycleActionFor(sb *models.Sandbox, now time.Time, globalIdle time.Duration) lifecycleAction {
	return lifecycleActionForWithFloor(sb, now, globalIdle, time.Time{})
}

// lifecycleActionForWithFloor is lifecycleActionFor with an explicit
// activity-floor timestamp injected by the sweep (e.g. the netstats
// poller's most recent BytesIn observation under bypass-on). When
// activityFloor is later than sb.LastActiveAt, idle is measured from
// activityFloor; otherwise the function behaves identically to
// lifecycleActionFor. Pure: callers compute the floor.
func lifecycleActionForWithFloor(sb *models.Sandbox, now time.Time, globalIdle time.Duration, activityFloor time.Time) lifecycleAction {
	action, _ := lifecycleDecision(sb, now, globalIdle, activityFloor)
	return action
}

// lifecycleDecision is lifecycleActionForWithFloor plus why: for a stop,
// the status reason it records (models.StatusReasonIdle or
// StatusReasonMaxAge); for a destroy, the timer that fired (idle, max_age,
// or program_exited for destroy_after_exit_for), which the audit record and
// the expired counter name; "" for no action. Idle is checked first, as
// before, so a sandbox past both timers reports idle.
func lifecycleDecision(sb *models.Sandbox, now time.Time, globalIdle time.Duration, activityFloor time.Time) (lifecycleAction, string) {
	if sb == nil || sb.Status == models.SandboxStatusDestroyed {
		return lifecycleNone, ""
	}
	floor := sb.LastActiveAt
	if !activityFloor.IsZero() && activityFloor.After(floor) {
		floor = activityFloor
	}
	idle := now.Sub(floor)
	age := now.Sub(sb.CreatedAt)

	l := sb.Lifecycle
	// Destroy first: if any destroy condition is met we go straight there.
	if l.DestroyIfIdleFor > 0 && idle >= l.DestroyIfIdleFor {
		return lifecycleDestroy, models.StatusReasonIdle
	}
	if l.DestroyAtAge > 0 && age >= l.DestroyAtAge {
		return lifecycleDestroy, models.StatusReasonMaxAge
	}
	// The main program's end, as the sweep recorded it, counts whatever the
	// status: a sandbox stopped after its program ended is still done.
	if l.DestroyAfterExitFor > 0 && sb.ProgramExitedAt != nil && now.Sub(*sb.ProgramExitedAt) >= l.DestroyAfterExitFor {
		return lifecycleDestroy, models.StatusReasonProgramExited
	}
	// Stop only applies to running sandboxes — re-stopping a stopped one
	// is wasted Docker calls and noisy logs.
	if sb.Status != models.SandboxStatusStarted {
		return lifecycleNone, ""
	}
	if l.StopIfIdleFor > 0 && idle >= l.StopIfIdleFor {
		return lifecycleStop, models.StatusReasonIdle
	}
	if l.StopAtAge > 0 && age >= l.StopAtAge {
		return lifecycleStop, models.StatusReasonMaxAge
	}
	// Legacy global idle fallback: only applies when the sandbox has no
	// per-sandbox config, so an explicit "no auto-stop" Lifecycle (e.g.
	// just DestroyAtAge=24h with stop fields zero) doesn't accidentally
	// inherit the operator's global timeout.
	if l.IsZero() && globalIdle > 0 && idle >= globalIdle {
		return lifecycleStop, models.StatusReasonIdle
	}
	return lifecycleNone, ""
}

// gcZombieCaddyEntries deletes caddy routes/servers whose @id (or layer4
// server name) follows our convention but doesn't correspond to any live
// sandbox row. The DB is the source of truth; anything in caddy that doesn't
// trace back to a non-destroyed sandbox is a leak from one of:
//   - a sandbox row that was deleted on reconcile (the destroyed branch
//     deletes rows immediately, so caddy entries can outlive their owner
//     by one reconcile tick if a previous teardown's caddy DELETE failed).
//   - a development DB wipe leaving caddy with stale state.
//   - an out-of-band caddy admin call from a previous version of this code.
//
// Best-effort: every cleanup runs through a non-fatal path so a single
// failing DELETE doesn't abort the rest of the sweep. The legitimate-set
// computation excludes destroyed sandboxes — by the time this runs, the
// destroyed-loop earlier in Reconcile has already cleaned their routes.
func (s *Service) gcZombieCaddyEntries(ctx context.Context, sandboxes []*models.Sandbox) error {
	if !s.caddy.Enabled() {
		return nil
	}
	snap, err := s.caddy.Snapshot(ctx)
	if err != nil {
		s.logger.Warn("caddy snapshot for zombie gc failed", "error", err)
		return nil
	}
	// Rows read before this snapshot can't explain a route made after them
	// (a sandbox created, a port exposed), so the sweep reads the rows once,
	// after the snapshot, and uses only those: every route in the snapshot
	// is then either explained by a row or a real zombie (a create in flight
	// is exempt below). The caller's rows are used only when there is no
	// store to read (tests). One read, not two merged: at fleet scale each
	// read is the whole sandboxes table.
	if s.store != nil {
		fresh, err := s.store.List(ctx)
		if err != nil {
			s.logger.Warn("zombie gc: sandbox list after the caddy snapshot failed; skipping this pass", "error", err)
			return fmt.Errorf("zombie gc list sandboxes: %w", err)
		}
		sandboxes = fresh
	}

	expectedHTTP := make(map[string]struct{})
	expectedTCPServers := make(map[string]struct{})
	expectedTLSRoutes := make(map[string]struct{})

	for _, sb := range sandboxes {
		if sb == nil || sb.Status == models.SandboxStatusDestroyed {
			continue
		}
		if !sandboxAllowsPublicTraffic(sb) {
			continue
		}
		s.expectLocalSandboxRoutes(expectedHTTP, expectedTCPServers, expectedTLSRoutes, sb)
	}
	s.addClusterIngressExpectedRoutes(expectedHTTP, expectedTCPServers, expectedTLSRoutes)

	for _, id := range snap.HTTPRouteIDs {
		if _, ok := expectedHTTP[id]; ok {
			continue
		}
		// A create installs its public route before it writes its row.
		if s.createsInFlight.ownsRoute(id) {
			continue
		}
		if err := s.publicRoutes().DeleteRouteByID(ctx, id); err != nil {
			s.logger.Warn("zombie http route delete failed", "route_id", id, "error", err)
			continue
		}
		s.logger.Info("audit zombie http route removed", "route_id", id)
	}
	for _, sid := range snap.L4TCPServerIDs {
		if _, ok := expectedTCPServers[sid]; ok {
			continue
		}
		if err := s.publicRoutes().DeleteTCPServer(ctx, sid); err != nil {
			s.logger.Warn("zombie tcp server delete failed", "server_id", sid, "error", err)
			continue
		}
		s.logger.Info("audit zombie tcp server removed", "server_id", sid)
	}
	for _, id := range snap.L4TLSRouteIDs {
		if _, ok := expectedTLSRoutes[id]; ok {
			continue
		}
		if s.createsInFlight.ownsRoute(id) {
			continue
		}
		if err := s.publicRoutes().DeleteRouteByID(ctx, id); err != nil {
			s.logger.Warn("zombie tls route delete failed", "route_id", id, "error", err)
			continue
		}
		s.logger.Info("audit zombie tls route removed", "route_id", id)
	}
	return nil
}

// expectLocalSandboxRoutes adds the routes one local sandbox row explains to
// a route sweep's keep sets. Both sweeps that delete the routes nothing
// explains use it: gcZombieCaddyEntries and the cluster ingress audit
// (gcUnexpectedClusterIngressRoutesIn, through
// addLocalIngressExpectedRoutes). Each used to keep its own list, and a fix
// to one missed the other: the ingress audit kept only the direct port
// route, so it deleted a token-gated port's wake route, the port's only
// route, and the gated URL answered Caddy's "Sandbox not found" (UC-426 on
// single-node-fc). It also dropped custom-domain routes and the wake routes
// of serverless sandboxes. The caller filters the rows.
func (s *Service) expectLocalSandboxRoutes(expectedHTTP, expectedTCPServers, expectedTLSRoutes map[string]struct{}, sb *models.Sandbox) {
	// The toolbox route lives at @id "sandbox-<id>"; per-port HTTP routes
	// at "sandbox-<id>-port-<p>". Keep both unconditionally — the rest
	// of Reconcile guarantees they're upserted for running sandboxes,
	// but stopped sandboxes intentionally lack routes and should still
	// not be GC'd here (they'll be rebuilt on Start).
	expectedHTTP["sandbox-"+sb.ID] = struct{}{}
	// Serverless sandboxes can have EITHER a direct port route (when
	// started) or a wake-aware port route (when stopped+armed, and
	// also when started under the wake-aware install path). The two
	// shapes can briefly coexist during install-then-delete transitions
	// in installHTTPPortRoute. Keep both @ids in the live set for any
	// HTTP exposure on a serverless sandbox so the GC doesn't race
	// the install cycle.
	isServerless := s.cfg.EnableServerless && sb.Lifecycle.Serverless
	for _, p := range sb.ExposedPorts {
		switch p.Protocol {
		case "", models.ExposedPortProtocolHTTP:
			// A token-gated port (A2) has only the wake-aware route,
			// serverless or not: only the ingress proxy checks the token.
			// So the sweep keeps its wake route (without this it deleted
			// it as a zombie every pass, and the gated URL answered
			// Caddy's "Sandbox not found", UC-465 on single-node-fc) and
			// does NOT keep a direct route for it: a direct route there
			// skips the token, so one left behind by any writer goes.
			if !p.TokenGated() {
				expectedHTTP[fmt.Sprintf("sandbox-%s-port-%d", sb.ID, p.Port)] = struct{}{}
			}
			if isServerless || p.TokenGated() {
				expectedHTTP[caddy.WakePortRouteID(sb.ID, p.Port)] = struct{}{}
			}
		case models.ExposedPortProtocolTCP:
			if p.HostPort > 0 {
				expectedTCPServers[fmt.Sprintf("tcp-port-%d", p.HostPort)] = struct{}{}
			}
		case models.ExposedPortProtocolTLS:
			expectedTLSRoutes[fmt.Sprintf("sandbox-%s-port-%d-tls", sb.ID, p.Port)] = struct{}{}
		}
	}
	// Custom-domain per-hostname HTTP routes share the same Caddy server
	// as the default sandbox route, so they have to be enumerated as
	// expected or the GC sweep will drop them on the next pass. The route
	// ID matches what pkg/caddy installs in upsertCustomDomainHTTPRoute.
	for _, cd := range sb.CustomDomains {
		if cd.Hostname == "" {
			continue
		}
		expectedHTTP[caddy.IngressCustomDomainHTTPRouteID(sb.ID, cd.Hostname)] = struct{}{}
	}
}

func (s *Service) addClusterIngressExpectedRoutes(expectedHTTP, expectedTCPServers, expectedTLSRoutes map[string]struct{}) {
	if !s.cfg.EnableCluster {
		return
	}
	// Role gate FIRST. A node that serves no ingress installs no
	// peer-forwarding routes, so it has no cluster-wide keep-set to compute —
	// and computing one made every worker's zombie-route sweep read placements
	// it has no use for. The sweep still GCs this node's OWN sandbox routes;
	// that keep-set is built from the local store above.
	if !s.servesClusterIngress() {
		return
	}
	c := s.Cluster()
	if c == nil {
		return
	}
	self := c.SelfNodeID()
	for _, p := range c.PlacementsForShards(s.clusterIngressShardFilter(c, self)) {
		if p.SandboxID == "" || p.OwnerNodeID == self {
			continue
		}
		if !placementAllowsPublicTraffic(p) {
			continue
		}
		// Orphaned placement, or an owner this ingress cannot confirm (its
		// addresses blanked past the age limit): the in-flux 503 routes are
		// the expected state. Keep them; the live routes are intentionally
		// absent. Same test as buildClusterIngressIntents.
		if p.OwnerNodeID == "" || dataPlaneHostForPlacement(p) == "" {
			expectedHTTP[caddy.InFluxSandboxRouteID(p.SandboxID)] = struct{}{}
			for port, route := range cluster.ExposedPortRoutesForPlacement(p) {
				if route.Protocol == models.ExposedPortProtocolTCP {
					continue
				}
				expectedHTTP[caddy.InFluxPortRouteID(p.SandboxID, port)] = struct{}{}
			}
			continue
		}
		if s.cfg.Domain != "" {
			expectedTLSRoutes[caddy.IngressSandboxSNIRouteID(p.SandboxID)] = struct{}{}
			// Per-custom-hostname SNI passthrough routes are installed by
			// ingress_delta for every entry in p.CustomHostnames. Without
			// them in the GC keep-set the zombie sweep (which collects all
			// `sandbox-*` TLS @ids) would strip them on every reconcile
			// pass and ingress_delta would re-install them on the next
			// tick — visible as route flapping and a churn-storm of Caddy
			// PATCHes.
			for _, hostname := range p.CustomHostnames {
				expectedTLSRoutes[caddy.IngressCustomDomainSNIRouteID(p.SandboxID, hostname)] = struct{}{}
			}
		} else {
			expectedHTTP["sandbox-"+p.SandboxID] = struct{}{}
		}
		for port, route := range cluster.ExposedPortRoutesForPlacement(p) {
			protocol := route.Protocol
			if protocol == "" {
				protocol = models.ExposedPortProtocolHTTP
			}
			switch protocol {
			case models.ExposedPortProtocolHTTP:
				if s.cfg.Domain != "" {
					expectedTLSRoutes[caddy.IngressPortSNIRouteID(p.SandboxID, port)] = struct{}{}
				} else {
					expectedHTTP[fmt.Sprintf("sandbox-%s-port-%d", p.SandboxID, port)] = struct{}{}
				}
			case models.ExposedPortProtocolTCP:
				if route.HostPort > 0 {
					expectedTCPServers[fmt.Sprintf("tcp-port-%d", route.HostPort)] = struct{}{}
				}
			case models.ExposedPortProtocolTLS:
				if s.cfg.Domain != "" {
					expectedTLSRoutes[caddy.IngressPortSNIRouteID(p.SandboxID, port)] = struct{}{}
				}
			}
		}
	}
}

// StartBuiltImageGC launches the periodic janitor that removes locally-built
// images (BuiltImageNamespace, i.e. "aerolvm-build/*") that are no longer
// referenced by any active sandbox AND were created more than the configured
// TTL ago. Without this, two failure modes leak images forever:
//
//   - POST /v1/images/build called standalone (no follow-up CreateSandbox).
//   - Build succeeded, CreateSandbox failed AND the daytona facade's inline
//     rollback couldn't reach the daemon (e.g. server-side panic, dropped
//     connection between build success and rollback call).
//
// The TTL keeps the janitor from racing the dominant build+create flow: an
// image built moments ago must clear ImageBuildGCTTL before it's eligible,
// so a transient network hiccup between build and create can't have the
// janitor yanking an image the client is about to consume.
//
// No-op if ImageBuildGCEnabled is false or ImageBuildGCInterval <= 0.
func (s *Service) StartBuiltImageGC(ctx context.Context) {
	if !s.cfg.ImageBuildGCEnabled {
		return
	}
	ctx = withAuditSubsystem(ctx, auditSubsystemImageGC)
	interval := s.cfg.ImageBuildGCInterval
	if interval <= 0 {
		return
	}
	if s.dockerAux == nil {
		s.logger.Warn("built-image GC disabled: docker client is nil")
		return
	}
	s.startPeriodic(ctx, interval, 30*time.Second, func(c context.Context) {
		s.runBuiltImageGC(c, s.dockerAux.ListBuiltImages)
	})
}

// builtImageListFn is the indirection runBuiltImageGC takes so tests can
// supply a synthetic image list without standing up a Docker daemon. The
// only production caller is StartBuiltImageGC, which always passes
// s.events.ListBuiltImages.
type builtImageListFn func(ctx context.Context) ([]docker.BuiltImage, error)

// runBuiltImageGC is one pass of the built-image janitor. Idempotent: every
// removal decision is gated by an indexed Store.HasActiveImageRef check, so
// a sandbox created between list-time and remove-time is protected (the
// store sees its row before we ask). Failures are logged, not returned —
// the janitor must not block on a bad image; the next tick will retry.
func (s *Service) runBuiltImageGC(ctx context.Context, list builtImageListFn) {
	images, err := list(ctx)
	if err != nil {
		s.logger.Warn("built-image gc list failed", "error", err)
		return
	}
	cutoff := time.Now().UTC().Add(-s.cfg.ImageBuildGCTTL)
	for _, img := range images {
		if img.LastTagTime.After(cutoff) {
			continue
		}
		if s.imageGCWhitelisted(img.Tag) {
			continue
		}
		referenced, err := s.store.HasActiveImageRef(ctx, img.Tag)
		if err != nil {
			s.logger.Warn("built-image gc ref check failed", "tag", img.Tag, "error", err)
			continue
		}
		if referenced {
			continue
		}
		if err := s.docker.RemoveImage(ctx, img.Tag); err != nil {
			s.logger.Warn("built-image gc remove failed", "tag", img.Tag, "error", err)
			continue
		}
		s.logger.Info("audit built image gc removed", "tag", img.Tag, "last_tag_time", img.LastTagTime)
	}
}

// StartPendingImageGC launches the periodic janitor that removes images
// scheduled by destroy paths (DestroySandbox, reconcile destroyed-branch,
// handleDestroyEvent). It piggybacks on ImageBuildGCEnabled / Interval /
// TTL: same enable switch, same cadence, same TTL — so an operator who
// wants to disable image GC entirely flips one knob, and tightening the
// TTL applies to both pulled images (this janitor) and built images
// (StartBuiltImageGC). No-op when disabled or Interval <= 0.
func (s *Service) StartPendingImageGC(ctx context.Context) {
	if !s.cfg.ImageBuildGCEnabled {
		return
	}
	ctx = withAuditSubsystem(ctx, auditSubsystemImageGC)
	interval := s.cfg.ImageBuildGCInterval
	if interval <= 0 {
		return
	}
	s.startPeriodic(ctx, interval, 30*time.Second, s.runPendingImageGC)
}

// pendingImageGCSweepLimit caps how many ledger rows one sweep
// processes. Each row is a serial Docker RemoveImage round-trip, so an
// unbounded backlog (operator re-enables GC after a long pause, or
// thousands of destroyed sandboxes share a few base images) would
// otherwise stall the daemon for minutes. The cap turns that into
// "drain over a few ticks" instead. Oldest-first ordering from the
// store keeps the long-overdue rows at the front of the queue.
const pendingImageGCSweepLimit = 256

// runPendingImageGC is one pass of the pending-image janitor. Reads
// ledger rows older than ImageBuildGCTTL, re-checks HasActiveImageRef
// (in case a new sandbox grabbed the image after scheduling), and
// removes the image from Docker. Idempotent: a failed RemoveImage
// leaves the row so the next tick retries; a successful one (or a
// "referenced now" outcome) deletes the row so we don't keep
// re-attempting. Failures are logged, never returned — the janitor
// must not block on a bad row.
//
// Refresh-race guard: each row's scheduled_at is captured at list time
// and re-verified before RemoveImage; the post-remove cleanup uses a
// conditional delete on (image, scheduled_at). If a destroy path
// re-upserted the row between list and remove, the row stays and the
// remove is skipped this tick — otherwise the freshly-extended TTL
// would be silently overridden.
func (s *Service) runPendingImageGC(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-s.cfg.ImageBuildGCTTL)
	entries, err := s.store.ListPendingImageGCDue(ctx, cutoff, pendingImageGCSweepLimit)
	if err != nil {
		s.logger.Warn("pending image gc list failed", "error", err)
		return
	}
	if s.testAfterPendingImageGCList != nil {
		s.testAfterPendingImageGCList()
	}
	for _, entry := range entries {
		s.sweepPendingImageGCEntry(ctx, entry)
	}
}

// sweepPendingImageGCEntry decides one ledger row: drop it, remove its image,
// or leave it for the next tick.
//
// A snapshot's own tag is decided under snapshotMu. CreateSnapshotWithOwnership
// writes its cleanup intent before the commit and holds snapshotMu until the
// catalogue row that owns the tag is in, so without the lock this sweep could
// see "no row names the tag" mid-create and remove the image the create just
// committed. Under it, the sweep sees either no create at all, or the
// finished one's row (and keeps the image).
func (s *Service) sweepPendingImageGCEntry(ctx context.Context, entry store.PendingImageGCEntry) {
	image := entry.Image
	engine := entry.Engine
	if s.imageGCWhitelisted(image) {
		// Operator whitelisted this image after the row landed.
		// Drop it so the ledger doesn't carry it forever; the
		// destroy path's short-circuit keeps new rows out.
		if _, err := s.store.DeletePendingImageGCIfScheduledAt(ctx, engine, image, entry.ScheduledAt); err != nil {
			s.logger.Warn("pending image gc whitelist row clear failed", "engine", engine, "image", image, "error", err)
		}
		return
	}
	if docker.IsSnapshotImageRef(image) {
		s.snapshotMu.Lock()
		defer s.snapshotMu.Unlock()
	}
	referenced, err := s.store.HasActiveImageRef(ctx, image)
	if err != nil {
		s.logger.Warn("pending image gc ref check failed", "image", image, "error", err)
		return
	}
	if referenced {
		// Image came back into use between scheduling and now.
		// Drop the row; if it goes idle again the destroy path
		// will re-schedule with a fresh timestamp.
		if err := s.store.DeletePendingImageGC(ctx, engine, image); err != nil {
			s.logger.Warn("pending image gc row clear failed", "engine", engine, "image", image, "error", err)
		}
		return
	}
	remover, err := s.imageRemoverForEngine(engine)
	if err != nil {
		// The engine that owns this copy is not wired on this node
		// (an operator flipped SB_CONTAINER_ENGINE). Leave the row:
		// removing through the other engine would miss the disk we
		// are trying to reclaim and could evict its cache instead.
		s.logger.Warn("pending image gc engine unavailable", "engine", engine, "image", image, "error", err)
		return
	}
	if err := remover.RemoveImage(ctx, image); err != nil {
		// Leave the row in place so the next tick retries. Note
		// docker.RemoveImage returns nil for 404/409, so the
		// "image vanished" and "still in use by an unknown
		// container" cases fall through to the delete below.
		s.logger.Warn("pending image gc remove failed", "engine", engine, "image", image, "error", err)
		return
	}
	// Conditional delete: if a destroy refreshed the row between
	// the list and now, leave the fresh row in place — the next
	// tick will pick it up after the new TTL elapses. The image
	// was already removed from Docker in that case, which is
	// acceptable: it gets re-pulled on the next create. The thing
	// we MUST avoid is silently throwing away the row that would
	// have extended the TTL.
	if _, err := s.store.DeletePendingImageGCIfScheduledAt(ctx, engine, image, entry.ScheduledAt); err != nil {
		s.logger.Warn("pending image gc row delete failed", "engine", engine, "image", image, "error", err)
		return
	}
	s.logger.Info("audit pending image gc removed", "engine", engine, "image", image)
}

func (s *Service) StartReconcileLoop(ctx context.Context) {
	interval := s.cfg.ReconcileInterval
	if interval <= 0 {
		return
	}
	s.startPeriodic(ctx, interval, 30*time.Second, func(c context.Context) {
		if err := s.Reconcile(c); err != nil {
			s.logger.Warn("periodic reconcile failed", "error", err)
		}
	})
}

func (s *Service) StartClusterIngressReconcile(ctx context.Context) {
	if !s.cfg.EnableCluster || !s.caddy.Enabled() {
		return
	}
	// Push-based wake: SubscribePlacement returns a channel the FSM signals
	// directly from Apply, so a leader-side raft commit reaches every node's
	// reconciler as soon as the log entry is delivered. No poll interval —
	// the previous version-poll watcher imposed a 500ms floor on convergence
	// and a constant background ticker; the push path eliminates both.
	//
	// The channel is nil in single-node mode (Noop) AND on a dedicated
	// ingress node (a non-Raft Agent) unless SB_INGRESS_PROXY_ROUTING runs
	// the placement delta feed. Selecting on nil is permanently un-ready, so
	// there the timer is the only trigger: a port exposed through another
	// node waits up to one interval for its route here (2.3s on
	// cluster-hetero ingress-1, 2026-10-04).
	wake := s.Cluster().SubscribePlacement(ctx)
	go func() {
		retry := clusterIngressTransientRetryDelay
		for {
			reconcileCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := s.ReconcileClusterIngress(reconcileCtx)
			cancel()
			if err != nil {
				s.logger.Warn("cluster ingress reconcile failed", "error", err)
			}
			var wait time.Duration
			wait, retry = nextClusterIngressWait(err, retry)

			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			case <-wake:
				t.Stop()
			}
		}
	}()
}

func (s *Service) ReconcileClusterIngress(ctx context.Context) error {
	if !s.cfg.EnableCluster || !s.caddy.Enabled() {
		return nil
	}
	ctx = withAuditSubsystem(ctx, auditSubsystemReconcile)
	// Peer-forwarding routes belong to the ingress tier. A dedicated worker or
	// server reconciling them downloaded a placement view it never installs
	// anything from.
	if !s.servesClusterIngress() {
		return nil
	}
	c := s.Cluster()
	if c == nil {
		return nil
	}
	self := c.SelfNodeID()
	if self == "" {
		return nil
	}
	shardFilter := s.clusterIngressShardFilter(c, self)
	placements := c.PlacementsForShards(shardFilter)

	// Idle-skip: hash the relevant slice of the placement view. If nothing
	// changed since the last successful reconcile, return without touching
	// Caddy admin. At 10K placements this drops a 2K-route-write tick to a
	// single hash() and a few atomic loads. The hash key includes
	// Version, so any FSM-level placement change forces a recompute.
	//
	// The live audit is the exception: it runs on its own cadence even over
	// an unchanged view, because Caddy losing routes does not change the
	// placement view.
	start := time.Now()
	viewHash, routeCounts, maxVersion := hashPlacementView(self, placements)
	audit := s.shouldRunClusterIngressFullGC()
	if viewHash == s.ingressLastHash.Load() && viewHash != 0 && !audit {
		recordIngressReconcile(reconcileSkipped, time.Since(start), routeCounts, maxVersion)
		return nil
	}

	var (
		firstErr error
		ops      int
	)
	desired, needL4 := s.buildClusterIngressIntents(placements, self)
	if needL4 {
		firstErr = s.RepairLayer4Ready(ctx)
	}
	if firstErr == nil {
		ops, firstErr = s.applyClusterIngress(ctx, desired, audit)
	}
	if firstErr == nil {
		s.logger.Debug("cluster ingress reconcile applied",
			"placement_shards", routeShardFilterLogValue(shardFilter),
			"routes", len(desired),
			"ops", ops,
			"live_audit", audit,
		)
	}
	// Stash the hash only on full success — partial failures must retry next
	// tick rather than wedging the idle-skip on a stale view. An audit that
	// did not finish is re-armed for the next pass instead of the next
	// minute.
	if firstErr == nil {
		s.ingressLastHash.Store(viewHash)
		recordIngressReconcile(reconcileApplied, time.Since(start), routeCounts, maxVersion)
	} else {
		s.ingressLastHash.Store(0)
		if audit {
			s.ingressLastFullGCUnix.Store(0)
		}
		recordIngressReconcile(reconcileErrored, time.Since(start), routeCounts, maxVersion)
	}
	// Publish lag regardless of pass outcome: even a failed tick gives the
	// operator the up-to-date "FSM is N versions ahead of installed routes"
	// signal. PlacementVersion() is the FSM's current monotonic apply counter
	// (raft log index); maxVersion is what this pass *would* have installed.
	SetIngressRouteLag(c.PlacementVersion())
	return firstErr
}

// applyInFluxRoute is the orphan / unresolvable-owner branch of the ingress
// reconciler. It removes any live route for the sandbox (so traffic can't
// keep flowing to a dead host) and installs the 503-with-Retry-After route
// for the sandbox and each replicated exposed port. All four mutations are
// best-effort and idempotent; we return the first error and let the caller
// reset the idle-skip hash so the next tick retries.
func (s *Service) applyInFluxRoute(ctx context.Context, p cluster.Placement) error {
	var firstErr error
	// Drop live HTTP / SNI routes (whichever mode wired them).
	if s.cfg.Domain == "" {
		if err := s.publicRoutes().DeleteSandboxRoute(ctx, p.SandboxID); err != nil {
			firstErr = err
		}
	} else {
		if err := s.publicRoutes().DeleteRouteByID(ctx, caddy.IngressSandboxSNIRouteID(p.SandboxID)); err != nil {
			firstErr = err
		}
	}
	if err := s.publicRoutes().UpsertInFluxSandboxRoute(ctx, p.SandboxID); err != nil && firstErr == nil {
		firstErr = err
	}
	// Per-port: same idea. We only mirror HTTP/TLS in-flux into Caddy; raw
	// TCP exposures don't have a hostname the client can match against, so
	// they fail at connect time rather than serving an in-flux response.
	for port, route := range cluster.ExposedPortRoutesForPlacement(p) {
		if route.Protocol == models.ExposedPortProtocolTCP {
			continue
		}
		if s.cfg.Domain == "" {
			if err := s.publicRoutes().DeleteRouteByID(ctx, caddy.PortRouteID(p.SandboxID, port)); err != nil && firstErr == nil {
				firstErr = err
			}
		} else {
			if err := s.publicRoutes().DeleteRouteByID(ctx, caddy.IngressPortSNIRouteID(p.SandboxID, port)); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := s.publicRoutes().UpsertInFluxPortRoute(ctx, p.SandboxID, port); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Service) gcClusterIngressRoutes(ctx context.Context) error {
	// gcZombieCaddyEntries reads the rows itself, after its Caddy snapshot.
	if err := s.gcZombieCaddyEntries(ctx, nil); err != nil {
		return fmt.Errorf("cluster ingress gc: %w", err)
	}
	return nil
}

func dataPlaneHostForPlacement(p cluster.Placement) string {
	if host := strings.TrimSpace(p.OwnerDataPlaneHost); host != "" {
		return hostFromURL(host)
	}
	return hostFromURL(p.OwnerAPIURL)
}

func hostFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	host := strings.TrimSpace(raw)
	trimmed := strings.Trim(host, "[]")
	if net.ParseIP(trimmed) != nil {
		return trimmed
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	if i := strings.LastIndex(host, ":"); i > -1 && !strings.Contains(host[i+1:], "/") && strings.Count(host, ":") == 1 {
		return strings.Trim(host[:i], "[]")
	}
	return trimmed
}

func l4ListenPort(listen string) int {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return 0
	}
	if _, port, err := net.SplitHostPort(listen); err == nil {
		n, _ := strconv.Atoi(port)
		return n
	}
	if strings.HasPrefix(listen, ":") {
		n, _ := strconv.Atoi(strings.TrimPrefix(listen, ":"))
		return n
	}
	if n, err := strconv.Atoi(listen); err == nil {
		return n
	}
	return 0
}

func normalizeCreateRequest(req models.CreateSandboxRequest) models.CreateSandboxRequest {
	// CompatState is replication-internal (B11): it rides the FSM spec only
	// through the service's own UpsertCompatState write-through, never from a
	// client create body. Strip anything supplied so a caller cannot inject it
	// (a failover recreate reads it off the raw replicated spec, before here).
	req.CompatState = nil
	if req.CPU <= 0 {
		req.CPU = models.DefaultCPU
	}
	if req.MemoryMB <= 0 {
		req.MemoryMB = models.DefaultMemoryMB
	}
	if req.DiskGB <= 0 {
		req.DiskGB = models.DefaultDiskGB
	}
	if req.OSUser == "" {
		req.OSUser = "root"
	}
	if req.Env == nil {
		req.Env = map[string]string{}
	}
	return req
}

func unsupportedFirecrackerOption(option string) error {
	return fmt.Errorf("runtime %q does not yet support %s (see plans/snapshot-clone-fast-boot.md): %w",
		models.RuntimeFirecracker, option, models.ErrRuntimeNotImplemented)
}

func NormalizeCreateFailover(req *models.CreateSandboxRequest) error {
	if req == nil || req.Failover == nil {
		return nil
	}
	policy, err := models.NormalizeFailoverPolicy(req.Failover.Policy)
	if err != nil {
		return fmt.Errorf("invalid failover: %w", err)
	}
	if policy == models.FailoverPolicyNone {
		req.Failover = nil
		return nil
	}
	if policy == models.FailoverPolicyRecreate && ImageRequiresLocalPlacement(*req) {
		return errors.New("failover.policy=recreate requires a portable image; local-only images cannot be recreated on another node")
	}
	req.Failover = &models.Failover{Policy: policy}
	return nil
}

func sandboxContainerRef(sandbox *models.Sandbox) string {
	if sandbox == nil {
		return ""
	}
	return sandbox.ContainerID
}

func generateToolboxToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// NewSandboxID mints a fresh sandbox ID in this node's cell
// (sandbox_id_cell.go). The shape, "sb-" plus 16 lowercase hex, is
// unchanged: clients tell an ID from a name by it
// (models.IsGeneratedSandboxID), and it is a valid container name.
//
// The cluster handler's reservation-first create mints through this too, so
// the router's ID and the local create's share one format. IDs derived from
// a key (an idempotent create's, the facades') keep their hashed form; like
// IDs made before cells, each is served where it lives.
func (s *Service) NewSandboxID() (string, error) {
	return newSandboxIDInCell(s.cfg.CellID, s.cfg.CellIDKey)
}

// imageStillReferenced reports whether any sandbox in the given slice still
// holds a live reference to image. A reference is "live" when the sandbox's
// status is anything other than destroyed — stopped, started, creating, and
// error all count, because their image is needed for a future start. The
// check is exact-match on the Image string, so a sandbox created with
// "alpine" and one with "alpine:latest" are treated as different images
// (matching the way Docker stores tags).
//
// This is the in-memory specification of the GC policy and is used in unit
// tests. Production callers go through Store.HasActiveImageRef so the check
// stays constant-cost as the destroyed-row history grows.
func imageStillReferenced(sandboxes []*models.Sandbox, image string) bool {
	if image == "" {
		return true
	}
	for _, sb := range sandboxes {
		if sb == nil {
			continue
		}
		if sb.Image == image && sb.Status != models.SandboxStatusDestroyed {
			return true
		}
	}
	return false
}

// schedulePendingImageGC records the image in the pending_image_gc
// ledger so the runPendingImageGC janitor can sweep it after
// ImageBuildGCTTL. Replaces the previous inline-delete path: a destroyed
// sandbox no longer yanks its image from the daemon immediately, which
// kept a destroy/recreate loop on the same image re-pulling on every
// cycle. Best-effort: errors are logged, never returned, because image
// GC must not block the sandbox lifecycle path that called us. If the
// ledger write fails (rare — SQLite is local), the image leaks until
// another destroy of a sandbox sharing the image re-schedules it.
// refreshPendingImageGCOnUse pushes any existing pending_image_gc row
// for image forward to "now". Called from the create path so that
// creating a new sandbox with an image that's pending GC restarts the
// TTL window from the most recent use — matching the existing
// "destroy refreshes the timestamp" semantics in reverse.
//
// UPDATE-only: this never inserts a row. Images that were never
// destroyed (and so never scheduled) stay out of pending_image_gc
// entirely. That keeps the table bounded by "images destroyed
// recently" rather than ballooning to one row per image ever used.
//
// Best-effort and off the boot-path-critical sequence: an error
// here is logged, not surfaced. The image still gets GC'd correctly
// either way — at worst the deadline is the original destroy's
// timestamp rather than this create's, which is the pre-existing
// behavior the rest of the janitor already handles.
func (s *Service) refreshPendingImageGCOnUse(ctx context.Context, image string) {
	if image == "" {
		return
	}
	if !s.cfg.ImageBuildGCEnabled {
		return
	}
	if s.imageGCWhitelisted(image) {
		return
	}
	if _, err := s.store.RefreshPendingImageGCIfExists(ctx, image, time.Now().UTC()); err != nil {
		s.logger.Warn("refresh pending image gc failed", "image", image, "error", err)
	}
}

// schedulePendingImageGC records one engine's copy of image for later removal.
// engine is the sandbox's own engine, not the host default: an image pulled by
// containerd has to be removed through containerd, and asking docker to remove
// it neither reclaims the disk nor leaves the ledger row in a state the next
// sweep can finish.
func (s *Service) schedulePendingImageGC(ctx context.Context, engine, image string) {
	if image == "" {
		return
	}
	// Mirror the janitor's kill switch: when ImageBuildGCEnabled is
	// false no sweep will ever drain the ledger, so writing here would
	// just grow pending_image_gc forever for an operator who has opted
	// out of image GC entirely. The trade-off is symmetric with the
	// disabled janitor: images of destroyed sandboxes are left on the
	// daemon (which is the explicit "don't reclaim" choice), and they
	// stay reachable for warm re-creates instead of getting yanked.
	if !s.cfg.ImageBuildGCEnabled {
		return
	}
	// Short-circuit on whitelist so the ledger doesn't accumulate rows
	// the janitor would only ever skip. Cheap O(N) scan over a small,
	// operator-curated list — much smaller than the per-tick scan cost.
	if s.imageGCWhitelisted(image) {
		return
	}
	if err := s.store.SchedulePendingImageGC(ctx, engine, image, time.Now().UTC()); err != nil {
		s.logger.Warn("schedule pending image gc failed", "engine", engine, "image", image, "error", err)
		return
	}
	s.logger.Info("audit image scheduled for gc", "engine", engine, "image", image)
}

// imageGCWhitelisted reports whether image is protected from both
// janitors by cfg.ImageGCWhitelist. Three match shapes:
//   - exact ref equality (entry == image)
//   - repo equality, tag/digest agnostic (entry has no tag/digest, and image
//     starts with entry followed by ':' or '@')
//   - registry/org prefix when entry ends in '/'
//
// Anchored boundaries on every shape so a "ubuntu" entry can't accidentally
// shield "ubuntu-base" — the operator gets exactly what they typed.
//
// The tag/digest detection inspects the segment AFTER the last '/' rather
// than the whole entry: Docker accepts ports in registry hosts
// ("localhost:5000/team/app"), so a literal ':' before the last '/' is
// part of the host, not a tag separator. Without this, every entry for a
// non-standard-port registry would silently degrade to exact-ref only.
func (s *Service) imageGCWhitelisted(image string) bool {
	if image == "" || len(s.cfg.ImageGCWhitelist) == 0 {
		return false
	}
	for _, entry := range s.cfg.ImageGCWhitelist {
		if entry == "" {
			continue
		}
		if entry == image {
			return true
		}
		if strings.HasSuffix(entry, "/") {
			if strings.HasPrefix(image, entry) {
				return true
			}
			continue
		}
		// Look for tag/digest separators only in the last path segment —
		// ':' inside a registry host (e.g. "localhost:5000/...") must
		// not be treated as a tag boundary.
		lastSeg := entry[strings.LastIndex(entry, "/")+1:]
		if !strings.ContainsAny(lastSeg, ":@") {
			if strings.HasPrefix(image, entry+":") || strings.HasPrefix(image, entry+"@") {
				return true
			}
		}
	}
	return false
}

// syncAllowedPorts pushes the sandbox's current set of exposed ports to
// toolboxd's in-memory allowlist. Best-effort — logged on failure. Without
// this, /proxy/<port>/ on the public sandbox URL refuses every request.
//
// sandbox says where to push; the list itself is read from the store under
// allowlistLocks (route_gate.go). Reconcile and the start paths pass a row
// read earlier, and pushing its ports could put a port that has since
// become token-gated back on the allowlist, around the gate.
func (s *Service) syncAllowedPorts(ctx context.Context, sandbox *models.Sandbox) {
	if sandbox == nil || sandbox.Status != models.SandboxStatusStarted || sandbox.ContainerIP == "" {
		return
	}
	if s.isWasmSandbox(sandbox) {
		s.syncWasmAllowedPorts(ctx, sandbox)
		return
	}
	if s.isIsolateSandbox(sandbox) {
		s.syncIsolateAllowedPorts(ctx, sandbox)
		return
	}
	cr, err := s.containerRuntimeForSandbox(sandbox)
	if err != nil {
		return
	}
	unlock := s.allowlistLocks.lock(sandbox.ID)
	defer unlock()
	exposed := sandbox.ExposedPorts
	if s.store != nil {
		if exposed, err = s.store.ListPorts(ctx, sandbox.ID); err != nil {
			// Push nothing rather than the old copy; the next push fixes it.
			s.logger.Warn("allowed ports not synced: could not read the exposed ports", "sandbox_id", sandbox.ID, "error", err)
			return
		}
	}
	s.afterRouteGateRead(gateReadAllowlist)
	if err := cr.PushAllowedPorts(ctx, sandbox.ContainerIP, sandbox.ToolboxToken, toolboxProxyPorts(exposed)); err != nil {
		s.logger.Warn("failed to sync allowed ports", "sandbox_id", sandbox.ID, "error", err)
	}
}

// maxMaskRequestHostLen bounds the stored value at the DNS name maximum so a
// pathological client can't balloon the column; a real Host (optionally with a
// :port suffix) never approaches this.
const maxMaskRequestHostLen = 253

// validateMaskRequestHost guards the Host-rewrite value. It is forwarded
// verbatim as an HTTP Host header, so it must be a single-line token: reject
// CR/LF (header-injection / response-splitting) and any other control or space
// character. Empty (after trim) is valid and means "no rewrite".
func validateMaskRequestHost(mask string) error {
	mask = strings.TrimSpace(mask)
	if mask == "" {
		return nil
	}
	if len(mask) > maxMaskRequestHostLen {
		return fmt.Errorf("mask_request_host must be at most %d characters", maxMaskRequestHostLen)
	}
	for _, r := range mask {
		// ASCII space and below covers CR, LF, tab, and other control chars;
		// DEL (0x7f) is rejected too. A Host token has no use for any of these.
		if r <= ' ' || r == 0x7f {
			return errors.New("mask_request_host must not contain spaces or control characters")
		}
	}
	return nil
}

// portProbeTimeout is the maximum time probeContainerPort waits for a container
// port to accept a connection. Non-fatal by design — the caller proceeds on
// timeout and logs a warning. 2 s is long enough to survive transient
// scheduling jitter on a loaded host while short enough not to block
// exposePort for slow-starting processes indefinitely.
const portProbeTimeout = 2 * time.Second

// skipPortProbeKey is the context key WithoutPortProbe sets.
type skipPortProbeKey struct{}

// WithoutPortProbe marks an expose whose port cannot be listening yet, so
// exposePort skips its best-effort probe. E2B's mcp option exposes the
// gateway port at create time, but the E2B SDK starts the gateway only after
// the create returns: the probe could never succeed there, and a dropped SYN
// made it wait out portProbeTimeout (2 s) on every such create.
func WithoutPortProbe(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipPortProbeKey{}, true)
}

func skipPortProbe(ctx context.Context) bool {
	skip, _ := ctx.Value(skipPortProbeKey{}).(bool)
	return skip
}

// probeContainerPort dials containerIP:port to verify the in-container process
// has bound its port before Caddy starts routing traffic to it. Called from
// exposePort on first-time exposures so clients do not receive
// connection-refused from Caddy when they immediately hit the returned URL.
// Non-fatal by design: the caller logs a warning and proceeds rather than
// blocking exposePort indefinitely for slow-starting processes.
func probeContainerPort(_ context.Context, containerIP string, port int) error {
	// Use a detached context so the probe is not killed when the caller's
	// request context (e.g. the exposePort HTTP request) is near its deadline.
	// The probe is a best-effort liveness check — its 2s window is independent
	// of the caller's remaining time.
	probeCtx, cancel := context.WithTimeout(context.Background(), portProbeTimeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(containerIP, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// probeSSHGateway opens a TCP connection to the gateway's listen address with
// a short timeout. We don't speak the SSH handshake — connect is enough to
// distinguish "process is up and accepting" from "wedged or never started."
// Listener is bound to 0.0.0.0 in production; we dial 127.0.0.1 explicitly so
// we don't depend on the box having a public IP.
func probeSSHGateway(ctx context.Context, listenAddr string) error {
	if listenAddr == "" {
		return errors.New("ssh listen addr is empty")
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("invalid ssh listen addr %q: %w", listenAddr, err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return fmt.Errorf("ssh gateway dial: %w", err)
	}
	_ = conn.Close()
	return nil
}
