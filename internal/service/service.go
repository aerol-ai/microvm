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
	"log/slog"
	mathrand "math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netstats"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
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

const clusterIngressReconcileInterval = 5 * time.Second

type Service struct {
	cfg    config.Config
	logger *slog.Logger
	store  *store.Store
	// docker holds the lifecycle-only runtime abstraction. The field name
	// stays "docker" because every existing call site is shaped around it;
	// the type is runtime.Runtime so a non-Docker driver can be slotted in
	// without touching service code.
	docker runtime.Runtime
	// events is the concrete Docker client for the daemon /events stream and
	// any other Docker-API-shaped surface that intentionally stays outside
	// the runtime abstraction. Today both fields point at the same instance.
	events   *docker.Client
	caddy    *caddy.Client
	cipher   *secrets.Cipher
	mounts   *mounts.Manager
	admitter *capacity.Admitter
	images   ImageDistributionProvider
	// snapshotPusher + snapshotPushReconciler are non-nil only when
	// cfg.SnapshotPushEnabled is true. The snapshot-create path checks
	// snapshotPusher for nil to decide whether to mark a new row as
	// "pending" vs straight-to-"active", and kicks the reconciler once
	// (best-effort, in a goroutine) so callers don't always wait for the
	// next reconciler tick.
	snapshotPusher         *SnapshotPusher
	snapshotPushReconciler *SnapshotPushReconciler
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
	l4LimitMu       sync.Mutex
	// pending counts L4 connections waiting for wake/target resolution.
	// active counts connections already admitted to proxy bytes. Keeping both
	// lets cold-start bursts shed excess work without blocking unrelated warm
	// traffic accounting.
	l4PendingGlobal       int
	l4PendingBySandbox    map[string]int
	l4ActiveGlobal        int
	l4ActiveBySandbox     map[string]int
	l4ActivityGenerations map[string]uint64
	l4ActivitySeq         uint64

	// netstatsReady latches the lazy bootstrap of the per-sandbox network
	// byte-counter poller. Same pattern as l4Ready: atomic fast-path on the
	// hot side, single-flight Mutex on the cold-start side. The poller is
	// kicked off either at daemon boot (best-effort) or on the first request
	// that needs network usage data — whichever happens first.
	netstatsMu       sync.Mutex
	netstatsReady    atomic.Bool
	netstatsPoller   *netstats.Poller
	netstatsLastTick atomic.Int64 // unix nanos; last successful tick for /usage staleness reporting

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
	warmCache   map[string]int64

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
	ingressRouteMu        sync.Mutex
	ingressRouteCache     map[string]ingressRouteIntent
	ingressLastFullGCUnix atomic.Int64
}

func New(cfg config.Config, logger *slog.Logger, db *store.Store, runtimeDriver runtime.Runtime, eventsClient *docker.Client, caddyClient *caddy.Client, cipher *secrets.Cipher, mountManager *mounts.Manager, admitter *capacity.Admitter) *Service {
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
		// cluster mode is enabled at boot.
		cluster: cluster.NewNoop("standalone", ""),
	}
	s.ensureTouchCoalescer()
	s.ensureCaddyCoalescer()
	return s
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
}

// SnapshotPushReconciler exposes the reconciler so main.go can drive it
// from a ticker. Returns nil when snapshot push is disabled — the ticker
// wrapper should no-op cleanly in that case.
func (s *Service) SnapshotPushReconciler() *SnapshotPushReconciler {
	return s.snapshotPushReconciler
}

// Cluster returns the attached cluster.Client. Always non-nil.
func (s *Service) Cluster() cluster.Client {
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()
	return s.cluster
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
	return s.clusterTopologyErrorFor(c.Members())
}

// clusterTopologyErrorFor evaluates the production-topology contract against a
// caller-supplied member snapshot. Extracted so Health() and the reconcile
// loop can run the same shard-aware-ingress check without re-fetching members
// or duplicating the threshold logic.
func (s *Service) clusterTopologyErrorFor(members []cluster.Member) error {
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
	return s.createSandbox(ctx, req, "")
}

// CreateSandboxWithID is the failover-recreate entry point: it behaves like
// CreateSandbox but uses the supplied ID instead of generating a fresh one.
// Idempotent at the cluster boundary — if a sandbox with this ID already
// exists locally we return the existing record without touching docker. Used
// by the cluster owner watcher to re-materialize a sandbox after its previous
// owner died.
func (s *Service) CreateSandboxWithID(ctx context.Context, req models.CreateSandboxRequest, id string) (*models.CreateSandboxResponse, error) {
	if id == "" {
		return nil, errors.New("CreateSandboxWithID: id required")
	}
	if existing, err := s.store.Get(ctx, id); err == nil && existing != nil {
		// Already present locally — recreate is a no-op. The watcher tick that
		// noticed the FSM-only entry must have raced with a local create.
		return &models.CreateSandboxResponse{Sandbox: *existing}, nil
	}
	return s.createSandbox(ctx, req, id)
}

// reconcileStaleOwnership destroys local sandboxes whose cluster placement
// no longer points to self. Single-node mode (Noop client) reports IsSelf=true
// for every id, so this is a no-op there. Errors are logged and swallowed —
// the next reconcile tick retries.
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
	for _, sb := range known {
		if sb == nil || sb.ID == "" {
			continue
		}
		owner, err := c.OwnerOf(sb.ID)
		if err != nil {
			// ErrUnknownSandbox: no FSM record yet (fresh boot before
			// AssertOwnership replay completes); leave it alone.
			// ErrOrphaned: the dead-owner reconciler is still mid-flight or
			// the sandbox has no spec to recreate from; leave it alone.
			continue
		}
		if owner.NodeID == "" || owner.NodeID == self {
			continue
		}
		s.logger.Warn("cluster: destroying stale local sandbox; ownership reassigned",
			"sandbox_id", sb.ID, "current_owner", owner.NodeID)
		if err := s.DestroySandbox(ctx, sb.ID); err != nil {
			s.logger.Warn("cluster: stale-destroy failed; will retry next reconcile",
				"sandbox_id", sb.ID, "err", err)
		}
	}
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
// storage. A decrypt failure is
// fatal to this attempt but non-fatal globally — the watcher's retry loop
// (now with reassign-after-K-failures) will eventually move the placement
// to a node whose key matches.
//
// Port replay tries every port but returns an error when any replay failed so
// the owner watcher keeps retrying and can eventually reassign the placement.
// ExposePort is idempotent, so a partial replay is safe to resume.
//
// Only placements whose create spec opted into failover.policy=recreate reach
// this path; default sandboxes remain non-HA and are orphaned on owner death.
func (s *Service) RecreateSandbox(ctx context.Context, id string, spec models.CreateSandboxRequest, secrets cluster.PlacementSecrets, exposedPorts map[int]cluster.ExposedPortRoute) error {
	if existing, err := s.store.Get(ctx, id); err == nil && existing != nil {
		// D1 reconstruction: on owner change, a Serverless && stopped row
		// without wake_armed is the new owner's first chance to install
		// wake routes and arm the bit. Done before port replay so the
		// wake-aware route shape is in place when replayClusterExposedPorts
		// touches HTTP exposures.
		s.ReconstructWakeArmedIfNeeded(ctx, existing)
		return s.replayClusterExposedPorts(ctx, id, exposedPorts)
	}
	nodeID := ""
	if c := s.Cluster(); c != nil {
		nodeID = c.SelfNodeID()
	}
	merged, err := s.OpenClusterSecretsForNode(ctx, spec, secrets, nodeID)
	if err != nil {
		return fmt.Errorf("recreate %s: %w", id, err)
	}
	if _, err := s.CreateSandboxWithID(ctx, merged, id); err != nil {
		return err
	}
	if err := s.replayClusterExposedPorts(ctx, id, exposedPorts); err != nil {
		return err
	}
	s.logger.Info("cluster: recreated sandbox after failover",
		"sandbox_id", id, "replayed_ports", len(exposedPorts))
	return nil
}

func (s *Service) replayClusterExposedPorts(ctx context.Context, id string, exposedPorts map[int]cluster.ExposedPortRoute) error {
	var firstErr error
	for port, route := range exposedPorts {
		if _, err := s.exposePort(ctx, id, port, route.Protocol, route.HostPort); err != nil {
			s.logger.Warn("cluster: re-expose after recreate failed; owner watcher will retry",
				"sandbox_id", id, "port", port, "protocol", route.Protocol, "host_port", route.HostPort, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("replay exposed port %d: %w", port, err)
			}
		}
	}
	return firstErr
}

func capacityRequestFromCreate(req models.CreateSandboxRequest) capacity.Request {
	return capacity.Request{
		CPU:       req.CPU,
		MemoryMB:  req.MemoryMB,
		DiskGB:    req.DiskGB,
		Runtime:   req.Runtime,
		GPUs:      gpuCountForCapacity(req.GPUs),
		GPUVendor: gpuVendorForCapacity(req.GPUs),
	}
}

func capacityRequestFromSandbox(sandbox *models.Sandbox) capacity.Request {
	if sandbox == nil {
		return capacity.Request{}
	}
	return capacity.Request{
		CPU:       sandbox.CPU,
		MemoryMB:  sandbox.MemoryMB,
		DiskGB:    sandbox.DiskGB,
		Runtime:   sandbox.Runtime,
		GPUs:      gpuCountForCapacity(sandbox.GPUs),
		GPUVendor: gpuVendorForCapacity(sandbox.GPUs),
	}
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
	done := beginSandboxCreateMetric()
	defer func() { done(err) }()
	if err := s.ClusterTopologyError(); err != nil {
		return nil, err
	}
	if s.cfg.EnableCluster && !s.cfg.IsWorker() {
		return nil, cluster.ErrNoPlacementTarget
	}

	req = normalizeCreateRequest(req)
	if err := s.NormalizeCreateImageDistribution(ctx, &req); err != nil {
		return nil, err
	}
	if err := NormalizeCreateFailover(&req); err != nil {
		return nil, err
	}
	if req.Image == "" {
		return nil, errors.New("image is required")
	}
	// Custom-domain validation runs early so an invalid or unsupported
	// payload fails before admission/mounts/docker.Create burn resources.
	// On success req.CustomDomains is rewritten with the canonical slice.
	if err := s.validateCreateCustomDomains(&req); err != nil {
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
	req.Runtime = chosenRuntime

	if len(req.Mounts) > models.MaxMountsPerSandbox {
		return nil, fmt.Errorf("too many mounts: max %d", models.MaxMountsPerSandbox)
	}
	for i := range req.Mounts {
		if err := req.Mounts[i].Validate(s.cfg.ToolboxMountPath); err != nil {
			return nil, fmt.Errorf("mount %d: %w", i, err)
		}
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

	toolboxToken, err := generateToolboxToken()
	if err != nil {
		return nil, fmt.Errorf("generate toolbox token: %w", err)
	}

	authorizedKey, privateKeyPEM, err := generateSandboxSSHKeys()
	if err != nil {
		return nil, fmt.Errorf("generate ssh keypair: %w", err)
	}

	// Choose the sandbox ID up-front so we have stable host paths to bind
	// before docker.Create runs. The ID also becomes the container's name.
	// idOverride is non-empty only on the cluster owner watcher's recreate
	// path — preserving the original ID is what makes failover transparent
	// to clients holding the sandbox URL.
	sandboxID := idOverride
	if sandboxID == "" {
		var err error
		sandboxID, err = generateSandboxID()
		if err != nil {
			return nil, fmt.Errorf("generate sandbox id: %w", err)
		}
	}

	// Admission check uses normalized values (req.CPU/MemoryMB are guaranteed
	// > 0 by normalizeCreateRequest above), so a default-sized request still
	// counts against the host budget. Reservation happens here; every failure
	// path below must release it.
	if s.admitter != nil {
		if err := s.admitter.Admit(sandboxID, capacityRequestFromCreate(req)); err != nil {
			return nil, err
		}
	}
	releaseAdmission := func() {
		if s.admitter != nil {
			s.admitter.Release(sandboxID)
		}
	}

	binds, err := s.mounts.MountAll(ctx, sandboxID, req.Mounts)
	if err != nil {
		releaseAdmission()
		return nil, fmt.Errorf("mount external storage: %w", err)
	}
	cleanupMounts := func() {
		if err := s.mounts.UnmountAll(sandboxID); err != nil {
			s.logger.Warn("cleanup unmount failed", "sandbox_id", sandboxID, "error", err)
		}
	}

	state, err := s.docker.Create(ctx, req, sandboxID, toolboxToken, binds)
	if err != nil {
		cleanupMounts()
		releaseAdmission()
		return nil, err
	}

	// Seal the registry creds (if any) BEFORE building the row so a marshal
	// or encrypt error doesn't leave a half-created sandbox: we already passed
	// docker.Create at this point, so failure here goes through the same
	// rollback chain as any later store error below.
	sealedRegistry, err := s.sealRegistry(req.Registry)
	if err != nil {
		_ = s.docker.Destroy(ctx, &models.Sandbox{ID: state.SandboxID, ContainerID: state.ContainerID, Runtime: chosenRuntime})
		cleanupMounts()
		releaseAdmission()
		return nil, err
	}

	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID:                   state.SandboxID,
		Image:                req.Image,
		Status:               state.Status,
		PublicURL:            s.caddy.SandboxPublicURL(state.SandboxID),
		ContainerID:          state.ContainerID,
		ContainerIP:          state.ContainerIP,
		CPU:                  req.CPU,
		MemoryMB:             req.MemoryMB,
		DiskGB:               req.DiskGB,
		OSUser:               req.OSUser,
		Env:                  req.Env,
		NetworkBlockAll:      req.NetworkBlockAll,
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
		GPUs:                 req.GPUs,
		RegistryAuthSealed:   sealedRegistry,
		NetworkBytesInLimit:  req.NetworkBytesInLimit,
		NetworkBytesOutLimit: req.NetworkBytesOutLimit,
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

	if err := s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort, sandboxCustomHostnames(sandbox)); err != nil {
		_ = s.docker.Destroy(ctx, sandbox)
		cleanupMounts()
		releaseAdmission()
		return nil, err
	}

	if err := s.store.Create(ctx, sandbox); err != nil {
		_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
		_ = s.docker.Destroy(ctx, sandbox)
		cleanupMounts()
		releaseAdmission()
		return nil, err
	}

	if len(sealedMounts) > 0 {
		if err := s.store.PutMounts(ctx, sandbox.ID, sealedMounts); err != nil {
			_ = s.store.Delete(ctx, sandbox.ID)
			_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
			_ = s.docker.Destroy(ctx, sandbox)
			cleanupMounts()
			releaseAdmission()
			return nil, fmt.Errorf("persist sandbox mounts: %w", err)
		}
	}

	if err := s.persistCustomDomainsOnCreate(ctx, sandbox.ID, req.CustomDomains); err != nil {
		// Same rollback chain as a mount-persist failure. ErrCustomDomainConflict
		// flows through unchanged so the API layer can map it to 409.
		_ = s.store.Delete(ctx, sandbox.ID)
		_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
		_ = s.docker.Destroy(ctx, sandbox)
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
	stored, err := s.store.Get(ctx, sandbox.ID)
	if err != nil {
		return nil, err
	}
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
// the persisted Sandbox row.
func (s *Service) UnsealRegistry(sealed []byte) (*models.RegistryAuth, error) {
	if len(sealed) == 0 {
		return nil, nil
	}
	plain, err := s.cipher.Decrypt(sealed)
	if err != nil {
		return nil, fmt.Errorf("decrypt registry auth: %w", err)
	}
	var auth models.RegistryAuth
	if err := json.Unmarshal(plain, &auth); err != nil {
		return nil, fmt.Errorf("unmarshal registry auth: %w", err)
	}
	return &auth, nil
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
// Returns nil, nil when the sandbox has no mounts.
func (s *Service) loadMounts(ctx context.Context, sandboxID string) ([]models.MountSpec, error) {
	sealed, err := s.store.GetMounts(ctx, sandboxID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	plain, err := s.cipher.Decrypt(sealed)
	if err != nil {
		return nil, fmt.Errorf("decrypt mounts: %w", err)
	}
	var file models.MountSpecFile
	if err := json.Unmarshal(plain, &file); err != nil {
		return nil, fmt.Errorf("unmarshal mounts: %w", err)
	}
	return file.Mounts, nil
}

// ListMounts returns the redacted mount config for a sandbox. Credentials are
// never included in the response — they are write-only via CreateSandbox.
func (s *Service) ListMounts(ctx context.Context, sandboxID string) ([]models.MountSpecRedacted, error) {
	if _, err := s.store.Get(ctx, sandboxID); err != nil {
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

func (s *Service) GetSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	return s.store.Get(ctx, id)
}

// ListSandboxes returns sandboxes whose Tags match every entry in tagFilter.
// A nil or empty filter returns every sandbox on this node. Filtering happens
// in-memory after the store read because Tags is JSON-encoded; pushing the
// filter into SQL via json_extract is a follow-up once row counts make the
// extra hop worth it. The filter exists so an external control plane can ask
// "give me the sandboxes belonging to user X" without round-tripping every
// sandbox in the cluster (see plans/multi-tenancy-via-control-plane.md).
func (s *Service) ListSandboxes(ctx context.Context, tagFilter map[string]string) ([]*models.Sandbox, error) {
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	if len(tagFilter) == 0 {
		return sandboxes, nil
	}
	filtered := sandboxes[:0]
	for _, sb := range sandboxes {
		if sandboxMatchesTags(sb, tagFilter) {
			filtered = append(filtered, sb)
		}
	}
	return filtered, nil
}

// sandboxMatchesTags returns true iff every key in want is present on sb.Tags
// with the same value. An empty want matches everything (caller short-circuits).
func sandboxMatchesTags(sb *models.Sandbox, want map[string]string) bool {
	for k, v := range want {
		if sb.Tags[k] != v {
			return false
		}
	}
	return true
}

func (s *Service) StartSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
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

	state, err := s.docker.Start(ctx, sandboxContainerRef(sandbox))
	if err != nil {
		_ = s.mounts.UnmountAll(id)
		releaseAdmission()
		_ = s.store.UpdateStatus(ctx, id, models.SandboxStatusError, err.Error())
		s.invalidateWarm(id)
		return nil, err
	}

	sandbox.ContainerID = state.ContainerID
	sandbox.ContainerIP = state.ContainerIP
	sandbox.Status = state.Status
	sandbox.WakeArmed = false
	sandbox.UpdatedAt = time.Now().UTC()
	sandbox.LastActiveAt = time.Now().UTC()

	// Reapply the per-IP egress DROP rule. The stop event clears it (the IP
	// can be reassigned to another container), so a Stop+Start cycle would
	// otherwise come back without network isolation. Fail closed: if we can't
	// reinstall the rule, stop the container and surface the error.
	if sandbox.NetworkBlockAll {
		if err := s.docker.ApplyNetworkBlockAll(sandbox.ContainerIP); err != nil {
			_ = s.docker.Stop(ctx, sandboxContainerRef(sandbox))
			_ = s.mounts.UnmountAll(id)
			releaseAdmission()
			_ = s.store.UpdateStatus(ctx, id, models.SandboxStatusError, err.Error())
			return nil, fmt.Errorf("apply network block on start: %w", err)
		}
	}

	if err := s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort, sandboxCustomHostnames(sandbox)); err != nil {
		return nil, err
	}
	for _, port := range sandbox.ExposedPorts {
		if err := s.upsertExposedPortRoute(ctx, sandbox, port); err != nil {
			return nil, err
		}
	}

	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return nil, err
	}
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
		s.warmCacheSet(id)
	}
	return refreshed, nil
}

// StopSandbox is the operator-initiated stop (API surface, manual). It is a
// thin wrapper over stopSandboxInternal that pins the stop mode to manual:
// wake_armed is always cleared, so a serverless sandbox stopped via this
// path stays down until the operator explicitly starts it again.
// See serverless.go for the full wake-arming policy.
func (s *Service) StopSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	return s.stopSandboxInternal(ctx, id, stopModeManual)
}

func (s *Service) DestroySandbox(ctx context.Context, id string) error {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	for _, port := range sandbox.ExposedPorts {
		_ = s.deleteExposedPortRoute(ctx, sandbox, port)
	}
	_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
	if err := s.docker.Destroy(ctx, sandbox); err != nil {
		return err
	}
	if err := s.mounts.UnmountAll(id); err != nil {
		s.logger.Warn("unmount on destroy failed", "sandbox_id", id, "error", err)
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.forgetWakeFlight(id)
	s.invalidateWarm(id)
	s.forgetNetstatsActivity(id)
	if err := s.DeleteClusterSecrets(ctx, id); err != nil {
		return err
	}
	if s.admitter != nil {
		s.admitter.Release(id)
	}
	s.logger.Info("audit sandbox destroyed", "sandbox_id", id, "image", sandbox.Image)
	s.maybeRemoveImage(ctx, sandbox.Image)
	return nil
}

func (s *Service) deleteSelfOwnedClusterPlacement(ctx context.Context, id, reason string) {
	if !s.cfg.EnableCluster || id == "" {
		return
	}
	c := s.Cluster()
	if c == nil {
		return
	}
	owner, err := c.OwnerOf(id)
	if err != nil {
		if !errors.Is(err, cluster.ErrUnknownSandbox) && !errors.Is(err, cluster.ErrOrphaned) {
			s.logger.Warn("cluster placement ownership check before delete failed",
				"sandbox_id", id, "reason", reason, "error", err)
		}
		return
	}
	if !owner.IsSelf {
		return
	}
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.DeletePlacement(commitCtx, id); err != nil {
		s.logger.Warn("cluster placement delete after local destroy failed",
			"sandbox_id", id, "reason", reason, "error", err)
	}
}

// CreateSnapshot commits the sandbox container into a reusable local image.
// Idempotency is by snapshot name: repeated requests for the same sandbox +
// name return the stored snapshot metadata, while a different sandbox trying
// to claim the same name is rejected with a conflict.
func (s *Service) CreateSnapshot(ctx context.Context, sandboxID string, req models.CreateSandboxSnapshotRequest) (*models.SandboxSnapshot, error) {
	snapshot, _, err := s.CreateSnapshotWithOwnership(ctx, sandboxID, req)
	return snapshot, err
}

// RegisterSnapshot persists a snapshot row whose Image was resolved out-of-band
// — either a pre-existing registry image the caller supplied by name, or a
// freshly built local tag produced by the image builder (e.g. the daytona
// facade's buildInfo path). It does NOT call docker.CreateSnapshot; the image
// is assumed to already be runnable. Idempotency is by snapshot name; a
// re-register with matching image is treated as a no-op so SDK retries don't
// fail. A different image under the same name is a conflict.
func (s *Service) RegisterSnapshot(ctx context.Context, snapshot *models.SandboxSnapshot) (*models.SandboxSnapshot, error) {
	if snapshot == nil {
		return nil, errors.New("snapshot is required")
	}
	name := strings.TrimSpace(snapshot.Name)
	if name == "" {
		return nil, errors.New("snapshot name is required")
	}
	if strings.TrimSpace(snapshot.Image) == "" {
		return nil, errors.New("snapshot image is required")
	}
	if err := s.normalizeSnapshotImageDistribution(ctx, snapshot, false); err != nil {
		return nil, err
	}

	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()

	if existing, err := s.store.GetSnapshot(ctx, name); err == nil {
		// Retry semantics: same name + same image → echo back the existing
		// row. Different image under the same name is a conflict.
		if strings.TrimSpace(existing.Image) == strings.TrimSpace(snapshot.Image) {
			return existing, nil
		}
		return nil, store.ErrSnapshotNameConflict
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	if snapshot.CreatedAt.IsZero() {
		snapshot.CreatedAt = time.Now().UTC()
	}
	snapshot.Name = name
	snapshot.PushState = s.initialSnapshotPushState(snapshot)
	if err := s.store.CreateSnapshot(ctx, snapshot); err != nil {
		return nil, err
	}
	s.kickSnapshotPushReconciler(snapshot)
	return snapshot, nil
}

// CreateSnapshotWithOwnership commits a sandbox image and reports whether this
// call created the native snapshot row. Callers that add companion metadata can
// use the flag to avoid rolling back a snapshot that already existed.
func (s *Service) CreateSnapshotWithOwnership(ctx context.Context, sandboxID string, req models.CreateSandboxSnapshotRequest) (*models.SandboxSnapshot, bool, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, false, errors.New("snapshot name is required")
	}

	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()

	if existing, err := s.store.GetSnapshot(ctx, name); err == nil {
		if existing.SourceSandboxID == sandboxID {
			return existing, false, nil
		}
		return nil, false, store.ErrSnapshotNameConflict
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}

	sandbox, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		return nil, false, err
	}

	imageID, err := s.docker.CreateSnapshot(ctx, sandboxContainerRef(sandbox), name)
	if err != nil {
		return nil, false, err
	}

	snapshot := &models.SandboxSnapshot{
		Name:            name,
		Image:           name,
		ImageID:         imageID,
		SourceSandboxID: sandboxID,
		CreatedAt:       time.Now().UTC(),
	}
	if err := s.normalizeSnapshotImageDistribution(ctx, snapshot, true); err != nil {
		return nil, false, err
	}
	snapshot.PushState = s.initialSnapshotPushState(snapshot)
	if err := s.store.CreateSnapshot(ctx, snapshot); err != nil {
		if errors.Is(err, store.ErrSnapshotNameConflict) {
			existing, getErr := s.store.GetSnapshot(ctx, name)
			if getErr == nil && existing.SourceSandboxID == sandboxID {
				return existing, false, nil
			}
		}
		return nil, false, err
	}
	s.kickSnapshotPushReconciler(snapshot)
	return snapshot, true, nil
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

// kickSnapshotPushReconciler runs the reconciler once in a background
// goroutine after a snapshot was just inserted in 'pending' state. This
// is purely a latency optimization — without it, the caller would have
// to wait up to SnapshotPushReconcileInterval before the push begins.
// The reconciler is safe to invoke concurrently; the 'pushing' state
// guards against double-claim.
func (s *Service) kickSnapshotPushReconciler(snapshot *models.SandboxSnapshot) {
	if s.snapshotPushReconciler == nil || snapshot == nil {
		return
	}
	if snapshot.PushState != models.SnapshotPushStatePending {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		if _, err := s.snapshotPushReconciler.RunOnce(ctx); err != nil && s.logger != nil {
			s.logger.Warn("snapshot push: post-create reconciler tick failed",
				"snapshot", snapshot.Name, "error", err)
		}
	}()
}

func (s *Service) GetSnapshot(ctx context.Context, idOrName string) (*models.SandboxSnapshot, error) {
	needle := strings.TrimSpace(idOrName)
	if needle == "" {
		return nil, store.ErrNotFound
	}
	snapshot, err := s.store.GetSnapshot(ctx, needle)
	if err == nil {
		return snapshot, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	snapshots, err := s.store.ListSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	for _, snapshot := range snapshots {
		if snapshot != nil && strings.TrimSpace(snapshot.ImageID) == needle {
			return snapshot, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Service) ListSnapshots(ctx context.Context) ([]*models.SandboxSnapshot, error) {
	return s.store.ListSnapshots(ctx)
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
	if err := s.docker.RemoveImage(ctx, snapshot.Image); err != nil {
		return err
	}
	return s.store.DeleteSnapshot(ctx, snapshot.Name)
}

func (s *Service) ResizeSandbox(ctx context.Context, id string, req models.ResizeSandboxRequest) (*models.Sandbox, error) {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

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

	if err := s.docker.Resize(ctx, sandboxContainerRef(sandbox), req); err != nil {
		// Restore the prior reservation; the resize did not actually take
		// effect on the container, so accounting must reflect the unchanged
		// footprint.
		if s.admitter != nil {
			s.admitter.Reserve(id, capacityRequestFromSandbox(sandbox))
		}
		return nil, err
	}
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
		return nil, err
	}
	// Mirror the resize into the FSM-replicated spec so a future failover
	// recreate uses the post-resize footprint, not the create-time one. Lives
	// in the service layer so v1, Daytona, and E2B all inherit the write-
	// through; previously this was duplicated in the v1 handler and silently
	// missing from the facades.
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

// UpdateLifecycle replaces the lifecycle timers on an existing sandbox.
// Full-replacement semantics: pass zero in any field to clear that timer.
// The sweep picks up the new values on its next tick (within ~1 minute),
// so a tightened deadline can fire as soon as the next sweep runs.
func (s *Service) UpdateLifecycle(ctx context.Context, id string, l models.Lifecycle) (*models.Sandbox, error) {
	if err := s.validateLifecycle(l); err != nil {
		return nil, fmt.Errorf("invalid lifecycle: %w", err)
	}
	priorSandbox, _ := s.store.Get(ctx, id)
	if err := s.store.UpdateLifecycle(ctx, id, l); err != nil {
		return nil, err
	}
	lc := l
	s.replicateSpecPatch(ctx, id, func(spec *models.CreateSandboxRequest) {
		spec.Lifecycle = &lc
	})
	updated, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
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
			if err := s.upsertExposedPortRoute(ctx, updated, port); err != nil {
				if s.logger != nil {
					s.logger.Warn("re-install port route after lifecycle change failed",
						"sandbox_id", id, "port", port.Port, "err", err)
				}
			}
		}
	}
	return updated, nil
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
	return s.exposePort(ctx, id, port, protocol, 0)
}

func (s *Service) exposePort(ctx context.Context, id string, port int, protocol string, preferredHostPort int) (models.ExposePortResponse, error) {
	sandbox, err := s.store.Get(ctx, id)
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
	// IRON RULE (plans/custom-domains.md): a sandbox with custom domains
	// cannot also publish protocol=tcp/tls exposures. The L4 listener is
	// SNI/port-routed only, with no way to honor a host-based match — a
	// shared :443 listener would steer custom-domain traffic to the wrong
	// container. Reject at the entry point rather than letting the L4 path
	// install a half-broken route.
	if (canonicalProto == models.ExposedPortProtocolTCP || canonicalProto == models.ExposedPortProtocolTLS) && hasCustomDomains(sandbox) {
		return models.ExposePortResponse{}, ErrCustomDomainProtocolConflict
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
	switch canonicalProto {
	case models.ExposedPortProtocolHTTP:
		publicURL := s.caddy.PortPublicURL(id, port)
		if err := s.installHTTPPortRoute(ctx, sandbox, port); err != nil {
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
			_ = s.removeHTTPPortRoute(ctx, id, port)
			return models.ExposePortResponse{}, err
		}
		if err := s.recordClusterExposedPort(ctx, id, port, cluster.ExposedPortRoute{Protocol: canonicalProto, PublicURL: publicURL}); err != nil {
			if existingBefore == nil {
				_ = s.removeHTTPPortRoute(ctx, id, port)
				_ = s.store.DeletePort(ctx, id, port)
			}
			return models.ExposePortResponse{}, err
		}
		s.touchAllowedPorts(ctx, id)
		return models.ExposePortResponse{Protocol: canonicalProto, PublicURL: publicURL}, nil

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
			_ = s.caddy.DeleteTCPRoute(ctx, hostPort)
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
	if s.l4Ready.Load() {
		return nil
	}
	s.l4Mu.Lock()
	defer s.l4Mu.Unlock()
	if s.l4Ready.Load() {
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
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	exposure := findExposure(sandbox, port)
	// Best-effort tear-down of every caddy surface the exposure could be on.
	// We dispatch on the recorded protocol when it's known, but also fall
	// back to the legacy HTTP path so old rows that pre-date the protocol
	// column are still cleaned up correctly.
	if exposure == nil {
		_ = s.caddy.DeletePortRoute(ctx, id, port)
	} else {
		if err := s.deleteExposedPortRoute(ctx, sandbox, *exposure); err != nil {
			return err
		}
	}
	if err := s.store.DeletePort(ctx, id, port); err != nil {
		return err
	}
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
		return s.caddy.DeleteTCPRoute(ctx, port.HostPort)
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
func (s *Service) applyHTTPPortRoute(ctx context.Context, sandbox *models.Sandbox, port int) error {
	switch s.chooseRouteShape(sandbox, RouteKindHTTP) {
	case RouteShapeDirect:
		// Non-serverless callers (and serverless-bypass-off callers)
		// fall through to UpsertPortRoute byte-for-byte, so the
		// non-serverless JSON regression test stays valid. Only the
		// warm-bypass path adopts the retry window.
		if s.serverlessWakeEnabled(sandbox) && s.cfg.HTTPWakeDirectBypassEnabled {
			if err := s.caddy.UpsertPortRouteWithRetry(ctx, sandbox.ID, sandbox.ContainerIP, port, s.cfg.HTTPWakeDirectRouteRetryDuration); err != nil {
				return err
			}
		} else {
			if err := s.caddy.UpsertPortRoute(ctx, sandbox.ID, sandbox.ContainerIP, port); err != nil {
				return err
			}
		}
		// Best-effort: any leftover wake route from a prior
		// Stopped+armed state (or a flag flip back to bypass-on) must
		// go so Caddy doesn't keep two routes matching the same host.
		// DeleteWakeHTTPPortRoute treats 404 as success.
		_ = s.caddy.DeleteWakeHTTPPortRoute(ctx, sandbox.ID, port)
		return nil
	case RouteShapeWake:
		if err := s.caddy.UpsertWakeHTTPPortRoute(ctx, sandbox.ID, s.cfg.InternalIngressAddr, port); err != nil {
			return err
		}
		_ = s.caddy.DeletePortRoute(ctx, sandbox.ID, port)
		return nil
	case RouteShapeNone:
		// Destroyed sandboxes or stopped-unarmed serverless sandboxes
		// publish neither route. Idempotent deletes; either or both
		// may already be absent.
		_ = s.caddy.DeletePortRoute(ctx, sandbox.ID, port)
		_ = s.caddy.DeleteWakeHTTPPortRoute(ctx, sandbox.ID, port)
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
	switch s.chooseRouteShape(sandbox, RouteKindL4) {
	case RouteShapeDirect:
		return s.caddy.UpsertTCPRoute(ctx, sandbox.ID, sandbox.ContainerIP, port, hostPort)
	case RouteShapeWake:
		return s.caddy.UpsertWakeTCPRoute(ctx, sandbox.ID, port, hostPort, s.cfg.InternalL4WakeAddr)
	case RouteShapeNone:
		return s.caddy.DeleteTCPRoute(ctx, hostPort)
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
	if err := s.caddy.DeletePortRoute(ctx, id, port); err != nil {
		return err
	}
	if err := s.caddy.DeleteWakeHTTPPortRoute(ctx, id, port); err != nil {
		return err
	}
	return nil
}

// touchAllowedPorts is a small wrapper that refreshes the toolbox's allowlist
// after a port-table mutation. The store round-trip pulls the fresh ExposedPorts
// so syncAllowedPorts sees post-write state.
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
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return ToolboxEndpoint{}, err
	}
	if sandbox.ContainerIP == "" {
		return ToolboxEndpoint{}, errors.New("sandbox container IP is not available")
	}
	return ToolboxEndpoint{
		URL:   fmt.Sprintf("http://%s:%d", sandbox.ContainerIP, s.cfg.ToolboxPort),
		Token: sandbox.ToolboxToken,
	}, nil
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
	if sandbox.ContainerIP == "" {
		return PortEndpoint{}, errors.New("sandbox container IP is not available")
	}
	exposure := findExposure(sandbox, port)
	if exposure == nil || (exposure.Protocol != "" && exposure.Protocol != models.ExposedPortProtocolHTTP) {
		return PortEndpoint{}, fmt.Errorf("sandbox %s does not expose HTTP port %d", id, port)
	}
	return PortEndpoint{URL: fmt.Sprintf("http://%s:%d", sandbox.ContainerIP, port)}, nil
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
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return false, err
	}
	started := sb.Status == models.SandboxStatusStarted
	if started {
		s.warmCacheSet(id)
	}
	return started, nil
}

// warmCacheTTL is intentionally short (2s) so an entirely-missed
// invalidation self-heals fast. The explicit invalidation hooks below
// keep the normal staleness window sub-second; the TTL is the backstop
// for the pathological case where an invalidation never fires.
const warmCacheTTL = 2 * time.Second

func (s *Service) warmCacheHit(id string) bool {
	s.warmCacheMu.RLock()
	exp, ok := s.warmCache[id]
	s.warmCacheMu.RUnlock()
	if !ok {
		return false
	}
	return time.Now().UnixNano() < exp
}

func (s *Service) warmCacheSet(id string) {
	exp := time.Now().Add(warmCacheTTL).UnixNano()
	s.warmCacheMu.Lock()
	if s.warmCache == nil {
		s.warmCache = make(map[string]int64)
	}
	s.warmCache[id] = exp
	s.warmCacheMu.Unlock()
}

// invalidateWarm drops id from the warm cache. Called from every state
// transition that takes a sandbox out of Started: StartSandbox failure
// paths, every stop path (manual, lifecycle, involuntary die/oom), and
// every destroy path. Safe on a missing key.
func (s *Service) invalidateWarm(id string) {
	s.warmCacheMu.Lock()
	delete(s.warmCache, id)
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
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		return models.HealthStatus{}, err
	}

	live := 0
	for _, sandbox := range sandboxes {
		if sandbox.Status != models.SandboxStatusDestroyed {
			live++
		}
	}

	dockerStatus := "ok"
	if err := s.docker.Ping(ctx); err != nil {
		dockerStatus = err.Error()
	}

	caddyStatus := "ok"
	if err := s.caddy.Ping(ctx); err != nil {
		caddyStatus = err.Error()
	}

	// "disabled" is distinct from "ok" / failure — it tells the operator
	// "we didn't probe this on purpose" rather than masking a real fault.
	sshStatus := "disabled"
	if s.cfg.EnableSSHGateway {
		if err := probeSSHGateway(ctx, s.cfg.SSHListenAddr); err != nil {
			sshStatus = err.Error()
		} else {
			sshStatus = "ok"
		}
	}

	status := "ok"
	if dockerStatus != "ok" || caddyStatus != "ok" {
		status = "degraded"
	}
	// SSH gateway being down only degrades health when it's expected to be up.
	if s.cfg.EnableSSHGateway && sshStatus != "ok" {
		status = "degraded"
	}

	clusterTopology := ""
	clusterNodes := 0
	if s.cfg.EnableCluster {
		clusterTopology = "ok"
		if c := s.Cluster(); c != nil {
			members := c.Members()
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
		SSHGateway:      sshStatus,
		ClusterTopology: clusterTopology,
		ClusterNodes:    clusterNodes,
		Version:         version.Version,
	}, nil
}

// Capacity returns the admitter's current snapshot. Returns the zero value
// when no admitter is configured (e.g. in tests).
func (s *Service) Capacity() capacity.Snapshot {
	if s.admitter == nil {
		return capacity.Snapshot{CanAdmit: true}
	}
	return s.admitter.Snapshot()
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
	// Topology heartbeat: surface a cluster that has crossed the
	// 10-ingress-node sharding threshold without operator opt-in to
	// SB_CLUSTER_SHARD_AWARE_INGRESS. /health also reports this, but the
	// reconcile log line makes it visible to anyone reading sandboxd logs
	// (no metrics scrape required) and repeats on every cycle until fixed,
	// which is the desired loud signal — sharded ingress + naive LB silently
	// black-holes ~(N-1)/N of public traffic.
	if s.cfg.EnableCluster {
		if c := s.Cluster(); c != nil {
			if err := s.clusterTopologyErrorFor(c.Members()); err != nil {
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

	known, err := s.store.List(ctx)
	if err != nil {
		return err
	}

	managed, err := s.docker.ListManaged(ctx)
	if err != nil {
		return err
	}

	s.reconcileLocalClusterOwnership(ctx, known, managed)

	knownIDs := make(map[string]struct{}, len(known))
	for _, sandbox := range known {
		knownIDs[sandbox.ID] = struct{}{}
	}
	s.reconcileMissingSelfOwnedPlacements(ctx, knownIDs)

	for _, sandbox := range known {
		state, ok := managed[sandbox.ID]
		if !ok {
			// Container is gone (manual `docker rm`, OOM kill, host reboot,
			// previous reconcile pass already destroyed it via events). Tear
			// down all our state and delete the row outright. Cascades through
			// exposed_ports, immediately freeing any reserved host_port back
			// to the L4 allocator pool — the partial unique index on
			// host_port doesn't filter by sandbox status, so a destroyed-but-
			// retained row would otherwise hold its host_port slot forever.
			//
			// docker.Destroy is intentionally skipped: the container is the
			// reason we're in this branch. Caddy / mounts / admitter / image
			// cleanup is best-effort and mirrors DestroySandbox's order;
			// failures here are picked up by gcZombieCaddyEntries on a later
			// pass and by the mounts.Sweep at the end of Reconcile.
			_ = s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)
			for _, port := range sandbox.ExposedPorts {
				_ = s.deleteExposedPortRoute(ctx, sandbox, port)
			}
			if err := s.mounts.UnmountAll(sandbox.ID); err != nil {
				s.logger.Warn("reconcile destroyed unmount failed", "sandbox_id", sandbox.ID, "error", err)
			}
			// store.Delete must happen BEFORE maybeRemoveImage: HasActiveImageRef
			// queries the sandboxes table and treats any non-destroyed row as a
			// live reference. While our row still exists with its pre-destroy
			// status (typically "started"), the image GC would always skip,
			// leaking image layers across reconcile cycles.
			if err := s.store.Delete(ctx, sandbox.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			s.forgetWakeFlight(sandbox.ID)
			s.invalidateWarm(sandbox.ID)
			s.forgetNetstatsActivity(sandbox.ID)
			if s.admitter != nil {
				s.admitter.Release(sandbox.ID)
			}
			s.deleteSelfOwnedClusterPlacement(ctx, sandbox.ID, "reconcile-destroyed")
			s.maybeRemoveImage(ctx, sandbox.Image)
			s.logger.Info("audit reconcile destroyed",
				"sandbox_id", sandbox.ID,
				"image", sandbox.Image,
			)
			continue
		}

		sandbox.ContainerID = state.ContainerID
		sandbox.ContainerIP = state.ContainerIP
		sandbox.Status = state.Status
		sandbox.PublicURL = s.caddy.SandboxPublicURL(sandbox.ID)
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
		if state.Status == models.SandboxStatusStarted {
			sandbox.WakeArmed = false
			// Heal the per-IP egress DROP rule for sandboxes opted into
			// NetworkBlockAll. Idempotent at the netrules layer (Exists check
			// before insert), so this is safe to run on every reconcile pass.
			// Catches host-side state loss: iptables flush, daemon restart
			// rebuilding chains, or a missed Create/Start install.
			if sandbox.NetworkBlockAll {
				if err := s.docker.ApplyNetworkBlockAll(sandbox.ContainerIP); err != nil {
					s.logger.Warn("reconcile reapply network block failed",
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
			if err := s.caddy.UpsertSandboxRoute(ctx, sandbox.ID, sandbox.ContainerIP, s.cfg.ToolboxPort, sandboxCustomHostnames(sandbox)); err != nil {
				return err
			}
			for _, port := range sandbox.ExposedPorts {
				if err := s.upsertExposedPortRoute(ctx, sandbox, port); err != nil {
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
		if err := s.store.Upsert(ctx, sandbox); err != nil {
			return err
		}
	}

	// Orphan containers: managed by us but no DB row. Remove them so leaked
	// state from a crashed create or a wiped DB doesn't accumulate.
	for sandboxID, state := range managed {
		if _, ok := knownIDs[sandboxID]; ok {
			continue
		}
		s.logger.Warn("removing orphan container",
			"sandbox_id", sandboxID,
			"container_id", state.ContainerID,
		)
		stub := &models.Sandbox{ContainerID: state.ContainerID, ContainerIP: state.ContainerIP}
		if err := s.docker.Destroy(ctx, stub); err != nil {
			s.logger.Warn("orphan container removal failed",
				"sandbox_id", sandboxID,
				"error", err,
			)
		}
		_ = s.caddy.DeleteSandboxRoute(ctx, sandboxID)
		_ = s.mounts.UnmountAll(sandboxID)
	}

	// Zombie caddy entry sweep. The destroyed-sandbox loop above already
	// drops routes for sandboxes that exist in the DB but lost their
	// container — this catches the orthogonal case where caddy holds an
	// entry for a sandbox row that was deleted out-of-band (DB wipe,
	// manual surgery) and no destroy ran. Without this, caddy accumulates
	// dead routes forever.
	s.gcZombieCaddyEntries(ctx, known)

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
	s.mounts.Sweep(keep)

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
	for _, p := range c.Placements() {
		if p.SandboxID == "" || p.OwnerNodeID != self || p.IsReserved() || p.IsOrphaned() {
			continue
		}
		if _, ok := knownIDs[p.SandboxID]; ok {
			continue
		}
		if spec := c.SpecOf(p.SandboxID); spec != nil && spec.ShouldRecreateOnFailover() {
			continue
		}
		s.deleteSelfOwnedClusterPlacement(ctx, p.SandboxID, "missing-local-row")
	}
}

// StartLifecycleSweep launches the per-sandbox lifecycle ticker. Every minute
// it evaluates each sandbox's Lifecycle timers (StopIfIdleFor / DestroyIfIdleFor
// / StopAtAge / DestroyAtAge) plus the legacy global SB_IDLE_TIMEOUT_MIN
// fallback for sandboxes that don't declare any per-sandbox timers. Without
// either configured, the sweep still runs but is a no-op — kept on so a
// later UpdateLifecycle call doesn't need to start a goroutine.
func (s *Service) StartLifecycleSweep(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				s.runLifecycleSweep(sweepCtx)
				cancel()
			}
		}
	}()
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
	for _, sandbox := range sandboxes {
		floor := s.activityFloorFor(sandbox, netstatsFallback)
		switch lifecycleActionForWithFloor(sandbox, now, globalIdle, floor) {
		case lifecycleDestroy:
			if err := s.DestroySandbox(ctx, sandbox.ID); err != nil {
				s.logger.Warn("auto-destroy failed", "sandbox_id", sandbox.ID, "error", err)
			} else {
				s.deleteSelfOwnedClusterPlacement(ctx, sandbox.ID, "lifecycle-auto-destroy")
				s.logger.Info("audit lifecycle auto-destroy", "sandbox_id", sandbox.ID)
			}
		case lifecycleStop:
			// Lifecycle stop: pass mode=stopModeLifecycle so serverless
			// sandboxes arm wake (the next inbound HTTP request will
			// resurrect the sandbox transparently).
			if _, err := s.stopSandboxInternal(ctx, sandbox.ID, stopModeLifecycle); err != nil {
				s.logger.Warn("auto-stop failed", "sandbox_id", sandbox.ID, "error", err)
			} else {
				s.logger.Info("audit lifecycle auto-stop",
					formatStopAuditFields(sandbox.ID, stopModeLifecycle, s.shouldArmWake(sandbox, stopModeLifecycle))...)
			}
		}
	}
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
	if sb == nil || sb.Status == models.SandboxStatusDestroyed {
		return lifecycleNone
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
		return lifecycleDestroy
	}
	if l.DestroyAtAge > 0 && age >= l.DestroyAtAge {
		return lifecycleDestroy
	}
	// Stop only applies to running sandboxes — re-stopping a stopped one
	// is wasted Docker calls and noisy logs.
	if sb.Status != models.SandboxStatusStarted {
		return lifecycleNone
	}
	if l.StopIfIdleFor > 0 && idle >= l.StopIfIdleFor {
		return lifecycleStop
	}
	if l.StopAtAge > 0 && age >= l.StopAtAge {
		return lifecycleStop
	}
	// Legacy global idle fallback: only applies when the sandbox has no
	// per-sandbox config, so an explicit "no auto-stop" Lifecycle (e.g.
	// just DestroyAtAge=24h with stop fields zero) doesn't accidentally
	// inherit the operator's global timeout.
	if l.IsZero() && globalIdle > 0 && idle >= globalIdle {
		return lifecycleStop
	}
	return lifecycleNone
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
func (s *Service) gcZombieCaddyEntries(ctx context.Context, sandboxes []*models.Sandbox) {
	if !s.caddy.Enabled() {
		return
	}
	snap, err := s.caddy.Snapshot(ctx)
	if err != nil {
		s.logger.Warn("caddy snapshot for zombie gc failed", "error", err)
		return
	}

	expectedHTTP := make(map[string]struct{})
	expectedTCPServers := make(map[string]struct{})
	expectedTLSRoutes := make(map[string]struct{})

	for _, sb := range sandboxes {
		if sb == nil || sb.Status == models.SandboxStatusDestroyed {
			continue
		}
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
				expectedHTTP[fmt.Sprintf("sandbox-%s-port-%d", sb.ID, p.Port)] = struct{}{}
				if isServerless {
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
	}
	s.addClusterIngressExpectedRoutes(expectedHTTP, expectedTCPServers, expectedTLSRoutes)

	for _, id := range snap.HTTPRouteIDs {
		if _, ok := expectedHTTP[id]; ok {
			continue
		}
		if err := s.caddy.DeleteRouteByID(ctx, id); err != nil {
			s.logger.Warn("zombie http route delete failed", "route_id", id, "error", err)
			continue
		}
		s.logger.Info("audit zombie http route removed", "route_id", id)
	}
	for _, sid := range snap.L4TCPServerIDs {
		if _, ok := expectedTCPServers[sid]; ok {
			continue
		}
		if err := s.caddy.DeleteTCPServer(ctx, sid); err != nil {
			s.logger.Warn("zombie tcp server delete failed", "server_id", sid, "error", err)
			continue
		}
		s.logger.Info("audit zombie tcp server removed", "server_id", sid)
	}
	for _, id := range snap.L4TLSRouteIDs {
		if _, ok := expectedTLSRoutes[id]; ok {
			continue
		}
		if err := s.caddy.DeleteRouteByID(ctx, id); err != nil {
			s.logger.Warn("zombie tls route delete failed", "route_id", id, "error", err)
			continue
		}
		s.logger.Info("audit zombie tls route removed", "route_id", id)
	}
}

func (s *Service) addClusterIngressExpectedRoutes(expectedHTTP, expectedTCPServers, expectedTLSRoutes map[string]struct{}) {
	if !s.cfg.EnableCluster {
		return
	}
	c := s.Cluster()
	if c == nil {
		return
	}
	self := c.SelfNodeID()
	for _, p := range c.PlacementsForShards(clusterIngressShardFilter(c, self)) {
		if p.SandboxID == "" || p.OwnerNodeID == self {
			continue
		}
		// Orphaned placement: the in-flux 503 routes are the expected
		// state. Keep them; the live routes are intentionally absent.
		if p.OwnerNodeID == "" {
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
	interval := s.cfg.ImageBuildGCInterval
	if interval <= 0 {
		return
	}
	if s.events == nil {
		s.logger.Warn("built-image GC disabled: docker events client is nil")
		return
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				s.runBuiltImageGC(sweepCtx, s.events.ListBuiltImages)
				cancel()
			}
		}
	}()
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

func (s *Service) StartReconcileLoop(ctx context.Context) {
	interval := s.cfg.ReconcileInterval
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reconcileCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				if err := s.Reconcile(reconcileCtx); err != nil {
					s.logger.Warn("periodic reconcile failed", "error", err)
				}
				cancel()
			}
		}
	}()
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
	// In single-node mode (Noop) the channel is nil; selecting on nil is
	// permanently un-ready, so the loop falls back to the slow timer.
	wake := s.Cluster().SubscribePlacement(ctx)
	go func() {
		for {
			reconcileCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := s.ReconcileClusterIngress(reconcileCtx); err != nil {
				s.logger.Warn("cluster ingress reconcile failed", "error", err)
			}
			cancel()

			t := time.NewTimer(clusterIngressReconcileInterval)
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
	c := s.Cluster()
	if c == nil {
		return nil
	}
	self := c.SelfNodeID()
	if self == "" {
		return nil
	}
	shardFilter := clusterIngressShardFilter(c, self)
	placements := c.PlacementsForShards(shardFilter)

	// Idle-skip: hash the relevant slice of the placement view. If nothing
	// changed since the last successful reconcile, return without touching
	// Caddy admin. At 10K placements this drops a 2K-route-write tick to a
	// single hash() and a few atomic loads. The hash key includes
	// Version, so any FSM-level placement change forces a recompute.
	start := time.Now()
	viewHash, routeCounts, maxVersion := hashPlacementView(self, placements)
	runFullGC := s.shouldRunClusterIngressFullGC()
	if viewHash == s.ingressLastHash.Load() && viewHash != 0 && !runFullGC {
		recordIngressReconcile(reconcileSkipped, time.Since(start), routeCounts, maxVersion)
		return nil
	}

	var firstErr error
	desired, needL4 := s.buildClusterIngressIntents(placements, self)
	if needL4 {
		if err := s.EnsureLayer4Ready(ctx); err != nil {
			return err
		}
	}

	ops, commitDelta := s.planClusterIngressDelta(desired)
	if err := runIngressOpsBatched(ctx, ops, clusterIngressMaxConcurrentWrites, clusterIngressBatchSize); err != nil {
		firstErr = err
	}
	if runFullGC {
		if err := s.gcUnexpectedClusterIngressRoutes(ctx, desired); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		commitDelta()
	}
	if firstErr == nil {
		s.logger.Debug("cluster ingress reconcile applied",
			"placement_shards", routeShardFilterLogValue(shardFilter),
			"routes", len(desired),
			"ops", len(ops),
			"full_gc", runFullGC,
		)
	}
	// Stash the hash only on full success — partial failures must retry next
	// tick rather than wedging the idle-skip on a stale view.
	if firstErr == nil {
		s.ingressLastHash.Store(viewHash)
		recordIngressReconcile(reconcileApplied, time.Since(start), routeCounts, maxVersion)
	} else {
		s.ingressLastHash.Store(0)
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
		if err := s.caddy.DeleteSandboxRoute(ctx, p.SandboxID); err != nil {
			firstErr = err
		}
	} else {
		if err := s.caddy.DeleteRouteByID(ctx, caddy.IngressSandboxSNIRouteID(p.SandboxID)); err != nil {
			firstErr = err
		}
	}
	if err := s.caddy.UpsertInFluxSandboxRoute(ctx, p.SandboxID); err != nil && firstErr == nil {
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
			if err := s.caddy.DeleteRouteByID(ctx, caddy.PortRouteID(p.SandboxID, port)); err != nil && firstErr == nil {
				firstErr = err
			}
		} else {
			if err := s.caddy.DeleteRouteByID(ctx, caddy.IngressPortSNIRouteID(p.SandboxID, port)); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := s.caddy.UpsertInFluxPortRoute(ctx, p.SandboxID, port); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Service) gcClusterIngressRoutes(ctx context.Context) error {
	known, err := s.store.List(ctx)
	if err != nil {
		return fmt.Errorf("cluster ingress gc list sandboxes: %w", err)
	}
	s.gcZombieCaddyEntries(ctx, known)
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
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// GenerateSandboxID is the exported entry point for the cluster handler's
// reservation-first create path: the router (Node A) needs to mint a sandbox
// ID before opReserve so the chosen target (Node T) can accept the forward
// with X-Cluster-Create-ID and run CreateSandboxWithID against the same
// reservation. Routes through the package-private generateSandboxID so the
// format stays in lockstep with the local create path.
func GenerateSandboxID() (string, error) { return generateSandboxID() }

// generateSandboxID returns a 16-hex-char sandbox identifier. It is used as
// both the daemon's primary key for the sandbox and the Docker container's
// name, so it must satisfy Docker's name restrictions ([a-zA-Z0-9_.-]).
func generateSandboxID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "sb-" + hex.EncodeToString(buf), nil
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

// maybeRemoveImage deletes the given image from Docker if no non-destroyed
// sandbox still references it. Best-effort: store and Docker errors are
// logged, never returned, because image GC must not block the sandbox
// lifecycle path that called us. Uses Store.HasActiveImageRef so the cost
// is one indexed query rather than a full table scan, even when there are
// 10k+ destroyed rows in history.
func (s *Service) maybeRemoveImage(ctx context.Context, image string) {
	if image == "" {
		return
	}
	stillUsed, err := s.store.HasActiveImageRef(ctx, image)
	if err != nil {
		s.logger.Warn("image gc reference check failed", "image", image, "error", err)
		return
	}
	if stillUsed {
		return
	}
	if err := s.docker.RemoveImage(ctx, image); err != nil {
		s.logger.Warn("image gc remove failed", "image", image, "error", err)
		return
	}
	s.logger.Info("audit image removed", "image", image)
}

// syncAllowedPorts pushes the sandbox's current set of exposed ports to
// toolboxd's in-memory allowlist. Best-effort — logged on failure. Without
// this, /proxy/<port>/ on the public sandbox URL refuses every request.
func (s *Service) syncAllowedPorts(ctx context.Context, sandbox *models.Sandbox) {
	if sandbox == nil || sandbox.Status != models.SandboxStatusStarted || sandbox.ContainerIP == "" {
		return
	}
	ports := make([]int, 0, len(sandbox.ExposedPorts))
	for _, p := range sandbox.ExposedPorts {
		ports = append(ports, p.Port)
	}
	if err := s.docker.PushAllowedPorts(ctx, sandbox.ContainerIP, sandbox.ToolboxToken, ports); err != nil {
		s.logger.Warn("failed to sync allowed ports", "sandbox_id", sandbox.ID, "error", err)
	}
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
