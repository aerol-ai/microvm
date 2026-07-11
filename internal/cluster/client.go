package cluster

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/google/uuid"
	"github.com/hashicorp/raft"
)

// Cluster is the multi-node Client implementation. Construct with New.
type Cluster struct {
	cfg           config.Config
	logger        *slog.Logger
	nodeID        string
	apiURL        string
	dataPlaneHost string

	fsm    *placementFSM
	raft   *raftNode
	gossip *gossipNode

	// patToken authenticates leader-forwarded raft applies. Sourced from
	// cfg.PATToken at construction; same value every node already shares for
	// regular API auth, so no new secret-distribution surface. With mTLS
	// enabled the PAT is belt-and-braces — the TLS handshake already proved
	// cluster membership — but we keep sending it so the receiving handler can
	// stay symmetric with the public endpoint and so a node that briefly loses
	// its TLS material can fall back without breaking auth.
	patToken   string
	httpClient *http.Client
	// internalURL is this node's cluster-internal mTLS advertise URL (e.g.
	// https://10.0.0.5:7002). Empty when running without SB_CLUSTER_TLS_DIR.
	// Gossiped to peers so leader-forward can prefer the mTLS channel over
	// the public API URL.
	internalURL string
	// tls holds the loaded cluster CA + node keypair used by both the raft
	// transport (via raftSetupConfig.TLS) and the internal HTTPS listener.
	// nil when SB_CLUSTER_TLS_DIR is unset — that's the legacy plaintext path
	// for operators on a fully isolated network.
	tls *ClusterTLS
	// internalServer is the mTLS HTTPS listener that accepts leader-forwarded
	// raft applies from peers. nil when tls is nil. Owned by Close.
	internalServer *internalServer
	// internalClient is an HTTPS client preconfigured with the cluster CA +
	// our node cert. Used to dial peers' InternalURL when both sides have
	// TLS material. nil when tls is nil.
	internalClient *http.Client
	// publicProxies caches httputil.ReverseProxy instances keyed on peer
	// APIURL (the legacy public-API path). Shared across forwarded requests
	// so the underlying transport's connection pool isn't rebuilt per call.
	publicProxies *proxyCache
	// mtlsProxies caches httputil.ReverseProxy instances keyed on peer
	// InternalURL. Each proxy rides an mTLS transport configured with the
	// cluster CA + this node's cert. nil when tls is nil — owner forwarding
	// then falls back to publicProxies + PAT auth.
	mtlsProxies *proxyCache

	commitTimeout time.Duration

	// voterReconcileStop cancels the auto-voter reconcile goroutine on Close.
	voterReconcileStop context.CancelFunc

	// deadOwners tracks per-node "first observed dead" timestamps for the
	// dead-owner reconciler. Lives on the cluster (not in dead_owner.go) so
	// Close can stop its loop. See dead_owner.go for the reconciler logic.
	deadOwners        *deadOwnerTracker
	deadOwnerLoopStop context.CancelFunc

	// reservationGCStop cancels the leader-only sweep that cancels expired
	// opReserve rows. Followers run no loop because every CancelReservation
	// has to land via raft anyway. See dead_owner.go for the loop body.
	reservationGCStop context.CancelFunc
	// capacityLeases holds authenticated worker capacity heartbeats used by
	// SelectPlacement. Gossip carries identity only; placement requires a
	// fresh lease before a worker can receive new sandboxes.
	capacityLeases    *capacityLeaseCache
	capacityLeaseStop context.CancelFunc
	// reservationAdmissionMu serializes leader-side reservation admission.
	// Capacity leases are outside the Raft FSM, so the leader must check
	// target capacity + per-worker pending caps under one queue before
	// appending opReserve/opReserveBatch. Otherwise two routers can both
	// validate against the same pending snapshot and overfill a worker.
	reservationAdmissionMu sync.Mutex

	// recreator is the service-layer hook the owner watcher uses to bring up
	// a sandbox the FSM says we own but the local store doesn't have. Set via
	// AttachRecreator after construction (avoids a cluster→service import
	// cycle). nil disables the watcher's effect — the loop still runs.
	recreator        SandboxRecreator
	recreatorMu      sync.Mutex
	ownerWatcherStop context.CancelFunc
	// recreateFailures counts consecutive recreate failures per sandbox so
	// the watcher can escalate to "ask for reassignment" instead of looping
	// forever on a permanent local failure (image gone, runtime missing,
	// disk full). Initialized in startOwnerWatcher.
	recreateFailures *recreateFailureTracker
}

// New constructs the server-role Cluster for cfg.EnableCluster=true. Caller
// takes ownership of Close. For worker/ingress-only roles call NewAgent; for
// cfg.EnableCluster=false call NewNoop.
func New(cfg config.Config, logger *slog.Logger, admitter *capacity.Admitter) (*Cluster, error) {
	if !cfg.EnableCluster {
		return nil, errors.New("cluster.New: cfg.EnableCluster is false; use NewNoop")
	}
	if !cfg.IsServer() {
		return nil, fmt.Errorf("cluster.New: SB_NODE_ROLE=%q is not a server role; use NewAgent for worker/ingress nodes", cfg.NodeRole)
	}

	nodeID := cfg.NodeID
	if nodeID == "" {
		// Stable-per-boot ID. Persisting nodeID across restarts is a Phase 2
		// concern — for Phase 1 we require operators to set SB_NODE_ID to a
		// stable value (the validator nudges them). A random ID still works
		// but will accumulate ghost members in raft config until pruned.
		nodeID = "node-" + uuid.NewString()[:8]
	}

	if cfg.SelfAPIAdvertiseURL == "" {
		return nil, errors.New("cluster.New: SelfAPIAdvertiseURL required in cluster mode")
	}

	fsm, err := newPlacementFSMWithFileRecovery(cfg.RaftDataDir)
	if err != nil {
		return nil, fmt.Errorf("cluster.New: recovery store: %w", err)
	}

	// Load cluster TLS material first — both raft transport and the internal
	// HTTPS listener need it. Empty SB_CLUSTER_TLS_DIR keeps the legacy
	// plaintext path for operators on a fully isolated network.
	clusterTLS, err := loadClusterTLS(cfg.ClusterTLSDir)
	if err != nil {
		return nil, fmt.Errorf("cluster.New: load tls: %w", err)
	}

	rn, err := setupRaft(raftSetupConfig{
		NodeID:           nodeID,
		BindAddr:         cfg.RaftBindAddr,
		AdvertiseAddr:    cfg.RaftAdvertiseAddr,
		DataDir:          cfg.RaftDataDir,
		BootstrapCluster: cfg.ClusterBootstrap,
		TLS:              clusterTLS,
	}, fsm, logger)
	if err != nil {
		return nil, fmt.Errorf("cluster.New: raft: %w", err)
	}

	commitTimeout := cfg.ClusterRaftCommitTimeout
	if commitTimeout <= 0 {
		commitTimeout = 5 * time.Second
	}

	c := &Cluster{
		cfg:           cfg,
		logger:        logger,
		nodeID:        nodeID,
		apiURL:        cfg.SelfAPIAdvertiseURL,
		dataPlaneHost: cfg.DataPlaneAdvertiseHost,
		fsm:           fsm,
		raft:          rn,
		patToken:      cfg.PATToken,
		httpClient:    &http.Client{Timeout: commitTimeout + 2*time.Second},
		commitTimeout: commitTimeout,
		deadOwners:    newDeadOwnerTracker(),
		tls:           clusterTLS,
		publicProxies: newProxyCache(defaultPublicTransport),
	}
	fsm.recoveryResolver = c.fetchRecoveryBlob

	// Build the cluster-internal HTTPS client + listener when TLS is loaded.
	// Both ride on the same CA + node keypair as raft, so a peer's cert can
	// fail handshake in exactly one way (chain mismatch) regardless of which
	// channel they hit.
	if clusterTLS != nil {
		c.internalClient = &http.Client{
			Timeout:   commitTimeout + 2*time.Second,
			Transport: newInternalTransport(clusterTLS.clientConfig()),
		}
		c.mtlsProxies = newProxyCache(newMTLSProxyTransport(clusterTLS.clientConfig()))
		is, err := startInternalServer(cfg.ClusterInternalListenAddr, clusterTLS, c.ApplyEncoded, logger)
		if err != nil {
			_ = rn.Close()
			return nil, fmt.Errorf("cluster.New: internal server: %w", err)
		}
		c.internalServer = is
		c.internalURL = deriveInternalAdvertiseURL(cfg.ClusterInternalAdvertiseURL, cfg.ClusterInternalListenAddr, is.Addr())
	}

	// Carry the raft transport's *advertise* address (post-resolution) so peers
	// can reach us. Falls back to the configured bind address if advertise
	// wasn't set explicitly.
	raftAdvertise := cfg.RaftAdvertiseAddr
	if raftAdvertise == "" {
		raftAdvertise = cfg.RaftBindAddr
	}
	if rn.transport != nil {
		raftAdvertise = string(rn.transport.LocalAddr())
	}

	secretKey, err := decodeGossipSecretKey(cfg.ClusterGossipSecretKey)
	if err != nil {
		_ = rn.Close()
		return nil, fmt.Errorf("cluster.New: %w", err)
	}
	if len(secretKey) == 0 {
		// Plaintext gossip is allowed only via the explicit SB_CLUSTER_INSECURE_GOSSIP
		// escape hatch (config.Load enforces this). Still loud-warn here so the
		// boot log shows the deviation from the secure default.
		logger.Warn("cluster: gossip is unencrypted (SB_CLUSTER_INSECURE_GOSSIP=true); voter auto-promotion will admit any reachable peer — keep raft+gossip ports on a private network")
	}

	gn, err := setupGossip(gossipSetupConfig{
		NodeID:         nodeID,
		NodeName:       cfg.NodeName,
		BindAddr:       cfg.GossipBindAddr,
		AdvertiseAddr:  cfg.GossipAdvertiseAddr,
		APIURL:         cfg.SelfAPIAdvertiseURL,
		DataPlaneHost:  cfg.DataPlaneAdvertiseHost,
		RaftAddr:       raftAdvertise,
		InternalURL:    c.internalURL,
		Role:           cfg.NodeRole,
		PublicHost:     cfg.EffectivePublicHost(),
		BootstrapPeers: cfg.BootstrapPeers,
		GossipInterval: cfg.ClusterCapacityGossipInterval,
		SecretKey:      secretKey,
		Events:         &voterAutoJoinDelegate{c: c},
	}, admitter, logger)
	if err != nil {
		if c.internalServer != nil {
			_ = c.internalServer.Close()
		}
		_ = rn.Close()
		return nil, fmt.Errorf("cluster.New: gossip: %w", err)
	}
	c.gossip = gn
	c.capacityLeases = newCapacityLeaseCache(c.nodeID, admitter, cfg.ClusterCapacityGossipInterval, logger)
	c.startCapacityLeaseLoop(cfg.ClusterCapacityGossipInterval)

	// Slow reconcile loop: catches the "joined too fast" race where the
	// memberlist event fires before the joiner's nodeMeta has propagated. The
	// loop is no-op when self isn't leader.
	c.startVoterReconcileLoop()

	// Dead-owner reconciler: the leader periodically checks for nodes whose
	// gossip-leave grace period has expired and orphans their placements +
	// removes them from the raft configuration. Followers maintain the
	// in-memory tracker (cheap) but never act.
	c.startDeadOwnerLoop()

	// Reservation GC: leader-only sweep that cancels opReserve rows whose
	// 120s TTL has elapsed (target node never promoted via opPlace, e.g.
	// crashed mid-create or the forward never landed). Without this, dead
	// reservations leak headroom from SelectPlacement scoring forever.
	c.startReservationGCLoop()

	// Owner watcher: every node polls the FSM for placements pointing to self
	// that have no local sandbox row, and re-materializes them via the
	// service recreate hook. This is the consume side of the spec-replication
	// pipeline written by RecordPlacement / UpsertSpec.
	c.startOwnerWatcher()

	return c, nil
}

func (c *Cluster) SelfNodeID() string { return c.nodeID }
func (c *Cluster) SelfAPIURL() string { return c.apiURL }

// AttachRecreator wires the service-layer recreate hook used by the owner
// watcher. Called once from cmd/sandboxd/main after both service.New and
// cluster.New have returned. Safe to call concurrently with the watcher loop.
func (c *Cluster) AttachRecreator(r SandboxRecreator) {
	c.recreatorMu.Lock()
	defer c.recreatorMu.Unlock()
	c.recreator = r
}

func (c *Cluster) currentRecreator() SandboxRecreator {
	c.recreatorMu.Lock()
	defer c.recreatorMu.Unlock()
	return c.recreator
}

// OwnerOf reads the placement map from the local FSM (no network round-trip).
// Returns ErrUnknownSandbox if no row exists, or ErrOrphaned if the placement
// exists but has no active owner (auto-orphaned after the owning node died —
// see voter_autojoin / dead-owner reconciler).
func (c *Cluster) OwnerOf(sandboxID string) (OwnerInfo, error) {
	p, ok := c.fsm.get(sandboxID)
	if !ok {
		return OwnerInfo{}, ErrUnknownSandbox
	}
	if p.IsOrphaned() {
		return OwnerInfo{}, ErrOrphaned
	}
	apiURL := p.OwnerAPIURL
	if apiURL == "" {
		// Fall back to gossip in case the placement was written before the
		// owner advertised its URL.
		apiURL = c.gossip.peerAPIURL(p.OwnerNodeID)
	}
	// InternalURL is only on gossip (it isn't in the persisted Placement
	// record — operators can toggle TLS without rewriting raft state). Empty
	// for owners that run without SB_CLUSTER_TLS_DIR; the forwarder then
	// falls back to apiURL + PAT.
	internalURL := c.gossip.peerInternalURL(p.OwnerNodeID)
	return OwnerInfo{
		NodeID:      p.OwnerNodeID,
		APIURL:      apiURL,
		InternalURL: internalURL,
		IsSelf:      p.OwnerNodeID == c.nodeID,
	}, nil
}

// OwnerOfName resolves a replicated sandbox Name to its placement owner. This
// is intentionally a local FSM read just like OwnerOf; the name index is
// maintained inside the FSM apply path so it tracks the authoritative
// placement map exactly.
func (c *Cluster) OwnerOfName(name string) (string, OwnerInfo, error) {
	sandboxID, ok := c.fsm.sandboxIDByName(name)
	if !ok {
		return "", OwnerInfo{}, ErrUnknownSandbox
	}
	owner, err := c.OwnerOf(sandboxID)
	if err != nil {
		return sandboxID, OwnerInfo{}, err
	}
	return sandboxID, owner, nil
}

// AttachInternalHandler wires the public API mux into the cluster-internal
// mTLS listener so peers can reverse-proxy owner API calls over the
// cert-pinned channel. No-op when this node has no TLS material loaded
// (SB_CLUSTER_TLS_DIR empty) — there's no listener to attach to. Called once
// from cmd/sandboxd after the API server is constructed; the order avoids a
// service→cluster→api construction cycle.
func (c *Cluster) AttachInternalHandler(h http.Handler) {
	if c.internalServer == nil {
		return
	}
	c.internalServer.SetExtraHandler(h)
}

// RecordPlacement commits sandboxID -> self into the FSM via raft along with
// the (optional) creation spec. Idempotent. Safe to call from any node:
// applyCommand transparently forwards to the current leader if we're a
// follower. Passing spec=nil preserves a previously-recorded spec — see
// fsm.go opPlace handling.
//
// spec MUST be redacted before being passed in; secrets is the provider
// handle the caller produces via service.PutClusterSecretsForRecipient.
// Passing an empty handle preserves a previously-recorded handle.
func (c *Cluster) RecordPlacement(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, secrets PlacementSecrets) error {
	cmd := command{
		Op:                 opPlace,
		SandboxID:          sandboxID,
		OwnerNodeID:        c.nodeID,
		OwnerAPIURL:        c.apiURL,
		OwnerDataPlaneHost: c.dataPlaneHost,
		Spec:               spec,
		SecretRef:          secrets.Ref,
		SecretVersion:      secrets.Version,
	}
	return c.applyCommand(ctx, cmd)
}

// ClaimOrphan commits sandboxID -> self only if the existing placement is
// currently orphaned and was orphaned from this node (or predates the
// previous-owner metadata). This is the false-positive recovery path for a
// node that was marked dead by gossip but never actually lost its local
// sandbox.
func (c *Cluster) ClaimOrphan(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, secrets PlacementSecrets) error {
	cmd := command{
		Op:                 opClaimOrphan,
		SandboxID:          sandboxID,
		OwnerNodeID:        c.nodeID,
		OwnerAPIURL:        c.apiURL,
		OwnerDataPlaneHost: c.dataPlaneHost,
		Spec:               spec,
		SecretRef:          secrets.Ref,
		SecretVersion:      secrets.Version,
	}
	return c.applyCommand(ctx, cmd)
}

// UpsertSpec replicates a sandbox spec mutation (resize, lifecycle change)
// without changing ownership. Idempotent; nil spec + empty secrets is a
// no-op. Safe to call from any node — applyCommand forwards to the leader as
// needed.
//
// spec MUST be redacted; empty secrets preserves the previously replicated
// handle (resize/lifecycle never change credentials).
func (c *Cluster) UpsertSpec(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, secrets PlacementSecrets) error {
	if spec == nil && !secrets.hasUpdate() {
		return nil
	}
	cmd := command{
		Op:            opUpsertSpec,
		SandboxID:     sandboxID,
		Spec:          spec,
		SecretRef:     secrets.Ref,
		SecretVersion: secrets.Version,
	}
	return c.applyCommand(ctx, cmd)
}

// SecretsOf returns a copy of the provider handle paired with SpecOf's spec.
func (c *Cluster) SecretsOf(sandboxID string) PlacementSecrets {
	p, ok := c.fsm.get(sandboxID)
	if !ok {
		return PlacementSecrets{}
	}
	return secretsFromPlacement(p)
}

// SpecOf returns a deep-copy of the replicated spec for sandboxID, or nil if
// none is recorded. The returned spec is REDACTED — registry passwords and
// mount credentials are stripped at write time. Use SecretsOf to retrieve the
// matching secret ref and service.OpenClusterSecretsForNode to merge
// credentials back in. Callers may safely mutate the returned struct (it
// shares no memory with the FSM).
func (c *Cluster) SpecOf(sandboxID string) *models.CreateSandboxRequest {
	p, ok := c.fsm.get(sandboxID)
	if !ok || p.Spec == nil {
		return nil
	}
	cp := *p.Spec
	// Copy the maps and slices we touch in the patch helpers so callers can
	// freely mutate them. Other reference fields (Registry, GPUs, Lifecycle)
	// are pointers to immutable-by-convention payloads — patch helpers replace
	// the whole pointer rather than mutating in place.
	if cp.Env != nil {
		envCopy := make(map[string]string, len(cp.Env))
		for k, v := range cp.Env {
			envCopy[k] = v
		}
		cp.Env = envCopy
	}
	if cp.Mounts != nil {
		ms := make([]models.MountSpec, len(cp.Mounts))
		copy(ms, cp.Mounts)
		cp.Mounts = ms
	}
	if cp.PlatformVolumes != nil {
		pv := make([]models.PlatformVolumeMount, len(cp.PlatformVolumes))
		copy(pv, cp.PlatformVolumes)
		cp.PlatformVolumes = pv
	}
	if cp.ContainerCommand != nil {
		cmd := make([]string, len(cp.ContainerCommand))
		copy(cmd, cp.ContainerCommand)
		cp.ContainerCommand = cmd
	}
	return &cp
}

// AddExposedPort replicates a port-exposure intent. Idempotent when the route
// metadata is unchanged. Safe to call from any node.
func (c *Cluster) AddExposedPort(ctx context.Context, sandboxID string, port int, route ExposedPortRoute) error {
	if port <= 0 {
		return nil
	}
	cmd := command{
		Op:        opAddExposedPort,
		SandboxID: sandboxID,
		Port:      port,
		Protocol:  route.Protocol,
		HostPort:  route.HostPort,
		PublicURL: route.PublicURL,
	}
	return c.applyCommand(ctx, cmd)
}

// RemoveExposedPort drops a replicated port-exposure intent. Idempotent.
func (c *Cluster) RemoveExposedPort(ctx context.Context, sandboxID string, port int) error {
	if port <= 0 {
		return nil
	}
	cmd := command{Op: opRemoveExposedPort, SandboxID: sandboxID, Port: port}
	return c.applyCommand(ctx, cmd)
}

// ExposedPortsOf returns a copy of the replicated port route map. Returns nil
// if no placement exists or no ports are recorded.
func (c *Cluster) ExposedPortsOf(sandboxID string) map[int]ExposedPortRoute {
	p, ok := c.fsm.get(sandboxID)
	if !ok {
		return nil
	}
	return exposedPortRoutesForPlacement(p)
}

// AddCustomDomain replicates a sandbox→hostname binding through raft so every
// node can answer the TLS-ask probe and install the matching Caddy matcher.
// hostname is canonicalized (trim + lower) here so callers don't have to
// remember to do it themselves — the local SQLite layer already trims.
// Idempotent for the same (sandbox, hostname) pair; returns
// ErrCustomHostnameConflict when the hostname is held by a different sandbox.
func (c *Cluster) AddCustomDomain(ctx context.Context, sandboxID, hostname string) error {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if sandboxID == "" || hostname == "" {
		return nil
	}
	cmd := command{Op: opAddCustomDomain, SandboxID: sandboxID, Hostname: hostname}
	return c.applyCommand(ctx, cmd)
}

// RemoveCustomDomain releases the binding. Idempotent — a stale call after a
// successful DeletePlacement is a no-op.
func (c *Cluster) RemoveCustomDomain(ctx context.Context, sandboxID, hostname string) error {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if sandboxID == "" || hostname == "" {
		return nil
	}
	cmd := command{Op: opRemoveCustomDomain, SandboxID: sandboxID, Hostname: hostname}
	return c.applyCommand(ctx, cmd)
}

// CustomDomainsOf returns a sorted copy of the hostnames bound to sandboxID,
// or nil when none. Used by the ingress reconciler so a peer-owned sandbox
// still gets its TLS matchers installed in the local Caddy.
func (c *Cluster) CustomDomainsOf(sandboxID string) []string {
	return c.fsm.customHostnamesForSandbox(sandboxID)
}

// ResolveCustomDomain answers the TLS-ask probe from the local FSM index in
// O(1). Returns sandboxID, true when the hostname is bound somewhere in the
// cluster; false otherwise. hostname is canonicalized inside the FSM.
func (c *Cluster) ResolveCustomDomain(hostname string) (string, bool) {
	return c.fsm.sandboxIDByCustomHostname(hostname)
}

// DeletePlacement removes sandboxID from the placement map. Idempotent.
func (c *Cluster) DeletePlacement(ctx context.Context, sandboxID string) error {
	cmd := command{Op: opDelete, SandboxID: sandboxID}
	return c.applyCommand(ctx, cmd)
}

// ReserveOnTarget commits a capacity-and-name reservation for sandboxID
// owned by target before any docker side effect runs. The router calls this
// after SelectPlacement so the cluster has intent recorded the instant the
// router forwards the body to target. ttl bounds how long the reservation
// holds the slot before the leader GC sweep cancels it; pick large enough
// to cover the slowest expected image pull on the target.
//
// redacted MUST be stripped of plaintext credentials (call
// service.RedactClusterSecrets); secrets is the secret provider handle. Both
// ride the reservation so a successful promote via opPlace can inherit them
// without re-shipping the payload — see fsm.go opPlace preserve-on-empty
// rules.
//
// Returns ErrReservationConflict when the slot is already placed or held
// by a different owner; ErrNameConflict when redacted.Name is held
// cluster-wide. Either should map to 4xx at the API surface; transport
// errors stay 5xx (caller may retry).
func (c *Cluster) ReserveOnTarget(ctx context.Context, sandboxID string, target PlacementTarget, redacted *models.CreateSandboxRequest, secrets PlacementSecrets, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("cluster: reservation ttl must be > 0")
	}
	cmd := command{
		Op:                 opReserve,
		SandboxID:          sandboxID,
		OwnerNodeID:        target.NodeID,
		OwnerAPIURL:        target.APIURL,
		OwnerDataPlaneHost: target.DataPlaneHost,
		Spec:               redacted,
		SecretRef:          secrets.Ref,
		SecretVersion:      secrets.Version,
		ExpiresUnix:        time.Now().Add(ttl).Unix(),
	}
	return c.applyCommand(ctx, cmd)
}

// ReserveBatchOnTargets commits multiple reservation intents in one Raft entry.
// It is intended for create-burst frontends that have already selected targets
// and want the leader to admit the whole chunk against the same capacity view.
// The public one-create API still uses ReserveOnTarget, but scale harnesses and
// bulk create callers use this to avoid one Raft log entry per sandbox.
func (c *Cluster) ReserveBatchOnTargets(ctx context.Context, reservations []PlacementReservation) error {
	if len(reservations) == 0 {
		return nil
	}
	cmd := command{Op: opReserveBatch, Reservations: make([]reservationCommand, 0, len(reservations))}
	now := time.Now()
	for _, r := range reservations {
		if r.TTL <= 0 {
			return fmt.Errorf("cluster: reservation ttl must be > 0")
		}
		cmd.Reservations = append(cmd.Reservations, reservationCommand{
			SandboxID:          r.SandboxID,
			OwnerNodeID:        r.Target.NodeID,
			OwnerAPIURL:        r.Target.APIURL,
			OwnerDataPlaneHost: r.Target.DataPlaneHost,
			Spec:               r.Redacted,
			SecretRef:          r.Secrets.Ref,
			SecretVersion:      r.Secrets.Version,
			ExpiresUnix:        now.Add(r.TTL).Unix(),
		})
	}
	return c.applyCommand(ctx, cmd)
}

// CancelReservation deletes a pending reservation for sandboxID. Safe to
// call at any rollback point: opCancelReserve only fires when the row is
// State == Reserved, so a stale cancel after a successful promote is a
// no-op. Idempotent; calling on a never-reserved id is also a no-op.
func (c *Cluster) CancelReservation(ctx context.Context, sandboxID string) error {
	cmd := command{Op: opCancelReserve, SandboxID: sandboxID}
	return c.applyCommand(ctx, cmd)
}

// SetNodeDrainState marks nodeID as drained (drained=true) or restores it to
// the SelectPlacement candidate pool (drained=false). Goes through raft so
// every node — including the drained node itself — sees the new state on its
// next placement decision. Idempotent.
//
// Drain is a no-op on existing placements: a drained node continues serving
// the sandboxes it already owns. Combine with the dead-owner reconciler (kill
// the process) to force ownership transfer, or use a separate evacuate command
// (not implemented) to move work proactively.
func (c *Cluster) SetNodeDrainState(ctx context.Context, nodeID string, drained bool) error {
	if nodeID == "" {
		return fmt.Errorf("cluster: SetNodeDrainState requires non-empty nodeID")
	}
	cmd := command{Op: opSetNodeDrainState, NodeID: nodeID, Drained: drained}
	return c.applyCommand(ctx, cmd)
}

// ReassignPlacement moves sandboxID to target via opReassign.
func (c *Cluster) ReassignPlacement(ctx context.Context, sandboxID string, target PlacementTarget) error {
	if sandboxID == "" {
		return fmt.Errorf("cluster: ReassignPlacement requires sandbox id")
	}
	if target.NodeID == "" {
		return fmt.Errorf("cluster: ReassignPlacement requires target node id")
	}
	cmd := command{
		Op:                 opReassign,
		SandboxID:          sandboxID,
		OwnerNodeID:        target.NodeID,
		OwnerAPIURL:        target.APIURL,
		OwnerDataPlaneHost: target.DataPlaneHost,
	}
	return c.applyCommand(ctx, cmd)
}

func (c *Cluster) wasmMigratePAT() string { return c.patToken }

func (c *Cluster) wasmMigrateHTTPClient(internalURL, apiURL string) (*http.Client, string, error) {
	if c.internalClient != nil && internalURL != "" {
		return c.internalClient, internalURL, nil
	}
	if apiURL == "" {
		return nil, "", fmt.Errorf("cluster: peer API URL unknown")
	}
	return c.httpClient, apiURL, nil
}

// RemoveMember explicitly retires nodeID from the raft configuration. It is an
// operator lifecycle command, not gossip failure detection: the caller should
// drain the node first, then stop/terminate it, then remove it from raft.
//
// Before RemoveServer, we persist a drain mark and orphan any placements owned
// by the retiring node so surviving nodes stop routing new work there and
// clients get a clear 410 for lost sandboxes under the current non-HA policy.
func (c *Cluster) RemoveMember(ctx context.Context, nodeID string, force bool) error {
	if nodeID == "" {
		return fmt.Errorf("cluster: RemoveMember requires non-empty nodeID")
	}
	if c.raft == nil || c.raft.raft == nil {
		return ErrUnknownMember
	}
	if c.raft.raft.State() != raft.Leader {
		return c.forwardRemoveMemberToLeader(ctx, nodeID, force)
	}
	return c.removeMemberLocal(ctx, nodeID, force)
}

func (c *Cluster) removeMemberLocal(ctx context.Context, nodeID string, force bool) error {
	srv, ok := c.configuredServer(nodeID)
	if !ok {
		return ErrUnknownMember
	}
	if srv.Suffrage == raft.Voter {
		voters, ok := c.currentVoterCount()
		if !ok {
			return fmt.Errorf("cluster: read raft configuration")
		}
		if voters <= 1 {
			return ErrLastVoter
		}
	}
	if !force && c.memberAlive(nodeID) {
		return ErrMemberStillAlive
	}
	if err := c.SetNodeDrainState(ctx, nodeID, true); err != nil {
		return err
	}
	if err := c.orphanOwner(ctx, nodeID); err != nil {
		return err
	}
	timeout := c.commitTimeout
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	f := c.raft.raft.RemoveServer(raft.ServerID(nodeID), 0, timeout)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			return ErrNotLeader
		}
		return fmt.Errorf("cluster: remove raft member: %w", err)
	}
	c.deadOwners.clear(nodeID)
	c.logger.Info("cluster: removed raft member", "node_id", nodeID, "force", force)
	return nil
}

func (c *Cluster) memberAlive(nodeID string) bool {
	if c.gossip == nil {
		return false
	}
	for _, m := range c.gossip.members() {
		if m.NodeID == nodeID {
			return m.Alive
		}
	}
	return false
}

func (c *Cluster) forwardRemoveMemberToLeader(ctx context.Context, nodeID string, force bool) error {
	leader := c.Leader()
	if leader == "" {
		return ErrNotLeader
	}
	path := "/v1/cluster/members/" + url.PathEscape(nodeID)
	if force {
		path += "?force=true"
	}
	if c.internalClient != nil && c.gossip != nil {
		if peerInternal := c.gossip.peerInternalURL(leader); peerInternal != "" {
			return c.doLeaderLifecycle(ctx, c.internalClient, strings.TrimRight(peerInternal, "/")+path, http.MethodDelete, nil)
		}
	}
	leaderURL := c.LeaderAPIURL()
	if leaderURL == "" {
		return ErrNotLeader
	}
	return c.doLeaderLifecycle(ctx, c.httpClient, strings.TrimRight(leaderURL, "/")+path, http.MethodDelete, nil)
}

func (c *Cluster) doLeaderLifecycle(ctx context.Context, client *http.Client, endpoint, method string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cluster: build lifecycle request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.patToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.patToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cluster: lifecycle request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	message := strings.TrimSpace(string(msg))
	switch resp.StatusCode {
	case http.StatusServiceUnavailable:
		if strings.Contains(message, ErrNotLeader.Error()) || strings.Contains(message, "not leader") {
			return ErrNotLeader
		}
	case http.StatusNotFound:
		if strings.Contains(message, ErrUnknownMember.Error()) {
			return ErrUnknownMember
		}
	case http.StatusConflict:
		if strings.Contains(message, ErrMemberStillAlive.Error()) {
			return ErrMemberStillAlive
		}
		if strings.Contains(message, ErrLastVoter.Error()) {
			return ErrLastVoter
		}
	}
	return fmt.Errorf("cluster: lifecycle request: status %d: %s", resp.StatusCode, message)
}

// IsNodeDrained reports the FSM's view of nodeID's drain state. Read from the
// local FSM with no network hop.
func (c *Cluster) IsNodeDrained(nodeID string) bool {
	if c.fsm == nil {
		return false
	}
	return c.fsm.isNodeDrained(nodeID)
}

// AssertOwnership reconciles local sandbox state against the cluster FSM at
// boot. Used at boot. Idempotent. Best-effort callers should log errors and
// retry later.
//
// Three-way decision per local row, with the FSM as the source of truth for
// ownership (never overwrite an existing non-self owner):
//
//   - **No FSM placement.** Write opPlace claiming self as owner, with spec +
//     secret ref so the new placement is born recoverable. This is the
//     normal case for sandboxes created before AssertOwnership last ran.
//
//   - **FSM owner == self.** No ownership change. Backfill missing Spec /
//     secret ref via opUpsertSpec (closes the pre-spec-replication gap)
//     and replay ExposedPort intents via opAddExposedPort (no-ops when
//     already recorded).
//
//   - **FSM orphaned from self.** Reclaim via opClaimOrphan, then replay the
//     same spec/port backfill. This is the false-positive dead-owner recovery
//     path: gossip/Raft marked us dead, but the local sandbox never left.
//
//   - **FSM owner != self, or orphaned from another owner.** **Do NOT reclaim.**
//     This is the failover-recovery/stale-local-row case. Calling
//     RecordPlacement here would overwrite another owner or steal a different
//     dead node's orphan. Instead: log loudly and leave the FSM alone.
//     service.reconcileStaleOwnership handles destroying stale local copies on
//     its next pass when the placement has an active different owner.
//
// Edge cases:
//   - Owner unknown to gossip yet (fresh boot, gossip not converged): we still
//     defer. Treating "presumed alive" as the safe default keeps us from racing
//     a peer whose announce just hasn't reached us. The next reconcile pass
//     reclassifies.
//   - Owner is dead in gossip: still defer until the leader has committed the
//     orphan transition. Claiming before the FSM records which previous owner
//     lost the row would recreate the overwrite hazard.
func (c *Cluster) AssertOwnership(ctx context.Context, local []LocalSandboxState) error {
	if len(local) == 0 {
		return nil
	}
	// Wait briefly for a leader to exist so we can apply. If no leader emerges
	// (e.g. fresh non-bootstrap node still joining), report the failure so the
	// caller can retry instead of permanently leaving local rows out of the
	// placement index.
	if err := c.waitForLeader(ctx, 10*time.Second); err != nil {
		c.logger.Warn("cluster: AssertOwnership skipped, no leader yet", "err", err)
		return err
	}
	var firstErr error
	for _, st := range local {
		if st.ID == "" {
			continue
		}
		existing, ok := c.fsm.get(st.ID)

		switch {
		case !ok:
			// No placement exists — claim ownership. Pass spec + secret handle
			// so the placement is born recoverable.
			if err := c.RecordPlacement(ctx, st.ID, st.Spec, st.Secrets); err != nil && firstErr == nil {
				firstErr = err
			}
			// Replay port intents so the FSM matches local truth.
			for port, route := range st.ExposedPorts {
				if err := c.AddExposedPort(ctx, st.ID, port, route); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			for _, hostname := range st.CustomHostnames {
				if err := c.AddCustomDomain(ctx, st.ID, hostname); err != nil && firstErr == nil {
					firstErr = err
				}
			}

		case existing.OwnerNodeID == c.nodeID && !existing.IsOrphaned() && existing.IsReserved():
			if err := c.RecordPlacement(ctx, st.ID, st.Spec, st.Secrets); err != nil && firstErr == nil {
				firstErr = err
			}
			for port, route := range st.ExposedPorts {
				if err := c.AddExposedPort(ctx, st.ID, port, route); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			for _, hostname := range st.CustomHostnames {
				if err := c.AddCustomDomain(ctx, st.ID, hostname); err != nil && firstErr == nil {
					firstErr = err
				}
			}

		case existing.OwnerNodeID == c.nodeID && !existing.IsOrphaned():
			// We legitimately own it. Backfill any missing spec/secrets so
			// future failover-recreate has everything it needs (closes the
			// pre-cluster-sandbox limitation), then replay port + hostname
			// intents. The FSM treats already-bound (sandbox, hostname) pairs
			// as idempotent no-ops, so re-replaying every boot is cheap.
			if existing.Spec == nil && st.Spec != nil {
				if err := c.UpsertSpec(ctx, st.ID, st.Spec, st.Secrets); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			for port, route := range st.ExposedPorts {
				if err := c.AddExposedPort(ctx, st.ID, port, route); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			for _, hostname := range st.CustomHostnames {
				if err := c.AddCustomDomain(ctx, st.ID, hostname); err != nil && firstErr == nil {
					firstErr = err
				}
			}

		case placementCanBeClaimedBy(existing, c.nodeID):
			if err := c.ClaimOrphan(ctx, st.ID, st.Spec, st.Secrets); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			for port, route := range st.ExposedPorts {
				if err := c.AddExposedPort(ctx, st.ID, port, route); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			// Failover claim: the new owner replays hostnames from local
			// truth. AddCustomDomain at the FSM is the uniqueness gate, so
			// a hostname still claimed by a dead prior owner stays with the
			// stale row until that row is reaped; the next AssertOwnership
			// pass after reap succeeds.
			for _, hostname := range st.CustomHostnames {
				if err := c.AddCustomDomain(ctx, st.ID, hostname); err != nil && firstErr == nil {
					firstErr = err
				}
			}

		default:
			// existing.OwnerNodeID != self, or the row is orphaned from some
			// other previous owner. MUST NOT call RecordPlacement here; see
			// comment above.
			c.logger.Warn("cluster: local sandbox row is stale or non-claimable; leaving FSM alone",
				"sandbox_id", st.ID,
				"fsm_owner", existing.OwnerNodeID,
				"owner_state", existing.OwnerState,
				"orphaned_owner", existing.OrphanedOwnerNodeID,
				"self", c.nodeID,
				"placement_version", existing.Version,
			)
		}
	}
	return firstErr
}

func placementCanBeClaimedBy(p Placement, nodeID string) bool {
	if nodeID == "" || !p.IsOrphaned() {
		return false
	}
	return p.OrphanedOwnerNodeID == "" || p.OrphanedOwnerNodeID == nodeID
}

// applyCommand encodes and submits a raft log entry. On a follower the
// command is forwarded over HTTP to the current leader's API; the leader
// applies it on behalf of the caller. This makes mutating raft writes
// (RecordPlacement, UpsertSpec, AddExposedPort, RemoveExposedPort,
// DeletePlacement) safe to call from any node — without it, every owner-side
// caller would have to know whether it's the leader and forward by hand.
func (c *Cluster) applyCommand(ctx context.Context, cmd command) error {
	if err := validateCommandRecoverySize(cmd); err != nil {
		return err
	}
	payload, err := encodeCommand(cmd)
	if err != nil {
		return fmt.Errorf("cluster: encode command: %w", err)
	}
	if c.raft.raft.State() == raft.Leader {
		if cmd.Op == opReserve || cmd.Op == opReserveBatch {
			return c.applyReservationEncodedLocal(ctx, payload, cmd)
		}
		return c.applyEncodedLocal(ctx, payload)
	}
	return c.forwardApplyToLeader(ctx, payload)
}

// ApplyEncoded is the receiving side of leader-forwarded raft writes. It
// decodes-validates the payload (so a malformed body never reaches the FSM)
// and applies it locally. Returns ErrNotLeader if leadership has changed
// since the forwarder picked us — the caller is expected to retry.
func (c *Cluster) ApplyEncoded(ctx context.Context, payload []byte) error {
	cmd, err := decodeCommand(payload)
	if err != nil {
		return fmt.Errorf("cluster: decode forwarded command: %w", err)
	}
	if c.raft.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	if err := validateCommandRecoverySize(cmd); err != nil {
		return err
	}
	if cmd.Op == opReserve || cmd.Op == opReserveBatch {
		return c.applyReservationEncodedLocal(ctx, payload, cmd)
	}
	return c.applyEncodedLocal(ctx, payload)
}

func (c *Cluster) applyReservationEncodedLocal(ctx context.Context, payload []byte, cmd command) error {
	c.reservationAdmissionMu.Lock()
	defer c.reservationAdmissionMu.Unlock()
	if c.raft.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	if err := c.admitReservationCommand(cmd); err != nil {
		return err
	}
	return c.applyEncodedLocal(ctx, payload)
}

// applyEncodedLocal submits an already-encoded command to the local raft.
// Caller is responsible for verifying we're the leader before this point —
// raft itself returns ErrNotLeader if we lost leadership between the check
// and the Apply call, which is mapped back to cluster.ErrNotLeader.
func (c *Cluster) applyEncodedLocal(ctx context.Context, payload []byte) (err error) {
	done := beginRaftApply()
	defer func() { done(err) }()
	timeout := c.commitTimeout
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	f := c.raft.raft.Apply(payload, timeout)
	if applyErr := f.Error(); applyErr != nil {
		if errors.Is(applyErr, raft.ErrNotLeader) || errors.Is(applyErr, raft.ErrLeadershipLost) {
			err = ErrNotLeader
			return ErrNotLeader
		}
		err = fmt.Errorf("cluster: raft apply: %w", applyErr)
		return err
	}
	if appErr, ok := f.Response().(error); ok && appErr != nil {
		err = fmt.Errorf("cluster: fsm apply: %w", appErr)
		return err
	}
	return nil
}

// forwardApplyToLeader posts an encoded raft command to the current leader's
// internal apply endpoint. Returns ErrNotLeader if no leader is known (so the
// caller can surface the same retry semantics as a stale local leader-check).
//
// Channel selection: if both this node and the leader have advertised an
// InternalURL (i.e. both have SB_CLUSTER_TLS_DIR set), we dial the leader's
// mTLS listener — the TLS handshake proves cluster membership before the
// payload is read. Otherwise we fall back to the public API URL, which only
// validates the shared PAT and is acceptable on a private overlay.
func (c *Cluster) forwardApplyToLeader(ctx context.Context, payload []byte) error {
	leader := c.Leader()
	if leader == "" {
		return ErrNotLeader
	}

	// Prefer the cluster-internal mTLS channel when both ends are TLS-equipped.
	if c.internalClient != nil {
		if peerInternal := c.gossip.peerInternalURL(leader); peerInternal != "" {
			endpoint := strings.TrimRight(peerInternal, "/") + InternalAPIPath
			err := c.doLeaderApply(ctx, c.internalClient, endpoint, payload)
			// Hard-fail (network/TLS) on the internal channel must NOT silently
			// fall back to the public path — that would defeat the security
			// promise. Only ErrNotLeader bubbles up so the caller retries the
			// new leader (which may pick the public path next iteration).
			return err
		}
	}

	// Fallback: public API URL with PAT-only auth. This path runs when the
	// peer (or self) doesn't have TLS material — typically a mixed-rollout
	// or a fully-plaintext private-network deployment.
	leaderURL := c.LeaderAPIURL()
	if leaderURL == "" {
		return ErrNotLeader
	}
	endpoint := strings.TrimRight(leaderURL, "/") + "/v1/cluster/internal/apply"
	return c.doLeaderApply(ctx, c.httpClient, endpoint, payload)
}

// doLeaderApply is the shared HTTP execution path used by both the mTLS
// internal channel and the PAT-only public-API fallback in forwardApplyToLeader.
func (c *Cluster) doLeaderApply(ctx context.Context, client *http.Client, endpoint string, payload []byte) (err error) {
	done := beginLeaderForwardApply()
	defer func() { done(err) }()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("cluster: build leader-forward request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.patToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.patToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cluster: leader-forward apply: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	message := strings.TrimSpace(string(body))
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("%w: %s", ErrCreateBackpressure, message)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		if strings.Contains(message, ErrCapacityExceeded.Error()) {
			return fmt.Errorf("%w: %s", ErrCapacityExceeded, message)
		}
		if strings.Contains(message, ErrNoPlacementTarget.Error()) {
			return fmt.Errorf("%w: %s", ErrNoPlacementTarget, message)
		}
		if strings.Contains(message, ErrCreateBackpressure.Error()) {
			return fmt.Errorf("%w: %s", ErrCreateBackpressure, message)
		}
		return ErrNotLeader
	}
	return fmt.Errorf("cluster: leader-forward apply: status %d: %s", resp.StatusCode, message)
}

// waitForLeader blocks until raft reports a leader or the deadline passes.
func (c *Cluster) waitForLeader(ctx context.Context, max time.Duration) error {
	deadline := time.Now().Add(max)
	for {
		if leader, _ := c.raft.raft.LeaderWithID(); leader != "" {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("cluster: timed out waiting for leader")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Members returns gossip-known members (self included), enriched with fresh
// capacity heartbeats where available.
func (c *Cluster) Members() []Member {
	if c.gossip == nil {
		return nil
	}
	return c.membersWithCapacity()
}

// IngressTargets aggregates live ingress-role members' gossiped PublicHost
// values. See aggregateIngressTargets for the partition / dedup / ordering
// rules — those are pinned by ingress_targets_test.go.
func (c *Cluster) IngressTargets() models.IngressTarget {
	if c.gossip == nil {
		return models.IngressTarget{Source: models.IngressTargetSourceUnknown}
	}
	return aggregateIngressTargets(c.gossip.members())
}

// SetLocalTemplateIDsProvider registers the Phase 6 PR-D callback used
// by the capacity lease cache to overlay Firecracker template inventory
// onto local heartbeats. Idempotent; passing nil unregisters. Wired by
// main.go after the service is attached. Single-node deployments and
// nodes without Firecracker enabled never call this and degrade to
// nil-provider behaviour (no LocalTemplateIDs on the snapshot, peers
// see the legacy "unknown, allow" placement).
func (c *Cluster) SetLocalTemplateIDsProvider(fn func() ([]string, bool)) {
	if c == nil || c.capacityLeases == nil {
		return
	}
	c.capacityLeases.SetLocalTemplateIDsProvider(fn)
}

// SetLocalWasmModuleIDsProvider registers the WASM module inventory callback.
func (c *Cluster) SetLocalWasmModuleIDsProvider(fn func() ([]string, bool)) {
	if c == nil || c.capacityLeases == nil {
		return
	}
	c.capacityLeases.SetLocalWasmModuleIDsProvider(fn)
}

func (c *Cluster) membersWithCapacity() []Member {
	members := c.gossip.members()
	if c.capacityLeases == nil {
		return members
	}
	return c.capacityLeases.apply(members, time.Now())
}

func (c *Cluster) Placements() []Placement {
	return c.PlacementsForShards(PlacementShardFilter{})
}

func (c *Cluster) PlacementsForShards(filter PlacementShardFilter) []Placement {
	if c.fsm == nil {
		return nil
	}
	return c.fsm.placementsForShards(filter)
}

func (c *Cluster) PlacementPage(req PlacementPageRequest) PlacementPageResponse {
	if c.fsm == nil {
		return PlacementPageResponse{}
	}
	return c.fsm.placementPage(req)
}

// PlacementOf returns the FSM record for sandboxID. Goes through f.get so the
// returned Placement is deep-cloned and safe to mutate without aliasing live
// FSM state (same guarantee as Placements).
func (c *Cluster) PlacementOf(sandboxID string) (Placement, bool) {
	if c.fsm == nil {
		return Placement{}, false
	}
	return c.fsm.get(sandboxID)
}

// PlacementVersion returns the FSM's monotonic apply counter — bumps on
// every committed raft log entry. Exposed for metrics and as a tie-breaker
// for tests; the ingress reconciler uses SubscribePlacement to wake on
// apply rather than polling this counter.
func (c *Cluster) PlacementVersion() uint64 {
	if c.fsm == nil {
		return 0
	}
	return c.fsm.currentVersion()
}

// SubscribePlacement returns a buffered (cap=1) wake channel that fires after
// every FSM apply on this node. Cancelling ctx removes the subscriber. See the
// Client.SubscribePlacement contract for semantics.
func (c *Cluster) SubscribePlacement(ctx context.Context) <-chan struct{} {
	if c.fsm == nil {
		return nil
	}
	ch := make(chan struct{}, 1)
	cancel := c.fsm.subscribe(ch)
	// Tie cleanup to the caller's context — when ctx fires, drop the
	// subscriber so the FSM doesn't keep handing it signals forever.
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ch
}

// Leader returns the node ID of the current raft leader. Empty if no leader.
func (c *Cluster) Leader() string {
	_, id := c.raft.raft.LeaderWithID()
	return string(id)
}

// LeaderAPIURL returns the API URL of the current leader, or empty if unknown.
// Used by the API wrapper to forward mutating raft writes to the leader.
func (c *Cluster) LeaderAPIURL() string {
	leader := c.Leader()
	if leader == "" {
		return ""
	}
	if leader == c.nodeID {
		return c.apiURL
	}
	return c.gossip.peerAPIURL(leader)
}

// ForwardHTTP is implemented in forward.go.

// Close shuts down gossip + raft. Idempotent.
func (c *Cluster) Close() error {
	var firstErr error
	if c.voterReconcileStop != nil {
		c.voterReconcileStop()
	}
	if c.deadOwnerLoopStop != nil {
		c.deadOwnerLoopStop()
	}
	if c.reservationGCStop != nil {
		c.reservationGCStop()
	}
	if c.capacityLeaseStop != nil {
		c.capacityLeaseStop()
	}
	if c.ownerWatcherStop != nil {
		c.ownerWatcherStop()
	}
	if c.gossip != nil {
		if err := c.gossip.Close(); err != nil {
			firstErr = fmt.Errorf("cluster: gossip close: %w", err)
		}
	}
	// Stop the internal HTTPS listener before closing raft so a peer that just
	// started a forward can see a clean shutdown rather than a mid-apply error.
	if c.internalServer != nil {
		if err := c.internalServer.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("cluster: internal server close: %w", err)
		}
	}
	if c.raft != nil {
		if err := c.raft.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("cluster: raft close: %w", err)
		}
	}
	return firstErr
}

// decodeGossipSecretKey parses the operator-provided gossip key. Empty input
// returns (nil, nil) — that's the plaintext path. Non-empty input must be
// base64-encoded and decode to 16, 24, or 32 bytes (AES-128/192/256-GCM).
// Anything else is rejected at boot rather than silently shipping plaintext.
func decodeGossipSecretKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("SB_GOSSIP_SECRET_KEY must be base64-encoded: %w", err)
	}
	switch len(key) {
	case 16, 24, 32:
		return key, nil
	default:
		return nil, fmt.Errorf("SB_GOSSIP_SECRET_KEY must decode to 16, 24, or 32 bytes (got %d)", len(key))
	}
}

// deriveInternalAdvertiseURL computes the URL peers should use to dial this
// node's cluster-internal mTLS listener. Operator-provided
// SB_CLUSTER_INTERNAL_ADVERTISE wins; otherwise we synthesize from the bound
// listener's address. The synthesis path tries to keep the host portion
// non-bogus: if the listener bound 0.0.0.0/:: we'd otherwise advertise an
// unroutable address, so we fall back to the listen-config host (which the
// operator may have set sensibly) or finally to "127.0.0.1" so single-node /
// loopback test setups still work.
func deriveInternalAdvertiseURL(operator string, listenAddr string, boundAddr string) string {
	if operator != "" {
		return strings.TrimRight(operator, "/")
	}
	host, port := splitHostForAdvertise(boundAddr)
	if isUnspecifiedHost(host) {
		// Listener bound a wildcard. Prefer the configured listen host (if
		// operator set one explicitly), otherwise loopback.
		lhost, _ := splitHostForAdvertise(listenAddr)
		if !isUnspecifiedHost(lhost) && lhost != "" {
			host = lhost
		} else {
			host = "127.0.0.1"
		}
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		return "https://" + host
	}
	return "https://" + host + ":" + port
}

// splitHostForAdvertise splits "host:port" tolerantly. Returns ("", "") on
// parse error so callers fall back to defaults.
func splitHostForAdvertise(addr string) (string, string) {
	if addr == "" {
		return "", ""
	}
	// net.SplitHostPort handles IPv6 brackets correctly; fall back to a manual
	// split if it fails (e.g. caller passed bare "host").
	h, p, err := splitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	if p == 0 {
		return h, ""
	}
	return h, fmt.Sprintf("%d", p)
}

func isUnspecifiedHost(host string) bool {
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}
	return false
}

// HealthyForReads is true once the FSM has caught up to the leader's last
// log index — i.e. our local OwnerOf reads are not stale by more than a
// single round trip. Used by EnsureClusterReady.
func (c *Cluster) HealthyForReads() bool {
	if c.raft == nil {
		return false
	}
	last, _ := c.raft.raft.LeaderWithID()
	return last != ""
}
