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
	cfg    config.Config
	logger *slog.Logger
	nodeID string
	apiURL string

	fsm    *placementFSM
	raft   *raftNode
	gossip *gossipNode

	// patToken authenticates leader-forwarded raft applies. Sourced from
	// cfg.PATToken at construction; same value every node already shares for
	// regular API auth, so no new secret-distribution surface.
	patToken   string
	httpClient *http.Client

	commitTimeout time.Duration

	// voterReconcileStop cancels the auto-voter reconcile goroutine on Close.
	voterReconcileStop context.CancelFunc

	// deadOwners tracks per-node "first observed dead" timestamps for the
	// dead-owner reconciler. Lives on the cluster (not in dead_owner.go) so
	// Close can stop its loop. See dead_owner.go for the reconciler logic.
	deadOwners        *deadOwnerTracker
	deadOwnerLoopStop context.CancelFunc

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

// New constructs a Cluster for cfg.EnableCluster=true. Caller takes ownership
// of Close. For cfg.EnableCluster=false call NewNoop instead.
func New(cfg config.Config, logger *slog.Logger, admitter *capacity.Admitter) (*Cluster, error) {
	if !cfg.EnableCluster {
		return nil, errors.New("cluster.New: cfg.EnableCluster is false; use NewNoop")
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

	fsm := newPlacementFSM()

	rn, err := setupRaft(raftSetupConfig{
		NodeID:           nodeID,
		BindAddr:         cfg.RaftBindAddr,
		AdvertiseAddr:    cfg.RaftAdvertiseAddr,
		DataDir:          cfg.RaftDataDir,
		BootstrapCluster: cfg.ClusterBootstrap,
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
		fsm:           fsm,
		raft:          rn,
		patToken:      cfg.PATToken,
		httpClient:    &http.Client{Timeout: commitTimeout + 2*time.Second},
		commitTimeout: commitTimeout,
		deadOwners:    newDeadOwnerTracker(),
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
		// Plaintext gossip + voter auto-promotion lets any reachable peer
		// become a raft voter. Make this loud so operators see the warning at
		// boot rather than discovering it after a hostile join.
		logger.Warn("cluster: gossip is unencrypted (SB_GOSSIP_SECRET_KEY not set); voter auto-promotion will admit any reachable peer — keep raft+gossip ports on a private network")
	}

	gn, err := setupGossip(gossipSetupConfig{
		NodeID:         nodeID,
		BindAddr:       cfg.GossipBindAddr,
		AdvertiseAddr:  cfg.GossipAdvertiseAddr,
		APIURL:         cfg.SelfAPIAdvertiseURL,
		RaftAddr:       raftAdvertise,
		BootstrapPeers: cfg.BootstrapPeers,
		GossipInterval: cfg.ClusterCapacityGossipInterval,
		SecretKey:      secretKey,
		Events:         &voterAutoJoinDelegate{c: c},
	}, admitter, logger)
	if err != nil {
		_ = rn.Close()
		return nil, fmt.Errorf("cluster.New: gossip: %w", err)
	}
	c.gossip = gn

	// Slow reconcile loop: catches the "joined too fast" race where the
	// memberlist event fires before the joiner's nodeMeta has propagated. The
	// loop is no-op when self isn't leader.
	c.startVoterReconcileLoop()

	// Dead-owner reconciler: the leader periodically checks for nodes whose
	// gossip-leave grace period has expired and orphans their placements +
	// removes them from the raft configuration. Followers maintain the
	// in-memory tracker (cheap) but never act.
	c.startDeadOwnerLoop()

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
// exists but its owner field is empty (auto-orphaned after the owning node
// died — see voter_autojoin / dead-owner reconciler).
func (c *Cluster) OwnerOf(sandboxID string) (OwnerInfo, error) {
	p, ok := c.fsm.get(sandboxID)
	if !ok {
		return OwnerInfo{}, ErrUnknownSandbox
	}
	if p.OwnerNodeID == "" {
		return OwnerInfo{}, ErrOrphaned
	}
	apiURL := p.OwnerAPIURL
	if apiURL == "" {
		// Fall back to gossip in case the placement was written before the
		// owner advertised its URL.
		apiURL = c.gossip.peerAPIURL(p.OwnerNodeID)
	}
	return OwnerInfo{
		NodeID: p.OwnerNodeID,
		APIURL: apiURL,
		IsSelf: p.OwnerNodeID == c.nodeID,
	}, nil
}

// RecordPlacement commits sandboxID -> self into the FSM via raft along with
// the (optional) creation spec. Idempotent. Safe to call from any node:
// applyCommand transparently forwards to the current leader if we're a
// follower. Passing spec=nil preserves a previously-recorded spec — see
// fsm.go opPlace handling.
func (c *Cluster) RecordPlacement(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest) error {
	cmd := command{
		Op:          opPlace,
		SandboxID:   sandboxID,
		OwnerNodeID: c.nodeID,
		OwnerAPIURL: c.apiURL,
		Spec:        spec,
	}
	return c.applyCommand(ctx, cmd)
}

// UpsertSpec replicates a sandbox spec mutation (resize, lifecycle change)
// without changing ownership. Idempotent; nil spec is a no-op. Safe to call
// from any node — applyCommand forwards to the leader as needed.
func (c *Cluster) UpsertSpec(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest) error {
	if spec == nil {
		return nil
	}
	cmd := command{Op: opUpsertSpec, SandboxID: sandboxID, Spec: spec}
	return c.applyCommand(ctx, cmd)
}

// SpecOf returns a deep-copy of the replicated spec for sandboxID, or nil if
// none is recorded. Callers may safely mutate the returned struct (it shares
// no memory with the FSM).
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
	if cp.ContainerCommand != nil {
		cmd := make([]string, len(cp.ContainerCommand))
		copy(cmd, cp.ContainerCommand)
		cp.ContainerCommand = cmd
	}
	return &cp
}

// AddExposedPort replicates a port-exposure intent. Idempotent (same
// port+protocol is a no-op at the FSM layer). Safe to call from any node.
func (c *Cluster) AddExposedPort(ctx context.Context, sandboxID string, port int, protocol string) error {
	if port <= 0 {
		return nil
	}
	cmd := command{Op: opAddExposedPort, SandboxID: sandboxID, Port: port, Protocol: protocol}
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

// ExposedPortsOf returns a copy of the replicated port→protocol map. Returns
// nil if no placement exists or no ports are recorded.
func (c *Cluster) ExposedPortsOf(sandboxID string) map[int]string {
	p, ok := c.fsm.get(sandboxID)
	if !ok || len(p.ExposedPorts) == 0 {
		return nil
	}
	out := make(map[int]string, len(p.ExposedPorts))
	for k, v := range p.ExposedPorts {
		out[k] = v
	}
	return out
}

// DeletePlacement removes sandboxID from the placement map. Idempotent.
func (c *Cluster) DeletePlacement(ctx context.Context, sandboxID string) error {
	cmd := command{Op: opDelete, SandboxID: sandboxID}
	return c.applyCommand(ctx, cmd)
}

// AssertOwnership ensures every entry in local is recorded as owned by self,
// and backfills any missing Spec / ExposedPorts so a future failover-recreate
// has everything it needs. Used at boot. Idempotent. Best-effort: errors are
// logged but do not abort boot — the next reconcile loop will retry.
//
// Backfill rules:
//   - If the FSM has no placement for this id, write opPlace with the local
//     spec (if available) so the new placement is born with a recoverable spec.
//   - If the FSM has a placement but no Spec and we have one locally, send
//     opUpsertSpec to attach it. This is what closes the pre-cluster-sandbox
//     limitation: a sandbox created before spec replication shipped will pick
//     up its spec on the next boot under cluster mode.
//   - For every locally-recorded port intent, send opAddExposedPort. The op
//     is a no-op if the FSM already records the same (port, protocol).
func (c *Cluster) AssertOwnership(ctx context.Context, local []LocalSandboxState) error {
	if len(local) == 0 {
		return nil
	}
	// Wait briefly for a leader to exist so we can apply. If no leader emerges
	// (e.g. fresh non-bootstrap node still joining), defer to reconcile.
	if err := c.waitForLeader(ctx, 10*time.Second); err != nil {
		c.logger.Warn("cluster: AssertOwnership skipped, no leader yet", "err", err)
		return nil
	}
	var firstErr error
	for _, st := range local {
		if st.ID == "" {
			continue
		}
		existing, ok := c.fsm.get(st.ID)
		needsPlace := !ok || existing.OwnerNodeID != c.nodeID
		needsSpecBackfill := ok && existing.Spec == nil && st.Spec != nil
		if needsPlace {
			// Either no placement exists or another node thinks they own this
			// sandbox (unlikely but possible after a split-brain recovery). In
			// both cases we (re)claim — this node has the sandbox locally so
			// it IS the owner. Pass spec so the placement is born recoverable.
			if err := c.RecordPlacement(ctx, st.ID, st.Spec); err != nil && firstErr == nil {
				firstErr = err
			}
		} else if needsSpecBackfill {
			// Existing placement, no spec yet — attach one so future failover
			// can recreate this pre-cluster sandbox.
			if err := c.UpsertSpec(ctx, st.ID, st.Spec); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		for port, protocol := range st.ExposedPorts {
			if err := c.AddExposedPort(ctx, st.ID, port, protocol); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// applyCommand encodes and submits a raft log entry. On a follower the
// command is forwarded over HTTP to the current leader's API; the leader
// applies it on behalf of the caller. This makes mutating raft writes
// (RecordPlacement, UpsertSpec, AddExposedPort, RemoveExposedPort,
// DeletePlacement) safe to call from any node — without it, every owner-side
// caller would have to know whether it's the leader and forward by hand.
func (c *Cluster) applyCommand(ctx context.Context, cmd command) error {
	payload, err := encodeCommand(cmd)
	if err != nil {
		return fmt.Errorf("cluster: encode command: %w", err)
	}
	if c.raft.raft.State() == raft.Leader {
		return c.applyEncodedLocal(ctx, payload)
	}
	return c.forwardApplyToLeader(ctx, payload)
}

// ApplyEncoded is the receiving side of leader-forwarded raft writes. It
// decodes-validates the payload (so a malformed body never reaches the FSM)
// and applies it locally. Returns ErrNotLeader if leadership has changed
// since the forwarder picked us — the caller is expected to retry.
func (c *Cluster) ApplyEncoded(ctx context.Context, payload []byte) error {
	if _, err := decodeCommand(payload); err != nil {
		return fmt.Errorf("cluster: decode forwarded command: %w", err)
	}
	if c.raft.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	return c.applyEncodedLocal(ctx, payload)
}

// applyEncodedLocal submits an already-encoded command to the local raft.
// Caller is responsible for verifying we're the leader before this point —
// raft itself returns ErrNotLeader if we lost leadership between the check
// and the Apply call, which is mapped back to cluster.ErrNotLeader.
func (c *Cluster) applyEncodedLocal(ctx context.Context, payload []byte) error {
	timeout := c.commitTimeout
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	f := c.raft.raft.Apply(payload, timeout)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			return ErrNotLeader
		}
		return fmt.Errorf("cluster: raft apply: %w", err)
	}
	if appErr, ok := f.Response().(error); ok && appErr != nil {
		return fmt.Errorf("cluster: fsm apply: %w", appErr)
	}
	return nil
}

// forwardApplyToLeader posts an encoded raft command to the current leader's
// internal apply endpoint. Returns ErrNotLeader if no leader is known (so the
// caller can surface the same retry semantics as a stale local leader-check).
func (c *Cluster) forwardApplyToLeader(ctx context.Context, payload []byte) error {
	leaderURL := c.LeaderAPIURL()
	if leaderURL == "" {
		return ErrNotLeader
	}
	endpoint := strings.TrimRight(leaderURL, "/") + "/v1/cluster/internal/apply"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("cluster: build leader-forward request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.patToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.patToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cluster: leader-forward apply: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode == http.StatusServiceUnavailable {
		// 503 from the receiving node means it's not the leader anymore — let
		// the caller retry against a refreshed leader URL.
		return ErrNotLeader
	}
	return fmt.Errorf("cluster: leader-forward apply: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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

// Members returns gossip-known members (self included).
func (c *Cluster) Members() []Member { return c.gossip.members() }

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
	if c.ownerWatcherStop != nil {
		c.ownerWatcherStop()
	}
	if c.gossip != nil {
		if err := c.gossip.Close(); err != nil {
			firstErr = fmt.Errorf("cluster: gossip close: %w", err)
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
