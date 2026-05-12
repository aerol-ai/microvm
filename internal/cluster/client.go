package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
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

	commitTimeout time.Duration

	// voterReconcileStop cancels the auto-voter reconcile goroutine on Close.
	voterReconcileStop context.CancelFunc

	// deadOwners tracks per-node "first observed dead" timestamps for the
	// dead-owner reconciler. Lives on the cluster (not in dead_owner.go) so
	// Close can stop its loop. See dead_owner.go for the reconciler logic.
	deadOwners        *deadOwnerTracker
	deadOwnerLoopStop context.CancelFunc
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

	gn, err := setupGossip(gossipSetupConfig{
		NodeID:         nodeID,
		BindAddr:       cfg.GossipBindAddr,
		AdvertiseAddr:  cfg.GossipAdvertiseAddr,
		APIURL:         cfg.SelfAPIAdvertiseURL,
		RaftAddr:       raftAdvertise,
		BootstrapPeers: cfg.BootstrapPeers,
		GossipInterval: cfg.ClusterCapacityGossipInterval,
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

	return c, nil
}

func (c *Cluster) SelfNodeID() string { return c.nodeID }
func (c *Cluster) SelfAPIURL() string { return c.apiURL }

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

// RecordPlacement commits sandboxID -> self into the FSM via raft. Idempotent.
// Must be called on the leader; if this node is not the leader, returns
// ErrNotLeader and the caller should retry against c.Leader() (the API
// wrapper handles this by forwarding the create to the leader if needed).
func (c *Cluster) RecordPlacement(ctx context.Context, sandboxID string) error {
	cmd := command{
		Op:          opPlace,
		SandboxID:   sandboxID,
		OwnerNodeID: c.nodeID,
		OwnerAPIURL: c.apiURL,
	}
	return c.applyCommand(ctx, cmd)
}

// DeletePlacement removes sandboxID from the placement map. Idempotent.
func (c *Cluster) DeletePlacement(ctx context.Context, sandboxID string) error {
	cmd := command{Op: opDelete, SandboxID: sandboxID}
	return c.applyCommand(ctx, cmd)
}

// AssertOwnership ensures every id in localIDs is recorded as owned by self.
// Used at boot. Idempotent. Best-effort: errors are logged but do not abort
// boot — the next reconcile loop will retry.
func (c *Cluster) AssertOwnership(ctx context.Context, localIDs []string) error {
	if len(localIDs) == 0 {
		return nil
	}
	// Wait briefly for a leader to exist so we can apply. If no leader emerges
	// (e.g. fresh non-bootstrap node still joining), defer to reconcile.
	if err := c.waitForLeader(ctx, 10*time.Second); err != nil {
		c.logger.Warn("cluster: AssertOwnership skipped, no leader yet", "err", err)
		return nil
	}
	var firstErr error
	for _, id := range localIDs {
		existing, ok := c.fsm.get(id)
		if ok && existing.OwnerNodeID == c.nodeID {
			continue
		}
		// Either no placement exists or another node thinks they own this
		// sandbox (unlikely but possible after a split-brain recovery). In
		// both cases we (re)claim — this node has the sandbox locally so it
		// IS the owner, and the FSM should reflect that.
		if err := c.RecordPlacement(ctx, id); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// applyCommand encodes and submits a raft log entry. On non-leader rejections
// we surface ErrNotLeader so callers can decide whether to forward.
func (c *Cluster) applyCommand(ctx context.Context, cmd command) error {
	if c.raft.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	payload, err := encodeCommand(cmd)
	if err != nil {
		return fmt.Errorf("cluster: encode command: %w", err)
	}
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
