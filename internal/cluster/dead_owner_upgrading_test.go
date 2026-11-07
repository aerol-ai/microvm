package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Regression test for "upgrading is not dying" (plans/kubectl-style-cluster-ops.md
// §6.2, eng D6, Codex eng finding 2): a node the rollout marked upgrading
// is skipped by the dead-owner loop until its step deadline, so a restart
// longer than the grace sets off no failover; past the deadline it is
// judged as any dead node.
func TestReconcileDeadOwnersSkipsUpgradingNodeUntilDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "ldr", true, nil, func(cfg *config.Config) {
		cfg.ClusterDeadOwnerGrace = 50 * time.Millisecond
	})
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	c.rolloutStop()
	ctx := context.Background()

	payload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-up", OwnerNodeID: "wkr"})
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(400 * time.Millisecond)
	rec := newTestRollout("r1", "v2", &RolloutNodeRecord{NodeID: "wkr", Tier: rolloutTierWorker, State: upgradewire.NodePending})
	if _, err := c.proposeRolloutCommand(ctx, RolloutCommand{Event: evApply, New: rec, Target: "v2"}); err != nil {
		t.Fatal(err)
	}
	if res, err := c.proposeRolloutNode(ctx, RolloutNodeUpdate{RolloutID: "r1", NodeID: "wkr", State: upgradewire.NodeUpgrading, Op: "op", DeadlineUnixNano: deadline.UnixNano()}); err != nil || !res.Changed {
		t.Fatalf("mark upgrading = %+v %v", res, err)
	}
	c.deadOwners.markDead("wkr", time.Now())

	// Well past the 50ms grace, but before the deadline: no failover.
	time.Sleep(150 * time.Millisecond)
	c.reconcileDeadOwners(ctx)
	if owner, err := c.OwnerOf("sb-up"); err != nil || owner.NodeID != "wkr" {
		t.Fatalf("an upgrading node's sandbox moved: %+v %v", owner, err)
	}
	// Past the deadline the node is dead like any other.
	time.Sleep(time.Until(deadline) + 50*time.Millisecond)
	c.reconcileDeadOwners(ctx)
	if _, err := c.OwnerOf("sb-up"); err != ErrOrphaned {
		t.Fatalf("past the deadline OwnerOf err = %v, want ErrOrphaned", err)
	}
}
