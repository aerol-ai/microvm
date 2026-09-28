package cluster

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestAssertOwnershipGuardsAndStalePaths(t *testing.T) {
	c := &Cluster{
		nodeID: "self",
		fsm:    newPlacementFSM(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := c.AssertOwnership(context.Background(), nil); err != nil {
		t.Fatalf("empty local: %v", err)
	}
}

func TestRemoveMemberLocalLastVoterAndForce(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-rm", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	// Last voter cannot be removed.
	if err := leader.removeMemberLocal(context.Background(), leader.nodeID, true); !errors.Is(err, ErrLastVoter) {
		t.Fatalf("remove self last voter=%v", err)
	}

	follower, cleanupFollower := newTestCluster(t, "fol-rm", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	// Alive without force.
	if err := leader.removeMemberLocal(context.Background(), follower.nodeID, false); !errors.Is(err, ErrMemberStillAlive) {
		t.Fatalf("alive without force=%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := leader.removeMemberLocal(ctx, follower.nodeID, true); err != nil {
		t.Fatalf("force remove: %v", err)
	}
}

func TestDeriveInternalAdvertiseURLBranches(t *testing.T) {
	if got := deriveInternalAdvertiseURL("https://op.example/", "", ""); got != "https://op.example" {
		t.Fatalf("operator override=%q", got)
	}
	if got := deriveInternalAdvertiseURL("", "10.1.2.3:9443", "0.0.0.0:9443"); got != "https://10.1.2.3:9443" {
		t.Fatalf("wildcard bound prefer listen=%q", got)
	}
	if got := deriveInternalAdvertiseURL("", "0.0.0.0:9443", "0.0.0.0:9443"); got != "https://127.0.0.1:9443" {
		t.Fatalf("both wildcard=%q", got)
	}
	if got := deriveInternalAdvertiseURL("", "host-only", ""); !strings.HasPrefix(got, "https://") {
		t.Fatalf("bare host=%q", got)
	}
	if h, p := splitHostForAdvertise(""); h != "" || p != "" {
		t.Fatalf("empty split=%q %q", h, p)
	}
	if h, p := splitHostForAdvertise("barehost"); h != "barehost" || p != "" {
		t.Fatalf("bare split=%q %q", h, p)
	}
}

func TestRemoveMemberLocalExpiredDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-rm2", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-rm2", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	leader.gossip.memberIndex.upsert(Member{NodeID: follower.nodeID, Alive: false, Role: config.NodeRoleServer, RaftAddr: "x", APIURL: follower.apiURL})
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	_ = leader.removeMemberLocal(ctx, follower.nodeID, true)
}

func TestClientCloseStopFuncs(t *testing.T) {
	stopped := 0
	stop := func() { stopped++ }
	c := &Cluster{
		voterReconcileStop: stop,
		deadOwnerLoopStop:  stop,
		reservationGCStop:  stop,
		capacityLeaseStop:  stop,
		ownerWatcherStop:   stop,
		logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if stopped != 5 {
		t.Fatalf("stopped=%d", stopped)
	}
}

func TestDeriveInternalAdvertiseEmptyHostPort(t *testing.T) {
	// bound addr that parses to empty host shouldn't happen often; exercise port-empty path
	// via bare host already covered — force host=="" branch via listen/bound both empty-ish.
	if got := deriveInternalAdvertiseURL("", "", ":8443"); got != "https://127.0.0.1:8443" {
		t.Fatalf("empty hosts with port=%q", got)
	}
}
