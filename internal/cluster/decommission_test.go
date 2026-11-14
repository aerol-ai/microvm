package cluster

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeMoves is the worker side, recording what the leader asked.
type fakeMoves struct {
	mu        sync.Mutex
	released  []string
	stopped   []string
	noticed   []string
	prepared  []string
	releaseTo string // answer for every release ("released" by default)
	deadline  time.Time
	lifetimes map[string]string // the incarnation each release or stop named
}

func (f *fakeMoves) noteLifetimes(lifetimes map[string]string) {
	if f.lifetimes == nil {
		f.lifetimes = map[string]string{}
	}
	for id, inc := range lifetimes {
		f.lifetimes[id] = inc
	}
}

func (f *fakeMoves) ReleaseForMove(_ context.Context, ids []string, lifetimes map[string]string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noteLifetimes(lifetimes)
	out := map[string]string{}
	for _, id := range ids {
		f.released = append(f.released, id)
		out[id] = "released"
		if f.releaseTo != "" {
			out[id] = f.releaseTo
		}
	}
	return out
}

func (f *fakeMoves) StopForDecommission(_ context.Context, ids []string, lifetimes map[string]string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noteLifetimes(lifetimes)
	out := map[string]string{}
	for _, id := range ids {
		f.stopped = append(f.stopped, id)
		out[id] = "stopped"
	}
	return out
}

func (f *fakeMoves) PrepareMove(_ context.Context, spec models.CreateSandboxRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepared = append(f.prepared, spec.Image)
	return nil
}

func (f *fakeMoves) NoticeDecommission(_ context.Context, ids []string, deadline time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noticed = append(f.noticed, ids...)
	f.deadline = deadline
	return len(ids)
}

func TestRunMoveAction(t *testing.T) {
	ctx := context.Background()
	f := &fakeMoves{}
	if _, err := RunMoveAction(ctx, nil, MoveAction{Action: "release"}); !errors.Is(err, ErrNoMoveHandler) {
		t.Fatalf("nil handler = %v", err)
	}
	if out, err := RunMoveAction(ctx, f, MoveAction{Action: "release", IDs: []string{"a"}}); err != nil || out.Results["a"] != "released" {
		t.Fatalf("release = %+v %v", out, err)
	}
	if out, err := RunMoveAction(ctx, f, MoveAction{Action: "stop", IDs: []string{"b"}}); err != nil || out.Results["b"] != "stopped" {
		t.Fatalf("stop = %+v %v", out, err)
	}
	if out, err := RunMoveAction(ctx, f, MoveAction{Action: "notice", IDs: []string{"c"}, DeadlineUnix: 100}); err != nil || out.Count != 1 || f.deadline.Unix() != 100 {
		t.Fatalf("notice = %+v %v", out, err)
	}
	if _, err := RunMoveAction(ctx, f, MoveAction{Action: "prepare"}); err == nil {
		t.Fatal("prepare without a spec accepted")
	}
	if out, err := RunMoveAction(ctx, f, MoveAction{Action: "prepare", Spec: &models.CreateSandboxRequest{Image: "alpine"}}); err != nil || out.Error != "" {
		t.Fatalf("prepare = %+v %v", out, err)
	}
	if _, err := RunMoveAction(ctx, f, MoveAction{Action: "nuke"}); err == nil {
		t.Fatal("unknown action accepted")
	}
}

// A pass moves the recreate-policy sandboxes prepare-before-break, tells
// the owners of the rest once, and at the deadline stops them. Here the
// leader is the source too, so its own handler answers (a mixed node).
func TestEvacuateNodeMovesNoticesAndStops(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "ldr-ev", true, nil, func(cfg *config.Config) {
		cfg.NodeRole = config.NodeRoleMixed
	})
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	moves := &fakeMoves{}
	c.AttachMoveHandler(moves)

	room := capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384, CPUBudget: 8, MemoryBudgetMB: 16384, CanAdmit: true}
	self, _ := c.gossip.lookupMember(c.nodeID)
	self.Role = config.NodeRoleMixed
	target := Member{NodeID: "wkr-b", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-b", Capacity: room}
	seedGossipView(t, c, []Member{self, target})

	moved := placeFailoverPlacement(t, c, "sb-move", c.nodeID)
	payload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-stay", OwnerNodeID: c.nodeID, IncarnationID: "inc-stay"})
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}

	if _, err := c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{}); !errors.Is(err, ErrNodeNotDrained) {
		t.Fatalf("not drained = %v", err)
	}
	applyDrain(t, c, c.nodeID)
	deadline := time.Now().Add(time.Hour).Unix()
	res, err := c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{DeadlineUnix: deadline})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moved) != 1 || res.Moved[0] != "sb-move" || res.RemainingMovable != 0 || res.Remaining != 1 || res.Noticed != 1 || res.Done {
		t.Fatalf("first pass = %+v", res)
	}
	if owner, err := c.OwnerOf(moved.SandboxID); err != nil || owner.NodeID != "wkr-b" {
		t.Fatalf("sb-move owner = %+v %v", owner, err)
	}
	if strings.Join(moves.released, ",") != "sb-move" || strings.Join(moves.noticed, ",") != "sb-stay" || moves.deadline.Unix() != deadline {
		t.Fatalf("calls: released %v noticed %v deadline %v", moves.released, moves.noticed, moves.deadline)
	}

	// The deadline passed: the rest is stopped; owners are not told twice.
	res, err = c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{StopRemaining: true})
	if err != nil || res.Stopped != 1 || res.Noticed != 0 || len(moves.noticed) != 1 {
		t.Fatalf("deadline pass = %+v %v (noticed %v)", res, err, moves.noticed)
	}
	if strings.Join(moves.stopped, ",") != "sb-stay" {
		t.Fatalf("stopped %v", moves.stopped)
	}
	// Each stop named the lifetime the leader read (R10), so a worker can
	// refuse one that is no longer there.
	if moves.lifetimes["sb-move"] != moved.IncarnationID || moves.lifetimes["sb-stay"] != "inc-stay" {
		t.Fatalf("lifetimes sent %v, want sb-move=%s sb-stay=inc-stay", moves.lifetimes, moved.IncarnationID)
	}

	// A node gossip does not see alive is the dead-owner failover's.
	applyDrain(t, c, "ghost")
	if _, err := c.EvacuateNode(ctx, "ghost", EvacuateRequest{}); !errors.Is(err, ErrNodeNotAlive) {
		t.Fatalf("dead node = %v", err)
	}
	if _, err := c.EvacuateNode(ctx, " ", EvacuateRequest{}); err == nil {
		t.Fatal("empty node id accepted")
	}
}

// One executor: a move whose source did not release the sandbox does not
// move the placement.
func TestEvacuateNodeLeavesPlacementWhenReleaseFails(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "ldr-rf", true, nil, func(cfg *config.Config) {
		cfg.NodeRole = config.NodeRoleMixed
	})
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	moves := &fakeMoves{releaseTo: "error: stop failed"}
	c.AttachMoveHandler(moves)
	room := capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384, CPUBudget: 8, MemoryBudgetMB: 16384, CanAdmit: true}
	self, _ := c.gossip.lookupMember(c.nodeID)
	seedGossipView(t, c, []Member{self, {NodeID: "wkr-b", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-b", Capacity: room}})
	placeFailoverPlacement(t, c, "sb-keep", c.nodeID)
	applyDrain(t, c, c.nodeID)
	res, err := c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{Max: 100})
	if err != nil || len(res.Moved) != 0 || res.Failed["sb-keep"] == "" || res.RemainingMovable != 1 {
		t.Fatalf("pass = %+v %v", res, err)
	}
	if owner, err := c.OwnerOf("sb-keep"); err != nil || owner.NodeID != c.nodeID {
		t.Fatalf("placement moved without a release: %+v %v", owner, err)
	}
	// Without a handler at all, the release is refused the same way.
	c.AttachMoveHandler(nil)
	if res, _ := c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{}); res.Failed["sb-keep"] == "" {
		t.Fatalf("no handler: %+v", res)
	}
}

func TestEvacuateNodeNeedsTheLeader(t *testing.T) {
	if _, err := (&Cluster{}).EvacuateNode(context.Background(), "n", EvacuateRequest{}); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("no raft = %v", err)
	}
	var nilC *Cluster
	if _, err := nilC.EvacuateNode(context.Background(), "n", EvacuateRequest{}); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("nil = %v", err)
	}
}

func applyDrain(t *testing.T, c *Cluster, nodeID string) {
	t.Helper()
	raw, _ := encodeCommand(command{Op: opSetNodeDrainState, NodeID: nodeID, Drained: true})
	if err := c.raft.raft.Apply(raw, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
}
