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
	"github.com/aerol-ai/microvm/pkg/docker"
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

// gvisorWorker is one worker of a gvisorRig: its CheckpointMovesLabel ("",
// a worker that does not move gVisor sandboxes) and its CPUs.
type gvisorWorker struct {
	mode string
	cpus int
}

func gvisorRoom(cpus int) capacity.Snapshot {
	return capacity.Snapshot{HostCPUCores: cpus, HostMemoryTotalMB: 16384, CPUBudget: float64(cpus), MemoryBudgetMB: 16384, CanAdmit: true,
		SupportedRuntimes: []string{models.RuntimeGvisor}}
}

// gvisorRig is the leader, a mixed node that is also the decommission's
// source, with gVisor sandboxes on it, and other workers that each answer
// through their own fake.
type gvisorRig struct {
	c       *Cluster
	source  *fakeSnapshotMoves
	targets map[string]*fakeSnapshotMoves
	self    Member
	srcMode string
	cleanup func()
}

func newGvisorRig(t *testing.T, name, srcMode string, workers map[string]gvisorWorker, ids ...string) *gvisorRig {
	t.Helper()
	c, cleanup := newTestClusterWithCfg(t, name, true, nil, func(cfg *config.Config) { cfg.NodeRole = config.NodeRoleMixed })
	waitForLeader(t, c, 10*time.Second)
	g := &gvisorRig{c: c, source: &fakeSnapshotMoves{}, srcMode: srcMode, cleanup: cleanup}
	c.AttachMoveHandler(g.source)
	g.self, _ = c.gossip.lookupMember(c.nodeID)
	g.self.Role = config.NodeRoleMixed
	g.self.Capacity = gvisorRoom(8)
	g.seed(t, workers)
	for _, id := range ids {
		spec := models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128, Runtime: models.RuntimeGvisor}
		raw, err := encodeCommand(command{Op: opPlace, SandboxID: id, OwnerNodeID: c.nodeID, OwnerAPIURL: "http://" + c.nodeID, IncarnationID: "inc-" + id, Spec: &spec})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.raft.raft.Apply(raw, 2*time.Second).Error(); err != nil {
			t.Fatal(err)
		}
	}
	applyDrain(t, c, c.nodeID)
	return g
}

// seed sets the fleet: gossip, then the capacity heartbeats that carry the
// labels (gossip members carry none, as in production).
func (g *gvisorRig) seed(t *testing.T, workers map[string]gvisorWorker) {
	t.Helper()
	peers := map[string]MoveHandler{}
	if g.targets == nil {
		g.targets = map[string]*fakeSnapshotMoves{}
	}
	members := []Member{g.self}
	labelled := []Member{withCheckpointLabel(g.self, g.srcMode)}
	for id, w := range workers {
		if g.targets[id] == nil {
			g.targets[id] = &fakeSnapshotMoves{}
		}
		peers[id] = g.targets[id]
		m := Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, APIURL: "http://" + id, Capacity: gvisorRoom(w.cpus), Arch: g.self.Arch, Version: g.self.Version}
		members = append(members, m)
		labelled = append(labelled, withCheckpointLabel(m, w.mode))
	}
	g.c.moves.mu.Lock()
	g.c.moves.peers = peers
	g.c.moves.mu.Unlock()
	seedGossipView(t, g.c, members)
	seedCapacityHeartbeats(g.c, labelled)
}

func withCheckpointLabel(m Member, mode string) Member {
	if mode != "" {
		m.Capacity.Labels = map[string]string{CheckpointMovesLabel: mode}
	}
	return m
}

// The bug from the m1d-2 drill on EKS: a decommission never ended at its
// deadline when a sandbox counted as movable but could never move. Every
// pass past the deadline answered moved=0 failed=N remaining_movable=N
// stopped=0, and the operator, which ends a decommission past its deadline
// only once nothing movable is left, kept going for good. Both cases seen
// live: the source refused each move for good, and no other worker could
// restore the checkpoint. Now such a sandbox is one of the others from the
// first pass on: its owner is told, it is not tried again before the
// deadline, and at the deadline it is stopped with the rest, so nothing
// movable is left and the node can go.
func TestEvacuateNodeEndsAtTheDeadlineWhenASandboxCannotMove(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	for _, tc := range []struct {
		name    string
		raft    string
		workers map[string]gvisorWorker
		// release is the source's answer to a snapshot release ("": released).
		release string
		// reason is in each sandbox's Failed entry.
		reason string
		// releases is how many snapshot releases one try asks the source
		// for, per sandbox.
		releases int
	}{
		{
			name:     "warm-pool gVisor sandboxes: the source refuses each move for good (m1d-2 switch2)",
			raft:     "ldr-unmov-pool",
			workers:  map[string]gvisorWorker{"wkr-b": {mode: CheckpointMovesSingle, cpus: 8}},
			release:  MoveRefusedPrefix + "a sandbox from the warm pool moves by recreate only: its spec carries the pool's park socket",
			reason:   "moves by recreate only",
			releases: 1,
		},
		{
			name:     "gVisor on a single-mode worker whose every other worker is split (m1d-2 switch3)",
			raft:     "ldr-unmov-mode",
			workers:  map[string]gvisorWorker{"wkr-b": {mode: CheckpointMovesSplit, cpus: 8}, "wkr-c": {mode: CheckpointMovesSplit, cpus: 8}},
			reason:   "restores gVisor checkpoints in privilege mode split, the source saves them in single",
			releases: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGvisorRig(t, tc.raft, CheckpointMovesSingle, tc.workers, "sb-a", "sb-b")
			defer g.cleanup()
			g.source.releaseTo = tc.release
			ctx := context.Background()
			c := g.c
			deadline := time.Now().Add(time.Hour).Unix()
			for pass := 1; pass <= 2; pass++ {
				res, err := c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{DeadlineUnix: deadline})
				if err != nil {
					t.Fatal(err)
				}
				if len(res.Moved) != 0 || res.RemainingMovable != 0 || res.Remaining != 2 || res.Stopped != 0 || res.Done {
					t.Fatalf("pass %d before the deadline = %+v", pass, res)
				}
				for _, id := range []string{"sb-a", "sb-b"} {
					if !strings.HasPrefix(res.Failed[id], "not moved: ") || !strings.Contains(res.Failed[id], tc.reason) {
						t.Fatalf("pass %d: %s failed %q, want %q", pass, id, res.Failed[id], tc.reason)
					}
				}
				// The owners are told once, as for any sandbox that stays.
				if want := map[int]int{1: 2, 2: 0}[pass]; res.Noticed != want {
					t.Fatalf("pass %d noticed %d, want %d", pass, res.Noticed, want)
				}
			}
			// A refusal for good is not asked again; nothing was stopped
			// before the deadline.
			if got := g.source.countCalls("release "); got != 2*tc.releases {
				t.Fatalf("releases %d, want %d (%v)", got, 2*tc.releases, g.source.calls)
			}
			if len(g.source.stopped) != 0 || g.source.deadline.Unix() != deadline {
				t.Fatalf("stopped %v before the deadline; notice deadline %v", g.source.stopped, g.source.deadline)
			}
			for id, w := range g.targets {
				if len(w.calls) != 0 {
					t.Fatalf("%s was asked %v", id, w.calls)
				}
			}

			// The deadline: they stop with the rest, and nothing movable is
			// left, which is what ends the decommission.
			res, err := c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{StopRemaining: true})
			if err != nil || res.Stopped != 2 || res.RemainingMovable != 0 || res.Remaining != 2 {
				t.Fatalf("deadline pass = %+v %v", res, err)
			}
			if got := strings.Join(g.source.stopped, ","); got != "sb-a,sb-b" {
				t.Fatalf("stopped %s", got)
			}
			if g.source.lifetimes["sb-a"] != "inc-sb-a" {
				t.Fatalf("the stop named lifetimes %v (R10)", g.source.lifetimes)
			}

			// A new leader remembers none of it: it asks each source once
			// more and tells the owners again, and the pass still ends with
			// nothing movable.
			c.keepDecommission(c.nodeID, nil)
			res, err = c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{StopRemaining: true})
			if err != nil || res.Stopped != 2 || res.RemainingMovable != 0 || res.Noticed != 2 {
				t.Fatalf("a new leader's deadline pass = %+v %v", res, err)
			}
			if got := g.source.countCalls("release "); got != 4*tc.releases {
				t.Fatalf("releases %d after a leader change, want %d", got, 4*tc.releases)
			}
		})
	}
}

// A failure that may pass, here the target's import, is retried on every
// pass before the deadline, as before. Past the deadline the sandbox gets
// one more try; when that fails too, it stops with the rest and no longer
// counts as movable, so the decommission ends. A pass its caller cuts
// short is not that try.
func TestEvacuateNodeRetriesAPassingFailureUntilTheDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, source, target, cleanup := snapshotMovePair(t, "ldr-snap-retry")
	defer cleanup()
	target.importErr = errors.New("disk full")
	ctx := context.Background()
	for pass := 1; pass <= 3; pass++ {
		res, err := c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{})
		if err != nil || res.RemainingMovable != 1 || res.Remaining != 0 || res.Noticed != 0 || res.Done {
			t.Fatalf("pass %d = %+v %v", pass, res, err)
		}
		if why := res.Failed["sb-vm"]; !strings.Contains(why, "disk full") || strings.HasPrefix(why, "not moved") {
			t.Fatalf("pass %d failed %q, want a retried import error", pass, why)
		}
	}
	if got := target.countCalls("import "); got != 3 {
		t.Fatalf("imports %d, want one per pass", got)
	}

	// A deadline pass whose caller gives up mid-move: no verdict.
	cctx, cancel := context.WithCancel(ctx)
	target.duringImport = cancel
	res, err := c.EvacuateNode(cctx, c.nodeID, EvacuateRequest{StopRemaining: true})
	target.duringImport = nil
	if err != nil || res.RemainingMovable != 1 || res.Stopped != 0 || strings.HasPrefix(res.Failed["sb-vm"], "not moved") {
		t.Fatalf("a cut-short deadline pass = %+v %v", res, err)
	}

	// The deadline: one more try, which fails, and it stops with the rest.
	res, err = c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{StopRemaining: true})
	if err != nil || res.RemainingMovable != 0 || res.Remaining != 1 || res.Stopped != 1 || res.Noticed != 1 {
		t.Fatalf("deadline pass = %+v %v", res, err)
	}
	if why := res.Failed["sb-vm"]; !strings.Contains(why, "past the deadline") || !strings.Contains(why, "disk full") {
		t.Fatalf("deadline pass failed %q", why)
	}
	if strings.Join(source.stopped, ",") != "sb-vm" || target.countCalls("import ") != 5 {
		t.Fatalf("stopped %v, imports %d", source.stopped, target.countCalls("import "))
	}
	if owner, err := c.OwnerOf("sb-vm"); err != nil || owner.NodeID != c.nodeID {
		t.Fatalf("owner %+v %v: a failed move moved the placement", owner, err)
	}
	// No more tries after that one: the next pass only stops it again.
	res, err = c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{StopRemaining: true})
	if err != nil || res.RemainingMovable != 0 || res.Stopped != 1 || target.countCalls("import ") != 5 {
		t.Fatalf("pass after the deadline = %+v %v, imports %d", res, err, target.countCalls("import "))
	}

	// Uncordoned, the node keeps its sandboxes, and a later decommission
	// of it starts fresh: the give-up does not carry over.
	if err := c.SetNodeDrainState(ctx, c.nodeID, false); err != nil {
		t.Fatal(err)
	}
	p, _ := c.fsm.get("sb-vm")
	if why := c.unmovableReason(c.nodeID, p); why != "" {
		t.Fatalf("still given up after an uncordon: %q", why)
	}
	applyDrain(t, c, c.nodeID)
	res, err = c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{})
	if err != nil || res.RemainingMovable != 1 || target.countCalls("import ") != 6 {
		t.Fatalf("a later decommission = %+v %v, imports %d", res, err, target.countCalls("import "))
	}
}

// Review of #1435: a move that outlasts the pass. The evacuate route gives
// a pass 5 minutes, but a VM's import may take 15, and every pass past the
// deadline tried the same first 8 sandboxes. When the pass ran out of its
// own time, the give-up read it as a caller that went away, so the slow
// move was never given up and the decommission never ended; one slow move
// also held back the give-up of every other failed move in its batch. Now
// the pass cuts its moves itself, a little before its caller's deadline,
// judges each failed move on its own, and still stops them in the same
// pass. Only a caller that went away is not a try.
func TestEvacuateNodeGivesUpAMoveThatOutlastsThePass(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	for _, tc := range []struct {
		name string
		raft string
		// hold is how long sb-vm's import runs; pastCtx: whatever its
		// context says.
		hold    time.Duration
		pastCtx bool
		// pass is the caller's context for the deadline pass.
		pass       func() (context.Context, context.CancelFunc)
		wantGiveUp bool
	}{
		{
			name: "the pass's own budget cuts a slow import", raft: "ldr-bound-own", hold: time.Minute,
			pass: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 500*time.Millisecond)
			},
			wantGiveUp: true,
		},
		{
			name: "the evacuate route's bound ends the pass mid-move", raft: "ldr-bound-route", hold: 400 * time.Millisecond, pastCtx: true,
			pass: func() (context.Context, context.CancelFunc) {
				return context.WithTimeoutCause(context.Background(), 300*time.Millisecond, ErrEvacuatePassTimeout)
			},
			wantGiveUp: true,
		},
		{
			// The reviewer's repro: a plain deadline, a move that ignores it.
			name: "a caller's deadline ends the pass mid-move", raft: "ldr-bound-plain", hold: 400 * time.Millisecond, pastCtx: true,
			pass: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 300*time.Millisecond)
			},
			wantGiveUp: true,
		},
		{
			name: "the caller goes away mid-move: not a try", raft: "ldr-bound-gone", hold: time.Minute,
			pass: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(100*time.Millisecond, cancel)
				return ctx, cancel
			},
			wantGiveUp: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, source, target, cleanup := snapshotMovePair(t, tc.raft)
			defer cleanup()
			// A second sandbox in the same batch, whose import fails at once.
			placeFirecracker(t, c, "sb-fast", c.nodeID, models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128})
			target.importHold = map[string]time.Duration{"sb-vm": tc.hold, "sb-fast": time.Millisecond}
			target.holdPastCtx = tc.pastCtx
			target.importErr = errors.New("disk full")

			ctx, cancel := tc.pass()
			defer cancel()
			start := time.Now()
			res, err := c.EvacuateNode(ctx, c.nodeID, EvacuateRequest{StopRemaining: true})
			if took := time.Since(start); took > 5*time.Second {
				t.Fatalf("the pass took %s", took)
			}
			if !tc.wantGiveUp {
				// Not a try: both stay movable for the next pass, nothing stopped.
				if res.RemainingMovable != 2 || res.Stopped != 0 || len(source.stopped) != 0 {
					t.Fatalf("pass = %+v %v, stopped %v", res, err, source.stopped)
				}
				return
			}
			if err != nil || res.RemainingMovable != 0 || res.Remaining != 2 || res.Stopped != 2 {
				t.Fatalf("pass = %+v %v", res, err)
			}
			for _, id := range []string{"sb-fast", "sb-vm"} {
				if !strings.Contains(res.Failed[id], "past the deadline") {
					t.Fatalf("%s failed %q", id, res.Failed[id])
				}
			}
			if strings.Join(source.stopped, ",") != "sb-fast,sb-vm" {
				t.Fatalf("stopped %v, want both in the same pass", source.stopped)
			}
		})
	}
}

// A gVisor checkpoint goes only to a worker of the source's privilege
// mode. With none, the sandbox does not count as movable; a worker of its
// mode that joins makes it movable again on the next pass, and the move
// picks that worker even though one of the other mode has more room.
func TestEvacuateNodeMovesAGvisorSandboxOnlyToItsMode(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	split := gvisorWorker{mode: CheckpointMovesSplit, cpus: 64}
	g := newGvisorRig(t, "ldr-ckpt-mode", CheckpointMovesSingle, map[string]gvisorWorker{"wkr-b": split}, "sb-g")
	defer g.cleanup()
	c := g.c
	res, err := c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{})
	if err != nil || res.RemainingMovable != 0 || res.Remaining != 1 || !strings.Contains(res.Failed["sb-g"], "privilege mode split") {
		t.Fatalf("pass with no worker of its mode = %+v %v", res, err)
	}

	g.seed(t, map[string]gvisorWorker{"wkr-b": split, "wkr-c": {mode: CheckpointMovesSingle, cpus: 8}})
	res, err = c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{})
	if err != nil || strings.Join(res.Moved, ",") != "sb-g" || res.RemainingMovable != 0 || res.Remaining != 0 || !res.Done {
		t.Fatalf("pass with a worker of its mode = %+v %v", res, err)
	}
	if owner, err := c.OwnerOf("sb-g"); err != nil || owner.NodeID != "wkr-c" {
		t.Fatalf("sb-g owner = %+v %v, want wkr-c", owner, err)
	}
	if len(g.targets["wkr-b"].calls) != 0 {
		t.Fatalf("the split worker was asked %v", g.targets["wkr-b"].calls)
	}
}

// A recreate-policy sandbox whose image no other node can run (kept on
// this node only, or built here) does not count as movable: no target
// selection takes it elsewhere, so before it kept the decommission going
// past its deadline too. It stays with the others; the rest still move.
func TestEvacuateNodeKeepsANodeBoundImage(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "ldr-imgbound", true, nil, func(cfg *config.Config) { cfg.NodeRole = config.NodeRoleMixed })
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	moves := &fakeMoves{}
	c.AttachMoveHandler(moves)
	room := capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384, CPUBudget: 8, MemoryBudgetMB: 16384, CanAdmit: true}
	self, _ := c.gossip.lookupMember(c.nodeID)
	self.Role = config.NodeRoleMixed
	seedGossipView(t, c, []Member{self, {NodeID: "wkr-b", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-b", Capacity: room}})
	enc, ok := models.EncodeNodeAffinity(c.nodeID)
	if !ok {
		t.Fatalf("node id %q has no affinity encoding", c.nodeID)
	}
	for id, edit := range map[string]func(*models.CreateSandboxRequest){
		"sb-ok":    func(*models.CreateSandboxRequest) {},
		"sb-local": func(s *models.CreateSandboxRequest) { s.ImageDistributionMode = models.ImageDistributionLocalOnly },
		"sb-built": func(s *models.CreateSandboxRequest) {
			s.Image = docker.BuiltImageNamespace + "/node-" + enc + "/abc:latest"
		},
	} {
		p := failoverRecreatePlacement(id, c.nodeID)
		edit(p.Spec)
		raw, err := encodeCommand(command{Op: opPlace, SandboxID: id, OwnerNodeID: c.nodeID, OwnerAPIURL: "http://" + c.nodeID, IncarnationID: p.IncarnationID, Spec: p.Spec})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.raft.raft.Apply(raw, 2*time.Second).Error(); err != nil {
			t.Fatal(err)
		}
	}
	applyDrain(t, c, c.nodeID)
	res, err := c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{})
	if err != nil || strings.Join(res.Moved, ",") != "sb-ok" || res.RemainingMovable != 0 || res.Remaining != 2 || res.Noticed != 2 {
		t.Fatalf("pass = %+v %v", res, err)
	}
	if !strings.Contains(res.Failed["sb-local"], "local_only") || !strings.Contains(res.Failed["sb-built"], "built on this node") {
		t.Fatalf("failed %v", res.Failed)
	}
	if strings.Join(moves.released, ",") != "sb-ok" {
		t.Fatalf("released %v", moves.released)
	}
	res, err = c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{StopRemaining: true})
	if err != nil || res.Stopped != 2 || res.RemainingMovable != 0 {
		t.Fatalf("deadline pass = %+v %v", res, err)
	}
}

// What a leader remembers of a decommission: who was told, and which
// sandboxes it no longer moves, per lifetime; pruned to what the node still
// owns, and dropped with the node.
func TestDecommissionMemory(t *testing.T) {
	c := &Cluster{}
	p := Placement{SandboxID: "sb-a", IncarnationID: "inc-1"}
	if c.unmovableReason("n1", p) != "" {
		t.Fatal("a reason before any was recorded")
	}
	c.markUnmovable("n1", p, "the source refuses to move it")
	for _, tc := range []struct {
		name string
		node string
		p    Placement
		want string
	}{
		{"the same lifetime", "n1", p, "the source refuses to move it"},
		{"a new lifetime is asked again", "n1", Placement{SandboxID: "sb-a", IncarnationID: "inc-2"}, ""},
		{"another sandbox", "n1", Placement{SandboxID: "sb-b", IncarnationID: "inc-1"}, ""},
		{"another node", "n2", p, ""},
	} {
		if got := c.unmovableReason(tc.node, tc.p); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := strings.Join(c.noticeOnce("n1", []string{"sb-a", "sb-b"}), ","); got != "sb-a,sb-b" {
		t.Fatalf("first notice %s", got)
	}
	if got := c.noticeOnce("n1", []string{"sb-a", "sb-b", "sb-c"}); strings.Join(got, ",") != "sb-c" {
		t.Fatalf("second notice %v, want only the new one", got)
	}
	// sb-a left the node: forgotten, so a new owner row is told again.
	c.keepDecommission("n1", map[string]bool{"sb-b": true, "sb-c": true})
	if c.unmovableReason("n1", p) != "" || len(c.noticeOnce("n1", []string{"sb-a"})) != 1 {
		t.Fatal("a sandbox that left the node is still remembered")
	}
	c.keepDecommission("n1", nil)
	c.keepDecommission("n-never", nil)
	if len(c.moves.decom) != 0 {
		t.Fatalf("a deleted node is still remembered: %v", c.moves.decom)
	}
}

// A pass cuts its moves at its budget, or a little before its caller's
// deadline, keeping back at most a fifth of the caller's time.
func TestPassMovesDeadline(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	at := func(d time.Duration) context.Context {
		ctx, cancel := context.WithDeadline(context.Background(), now.Add(d))
		t.Cleanup(cancel)
		return ctx
	}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want time.Duration
	}{
		{"no caller deadline: the budget", context.Background(), evacuateMovesBudget},
		{"the evacuate route's 5 minutes", at(5 * time.Minute), 5*time.Minute - evacuateWrapUp},
		{"a long caller deadline: the budget", at(time.Hour), evacuateMovesBudget},
		{"a short one keeps a fifth back", at(time.Second), 800 * time.Millisecond},
		{"one already past", at(-time.Second), -time.Second},
	} {
		if got := passMovesDeadline(tc.ctx, now).Sub(now); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestPassTried(t *testing.T) {
	live := context.Background()
	own, cancelOwn := context.WithTimeoutCause(context.Background(), time.Nanosecond, ErrEvacuatePassTimeout)
	defer cancelOwn()
	plain, cancelPlain := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelPlain()
	gone, cancelGone := context.WithCancel(context.Background())
	cancelGone()
	<-own.Done()
	<-plain.Done()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{"a live pass", live, true},
		{"out of the pass's own time", own, true},
		{"a caller's own deadline", plain, true},
		{"a caller that went away", gone, false},
	} {
		if got := passTried(tc.ctx); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// An uncordon, proposed on the leader, drops what it remembers of the
// node's decommission; nothing else does.
func TestForgetUncordoned(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cmd    command
		forget bool
	}{
		{"uncordon", command{Op: opSetNodeDrainState, NodeID: " n1 ", Drained: false}, true},
		{"cordon", command{Op: opSetNodeDrainState, NodeID: "n1", Drained: true}, false},
		{"another node", command{Op: opSetNodeDrainState, NodeID: "n2"}, false},
		{"another op", command{Op: opReassign, NodeID: "n1"}, false},
	} {
		c := &Cluster{}
		p := Placement{SandboxID: "sb-a", IncarnationID: "inc-1"}
		c.markUnmovable("n1", p, "its move past the deadline failed")
		c.forgetUncordoned(tc.cmd)
		if forgot := c.unmovableReason("n1", p) == ""; forgot != tc.forget {
			t.Errorf("%s: forgot %v, want %v", tc.name, forgot, tc.forget)
		}
	}
}

// A source's answer to a release: "refused: ..." is a refusal for good;
// anything else is an error the next pass tries again.
func TestReleaseRefusal(t *testing.T) {
	var refused *moveRefusedError
	err := releaseRefusal("wkr-a", MoveRefusedPrefix+"a sandbox from the warm pool moves by recreate only")
	if !errors.As(err, &refused) || refused.reason != "a sandbox from the warm pool moves by recreate only" ||
		err.Error() != "wkr-a refuses to move it: a sandbox from the warm pool moves by recreate only" {
		t.Fatalf("refusal = %v", err)
	}
	for _, r := range []string{"error: runsc: checkpoint timed out", "stopped", "", "refused"} {
		if err := releaseRefusal("wkr-a", r); errors.As(err, &refused) || !strings.HasPrefix(err.Error(), "release on wkr-a: ") {
			t.Errorf("%q = %v, want a plain error", r, err)
		}
	}
}

func TestImageStaysOn(t *testing.T) {
	enc, _ := models.EncodeNodeAffinity("wkr-a")
	built := docker.BuiltImageNamespace + "/node-" + enc + "/abc:latest"
	for _, tc := range []struct {
		name string
		spec *models.CreateSandboxRequest
		want string
	}{
		{"no spec", nil, ""},
		{"a registry image", &models.CreateSandboxRequest{Image: "alpine"}, ""},
		{"kept on this node only", &models.CreateSandboxRequest{Image: "alpine", ImageDistributionMode: models.ImageDistributionLocalOnly}, "local_only"},
		{"built on this node", &models.CreateSandboxRequest{Image: built}, "built on this node"},
	} {
		got := imageStaysOn(Placement{Spec: tc.spec}, "wkr-a")
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := imageStaysOn(Placement{Spec: &models.CreateSandboxRequest{Image: built}}, "wkr-b"); got != "" {
		t.Fatalf("an image built on another node: %q", got)
	}
}
