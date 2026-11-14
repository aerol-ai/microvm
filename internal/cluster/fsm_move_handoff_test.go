package cluster

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// placeForHandoff places sb-m (incarnation inc-m) on node-a at index 1.
func placeForHandoff(t *testing.T, f *placementFSM) {
	t.Helper()
	if got := applyDenyLogAt(t, f, 1, command{Op: opPlace, SandboxID: "sb-m", OwnerNodeID: "node-a", IncarnationID: "inc-m",
		Spec: &models.CreateSandboxRequest{Image: "alpine", Runtime: models.RuntimeFirecracker}}); got != nil {
		t.Fatalf("place: %v", got)
	}
}

func beginHandoff(token, owner string) command {
	return command{Op: opMoveHandoff, SandboxID: "sb-m", ExpectedIncarnationID: "inc-m", ExpectedOwnerNodeID: owner, ExpectedOwnerNodeIDSet: true, MoveToken: token}
}

func abortHandoff(owner string) command {
	return abortMoveHandoffCommand("sb-m", "inc-m", owner)
}

func swapWith(token string) command {
	return command{Op: opReassign, SandboxID: "sb-m", OwnerNodeID: "node-b", ExpectedIncarnationID: "inc-m",
		ExpectedOwnerNodeID: "node-a", ExpectedOwnerNodeIDSet: true, ExpectedMoveToken: token, ReassignCause: reassignCauseFailover}
}

func ownerOf(t *testing.T, f *placementFSM) string {
	t.Helper()
	p, ok := f.get("sb-m")
	if !ok {
		t.Fatal("sb-m is gone")
	}
	return p.OwnerNodeID
}

// The review's N3: a source whose fence lapsed during a slow import aborts
// the handoff before it starts the sandbox again, and the import's late
// swap is then refused, so one copy runs. In the other order the swap wins
// and the abort is refused, so the source leaves its copy stopped.
func TestPlacementFSMMoveHandoffSwapAndAbortExclude(t *testing.T) {
	t.Run("abort first: the late swap is refused", func(t *testing.T) {
		f := newPlacementFSM()
		placeForHandoff(t, f)
		if got := applyDenyLogAt(t, f, 2, beginHandoff("tok-1", "node-a")); got != nil {
			t.Fatalf("begin: %v", got)
		}
		if f.moveHandoffToken("sb-m") != "tok-1" {
			t.Fatal("the handoff was not recorded")
		}
		if got := applyDenyLogAt(t, f, 3, abortHandoff("node-a")); got != nil {
			t.Fatalf("abort: %v", got)
		}
		if got := applyDenyLogAt(t, f, 4, swapWith("tok-1")); !errors.Is(asError(got), ErrMoveHandoffAborted) {
			t.Fatalf("late swap = %v, want ErrMoveHandoffAborted", got)
		}
		if ownerOf(t, f) != "node-a" {
			t.Fatal("a refused swap moved the placement")
		}
	})
	t.Run("swap first: the abort is refused", func(t *testing.T) {
		f := newPlacementFSM()
		placeForHandoff(t, f)
		applyDenyLogAt(t, f, 2, beginHandoff("tok-1", "node-a"))
		got := applyDenyLogAt(t, f, 3, swapWith("tok-1"))
		if res, ok := got.(reassignApplyResult); !ok || !res.Changed {
			t.Fatalf("swap = %#v, want applied", got)
		}
		if ownerOf(t, f) != "node-b" || f.moveHandoffToken("sb-m") != "" {
			t.Fatalf("after the swap: owner %s, handoff %q", ownerOf(t, f), f.moveHandoffToken("sb-m"))
		}
		if got := applyDenyLogAt(t, f, 4, abortHandoff("node-a")); !errors.Is(asError(got), ErrMoveHandoffMoved) {
			t.Fatalf("abort after the swap = %v, want ErrMoveHandoffMoved", got)
		}
	})
	t.Run("a swap with another move's token is refused", func(t *testing.T) {
		f := newPlacementFSM()
		placeForHandoff(t, f)
		applyDenyLogAt(t, f, 2, beginHandoff("tok-1", "node-a"))
		applyDenyLogAt(t, f, 3, beginHandoff("tok-2", "node-a")) // a later pass's move
		if got := applyDenyLogAt(t, f, 4, swapWith("tok-1")); !errors.Is(asError(got), ErrMoveHandoffAborted) {
			t.Fatalf("the first move's swap = %v, want ErrMoveHandoffAborted", got)
		}
		if got := applyDenyLogAt(t, f, 5, swapWith("tok-2")); asError(got) != nil {
			t.Fatalf("the current move's swap = %v", got)
		}
	})
}

// What else a handoff meets: a reassign without a token (a failover, a
// leader from before the handoff) and an orphaning end it; a delete drops
// it; the begin and abort check the lifetime and owner like any fenced
// write; an abort with nothing open is a no-op that still proves ownership.
func TestPlacementFSMMoveHandoffEdges(t *testing.T) {
	t.Run("begin and abort check lifetime, owner and row", func(t *testing.T) {
		f := newPlacementFSM()
		placeForHandoff(t, f)
		for _, tc := range []struct {
			name string
			cmd  command
			want error
		}{
			{"no lifetime", command{Op: opMoveHandoff, SandboxID: "sb-m", ExpectedOwnerNodeID: "node-a", ExpectedOwnerNodeIDSet: true, MoveToken: "t"}, ErrIncarnationConflict},
			{"no owner expectation", command{Op: opMoveHandoff, SandboxID: "sb-m", ExpectedIncarnationID: "inc-m", MoveToken: "t"}, ErrIncarnationConflict},
			{"another lifetime", command{Op: opMoveHandoff, SandboxID: "sb-m", ExpectedIncarnationID: "inc-other", ExpectedOwnerNodeID: "node-a", ExpectedOwnerNodeIDSet: true}, ErrIncarnationConflict},
			{"another owner", beginHandoff("t", "node-c"), ErrMoveHandoffMoved},
			{"an unknown sandbox", command{Op: opMoveHandoff, SandboxID: "sb-none", ExpectedIncarnationID: "inc-m", ExpectedOwnerNodeID: "node-a", ExpectedOwnerNodeIDSet: true}, ErrUnknownSandbox},
		} {
			if got := applyDenyLogAt(t, f, 2, tc.cmd); !errors.Is(asError(got), tc.want) {
				t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
			}
		}
		if f.moveHandoffToken("sb-m") != "" {
			t.Fatal("a refused begin opened a handoff")
		}
		if got := applyDenyLogAt(t, f, 3, abortHandoff("node-a")); got != nil {
			t.Fatalf("abort with nothing open: %v", got)
		}
	})
	t.Run("a reassign without a token ends the handoff", func(t *testing.T) {
		f := newPlacementFSM()
		placeForHandoff(t, f)
		applyDenyLogAt(t, f, 2, beginHandoff("tok-1", "node-a"))
		if got := applyDenyLogAt(t, f, 3, swapWith("")); asError(got) != nil {
			t.Fatalf("tokenless reassign: %v", got)
		}
		if f.moveHandoffToken("sb-m") != "" {
			t.Fatal("the handoff outlived a reassign")
		}
	})
	t.Run("an orphaning ends it", func(t *testing.T) {
		f := newPlacementFSM()
		placeForHandoff(t, f)
		applyDenyLogAt(t, f, 2, beginHandoff("tok-1", "node-a"))
		if got := applyDenyLogAt(t, f, 3, command{Op: opOrphanOwner, NodeID: "node-a"}); asError(got) != nil {
			t.Fatalf("orphan: %v", got)
		}
		if f.moveHandoffToken("sb-m") != "" {
			t.Fatal("the handoff outlived its owner's orphaning")
		}
	})
	t.Run("a delete drops it", func(t *testing.T) {
		f := newPlacementFSM()
		placeForHandoff(t, f)
		applyDenyLogAt(t, f, 2, beginHandoff("tok-1", "node-a"))
		if got := applyDenyLogAt(t, f, 3, command{Op: opDelete, SandboxID: "sb-m", ExpectedIncarnationID: "inc-m"}); asError(got) != nil {
			t.Fatalf("delete: %v", got)
		}
		if f.moveHandoffToken("sb-m") != "" || len(f.moveHandoffs) != 0 {
			t.Fatal("the handoff outlived its placement")
		}
	})
	t.Run("a placement being deleted opens none", func(t *testing.T) {
		f := newPlacementFSM()
		placeForHandoff(t, f)
		if got := applyDenyLogAt(t, f, 2, command{Op: opBeginDelete, SandboxID: "sb-m", ExpectedIncarnationID: "inc-m", ExpectedOwnerNodeID: "node-a", ExpectedOwnerNodeIDSet: true}); asError(got) != nil {
			t.Fatalf("begin delete: %v", got)
		}
		if got := applyDenyLogAt(t, f, 3, beginHandoff("tok-1", "node-a")); !errors.Is(asError(got), ErrReservationConflict) {
			t.Fatalf("begin on a deleting placement = %v, want ErrReservationConflict", got)
		}
	})
}

// The handoff is FSM state: a replica restored from a snapshot refuses the
// same late swap the live one does, and one of a placement the snapshot no
// longer has is not carried.
func TestPlacementFSMMoveHandoffSurvivesRestore(t *testing.T) {
	src := newPlacementFSM()
	placeForHandoff(t, src)
	applyDenyLogAt(t, src, 2, beginHandoff("tok-1", "node-a"))
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]*placementFSM{"live": src, "restored": restored} {
		if f.moveHandoffToken("sb-m") != "tok-1" {
			t.Fatalf("%s replica lost the handoff", name)
		}
		applyDenyLogAt(t, f, 3, abortHandoff("node-a"))
		if got := applyDenyLogAt(t, f, 4, swapWith("tok-1")); !errors.Is(asError(got), ErrMoveHandoffAborted) {
			t.Fatalf("%s replica: late swap = %v", name, got)
		}
	}
	// No placement, no handoff; an empty map snapshots as none.
	g := newPlacementFSM()
	g.restoreMoveHandoffsLocked(map[string]string{"sb-gone": "tok", "sb-m": ""})
	if g.moveHandoffs != nil || g.moveHandoffsSnapshotLocked() != nil {
		t.Fatalf("restored handoffs = %v", g.moveHandoffs)
	}
}

// A handoff's verdicts survive a hop as text.
func TestClassifyAbortError(t *testing.T) {
	if classifyAbortError(nil) != nil {
		t.Fatal("nil")
	}
	for _, tc := range []struct {
		in   error
		want error
	}{
		{fmt.Errorf("x: %w", ErrClusterVersion), ErrMoveHandoffUnsupported},
		{errors.New("status 500: " + ErrClusterVersion.Error()), ErrMoveHandoffUnsupported},
		{errors.New("status 409: " + ErrMoveHandoffMoved.Error()), ErrMoveHandoffMoved},
		{fmt.Errorf("%w: sb", ErrUnknownSandbox), ErrMoveHandoffMoved},
		{errors.New(ErrIncarnationConflict.Error() + ": want a have b"), ErrMoveHandoffMoved},
	} {
		if got := classifyAbortError(tc.in); !errors.Is(got, tc.want) {
			t.Errorf("%v -> %v, want %v", tc.in, got, tc.want)
		}
	}
	other := errors.New("leader unreachable")
	if got := classifyAbortError(other); got != other {
		t.Fatalf("a fault = %v, want it unchanged", got)
	}
	if forwardApplyStatus(http.StatusConflict, ErrMoveHandoffAborted.Error()) == nil ||
		!errors.Is(forwardApplyStatus(http.StatusConflict, ErrMoveHandoffAborted.Error()), ErrMoveHandoffAborted) ||
		!errors.Is(forwardApplyStatus(http.StatusConflict, ErrMoveHandoffMoved.Error()), ErrMoveHandoffMoved) {
		t.Fatal("a forwarded handoff verdict lost its sentinel")
	}
	if ApplyErrorStatus(ErrMoveHandoffMoved) != http.StatusConflict || ApplyErrorStatus(ErrMoveHandoffAborted) != http.StatusConflict {
		t.Fatal("handoff verdicts must answer 409")
	}
}

// TestClusterMoveHandoffThroughRaft runs the handoff through a real
// single-server raft: begin, abort and the token-checked swap, then an
// older server in the configuration turns all of it off on both the
// proposer and the leader.
func TestClusterMoveHandoffThroughRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "move-handoff", true, nil, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const id = "sb-h"
	if err := c.RecordPlacement(ctx, id, &models.CreateSandboxRequest{Image: "alpine"}, PlacementSecrets{IncarnationID: "inc-h"}); err != nil {
		t.Fatalf("place: %v", err)
	}
	p, ok := c.fsm.get(id)
	if !ok || p.OwnerNodeID != c.nodeID {
		t.Fatalf("placement %+v", p)
	}
	swap := func(token string) error {
		return c.applyCommand(ctx, command{Op: opReassign, SandboxID: id, OwnerNodeID: "node-x", ExpectedIncarnationID: "inc-h",
			ExpectedOwnerNodeID: c.nodeID, ExpectedOwnerNodeIDSet: true, ExpectedMoveToken: token, ReassignCause: reassignCauseFailover})
	}

	token, err := c.beginMoveHandoff(ctx, p, c.nodeID)
	if err != nil || token == "" {
		t.Fatalf("begin = %q, %v", token, err)
	}
	if err := c.AbortMoveHandoff(ctx, id, "inc-h"); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if err := swap(token); !errors.Is(err, ErrMoveHandoffAborted) {
		t.Fatalf("swap after the abort = %v, want ErrMoveHandoffAborted", err)
	}
	if err := c.AbortMoveHandoff(ctx, id, ""); !errors.Is(err, ErrMoveHandoffUnsupported) {
		t.Fatalf("abort without a lifetime = %v", err)
	}
	if err := c.AbortMoveHandoff(ctx, id, "inc-other"); !errors.Is(err, ErrMoveHandoffMoved) {
		t.Fatalf("abort of another lifetime = %v, want ErrMoveHandoffMoved", err)
	}

	// An older server joins: nothing of the handoff may reach the log.
	if err := c.raft.raft.AddNonvoter("old-server", "127.0.0.1:1", 0, 2*time.Second).Error(); err != nil {
		t.Fatalf("add old server: %v", err)
	}
	if c.moveHandoffReplicated() {
		t.Fatal("a server that does not report the handoff version must keep it off")
	}
	if got, err := c.beginMoveHandoff(ctx, p, c.nodeID); got != "" || err != nil {
		t.Fatalf("begin during the upgrade = %q, %v; want none, no error", got, err)
	}
	if err := c.AbortMoveHandoff(ctx, id, "inc-h"); !errors.Is(err, ErrMoveHandoffUnsupported) {
		t.Fatalf("abort during the upgrade = %v", err)
	}
	forwarded, _ := encodeCommand(abortMoveHandoffCommand(id, "inc-h", c.nodeID))
	if err := c.ApplyEncoded(ctx, forwarded); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("forwarded abort during the upgrade = %v, want ErrClusterVersion", err)
	}
	// A reassign that still carries a token lands without the check.
	if err := swap("tok-stale"); err != nil {
		t.Fatalf("swap during the upgrade = %v, want applied without the check", err)
	}
	if got, _ := c.fsm.get(id); got.OwnerNodeID != "node-x" {
		t.Fatalf("owner %q, want node-x", got.OwnerNodeID)
	}
	if (*Cluster)(nil).moveHandoffReplicated() || (&Cluster{}).moveHandoffReplicated() {
		t.Fatal("a cluster without raft cannot enable handoffs")
	}
}

// A worker aborts through the leader, only when every live member applies
// handoffs, and reads the leader's verdict back from its answer.
func TestAgentAbortMoveHandoff(t *testing.T) {
	newAgent := func(t *testing.T, sent *[]command, status int, message string, workerFV int) *Agent {
		var mu sync.Mutex
		agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || (r.URL.Path != PublicInternalApplyPath && r.URL.Path != InternalAPIPath) {
				http.NotFound(w, r)
				return
			}
			body, _ := io.ReadAll(r.Body)
			cmd, err := decodeCommand(body)
			if err != nil {
				http.Error(w, "bad command", http.StatusBadRequest)
				return
			}
			mu.Lock()
			*sent = append(*sent, cmd)
			mu.Unlock()
			if status != http.StatusNoContent {
				http.Error(w, message, status)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}), Member{NodeID: "worker-2", Alive: true, Role: config.NodeRoleWorker, FSMOpsVersion: workerFV})
		server, ok := agent.gossip.lookupMember("server-1")
		if !ok {
			t.Fatal("harness has no server-1")
		}
		server.FSMOpsVersion = moveHandoffFSMOpsVersion
		agent.gossip.memberIndex.upsert(server)
		return agent
	}
	ctx := context.Background()
	const fv = moveHandoffFSMOpsVersion

	var sent []command
	agent := newAgent(t, &sent, http.StatusNoContent, "", fv)
	if err := agent.AbortMoveHandoff(ctx, "sb-a", "inc-a"); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if len(sent) != 1 || sent[0].Op != opMoveHandoff || sent[0].MoveToken != "" || sent[0].ExpectedOwnerNodeID != agent.nodeID ||
		!sent[0].ExpectedOwnerNodeIDSet || sent[0].ExpectedIncarnationID != "inc-a" {
		t.Fatalf("sent %+v", sent)
	}
	if err := agent.AbortMoveHandoff(ctx, "sb-a", ""); !errors.Is(err, ErrMoveHandoffUnsupported) {
		t.Fatalf("abort without a lifetime = %v", err)
	}

	var movedSent []command
	moved := newAgent(t, &movedSent, http.StatusConflict, ErrMoveHandoffMoved.Error(), fv)
	if err := moved.AbortMoveHandoff(ctx, "sb-a", "inc-a"); !errors.Is(err, ErrMoveHandoffMoved) {
		t.Fatalf("abort after the swap = %v, want ErrMoveHandoffMoved", err)
	}
	var oldLeaderSent []command
	oldLeader := newAgent(t, &oldLeaderSent, http.StatusInternalServerError, ErrClusterVersion.Error()+": move handoffs", fv)
	if err := oldLeader.AbortMoveHandoff(ctx, "sb-a", "inc-a"); !errors.Is(err, ErrMoveHandoffUnsupported) {
		t.Fatalf("abort the leader cannot record = %v, want ErrMoveHandoffUnsupported", err)
	}

	var upgradingSent []command
	upgrading := newAgent(t, &upgradingSent, http.StatusNoContent, "", fv-1)
	if err := upgrading.AbortMoveHandoff(ctx, "sb-a", "inc-a"); !errors.Is(err, ErrMoveHandoffUnsupported) || len(upgradingSent) != 0 {
		t.Fatalf("abort during the upgrade = %v, sent %d", err, len(upgradingSent))
	}
	if (*Agent)(nil).moveHandoffReplicated() {
		t.Fatal("a nil agent cannot enable handoffs")
	}
}
