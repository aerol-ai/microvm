package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests for opSetRunStates (fsm_run_state.go; CLAUDE.md "Cluster
// mode is fragile"): it records an owner's run state without moving
// Placement.Version, only for the current owner and lifetime, and the
// change feed carries it.

func runStateLog(t *testing.T) *warmPoolLog {
	l := newWarmPoolLog(t)
	l.apply(command{Op: opPlace, SandboxID: "sb-a", OwnerNodeID: "w1", IncarnationID: "inc-a"})
	l.apply(command{Op: opPlace, SandboxID: "sb-b", OwnerNodeID: "w1", IncarnationID: "inc-b"})
	l.apply(command{Op: opReserve, SandboxID: "sb-r", OwnerNodeID: "w1", IncarnationID: "inc-r"})
	return l
}

func runReport(id, owner, inc string, state RunState) RunStateReport {
	return RunStateReport{SandboxID: id, OwnerNodeID: owner, IncarnationID: inc, State: state}
}

func TestFSMRunStatesApply(t *testing.T) {
	l := runStateLog(t)
	before := l.fsm.placements["sb-a"]
	res := l.apply(command{Op: opSetRunStates, RunStates: []RunStateReport{
		runReport("sb-a", "w1", "inc-a", RunStateSuspended),
		runReport("sb-b", "w2", "inc-b", RunStateSuspended),       // not the owner
		runReport("sb-b", "w1", "inc-old", RunStateSuspended),     // an earlier lifetime
		runReport("sb-r", "w1", "inc-r", RunStateSuspended),       // a reservation
		runReport("sb-gone", "w1", "inc-gone", RunStateSuspended), // no row
	}})
	if out, ok := res.(RunStateWriteResponse); !ok || out.Applied != 1 {
		t.Fatalf("apply = %#v, want 1 applied", res)
	}
	got := l.fsm.placements["sb-a"]
	if got.RunState != RunStateSuspended || got.RunStateIndex != l.idx {
		t.Fatalf("sb-a = %+v, want suspended at index %d", got, l.idx)
	}
	if got.Version != before.Version || got.IncarnationID != before.IncarnationID || got.OwnerNodeID != before.OwnerNodeID {
		t.Fatalf("the report moved more than the run state: %+v, was %+v", got, before)
	}
	if b := l.fsm.placements["sb-b"]; b.RunState != "" {
		t.Fatalf("sb-b = %+v, want no run state", b)
	}

	// The same state again is not a change, so nothing reaches the feed.
	at := l.idx
	if out := l.apply(command{Op: opSetRunStates, RunStates: []RunStateReport{runReport("sb-a", "w1", "inc-a", RunStateSuspended)}}).(RunStateWriteResponse); out.Applied != 0 {
		t.Fatalf("a repeat applied %d", out.Applied)
	}
	if ch := l.fsm.placementChanges(at); len(ch.Changes) != 0 {
		t.Fatalf("a repeat reached the feed: %+v", ch.Changes)
	}
	// A new reason is a change.
	r := runReport("sb-a", "w1", "inc-a", RunStateFailed)
	r.Reason = "exited 137"
	l.apply(command{Op: opSetRunStates, RunStates: []RunStateReport{r}})
	ch := l.fsm.placementChanges(at)
	if len(ch.Changes) != 1 || ch.Changes[0].Placement == nil || ch.Changes[0].Placement.RunStateReason != "exited 137" {
		t.Fatalf("feed = %+v, want sb-a failed", ch.Changes)
	}
}

func TestFSMRunStatesRefusesABadBatch(t *testing.T) {
	big := make([]RunStateReport, maxRunStateReports+1)
	for i := range big {
		big[i] = runReport("sb-a", "w1", "inc-a", RunStateRunning)
	}
	for name, batch := range map[string][]RunStateReport{
		"empty":    nil,
		"too many": big,
		"no state": {runReport("sb-a", "w1", "inc-a", "")},
		"no owner": {runReport("sb-a", "", "inc-a", RunStateRunning)},
		"no id":    {runReport("", "w1", "inc-a", RunStateRunning)},
		"unknown":  {runReport("sb-a", "w1", "inc-a", "paused")},
	} {
		t.Run(name, func(t *testing.T) {
			l := runStateLog(t)
			res := l.apply(command{Op: opSetRunStates, RunStates: batch})
			if err, ok := res.(error); !ok || !errors.Is(err, ErrBadRunStateBatch) {
				t.Fatalf("apply = %#v, want ErrBadRunStateBatch", res)
			}
		})
	}
}

// A spec write read before a stop still lands: the run state leaves the
// version the spec fence checks alone.
func TestFSMRunStatesKeepTheSpecFence(t *testing.T) {
	l := runStateLog(t)
	version := l.fsm.placements["sb-a"].Version
	l.apply(command{Op: opSetRunStates, RunStates: []RunStateReport{runReport("sb-a", "w1", "inc-a", RunStateSuspended)}})
	if err := specVersionFence(command{SandboxID: "sb-a", ExpectedPlacementVersion: version}, l.fsm.placements["sb-a"].Version); err != nil {
		t.Fatalf("spec fence after a run-state change: %v", err)
	}
}

func TestFSMRunStatesSurviveASnapshot(t *testing.T) {
	l := runStateLog(t)
	l.apply(command{Op: opSetRunStates, RunStates: []RunStateReport{runReport("sb-a", "w1", "inc-a", RunStateSuspended)}})
	want := l.fsm.placements["sb-a"]
	snap, err := l.fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	got := restored.placements["sb-a"]
	if got.RunState != want.RunState || got.RunStateIndex != want.RunStateIndex {
		t.Fatalf("restored = %+v, want run state %q at %d", got, want.RunState, want.RunStateIndex)
	}
}

// Gateways merge two copies of a row by (Version, RunStateIndex): a stop at
// the same Version replaces the row, and an older copy never wins.
func TestPlacementAtLeast(t *testing.T) {
	for _, tc := range []struct {
		name    string
		p, cur  Placement
		replace bool
	}{
		{"higher version", Placement{Version: 5}, Placement{Version: 4, RunStateIndex: 9}, true},
		{"lower version", Placement{Version: 4, RunStateIndex: 9}, Placement{Version: 5}, false},
		{"same version, later run state", Placement{Version: 5, RunStateIndex: 8}, Placement{Version: 5, RunStateIndex: 7}, true},
		{"same version, earlier run state", Placement{Version: 5, RunStateIndex: 7}, Placement{Version: 5, RunStateIndex: 8}, false},
		{"identical", Placement{Version: 5, RunStateIndex: 7}, Placement{Version: 5, RunStateIndex: 7}, true},
	} {
		if got := placementAtLeast(tc.p, tc.cur); got != tc.replace {
			t.Errorf("%s: placementAtLeast = %v, want %v", tc.name, got, tc.replace)
		}
	}
}

func TestAgentFeedMergesRunStates(t *testing.T) {
	a := &Agent{}
	f := &agentPlacementFeed{rows: map[string]Placement{"sb-a": {SandboxID: "sb-a", Version: 5, RunState: RunStateRunning, RunStateIndex: 6}}}
	stopped := Placement{SandboxID: "sb-a", Version: 5, RunState: RunStateSuspended, RunStateIndex: 8}
	if len(a.applyPlacementChanges(f, PlacementChangesResponse{Changes: []PlacementChange{{SandboxID: "sb-a", Index: 8, Placement: &stopped}}, Next: 8})) == 0 {
		t.Fatal("a stop at the same version was not merged")
	}
	stale := Placement{SandboxID: "sb-a", Version: 5, RunState: RunStateRunning, RunStateIndex: 6}
	if len(a.applyPlacementChanges(f, PlacementChangesResponse{Changes: []PlacementChange{{SandboxID: "sb-a", Index: 6, Placement: &stale}}, Next: 9})) > 0 {
		t.Fatal("an older run state replaced a newer one")
	}
	if got := f.rows["sb-a"]; got.RunState != RunStateSuspended {
		t.Fatalf("row = %+v, want suspended", got)
	}
}

func TestSetRunStatesValidatesBeforeSending(t *testing.T) {
	var a *Agent
	if _, err := a.SetRunStates(t.Context(), []RunStateReport{runReport("sb-a", "w1", "inc-a", RunStateRunning)}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("nil agent: %v", err)
	}
	if _, err := (&Agent{}).SetRunStates(t.Context(), nil); !errors.Is(err, ErrBadRunStateBatch) {
		t.Fatalf("empty batch: %v", err)
	}
	var c *Cluster
	if _, err := c.SetRunStates(t.Context(), nil); err == nil {
		t.Fatal("a cluster with no Raft state took a batch")
	}
}

// The leader applies a batch through Raft, and refuses it while any Raft
// server runs a build without opSetRunStates, rather than commit an entry
// an old replica would fail to apply.
func TestSetRunStatesThroughRaftAndTheGate(t *testing.T) {
	c, cleanup := newTestCluster(t, "rs-gate-a", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	place, err := encodeCommand(command{Op: opPlace, SandboxID: "sb-a", OwnerNodeID: "w1", IncarnationID: "inc-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.applyEncodedLocalResult(ctx, place); err != nil {
		t.Fatal(err)
	}
	batch := []RunStateReport{runReport("sb-a", "w1", "inc-a", RunStateSuspended)}
	if n, err := c.SetRunStates(ctx, batch); err != nil || n != 1 {
		t.Fatalf("SetRunStates = %d, %v", n, err)
	}
	if p, _ := c.fsm.get("sb-a"); p.RunState != RunStateSuspended || p.RunStateIndex == 0 {
		t.Fatalf("row = %+v", p)
	}
	if err := c.raft.raft.AddNonvoter("rs-gate-b", "127.0.0.1:1", 0, 0).Error(); err != nil {
		t.Fatal(err)
	}
	c.gossip.currentMemberIndex().upsert(Member{NodeID: "rs-gate-b", Alive: true, FSMOpsVersion: runStateFSMOpsVersion - 1})
	if _, err := c.SetRunStates(ctx, batch); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("a server on the previous build: %v", err)
	}
}

// A follower forwards a batch one hop to the leader, and a worker's Agent
// posts it to the server tier.
func TestRunStatesForwardAndAgentPost(t *testing.T) {
	batch := []RunStateReport{runReport("sb-a", "w1", "inc-a", RunStateSuspended)}
	var status atomic.Int32
	status.Store(http.StatusOK)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalRunStatesPath {
			http.NotFound(w, r)
			return
		}
		var req RunStateWriteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Reports) != 1 {
			http.Error(w, "bad batch", http.StatusBadRequest)
			return
		}
		w.WriteHeader(int(status.Load()))
		_ = json.NewEncoder(w).Encode(RunStateWriteResponse{Applied: len(req.Reports)})
	})

	follower, leaderID := newEgressInmemFollower(t)
	srv := httptest.NewServer(handler)
	defer srv.Close()
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: leaderID, InternalURL: srv.URL, Alive: true})
	c := &Cluster{nodeID: "rs-follower", raft: &raftNode{raft: follower}, internalClient: srv.Client(),
		patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	ctx := context.Background()
	if n, err := c.SetRunStates(ctx, batch); err != nil || n != 1 {
		t.Fatalf("forwarded = %d, %v", n, err)
	}
	status.Store(http.StatusServiceUnavailable)
	if _, err := c.SetRunStates(ctx, batch); err == nil {
		t.Fatal("a failed forward reported success")
	}

	status.Store(http.StatusOK)
	agent := newAgentControlPlaneHarness(t, handler)
	if n, err := agent.SetRunStates(ctx, batch); err != nil || n != 1 {
		t.Fatalf("agent = %d, %v", n, err)
	}
	status.Store(http.StatusServiceUnavailable)
	if _, err := agent.SetRunStates(ctx, batch); err == nil {
		t.Fatal("an agent post the servers refused reported success")
	}
}
