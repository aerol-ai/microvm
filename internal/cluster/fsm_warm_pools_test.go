package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression tests for warm-pool entries in the FSM (plans/agent-sandbox-
// feature-parity.md W1; CLAUDE.md "Cluster mode is fragile").

type warmPoolLog struct {
	t   *testing.T
	fsm *placementFSM
	idx uint64
}

func newWarmPoolLog(t *testing.T) *warmPoolLog {
	return &warmPoolLog{t: t, fsm: newPlacementFSM()}
}

func (l *warmPoolLog) apply(cmd command) any {
	l.t.Helper()
	data, err := encodeCommand(cmd)
	if err != nil {
		l.t.Fatal(err)
	}
	l.idx++
	return l.fsm.Apply(&raft.Log{Index: l.idx, Data: data})
}

func (l *warmPoolLog) put(image string, depth int) any {
	return l.apply(command{Op: opPutWarmPool, StampUnixNano: int64(1000 + l.idx), WarmPool: &WarmPoolRecord{Image: image, Depth: depth}})
}

func (l *warmPoolLog) del(image string) any {
	return l.apply(command{Op: opDeleteWarmPool, WarmPool: &WarmPoolRecord{Image: image}})
}

func (l *warmPoolLog) read(since uint64) WarmPoolReadResponse {
	return l.fsm.readWarmPools(WarmPoolReadRequest{Since: since})
}

func TestFSMWarmPoolPutGenerations(t *testing.T) {
	l := newWarmPoolLog(t)
	res, ok := l.put("python:3.12", 2).(warmPoolApplyResult)
	if !ok || !res.Changed || res.Pool.Generation != 1 || res.Pool.CreatedUnixNano == 0 || res.Pool.Depth != 2 {
		t.Fatalf("create = %+v", res)
	}
	created := res.Pool.CreatedUnixNano
	if v := l.read(0).Version; v != 1 {
		t.Fatalf("version after the create = %d, want its log index 1", v)
	}
	if res := l.put("python:3.12", 2).(warmPoolApplyResult); res.Changed || res.Pool.Generation != 1 {
		t.Fatalf("a retry of the same write must not bump the generation: %+v", res)
	}
	if v := l.read(0).Version; v != 1 {
		t.Fatalf("a no-op put must not move the version: %d", v)
	}
	res = l.put("python:3.12", 4).(warmPoolApplyResult)
	if !res.Changed || res.Pool.Generation != 2 || res.Pool.CreatedUnixNano != created || res.Pool.UpdatedUnixNano == created {
		t.Fatalf("update = %+v", res)
	}
	if err := asApplyErr(l.del("node:22")); err != nil {
		t.Fatalf("deleting a missing entry is a no-op: %v", err)
	}
	if v := l.read(0).Version; v != 3 {
		t.Fatalf("deleting a missing entry must not move the version: %d", v)
	}
	if err := asApplyErr(l.del("python:3.12")); err != nil {
		t.Fatal(err)
	}
	if got := l.read(0); got.Version != 5 || len(got.Pools) != 0 {
		t.Fatalf("after delete = %+v", got)
	}
	for _, cmd := range []command{{Op: opPutWarmPool}, {Op: opPutWarmPool, WarmPool: &WarmPoolRecord{Image: " "}}, {Op: opDeleteWarmPool}} {
		if err := asApplyErr(l.apply(cmd)); err == nil {
			t.Fatalf("%+v must fail", cmd)
		}
	}
}

// TestFSMWarmPoolLimitIsDecidedAtApply: the limit holds however creates
// race, because apply is serial and every replica counts the same set; an
// update of an existing entry is never refused by it.
func TestFSMWarmPoolLimitIsDecidedAtApply(t *testing.T) {
	a, b := newWarmPoolLog(t), newWarmPoolLog(t)
	for _, l := range []*warmPoolLog{a, b} {
		for i := 0; i < models.MaxWarmPools; i++ {
			if _, ok := l.put(fmt.Sprintf("img-%02d", i), 1).(warmPoolApplyResult); !ok {
				t.Fatalf("entry %d refused", i)
			}
		}
		err := asApplyErr(l.put("one-too-many", 1))
		if !errors.Is(err, ErrWarmPoolLimit) {
			t.Fatalf("past the limit: %v", err)
		}
		if res, ok := l.put("img-00", 7).(warmPoolApplyResult); !ok || !res.Changed {
			t.Fatalf("an update at the limit: %v", res)
		}
		l.del("img-01")
		if _, ok := l.put("one-too-many", 1).(warmPoolApplyResult); !ok {
			t.Fatal("a delete makes room")
		}
	}
	if !reflect.DeepEqual(a.fsm.warmPools, b.fsm.warmPools) || a.fsm.warmPoolsVersion != b.fsm.warmPoolsVersion {
		t.Fatal("two replicas applying the same log diverged")
	}
}

// TestFSMWarmPoolReadCursor: a reader holding the current version gets
// "unchanged" and no list; any other cursor, and none, gets the whole list
// in image order.
func TestFSMWarmPoolReadCursor(t *testing.T) {
	l := newWarmPoolLog(t)
	l.put("python:3.12", 2)
	l.put("alpine:3.20", 1)
	got := l.read(0)
	if got.Unchanged || !got.Authoritative || got.Version != 2 || len(got.Pools) != 2 || got.Pools[0].Image != "alpine:3.20" {
		t.Fatalf("first read = %+v", got)
	}
	if got := l.read(2); !got.Unchanged || got.Pools != nil || got.Version != 2 {
		t.Fatalf("current cursor = %+v", got)
	}
	if got := l.read(1); got.Unchanged || len(got.Pools) != 2 {
		t.Fatalf("stale cursor = %+v", got)
	}
	// A cursor from another server that is ahead (this one lags) is not
	// "current" either: the reader gets this server's list and version.
	if got := l.read(99); got.Unchanged || got.Version != 2 {
		t.Fatalf("cursor ahead = %+v", got)
	}
	empty := newWarmPoolLog(t)
	if got := empty.read(0); got.Unchanged || got.Pools == nil || len(got.Pools) != 0 {
		t.Fatalf("an FSM with no entries answers an empty list: %+v", got)
	}
}

func TestFSMWarmPoolSnapshotRestore(t *testing.T) {
	l := newWarmPoolLog(t)
	l.put("python:3.12", 2)
	l.put("alpine:3.20", 1)
	l.put("python:3.12", 3)
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
	if !reflect.DeepEqual(restored.warmPools, l.fsm.warmPools) {
		t.Fatalf("entries did not survive the snapshot: %+v", restored.warmPoolsSnapshotLocked())
	}
	if restored.warmPoolsVersion != 3 {
		t.Fatalf("restored version = %d, want the snapshot's index", restored.warmPoolsVersion)
	}
	// The log suffix after a restore applies on top as on any replica.
	data, _ := encodeCommand(command{Op: opPutWarmPool, StampUnixNano: 9, WarmPool: &WarmPoolRecord{Image: "python:3.12", Depth: 5}})
	if res, ok := restored.Apply(&raft.Log{Index: 4, Data: data}).(warmPoolApplyResult); !ok || res.Pool.Generation != 3 {
		t.Fatalf("apply after restore = %+v", res)
	}

	// A snapshot from a build without warm pools restores to none.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(fsmSnapshotPayload{Version: 7}); err != nil {
		t.Fatal(err)
	}
	old := newPlacementFSM()
	old.warmPools["stale"] = &WarmPoolRecord{Image: "stale"}
	if err := old.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatal(err)
	}
	if len(old.warmPools) != 0 || old.warmPoolsVersion != 7 {
		t.Fatalf("an old snapshot must restore to no entries at its version: %+v v%d", old.warmPools, old.warmPoolsVersion)
	}
	old.restoreWarmPoolsLocked([]WarmPoolRecord{{Image: ""}, {Image: "ok"}}, 8)
	if len(old.warmPools) != 1 {
		t.Fatal("a record with no image is dropped on restore")
	}
}

// TestFSMWarmPoolPutOnLiteralFSM: an FSM built as a struct literal in other
// tests has no map; the first put makes one instead of panicking.
func TestFSMWarmPoolPutOnLiteralFSM(t *testing.T) {
	f := &placementFSM{}
	if _, err := f.applyPutWarmPoolLocked(command{WarmPool: &WarmPoolRecord{Image: "a", Depth: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := f.applyDeleteWarmPoolLocked(command{WarmPool: &WarmPoolRecord{Image: "missing"}}); err != nil {
		t.Fatal(err)
	}
}

// TestWarmPoolWritesGate covers the rolling-upgrade gate: while any Raft
// server runs a build without the warm-pool ops (fv < 6), the leader
// refuses the write with ErrClusterVersion instead of committing an entry an
// old replica would fail to apply; once every server is upgraded it lands.
// A failed server counts at its last-known version.
func TestWarmPoolWritesGate(t *testing.T) {
	c, cleanup := newTestCluster(t, "wp-gate-a", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	write := func(depth int) (WarmPoolWriteResponse, error) {
		return c.WriteWarmPool(ctx, WarmPoolWriteRequest{Pool: WarmPoolRecord{Image: "python:3.12", Depth: depth}})
	}
	if resp, err := write(1); err != nil || resp.Pool.Generation != 1 || !resp.Changed {
		t.Fatalf("a one-server cluster on this build: %+v %v", resp, err)
	}
	if err := c.raft.raft.AddNonvoter("wp-gate-b", "127.0.0.1:1", 0, 0).Error(); err != nil {
		t.Fatal(err)
	}
	if _, err := write(2); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("a server never seen in gossip counts as old: %v", err)
	}
	index := c.gossip.currentMemberIndex()
	index.upsert(Member{NodeID: "wp-gate-b", Alive: false, FSMOpsVersion: warmPoolFSMOpsVersion - 1})
	if _, err := write(2); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("a failed server on the previous build: %v", err)
	}
	if read, _ := c.ReadWarmPools(ctx, WarmPoolReadRequest{}); len(read.Pools) != 1 || read.Pools[0].Depth != 1 {
		t.Fatalf("a refused write must change nothing: %+v", read)
	}
	index.upsert(Member{NodeID: "wp-gate-b", Alive: false, FSMOpsVersion: fsmOpsVersion})
	if resp, err := write(2); err != nil || resp.Pool.Generation != 2 {
		t.Fatalf("all upgraded: %+v %v", resp, err)
	}
	if resp, err := c.WriteWarmPool(ctx, WarmPoolWriteRequest{Delete: true, Pool: WarmPoolRecord{Image: "python:3.12"}}); err != nil || resp.Changed {
		t.Fatalf("delete = %+v %v", resp, err)
	}
	if read, _ := c.ReadWarmPools(ctx, WarmPoolReadRequest{}); len(read.Pools) != 0 {
		t.Fatalf("after delete = %+v", read)
	}
	if warmPoolFSMOpsVersion > fsmOpsVersion {
		t.Fatal("this build must advertise the version its own ops need")
	}
}

// TestFollowerWarmPoolWriteForwards: a follower forwards one hop to the
// leader and returns its record; the leader's refusals come back as the
// same sentinels; a 503 from the leader stays ErrNotLeader so callers retry.
func TestFollowerWarmPoolWriteForwards(t *testing.T) {
	follower, leaderID := newEgressInmemFollower(t)
	var status atomic.Int32
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalWarmPoolWritePath {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: leaderID, InternalURL: srv.URL, Alive: true})
	c := &Cluster{nodeID: "eg-raft-follower", raft: &raftNode{raft: follower}, internalClient: srv.Client(),
		patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	ctx := context.Background()
	req := WarmPoolWriteRequest{Pool: WarmPoolRecord{Image: "python:3.12", Depth: 2}}

	ok, _ := json.Marshal(WarmPoolWriteResponse{Pool: WarmPoolRecord{Image: "python:3.12", Depth: 2, Generation: 3}, Changed: true})
	status.Store(http.StatusOK)
	body.Store(string(ok))
	if resp, err := c.WriteWarmPool(ctx, req); err != nil || resp.Pool.Generation != 3 {
		t.Fatalf("forwarded write = %+v %v", resp, err)
	}
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusOK, mustJSON(t, WarmPoolWriteOutcome(fmt.Errorf("wrapped: %w", ErrWarmPoolLimit))), ErrWarmPoolLimit},
		{http.StatusOK, mustJSON(t, WarmPoolWriteOutcome(ErrClusterVersion)), ErrClusterVersion},
		{http.StatusServiceUnavailable, "not leader", ErrNotLeader},
	} {
		status.Store(int32(tc.status))
		body.Store(tc.body)
		if _, err := c.WriteWarmPool(ctx, req); !errors.Is(err, tc.want) {
			t.Fatalf("%s came back as %v, want %v", tc.body, err, tc.want)
		}
	}
	status.Store(http.StatusOK)
	body.Store(`{"code":"something_new","message":"m"}`)
	if _, err := c.WriteWarmPool(ctx, req); err == nil || !strings.Contains(err.Error(), "something_new") {
		t.Fatalf("an unknown outcome code must be an error: %v", err)
	}
	if out := WarmPoolWriteOutcome(errors.New("plain")); out.Code != "" {
		t.Fatalf("a plain error has no outcome code: %+v", out)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestAgentWarmPoolReadAndWrite: a worker reads and writes entries through
// the server tier; a non-authoritative read is refused rather than applied.
func TestAgentWarmPoolReadAndWrite(t *testing.T) {
	var authoritative atomic.Bool
	authoritative.Store(true)
	var sawSince atomic.Uint64
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PublicInternalWarmPoolReadPath:
			var req WarmPoolReadRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			sawSince.Store(req.Since)
			resp := WarmPoolReadResponse{Version: 4, Authoritative: authoritative.Load()}
			if req.Since == 4 {
				resp.Unchanged = true
			} else {
				resp.Pools = []WarmPoolRecord{{Image: "python:3.12", Depth: 2}}
			}
			_ = json.NewEncoder(w).Encode(resp)
		case PublicInternalWarmPoolWritePath:
			var req WarmPoolWriteRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Pool.Image == "full" {
				_ = json.NewEncoder(w).Encode(WarmPoolWriteOutcome(ErrWarmPoolLimit))
				return
			}
			_ = json.NewEncoder(w).Encode(WarmPoolWriteResponse{Pool: req.Pool, Changed: !req.Delete})
		default:
			http.NotFound(w, r)
		}
	}))
	ctx := context.Background()
	got, err := agent.ReadWarmPools(ctx, WarmPoolReadRequest{})
	if err != nil || got.Version != 4 || len(got.Pools) != 1 {
		t.Fatalf("first read = %+v %v", got, err)
	}
	if got, err := agent.ReadWarmPools(ctx, WarmPoolReadRequest{Since: 4}); err != nil || !got.Unchanged || sawSince.Load() != 4 {
		t.Fatalf("cursor read = %+v %v", got, err)
	}
	authoritative.Store(false)
	if _, err := agent.ReadWarmPools(ctx, WarmPoolReadRequest{}); err == nil {
		t.Fatal("a non-authoritative answer must not be applied")
	}
	if resp, err := agent.WriteWarmPool(ctx, WarmPoolWriteRequest{Pool: WarmPoolRecord{Image: "python:3.12", Depth: 2}}); err != nil || !resp.Changed {
		t.Fatalf("write = %+v %v", resp, err)
	}
	if _, err := agent.WriteWarmPool(ctx, WarmPoolWriteRequest{Pool: WarmPoolRecord{Image: "full"}}); !errors.Is(err, ErrWarmPoolLimit) {
		t.Fatalf("limit through a worker: %v", err)
	}
}

// TestWarmPoolsWithoutPlacementState: a node or agent that holds no
// placement state refuses reads and writes instead of answering from
// nothing, and an agent whose server tier is down says so.
func TestWarmPoolsWithoutPlacementState(t *testing.T) {
	ctx := context.Background()
	for _, c := range []*Cluster{nil, {}, {raft: &raftNode{}}} {
		if _, err := c.WriteWarmPool(ctx, WarmPoolWriteRequest{}); err == nil {
			t.Fatal("a write without raft must fail")
		}
	}
	for _, c := range []*Cluster{nil, {}} {
		if _, err := c.ReadWarmPools(ctx, WarmPoolReadRequest{}); err == nil {
			t.Fatal("a read without an FSM must fail")
		}
	}
	var a *Agent
	if _, err := a.WriteWarmPool(ctx, WarmPoolWriteRequest{}); err == nil {
		t.Fatal("a nil agent write must fail")
	}
	if _, err := a.ReadWarmPools(ctx, WarmPoolReadRequest{}); err == nil {
		t.Fatal("a nil agent read must fail")
	}
	down := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	if _, err := down.ReadWarmPools(ctx, WarmPoolReadRequest{}); err == nil {
		t.Fatal("a failing server tier must fail the read")
	}
	if _, err := down.WriteWarmPool(ctx, WarmPoolWriteRequest{Pool: WarmPoolRecord{Image: "a"}}); err == nil {
		t.Fatal("a failing server tier must fail the write")
	}
}
