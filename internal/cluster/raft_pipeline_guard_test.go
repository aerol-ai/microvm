package cluster

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// pipelinePair is a leader-side NetworkTransport and a follower that answers
// every AppendEntries, on loopback, with raft's real wire code.
type pipelinePair struct {
	leader, follower *raft.NetworkTransport
}

func newPipelinePair(t *testing.T, timeout time.Duration) pipelinePair {
	t.Helper()
	return newSlowPipelinePair(t, timeout, 0)
}

// newSlowPipelinePair is newPipelinePair with a follower that takes delay to
// answer each AppendEntries: a healthy but slow follower.
func newSlowPipelinePair(t *testing.T, timeout, delay time.Duration) pipelinePair {
	t.Helper()
	follower, err := raft.NewTCPTransport("127.0.0.1:0", nil, 2, timeout, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for rpc := range follower.Consumer() {
			time.Sleep(delay)
			rpc.Respond(&raft.AppendEntriesResponse{Success: true}, nil)
		}
	}()
	leader, err := raft.NewTCPTransport("127.0.0.1:0", nil, 2, timeout, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = leader.Close()
		_ = follower.Close()
	})
	return pipelinePair{leader: leader, follower: follower}
}

func appendReq() *raft.AppendEntriesRequest {
	return &raft.AppendEntriesRequest{RPCHeader: raft.RPCHeader{ProtocolVersion: raft.ProtocolVersionMax}}
}

// sendWithin runs one pipelined AppendEntries and reports its error, or
// blocked=true if it has not returned within d (the send keeps running).
func sendWithin(p raft.AppendPipeline, d time.Duration) (err error, blocked bool, done <-chan error) {
	ch := make(chan error, 1)
	go func() {
		_, err := p.AppendEntries(appendReq(), new(raft.AppendEntriesResponse))
		ch <- err
	}()
	select {
	case err := <-ch:
		return err, false, ch
	case <-time.After(d):
		return nil, true, ch
	}
}

// The raft behaviour the guard exists for, on raft's real NetworkTransport:
// once nothing reads a pipeline's answers (pipelineDecode has returned), the
// second send blocks past any timeout. If this part ever fails, raft has
// fixed the stall upstream and the guard can be reconsidered.
func TestRaftPipelineSendWithNoReaderBlocksUntilTheGuardClosesIt(t *testing.T) {
	const timeout = 200 * time.Millisecond

	t.Run("raft alone: the second send never returns", func(t *testing.T) {
		pp := newPipelinePair(t, timeout)
		p, err := pp.leader.AppendEntriesPipeline("f", pp.follower.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		if err, blocked, _ := sendWithin(p, 5*timeout); blocked || err != nil {
			t.Fatalf("first send: err %v, blocked %v; want it through", err, blocked)
		}
		_, blocked, done := sendWithin(p, 5*timeout)
		if !blocked {
			t.Fatal("second send returned on raft's own pipeline; raft no longer stalls here, so revisit pipelineGuardTransport")
		}
		_ = p.Close()
		if err := <-done; !errors.Is(err, raft.ErrPipelineShutdown) {
			t.Fatalf("after Close the send returned %v, want ErrPipelineShutdown", err)
		}
	})

	t.Run("guarded: the stalled pipeline is closed and the send returns", func(t *testing.T) {
		pp := newPipelinePair(t, timeout)
		var logs strings.Builder
		g := newPipelineGuardTransport(pp.leader, 3*timeout, slog.New(slog.NewTextHandler(&logs, nil)))
		p, err := g.AppendEntriesPipeline("f", pp.follower.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		before := raftPipelineStalls.Value()
		if err, blocked, _ := sendWithin(p, 5*timeout); blocked || err != nil {
			t.Fatalf("first send: err %v, blocked %v; want it through", err, blocked)
		}
		start := time.Now()
		err, blocked, _ := sendWithin(p, 10*timeout)
		if blocked {
			t.Fatal("second send still blocked: the guard did not close the stalled pipeline")
		}
		if !errors.Is(err, raft.ErrPipelineShutdown) {
			t.Fatalf("second send returned %v, want ErrPipelineShutdown (raft's signal to fall back to plain replication)", err)
		}
		if took := time.Since(start); took < 3*timeout {
			t.Fatalf("second send returned after %s, before stallAfter (%s)", took, 3*timeout)
		}
		if got := raftPipelineStalls.Value() - before; got != 1 {
			t.Fatalf("aerolvm_raft_pipeline_stalls_total moved by %d, want 1", got)
		}
		if n := g.openPipelines(); n != 0 {
			t.Fatalf("%d pipelines still tracked after the guard closed the only one", n)
		}
		if !strings.Contains(logs.String(), "raft replication pipeline send stalled") {
			t.Fatalf("no warning logged for the stall:\n%s", logs.String())
		}
	})

	t.Run("a pipeline that cannot open is not tracked", func(t *testing.T) {
		pp := newPipelinePair(t, timeout)
		g := newPipelineGuardTransport(pp.leader, time.Second, nil)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		closed := l.Addr().String()
		_ = l.Close()
		if _, err := g.AppendEntriesPipeline("gone", raft.ServerAddress(closed)); err == nil {
			t.Fatal("pipeline to a closed port opened")
		}
		if n := g.openPipelines(); n != 0 {
			t.Fatalf("%d pipelines tracked after a failed open", n)
		}
	})
}

// A healthy pipeline is never touched: sends whose answers are read return
// at once, the watchdog never fires, even after a pause longer than
// stallAfter, and the pipeline stays open and usable.
func TestRaftPipelineGuardLeavesHealthySendsAlone(t *testing.T) {
	const timeout = 200 * time.Millisecond
	pp := newPipelinePair(t, timeout)
	g := newPipelineGuardTransport(pp.leader, 2*timeout, nil)
	p, err := g.AppendEntriesPipeline("f", pp.follower.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	// What raft's pipelineDecode does: read every answer.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-p.Consumer():
			case <-stop:
				return
			}
		}
	}()
	before := raftPipelineStalls.Value()
	for i := range 20 {
		if err, blocked, _ := sendWithin(p, 5*timeout); blocked || err != nil {
			t.Fatalf("send %d: err %v, blocked %v", i, err, blocked)
		}
	}
	time.Sleep(3 * timeout) // longer than stallAfter: a leftover timer would fire now
	if err, blocked, _ := sendWithin(p, 5*timeout); blocked || err != nil {
		t.Fatalf("send after an idle pause: err %v, blocked %v; the watchdog must not close a healthy pipeline", err, blocked)
	}
	if got := raftPipelineStalls.Value() - before; got != 0 {
		t.Fatalf("aerolvm_raft_pipeline_stalls_total moved by %d on healthy sends", got)
	}
	if n := g.openPipelines(); n != 1 {
		t.Fatalf("%d pipelines tracked, want the 1 open one", n)
	}
	_ = p.Close()
	if n := g.openPipelines(); n != 0 {
		t.Fatalf("%d pipelines tracked after Close, want 0", n)
	}
}

// A follower that is slow but keeps answering makes every send wait about
// one answer's time for the pipeline's decoder; that is back-pressure, not a
// stall, and the guard must leave it alone. This pins the margin: if
// stallAfter is ever cut near a slow answer's time, pipelines to slow
// followers would churn between pipelining and plain replication.
func TestRaftPipelineGuardLeavesASlowButDrainingPipelineAlone(t *testing.T) {
	const (
		timeout = 2 * time.Second
		delay   = 150 * time.Millisecond
	)
	pp := newSlowPipelinePair(t, timeout, delay)
	g := newPipelineGuardTransport(pp.leader, 3*delay, nil)
	p, err := g.AppendEntriesPipeline("slow", pp.follower.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-p.Consumer():
			case <-stop:
				return
			}
		}
	}()
	before := raftPipelineStalls.Value()
	start := time.Now()
	for i := range 8 {
		if err, blocked, _ := sendWithin(p, timeout); blocked || err != nil {
			t.Fatalf("send %d: err %v, blocked %v; a slow but answering follower must keep its pipeline", i, err, blocked)
		}
	}
	if took := time.Since(start); took < 4*delay {
		t.Fatalf("8 sends took %s; the follower's %s delay was not felt, so this test no longer measures a busy pipeline", took, delay)
	}
	if got := raftPipelineStalls.Value() - before; got != 0 {
		t.Fatalf("the guard fired %d times on a slow but draining pipeline", got)
	}
	if n := g.openPipelines(); n != 1 {
		t.Fatalf("%d pipelines tracked, want the 1 still open", n)
	}
}

// raft turns features on by type-asserting its transport (pre-vote:
// trans.(raft.WithPreVote) in api.go and raft.go). The guard must not
// switch any of them off: it has to satisfy every interface the plain
// NetworkTransport does.
func TestPipelineGuardTransportKeepsRaftsOptionalInterfaces(t *testing.T) {
	nt, err := raft.NewTCPTransport("127.0.0.1:0", nil, 2, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nt.Close()
	var plain, guarded any = nt, newPipelineGuardTransport(nt, time.Second, nil)
	checks := map[string]func(any) bool{
		"Transport":         func(v any) bool { _, ok := v.(raft.Transport); return ok },
		"WithPreVote":       func(v any) bool { _, ok := v.(raft.WithPreVote); return ok },
		"WithClose":         func(v any) bool { _, ok := v.(raft.WithClose); return ok },
		"WithPeers":         func(v any) bool { _, ok := v.(raft.WithPeers); return ok },
		"LoopbackTransport": func(v any) bool { _, ok := v.(raft.LoopbackTransport); return ok },
	}
	for name, has := range checks {
		if has(plain) != has(guarded) {
			t.Errorf("%s: NetworkTransport %v, guard %v; the guard changed what raft can use", name, has(plain), has(guarded))
		}
	}
	if !checks["WithPreVote"](guarded) {
		t.Error("the guard does not offer pre-vote; raft would run without it")
	}
}

// On a slow shutdown raftNode.Close closes every pipeline at once, which
// frees a stuck send without waiting for stallAfter.
func TestPipelineGuardClosePipelinesFreesAStuckSend(t *testing.T) {
	const timeout = 200 * time.Millisecond
	pp := newPipelinePair(t, timeout)
	g := newPipelineGuardTransport(pp.leader, time.Hour, nil)
	stuck, err := g.AppendEntriesPipeline("f", pp.follower.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.AppendEntriesPipeline("f", pp.follower.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err, blocked, _ := sendWithin(stuck, 5*timeout); blocked || err != nil {
		t.Fatalf("first send: err %v, blocked %v", err, blocked)
	}
	_, blocked, done := sendWithin(stuck, 3*timeout)
	if !blocked {
		t.Fatal("second send did not block; the setup no longer reproduces a stuck send")
	}
	if n := g.closePipelines(); n != 2 {
		t.Fatalf("closePipelines closed %d, want 2", n)
	}
	select {
	case err := <-done:
		if !errors.Is(err, raft.ErrPipelineShutdown) {
			t.Fatalf("stuck send returned %v, want ErrPipelineShutdown", err)
		}
	case <-time.After(5 * timeout):
		t.Fatal("stuck send still blocked after closePipelines")
	}
	if n := g.openPipelines(); n != 0 {
		t.Fatalf("%d pipelines tracked after closePipelines", n)
	}
}

type fakeFuture struct{ done chan error }

func (f fakeFuture) Error() error { return <-f.done }

func TestAwaitRaftShutdown(t *testing.T) {
	errBoom := errors.New("boom")
	t.Run("finishes within the grace: pipelines left alone", func(t *testing.T) {
		f := fakeFuture{done: make(chan error, 1)}
		f.done <- errBoom
		var calls atomic.Int32
		err := awaitRaftShutdown(f, time.Second, func() int { calls.Add(1); return 0 }, nil)
		if !errors.Is(err, errBoom) || calls.Load() != 0 {
			t.Fatalf("err %v, closePipelines called %d times; want the future's error and no call", err, calls.Load())
		}
	})
	t.Run("stuck until the pipelines close: closed once, then it finishes", func(t *testing.T) {
		f := fakeFuture{done: make(chan error, 1)}
		var calls atomic.Int32
		var logs strings.Builder
		start := time.Now()
		err := awaitRaftShutdown(f, 50*time.Millisecond, func() int {
			calls.Add(1)
			f.done <- nil // closing the pipelines is what lets raft finish
			return 3
		}, slog.New(slog.NewTextHandler(&logs, nil)))
		if err != nil || calls.Load() != 1 {
			t.Fatalf("err %v, closePipelines called %d times; want nil and exactly 1", err, calls.Load())
		}
		if took := time.Since(start); took < 50*time.Millisecond {
			t.Fatalf("closed the pipelines after %s, before the grace", took)
		}
		if !strings.Contains(logs.String(), "pipelines_closed=3") {
			t.Fatalf("no warning with the count of closed pipelines:\n%s", logs.String())
		}
	})
	t.Run("no guard: keeps waiting for raft", func(t *testing.T) {
		f := fakeFuture{done: make(chan error, 1)}
		go func() {
			time.Sleep(100 * time.Millisecond)
			f.done <- nil
		}()
		if err := awaitRaftShutdown(f, 10*time.Millisecond, nil, nil); err != nil {
			t.Fatalf("err %v", err)
		}
	})
}

// setupRaft hands raft the guard, wrapped around the transport raftNode
// closes, so every pipeline the leader opens is watched.
func TestSetupRaftUsesThePipelineGuard(t *testing.T) {
	rn, err := setupRaft(raftSetupConfig{
		NodeID: "n1", BindAddr: "127.0.0.1:0", DataDir: t.TempDir(), BootstrapCluster: true,
	}, newPlacementFSM(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer rn.Close()
	if rn.pipelines == nil || rn.pipelines.NetworkTransport != rn.transport {
		t.Fatalf("raft was not given the guard around raftNode.transport (pipelines %v)", rn.pipelines)
	}
	if want := raftPipelineStallFactor * raftTransportTimeout; rn.pipelines.stallAfter != want {
		t.Fatalf("stallAfter %s, want %s (3 transport timeouts)", rn.pipelines.stallAfter, want)
	}
}
