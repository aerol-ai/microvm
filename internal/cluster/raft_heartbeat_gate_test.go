package cluster

import (
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// sendHeartbeat sends one heartbeat to target over raft's real wire code,
// from a fresh client transport, and returns the RPC's error on the channel.
func sendHeartbeat(t *testing.T, target raft.ServerAddress, timeout time.Duration) <-chan error {
	t.Helper()
	client, err := raft.NewTCPTransport("127.0.0.1:0", nil, 1, timeout, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	// A heartbeat, as the transport sees it: a term, the leader's address,
	// and no entries, previous entry or commit index.
	req := &raft.AppendEntriesRequest{
		RPCHeader: raft.RPCHeader{
			ProtocolVersion: raft.ProtocolVersionMax,
			ID:              []byte("hb-leader"),
			Addr:            client.EncodePeer("hb-leader", client.LocalAddr()),
		},
		Term: 7,
	}
	done := make(chan error, 1)
	go func() {
		done <- client.AppendEntries("hb-follower", target, req, new(raft.AppendEntriesResponse))
	}()
	return done
}

// Regression: raftNode.Close closed the stable store while a heartbeat was
// still inside raft, and raft panicked writing the term to it ("failed to
// save current term: database not open", CI on
// TestFollowerApplyEncodedReturnsNotLeader). handler stands in for raft's
// processHeartbeat after its one shutdown check: once let go, it writes
// the stable store, as raft's setCurrentTerm does. Close must wait for it.
func TestRaftNodeCloseWaitsForHeartbeatInFlight(t *testing.T) {
	// A fixed port: with :0 the transport advertises port 0.
	addr := fmt.Sprintf("127.0.0.1:%d", pickFreeTCPPort(t))
	rn, err := setupRaft(raftSetupConfig{
		NodeID: "hb-follower", BindAddr: addr, DataDir: t.TempDir(),
	}, newPlacementFSM(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if rn.heartbeats == nil || rn.heartbeats.pipelineGuardTransport != rn.pipelines {
		t.Fatalf("raft was not given the heartbeat gate around the pipeline guard (heartbeats %v)", rn.heartbeats)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	wrote := make(chan error, 1)
	rn.heartbeats.SetHeartbeatHandler(func(rpc raft.RPC) {
		close(entered)
		<-release
		wrote <- rn.stableStr.SetUint64([]byte("CurrentTerm"), 7)
		rpc.Respond(&raft.AppendEntriesResponse{Term: 7, Success: true}, nil)
	})
	sendHeartbeat(t, rn.transport.LocalAddr(), 5*time.Second)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		_ = rn.Close()
		t.Fatal("the heartbeat never reached the handler")
	}

	closed := make(chan error, 1)
	go func() { closed <- rn.Close() }()
	// Unfixed, Close returns in milliseconds here: raft's own goroutines are
	// done, and nothing waits for the transport's.
	select {
	case err := <-closed:
		t.Fatalf("Close returned (err %v) with a heartbeat still inside raft; its term write would hit a closed store", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-wrote; err != nil {
		t.Fatalf("the in-flight heartbeat's stable-store write failed: %v", err)
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close never returned after the heartbeat finished")
	}
}

// After closeHeartbeats no heartbeat reaches raft, and a nil handler stays
// nil (the transport then queues heartbeats for raft's main loop).
func TestHeartbeatGateTransport(t *testing.T) {
	t.Run("closed: a heartbeat is dropped, not handled", func(t *testing.T) {
		pp := newPipelinePair(t, time.Second)
		g := newHeartbeatGateTransport(newPipelineGuardTransport(pp.follower, time.Second, nil))
		var calls atomic.Int32
		g.SetHeartbeatHandler(func(rpc raft.RPC) {
			calls.Add(1)
			rpc.Respond(&raft.AppendEntriesResponse{Success: true}, nil)
		})
		if err := <-sendHeartbeat(t, pp.follower.LocalAddr(), time.Second); err != nil {
			t.Fatalf("open gate: heartbeat failed: %v", err)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("open gate: handler ran %d times, want 1", got)
		}
		g.closeHeartbeats()
		// Nothing answers a dropped heartbeat while the transport is still
		// open, so the sender times out; in raftNode.Close the transport is
		// already closed by then and answers ErrTransportShutdown.
		if err := <-sendHeartbeat(t, pp.follower.LocalAddr(), 200*time.Millisecond); err == nil {
			t.Fatal("closed gate: heartbeat got an answer")
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("closed gate: handler ran %d times, want still 1", got)
		}
	})

	t.Run("nil handler stays nil", func(t *testing.T) {
		pp := newPipelinePair(t, time.Second)
		g := newHeartbeatGateTransport(newPipelineGuardTransport(pp.follower, time.Second, nil))
		g.SetHeartbeatHandler(func(raft.RPC) { t.Error("the old handler ran after it was cleared") })
		g.SetHeartbeatHandler(nil)
		// With no handler the heartbeat goes to Consumer(), where the
		// pair's follower loop answers it.
		if err := <-sendHeartbeat(t, pp.follower.LocalAddr(), time.Second); err != nil {
			t.Fatalf("heartbeat with no handler: %v", err)
		}
	})
}
