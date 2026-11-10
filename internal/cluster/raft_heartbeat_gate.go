package cluster

import (
	"sync"

	"github.com/hashicorp/raft"
)

// heartbeatGateTransport is the transport raft is given: the pipeline guard
// (raft_pipeline_guard.go) plus a gate on the heartbeat handler, so
// raftNode.Close can wait for every heartbeat still inside raft before it
// closes the stores.
//
// Why: a heartbeat is the one RPC raft does not handle on its own
// goroutines. The transport calls raft's processHeartbeat directly from the
// connection's goroutine (NetworkTransport.handleCommand, the heartbeat fast
// path), and raft.Shutdown does not wait for it. processHeartbeat checks
// for shutdown only once, at the top. A heartbeat that got past that check
// just before Shutdown then finds raft's state is Shutdown, not Follower,
// and so saves the term to the stable store, which Close has closed
// meanwhile.
// raft panics on that write ("failed to save current term: database not
// open", raft.go setCurrentTerm), killing the process. A follower closes
// while its leader still sends it heartbeats every few tens of
// milliseconds, so every server stop can hit it (seen in CI on
// TestFollowerApplyEncodedReturnsNotLeader).
//
// The handler holds a read lock while it runs; closeHeartbeats takes the
// write lock, so it returns only once no heartbeat is inside raft, and a
// heartbeat that arrives later is dropped without reaching raft. Raft drops
// those too (its shutdown check), and the transport answers the sender
// with ErrTransportShutdown. The read lock costs one uncontended RLock per
// heartbeat.
type heartbeatGateTransport struct {
	*pipelineGuardTransport

	mu     sync.RWMutex
	closed bool
}

func newHeartbeatGateTransport(t *pipelineGuardTransport) *heartbeatGateTransport {
	return &heartbeatGateTransport{pipelineGuardTransport: t}
}

// SetHeartbeatHandler installs cb behind the gate. raft calls it once, from
// NewRaft, with its processHeartbeat. nil stays nil: the transport then
// sends heartbeats through raft's main loop like any other RPC.
func (t *heartbeatGateTransport) SetHeartbeatHandler(cb func(rpc raft.RPC)) {
	if cb == nil {
		t.pipelineGuardTransport.SetHeartbeatHandler(nil)
		return
	}
	t.pipelineGuardTransport.SetHeartbeatHandler(func(rpc raft.RPC) {
		t.mu.RLock()
		defer t.mu.RUnlock()
		if t.closed {
			return
		}
		cb(rpc)
	})
}

// closeHeartbeats waits for every heartbeat handler still running and stops
// later ones from reaching raft. raftNode.Close calls it after raft has shut
// down and before it closes the stores. A handler cannot block for long: a
// heartbeat carries no entries and no commit index, so raft only writes the
// term and answers on a buffered channel.
func (t *heartbeatGateTransport) closeHeartbeats() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
}
