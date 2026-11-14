package cluster

import (
	"errors"
	"expvar"
	"time"

	"github.com/hashicorp/raft"
)

// Stale reads on a cut-off follower (plan C4 part 2, invariant I7).
//
// A server answers worker and ingress placement reads from its local Raft
// FSM. A follower's FSM only moves when the leader sends it entries, so a
// follower on the losing side of a partition keeps answering from a view that
// has stopped: the leader on the other side can reassign a sandbox (dead-owner
// failover), and agents that ask this follower keep routing to the old owner
// for as long as the partition lasts.
//
// So a follower stops vouching for its view once its last contact with the
// leader is older than staleReadBound, and the internal placement reads answer
// 503. An agent moves on to the next server after a 503
// (Agent.doControlPlaneBytes), so a healthy server or the leader answers
// instead. The leader is never refused: its FSM is the newest there is, and a
// leader cut off from its quorum steps down after LeaderLeaseTimeout (500 ms by
// default), after which it is a follower like any other.
//
// raft.LastContact is set when this node accepts an AppendEntries (heartbeats
// included) or InstallSnapshot from the current leader, and when it grants a
// vote. It is not set by pre-vote, which is on by default, so the nodes on a
// minority side cannot keep each other's contact fresh by campaigning: they
// never win a pre-vote, and so never reach the real vote.

// ErrStalePlacementView means this server is a follower that has not heard
// from the raft leader within staleReadBound, so its placement view may be
// behind what the leader has committed. Callers answer 503 + Retry-After.
var ErrStalePlacementView = errors.New("cluster: this server has lost contact with the raft leader; its placement view may be stale")

// LeaderContactReporter is implemented by clients that answer placement reads
// from a local replica fed by a raft leader (*Cluster).
type LeaderContactReporter interface {
	PlacementViewStale() bool
}

// PlacementViewFresh reports whether c may answer a placement read from its
// local view. Clients without a local replica report true: an Agent's reads go
// to a server, which applies this gate itself; Noop is the whole truth.
func PlacementViewFresh(c Client) bool {
	if r, ok := c.(LeaderContactReporter); ok {
		return !r.PlacementViewStale()
	}
	return true
}

// PlacementViewStale reports whether this server is a follower (or candidate)
// whose last contact with the leader is older than staleReadBound. The leader,
// and a Cluster without raft (a single-process FSM, which is the whole truth),
// are never stale.
func (c *Cluster) PlacementViewStale() bool {
	if c == nil {
		return false
	}
	state, lastContact, ok := c.leaderContact()
	if !ok || state == raft.Leader {
		return false
	}
	// A follower that has never heard from a leader has the zero time here,
	// which is as stale as it gets: it has applied nothing it can vouch for.
	return time.Since(lastContact) > c.staleReadBound()
}

func (c *Cluster) leaderContact() (raft.RaftState, time.Time, bool) {
	if c.leaderContactHook != nil {
		state, last := c.leaderContactHook()
		return state, last, true
	}
	if c.raft == nil || c.raft.raft == nil {
		return raft.Shutdown, time.Time{}, false
	}
	return c.raft.raft.State(), c.raft.raft.LastContact(), true
}

// staleReadBound is twice the running raft's HeartbeatTimeout (2 s with the
// defaults this daemon uses).
//
// Why twice: a follower checks for its leader on a timer that fires at a
// random point between one and two HeartbeatTimeouts, and declares the leader
// lost if it has heard nothing for one HeartbeatTimeout. So once two have
// passed with no contact, raft itself has already given up on the leader and
// started (or tried to start) an election. A healthy leader sends a heartbeat
// every HeartbeatTimeout/10 (100 ms), so this is ~20 missed heartbeats: a
// slow network or a GC pause does not get here, and a false refusal costs one
// retry against another server anyway. Read from the live config, so a tuned
// raft moves this bound with it.
func (c *Cluster) staleReadBound() time.Duration {
	hb := raft.DefaultConfig().HeartbeatTimeout
	if c != nil && c.raft != nil && c.raft.raft != nil {
		if live := c.raft.raft.ReloadableConfig().HeartbeatTimeout; live > 0 {
			hb = live
		}
	}
	return 2 * hb
}

// clusterStaleReadRejects counts internal placement reads a follower answered
// 503 because it had lost contact with the leader. A rising count on one
// server means that server is cut off.
var clusterStaleReadRejects = expvar.NewInt("aerolvm_cluster_stale_placement_read_rejects_total")

// RecordStalePlacementReadReject counts one internal placement read this
// server answered 503 because it had lost contact with the leader.
func RecordStalePlacementReadReject() {
	clusterStaleReadRejects.Add(1)
}
