package cluster

import (
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// TestFollowerCutOffFromLeaderReportsStaleView is the I7 regression with real
// raft: a follower that stops hearing from its leader must stop vouching for
// its placement view. Before the fix nothing looked at leader contact, so the
// follower kept answering placement reads from an FSM that no longer moved,
// for as long as the partition lasted.
func TestFollowerCutOffFromLeaderReportsStaleView(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires opening real raft/memberlist sockets")
	}
	leader, cleanupLeader := newTestCluster(t, "stale-leader", true, nil)
	leaderClosed := false
	defer func() {
		if !leaderClosed {
			cleanupLeader()
		}
	}()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "stale-follower", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, "stale-follower", 10*time.Second)
	waitForFollowerToReachLeader(t, follower, "stale-leader", 10*time.Second)

	if leader.PlacementViewStale() {
		t.Fatal("the leader reported a stale placement view; the leader is never refused")
	}
	// Knowing the leader is not contact yet: raft records the leader before
	// it accepts the first AppendEntries, and a follower whose log does not
	// match yet is still behind. Wait for the first accepted one.
	waitFresh := time.Now().Add(10 * time.Second)
	for follower.PlacementViewStale() {
		if time.Now().After(waitFresh) {
			t.Fatal("a follower in contact with its leader still reports a stale placement view after 10s")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Two voters, one gone: the follower can never win an election, so it
	// stays without a leader. That is the cut-off side of a partition.
	cleanupLeader()
	leaderClosed = true
	closedAt := time.Now()

	bound := follower.staleReadBound()
	deadline := time.Now().Add(bound + 10*time.Second)
	for !follower.PlacementViewStale() {
		if time.Now().After(deadline) {
			t.Fatalf("follower still vouches for its placement view %s after losing its leader (last contact %s ago, bound %s)",
				bound+10*time.Second, time.Since(follower.raft.raft.LastContact()), bound)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if PlacementViewFresh(follower) {
		t.Fatal("PlacementViewFresh(follower) = true for a follower without its leader")
	}
	t.Logf("follower reported a stale view %s after its leader closed (bound %s)", time.Since(closedAt).Round(10*time.Millisecond), bound)
}

// TestPlacementViewStaleDecision pins the rule without sockets: the leader is
// never stale; a follower is stale only once its last contact with the leader
// is older than the bound; anything without raft is the whole truth.
func TestPlacementViewStaleDecision(t *testing.T) {
	withRaft := func(state raft.RaftState, lastContact time.Time) *Cluster {
		return &Cluster{leaderContactHook: func() (raft.RaftState, time.Time) { return state, lastContact }}
	}
	now := time.Now()
	bound := 2 * raft.DefaultConfig().HeartbeatTimeout
	for _, tc := range []struct {
		name string
		c    *Cluster
		want bool
	}{
		{name: "nil cluster", c: nil, want: false},
		{name: "no raft (single-process FSM)", c: &Cluster{}, want: false},
		{name: "raft node without raft", c: &Cluster{raft: &raftNode{}}, want: false},
		{name: "leader that has not heard from anyone", c: withRaft(raft.Leader, time.Time{}), want: false},
		{name: "follower in contact", c: withRaft(raft.Follower, now.Add(-100*time.Millisecond)), want: false},
		{name: "follower just inside the bound", c: withRaft(raft.Follower, now.Add(-bound+500*time.Millisecond)), want: false},
		{name: "follower past the bound", c: withRaft(raft.Follower, now.Add(-bound-500*time.Millisecond)), want: true},
		{name: "candidate past the bound", c: withRaft(raft.Candidate, now.Add(-10*time.Second)), want: true},
		{name: "follower that never heard from a leader", c: withRaft(raft.Follower, time.Time{}), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.PlacementViewStale(); got != tc.want {
				t.Fatalf("PlacementViewStale() = %v, want %v", got, tc.want)
			}
			if got := PlacementViewFresh(tc.c); tc.c != nil && got == tc.want {
				t.Fatalf("PlacementViewFresh() = %v, want %v", got, !tc.want)
			}
		})
	}
}

// Clients without a local replica (an Agent asks a server, which applies the
// gate itself; Noop is the whole truth) are always fresh.
func TestPlacementViewFreshForClientsWithoutAReplica(t *testing.T) {
	if !PlacementViewFresh(NewNoop("standalone", "", "")) {
		t.Fatal("Noop reported a stale placement view")
	}
	if !PlacementViewFresh(&Agent{}) {
		t.Fatal("Agent reported a stale placement view")
	}
}

// The bound follows the running raft's heartbeat timeout, so an operator who
// tunes raft does not leave this check behind.
func TestStaleReadBoundFollowsRaftHeartbeatTimeout(t *testing.T) {
	if got, want := (&Cluster{}).staleReadBound(), 2*raft.DefaultConfig().HeartbeatTimeout; got != want {
		t.Fatalf("staleReadBound without raft = %s, want %s", got, want)
	}
	_, trans := raft.NewInmemTransport("")
	cfg := raft.DefaultConfig()
	cfg.LocalID = "bound-node"
	cfg.HeartbeatTimeout = 3 * time.Second
	cfg.ElectionTimeout = 3 * time.Second
	cfg.LeaderLeaseTimeout = time.Second
	store := raft.NewInmemStore()
	r, err := raft.NewRaft(cfg, &raft.MockFSM{}, store, store, raft.NewInmemSnapshotStore(), trans)
	if err != nil {
		t.Fatalf("NewRaft: %v", err)
	}
	defer r.Shutdown()
	c := &Cluster{raft: &raftNode{raft: r}}
	if got := c.staleReadBound(); got != 6*time.Second {
		t.Fatalf("staleReadBound = %s, want 6s (twice the 3s heartbeat timeout)", got)
	}
}

func TestRecordStalePlacementReadReject(t *testing.T) {
	before := clusterStaleReadRejects.Value()
	RecordStalePlacementReadReject()
	if got := clusterStaleReadRejects.Value(); got != before+1 {
		t.Fatalf("stale read rejects = %d, want %d", got, before+1)
	}
}
