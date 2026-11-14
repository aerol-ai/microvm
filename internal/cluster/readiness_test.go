package cluster

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/raft"
)

// C1 (TODOS.md "A partitioned node keeps serving"): a server's readiness
// comes from its raft view.
func TestClusterControlPlaneContact(t *testing.T) {
	now := time.Now()
	old := now.Add(-30 * time.Second)
	withRaft := func(state raft.RaftState, last time.Time, member bool) *Cluster {
		return &Cluster{
			leaderContactHook: func() (raft.RaftState, time.Time) { return state, last },
			raftMemberHook:    func() bool { return member },
		}
	}
	for _, tc := range []struct {
		name       string
		c          *Cluster
		wantMember bool
		wantFresh  bool // Last within a second of now
		wantLast   time.Time
	}{
		{name: "the leader is the newest view there is", c: withRaft(raft.Leader, time.Time{}, true), wantMember: true, wantFresh: true},
		{name: "a follower reports its last leader contact", c: withRaft(raft.Follower, old, true), wantMember: true, wantLast: old},
		{name: "a candidate that never heard a leader", c: withRaft(raft.Candidate, time.Time{}, true), wantMember: true, wantLast: time.Time{}},
		{name: "a server removed from the configuration", c: withRaft(raft.Follower, now, false), wantMember: false, wantLast: now},
		{name: "no raft: a single-process FSM is the whole control plane", c: &Cluster{}, wantMember: true, wantFresh: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.c.ControlPlaneContact(context.Background())
			if got.Member != tc.wantMember {
				t.Fatalf("Member = %v, want %v", got.Member, tc.wantMember)
			}
			if tc.wantFresh {
				if time.Since(got.Last) > time.Second {
					t.Fatalf("Last = %v, want about now", got.Last)
				}
				return
			}
			if !got.Last.Equal(tc.wantLast) {
				t.Fatalf("Last = %v, want %v", got.Last, tc.wantLast)
			}
		})
	}
}

func TestClusterRaftMemberWithoutRaft(t *testing.T) {
	// A raftNode whose raft is not up yet: no configuration to read, so the
	// contact time decides, not membership.
	if !(&Cluster{raft: &raftNode{}}).raftMember() {
		t.Fatal("a node with no raft yet must not read as removed")
	}
}

// An agent's readiness comes from its last successful control-plane
// exchange, refreshed by one shared probe when it is old.
func TestAgentControlPlaneContact(t *testing.T) {
	oldAfter := agentContactProbeAfter
	t.Cleanup(func() { agentContactProbeAfter = oldAfter })
	agentContactProbeAfter = time.Second

	t.Run("fresh contact sends no probe", func(t *testing.T) {
		a := &Agent{leaderProbeHook: func() string { t.Fatal("probed with fresh contact"); return "" }}
		a.contact.record(time.Now())
		if got := a.ControlPlaneContact(context.Background()); !got.Member || time.Since(got.Last) > time.Second {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("old contact: a probe that finds a leader refreshes it", func(t *testing.T) {
		a := &Agent{leaderProbeHook: func() string { return "srv-1" }}
		a.contact.record(time.Now().Add(-time.Minute))
		if got := a.ControlPlaneContact(context.Background()); time.Since(got.Last) > time.Second {
			t.Fatalf("Last = %v, want refreshed", got.Last)
		}
	})
	t.Run("a probe with no leader does not count", func(t *testing.T) {
		a := &Agent{leaderProbeHook: func() string { return "" }}
		if got := a.ControlPlaneContact(context.Background()); !got.Last.IsZero() {
			t.Fatalf("Last = %v, want never", got.Last)
		}
	})
	t.Run("concurrent checks share one probe", func(t *testing.T) {
		var probes atomic.Int32
		release := make(chan struct{})
		a := &Agent{leaderProbeHook: func() string {
			probes.Add(1)
			<-release
			return "srv-1"
		}}
		var wg sync.WaitGroup
		results := make(chan ControlPlaneContact, 20)
		for range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- a.ControlPlaneContact(context.Background())
			}()
		}
		// Let every caller reach the probe or the wait for it.
		deadline := time.Now().Add(2 * time.Second)
		for probes.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond)
		close(release)
		wg.Wait()
		close(results)
		if n := probes.Load(); n != 1 {
			t.Fatalf("%d probes, want 1 shared by every caller", n)
		}
		for r := range results {
			if time.Since(r.Last) > 2*time.Second {
				t.Fatalf("a caller got stale contact %v", r.Last)
			}
		}
	})
}

// Against real raft: a seeded server is a member with fresh contact, and an
// agent's ordinary control-plane call is recorded without any probe.
func TestReadinessAgainstRealRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}
	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listen: %v", err)
	}
	server, cleanupServer := newTestClusterWithAPI(t, "srv-ready", true, nil, "http://"+apiListener.Addr().String())
	defer cleanupServer()
	waitForLeader(t, server, 10*time.Second)
	if got := server.ControlPlaneContact(context.Background()); !got.Member || time.Since(got.Last) > time.Second {
		t.Fatalf("seeded leader: %+v, want a member with fresh contact", got)
	}

	srv := startAgentControlPlaneServer(t, server, apiListener)
	defer srv.Close()
	agent, cleanupAgent := newTestAgentWithRole(t, "wkr-ready", config.NodeRoleWorker,
		[]string{server.gossip.ml.LocalNode().Address()})
	defer cleanupAgent()
	waitForGossipMember(t, server, "wkr-ready", 10*time.Second)

	agent.leaderProbeHook = func() string { t.Fatal("probed although a call had just succeeded"); return "" }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := agent.RecordPlacement(ctx, "sb-ready", nil, PlacementSecrets{IncarnationID: "inc-sb-ready"}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	if got := agent.ControlPlaneContact(ctx); !got.Member || time.Since(got.Last) > 5*time.Second {
		t.Fatalf("agent after a successful call: %+v, want fresh contact", got)
	}
}
