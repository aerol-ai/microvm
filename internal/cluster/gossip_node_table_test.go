package cluster

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/memberlist"
)

func TestGossipNodeTableKeepsDeepCopies(t *testing.T) {
	tbl := newGossipNodeTable()
	src := &memberlist.Node{
		Name:  "peer",
		Addr:  net.ParseIP("10.0.0.7").To4(),
		Port:  7946,
		Meta:  []byte(`{"node_id":"peer"}`),
		State: memberlist.StateAlive,
	}
	tbl.put(src)

	// memberlist rewrites its own struct later; the table must not see it.
	src.Meta[0] = 'X'
	src.Addr[3] = 99
	src.State = memberlist.StateDead

	got := tbl.snapshot()
	if len(got) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(got))
	}
	if string(got[0].Meta) != `{"node_id":"peer"}` || got[0].Addr.String() != "10.0.0.7" || got[0].State != memberlist.StateAlive {
		t.Fatalf("snapshot = %+v, want the values at put time", got[0])
	}

	// A caller that edits its snapshot must not change the table either.
	got[0].Meta[0] = 'Y'
	got[0].Addr[3] = 1
	again := tbl.snapshot()
	if string(again[0].Meta) != `{"node_id":"peer"}` || again[0].Addr.String() != "10.0.0.7" {
		t.Fatalf("table changed through a snapshot: %+v", again[0])
	}
	if addr := tbl.address("peer"); addr != "10.0.0.7:7946" {
		t.Fatalf("address = %q, want 10.0.0.7:7946", addr)
	}
}

func TestGossipNodeTableCases(t *testing.T) {
	cases := []struct {
		name      string
		run       func(*gossipNodeTable)
		wantNames []string
	}{
		{"put then remove", func(tb *gossipNodeTable) {
			tb.put(&memberlist.Node{Name: "a"})
			tb.put(&memberlist.Node{Name: "b"})
			tb.remove("a")
		}, []string{"b"}},
		{"put replaces", func(tb *gossipNodeTable) {
			tb.put(&memberlist.Node{Name: "a", Port: 1})
			tb.put(&memberlist.Node{Name: "a", Port: 2})
		}, []string{"a"}},
		{"nil node and empty name ignored", func(tb *gossipNodeTable) {
			tb.put(nil)
			tb.put(&memberlist.Node{})
			tb.remove("")
			tb.remove("missing")
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tb := newGossipNodeTable()
			tc.run(tb)
			got := tb.snapshot()
			if len(got) != len(tc.wantNames) {
				t.Fatalf("snapshot = %d nodes, want %v", len(got), tc.wantNames)
			}
			for i, want := range tc.wantNames {
				if got[i].Name != want {
					t.Fatalf("snapshot[%d] = %q, want %q", i, got[i].Name, want)
				}
			}
		})
	}

	var nilTable *gossipNodeTable
	nilTable.put(&memberlist.Node{Name: "a"})
	nilTable.remove("a")
	if nilTable.snapshot() != nil || nilTable.address("a") != "" {
		t.Fatal("nil table must read as empty")
	}
	if newGossipNodeTable().address("missing") != "" {
		t.Fatal("address of a missing node must be empty")
	}
}

func TestIndexedEventDelegateMaintainsTheNodeTable(t *testing.T) {
	tbl := newGossipNodeTable()
	d := &indexedEventDelegate{index: newGossipMemberIndex(), nodes: tbl}
	server := &memberlist.Node{Name: "s1", Addr: net.ParseIP("10.0.0.2"), Port: 7946, State: memberlist.StateAlive,
		Meta: encodedMeta(t, "s1", config.NodeRoleServer)}

	d.NotifyJoin(server)
	gn := &gossipNode{nodes: tbl, delegate: &gossipDelegate{nodeID: "self"}}
	if got := liveControlPlanePeerAddrs(gn.memberlistNodes(), "self"); len(got) != 1 || got[0] != "10.0.0.2:7946" {
		t.Fatalf("peer addrs after join = %v, want [10.0.0.2:7946]", got)
	}

	moved := *server
	moved.Meta = encodedMeta(t, "s1", config.NodeRoleWorker)
	d.NotifyUpdate(&moved)
	if got := liveControlPlanePeerAddrs(gn.memberlistNodes(), "self"); len(got) != 0 {
		t.Fatalf("peer addrs after the node became a worker = %v, want none", got)
	}

	d.NotifyLeave(&moved)
	if got := gn.memberlistNodes(); len(got) != 0 {
		t.Fatalf("nodes after leave = %v, want none (memberlist drops dead nodes from Members too)", got)
	}
	d.NotifyLeave(nil)
}

// TestGossipReadsDoNotRaceMemberlistUpdates is the regression test for the
// data race that failed TestRestartedSeedRejoinsAfterEviction under -race:
// scanMembers and the peer helpers read Meta / Addr / State through the
// pointers ml.Members() returns, while memberlist.aliveNode rewrites those
// fields each time a peer re-announces itself. Node b re-announces in a loop
// (UpdateNode bumps its incarnation, so node a rewrites b's entry on every
// message) while node a reads. With -race this fails on the old code; without
// -race it only checks the reads keep working.
func TestGossipReadsDoNotRaceMemberlistUpdates(t *testing.T) {
	start := func(id string, peers []string) *gossipNode {
		t.Helper()
		gn, err := setupGossip(gossipSetupConfig{
			NodeID:         id,
			BindAddr:       "127.0.0.1:0",
			BootstrapPeers: peers,
			GossipInterval: time.Hour, // keep the refresh loop out of the way
			InternalURL:    "https://" + id + ".internal:7002",
			Role:           config.NodeRoleServer,
		}, nil, nil)
		if err != nil {
			t.Fatalf("setupGossip(%s): %v", id, err)
		}
		t.Cleanup(func() { _ = gn.Close() })
		return gn
	}
	a := start("race-a", nil)
	b := start("race-b", []string{a.selfGossipAddr})

	deadline := time.Now().Add(10 * time.Second)
	for {
		if m, ok := a.lookupMember("race-b"); ok && m.Alive {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("node a never saw node b join")
		}
		time.Sleep(10 * time.Millisecond)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = b.ml.UpdateNode(time.Second)
		}
	}()

	sawB := false
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		nodes := a.memberlistNodes()
		for _, addr := range liveControlPlanePeerAddrs(nodes, "race-a") {
			if addr == b.selfGossipAddr {
				sawB = true
			}
		}
		_ = hasLiveControlPlaneMember(nodes, "race-a")
		_ = a.scanMembers()
	}
	close(stop)
	wg.Wait()
	if !sawB {
		t.Fatalf("node a never listed node b (%s) as a live control-plane peer", b.selfGossipAddr)
	}
}
