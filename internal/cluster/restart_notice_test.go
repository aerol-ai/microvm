package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/hashicorp/memberlist"
)

// C8 (plans/kubernetes-v2-architecture.md §10.2, lesson L2): a planned
// restart is not a death. A node that announced a restart on SIGTERM keeps
// its sandboxes for the restart window; a crash, a node with the window off
// and a deleted node keep today's grace. These rows hold on plain VM
// clusters too (eng review D9): nothing here is Kubernetes-only.
func TestReconcileDeadOwnersRestartNotice(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	const (
		grace  = 50 * time.Millisecond
		window = 400 * time.Millisecond
	)
	cases := []struct {
		name       string
		window     time.Duration
		restarting bool
		deny       bool
		// keptPastGrace: the sandbox still belongs to the node after the
		// grace but inside the window.
		keptPastGrace bool
	}{
		{name: "announced restart waits the window", window: window, restarting: true, keptPastGrace: true},
		{name: "crash (no notice) gets only the grace", window: window, restarting: false},
		{name: "window off: notice ignored", window: 0, restarting: true},
		{name: "window no longer than the grace changes nothing", window: grace / 2, restarting: true},
		{name: "deleted node never waits", window: window, restarting: true, deny: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, cleanup := newTestClusterWithCfg(t, "ldr", true, nil, func(cfg *config.Config) {
				cfg.ClusterDeadOwnerGrace = grace
				cfg.ClusterRestartWindow = tc.window
			})
			defer cleanup()
			waitForLeader(t, c, 10*time.Second)
			c.rolloutStop()
			ctx := context.Background()

			payload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-rs", OwnerNodeID: "wkr"})
			if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
				t.Fatal(err)
			}
			if tc.deny {
				deny, _ := encodeCommand(command{Op: opDenyNode, StampUnixNano: time.Now().UnixNano(), NodeDeny: &NodeDenyRecord{NodeID: "wkr", Role: config.NodeRoleWorker}})
				if err := c.raft.raft.Apply(deny, 2*time.Second).Error(); err != nil {
					t.Fatal(err)
				}
			}
			c.handleMemberLeave("wkr", tc.restarting)

			time.Sleep(3 * grace)
			c.reconcileDeadOwners(ctx)
			_, err := c.OwnerOf("sb-rs")
			if tc.keptPastGrace {
				if err != nil {
					t.Fatalf("inside the restart window the sandbox moved: %v", err)
				}
				time.Sleep(window)
				c.reconcileDeadOwners(ctx)
				if _, err := c.OwnerOf("sb-rs"); !errors.Is(err, ErrOrphaned) {
					t.Fatalf("past the window OwnerOf err = %v, want ErrOrphaned", err)
				}
				return
			}
			if !errors.Is(err, ErrOrphaned) {
				t.Fatalf("past the grace OwnerOf err = %v, want ErrOrphaned", err)
			}
		})
	}
}

func TestDeadOwnerTrackerRestartDeadline(t *testing.T) {
	tr := newDeadOwnerTracker()
	first := time.Unix(100, 0)
	tr.markRestarting("n", first)
	// A second notice cannot push the deadline out.
	tr.markRestarting("n", first.Add(time.Hour))
	if got, ok := tr.restarting("n"); !ok || !got.Equal(first) {
		t.Fatalf("restarting = %v %v, want %v", got, ok, first)
	}
	tr.markDead("n", first)
	// A rejoin clears both marks, so the next leave starts fresh.
	tr.clear("n")
	if _, ok := tr.restarting("n"); ok {
		t.Fatal("clear kept the restart deadline")
	}
	if _, ok := tr.snapshot()["n"]; ok {
		t.Fatal("clear kept the dead mark")
	}
}

func TestHandleMemberLeaveRecordsRestartOnlyWithAWindow(t *testing.T) {
	for _, tc := range []struct {
		window     time.Duration
		restarting bool
		want       bool
	}{
		{window: time.Minute, restarting: true, want: true},
		{window: time.Minute, restarting: false, want: false},
		{window: 0, restarting: true, want: false},
		{window: -time.Second, restarting: true, want: false},
	} {
		c := &Cluster{nodeID: "self", deadOwners: newDeadOwnerTracker(), cfg: config.Config{ClusterRestartWindow: tc.window}}
		c.handleMemberLeave("peer", tc.restarting)
		if _, ok := c.deadOwners.snapshot()["peer"]; !ok {
			t.Fatalf("%+v: leave not marked dead", tc)
		}
		if _, ok := c.deadOwners.restarting("peer"); ok != tc.want {
			t.Fatalf("%+v: restart recorded = %v, want %v", tc, ok, tc.want)
		}
	}
	if got := RestartWindow(&config.Config{}); got != 0 {
		t.Fatalf("RestartWindow(zero) = %v", got)
	}
}

// The leave callback reads the last meta the peer gossiped, which is how the
// notice reaches the leader.
func TestVoterAutoJoinLeaveCarriesRestartNotice(t *testing.T) {
	c := &Cluster{nodeID: "self", deadOwners: newDeadOwnerTracker(), cfg: config.Config{ClusterRestartWindow: time.Minute}}
	d := &voterAutoJoinDelegate{c: c}
	meta, _ := json.Marshal(nodeMeta{NodeID: "peer", Restarting: true})
	d.NotifyLeave(&memberlist.Node{Name: "peer", Meta: meta})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := c.deadOwners.restarting("peer"); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a leave with rs set recorded no restart")
}

func TestGossipMetaCarriesRestarting(t *testing.T) {
	d := newGossipDelegate("n1", "", "http://n1", "", "10.0.0.1:7000", "https://n1:9443", "worker", "", nil)
	if strings.Contains(string(d.NodeMeta(512)), `"rs"`) {
		t.Fatal("a running node's meta carries rs")
	}
	g := &gossipNode{delegate: d}
	if err := g.announceRestart(time.Second); err != nil {
		t.Fatal(err)
	}
	// Idempotent: the second call sends nothing new.
	if err := g.announceRestart(time.Second); err != nil {
		t.Fatal(err)
	}
	var meta nodeMeta
	if err := json.Unmarshal(d.NodeMeta(512), &meta); err != nil || !meta.Restarting {
		t.Fatalf("meta after announce = %+v %v", meta, err)
	}
	m := memberFromMemberlistNode(&memberlist.Node{Name: "n1", Meta: d.NodeMeta(512), State: memberlist.StateAlive})
	if !m.Restarting {
		t.Fatal("decoded member lost Restarting")
	}
	if !g.selfMember().Restarting {
		t.Fatal("selfMember lost Restarting")
	}

	// Near the 512-byte cap the first fallback tiers keep rs; the bare
	// identity tiers drop it, which only fails over sooner.
	d.mu.Lock()
	d.publicHost = strings.Repeat("p", 300)
	d.mu.Unlock()
	d.refreshMeta()
	enc := d.NodeMeta(320)
	if len(enc) > 320 {
		t.Fatalf("fallback meta is %d bytes", len(enc))
	}
	meta = nodeMeta{}
	if err := json.Unmarshal(enc, &meta); err != nil || !meta.Restarting || meta.RaftAddr == "" {
		t.Fatalf("first fallback tier = %s %v", enc, err)
	}

	var nilNode *gossipNode
	if err := nilNode.announceRestart(time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestPlacementSkipsRestartingNode(t *testing.T) {
	room := capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 4096, CPUBudget: 4, MemoryBudgetMB: 4096}
	worker := func(id string, restarting bool) Member {
		return Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, APIURL: "http://" + id, Capacity: room, Restarting: restarting}
	}
	c := &Cluster{nodeID: "srv", apiURL: "http://srv", fsm: newPlacementFSM(), gossip: &gossipNode{memberIndex: newGossipMemberIndex()}}
	c.gossip.memberIndex.replace([]Member{worker("going", true)})
	if _, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 128}); !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("only a restarting node: err = %v, want ErrNoPlacementTarget", err)
	}
	c.gossip.memberIndex.replace([]Member{worker("going", true), worker("staying", false)})
	for i := 0; i < 20; i++ {
		target, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 128})
		if err != nil || target.NodeID != "staying" {
			t.Fatalf("placement = %+v %v, want staying", target, err)
		}
	}

	// The failover scan skips it too: a sandbox moved there would move again.
	p := Placement{SandboxID: "sb", OwnerNodeID: "dead", Spec: recreatePolicySpec(1)}
	target, err := c.selectRecreationTargetFor(p, "dead")
	if err != nil || target.NodeID != "staying" {
		t.Fatalf("recreation target = %+v %v, want staying", target, err)
	}
	c.gossip.memberIndex.replace([]Member{worker("going", true)})
	if _, err := c.selectRecreationTargetFor(p, "dead"); err == nil {
		t.Fatal("a restarting node was chosen as the failover target")
	}
}

// A leading server hands Raft leadership to the other voter before it stops,
// and its peers see the restart notice.
func TestPrepareShutdownHandsOffLeadershipAndAnnounces(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-c8", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	follower, cleanupFollower := newTestCluster(t, "fol-c8", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)
	waitForFollowerToReachLeader(t, follower, leader.nodeID, 10*time.Second)

	before := expvarMapInt(shutdownHandoffs, "ok")
	leader.PrepareShutdown(context.Background())
	if leader.IsLeader() {
		t.Fatal("the leader still leads after PrepareShutdown")
	}
	if !follower.IsLeader() {
		t.Fatalf("leadership went to %q, want %s", follower.Leader(), follower.nodeID)
	}
	if got := expvarMapInt(shutdownHandoffs, "ok"); got != before+1 {
		t.Fatalf("handoffs ok = %d, want %d", got, before+1)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if m, ok := follower.gossip.lookupMember(leader.nodeID); ok && m.Restarting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the follower never saw the restart notice")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A second call is harmless: no longer the leader, already announced.
	leader.PrepareShutdown(context.Background())
}

// The only voter has nobody to hand leadership to: it keeps it, announces,
// and stops on its own.
func TestPrepareShutdownSingleVoterKeepsLeadership(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "solo-c8", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	c.PrepareShutdown(context.Background())
	if !c.IsLeader() {
		t.Fatal("the only voter gave up leadership")
	}
	if !c.gossip.selfMember().Restarting {
		t.Fatal("no restart notice")
	}
}

func TestPrepareShutdownWithoutRaftOrGossip(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	(&Cluster{logger: logger}).PrepareShutdown(context.Background())
	(&Agent{logger: logger}).PrepareShutdown(context.Background())
	d := newGossipDelegate("w1", "", "http://w1", "", "", "", "worker", "", nil)
	a := &Agent{logger: logger, gossip: &gossipNode{delegate: d}}
	a.PrepareShutdown(context.Background())
	if !a.gossip.selfMember().Restarting {
		t.Fatal("agent did not announce")
	}
	var _ ShutdownPreparer = (*Cluster)(nil)
	var _ ShutdownPreparer = (*Agent)(nil)
}

func expvarMapInt(m *expvar.Map, key string) int64 {
	if v, ok := m.Get(key).(*expvar.Int); ok {
		return v.Value()
	}
	return 0
}
