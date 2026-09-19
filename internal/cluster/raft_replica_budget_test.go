package cluster

import (
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/raft"
)

// seedGossipView installs a deterministic membership view on a real cluster so
// the test controls the topology regime without standing up N memberlist
// processes.
// newReplicaBudgetCluster is a real single-voter raft leader. The voter cap is
// pinned to 1 so every admitted peer joins as a NON-VOTER: a non-voter still
// receives the full log and FSM (the thing the budget exists to bound) but
// does not change quorum, so unreachable test endpoints cannot depose the
// leader mid-test.
func newReplicaBudgetCluster(t *testing.T, nodeID string) (*Cluster, func()) {
	t.Helper()
	c, cleanup := newTestCluster(t, nodeID, true, nil)
	c.cfg.ClusterMaxAutoVoters = 1
	waitForLeader(t, c, 10*time.Second)
	return c, cleanup
}

func seedGossipView(t *testing.T, c *Cluster, members []Member) {
	t.Helper()
	index := newGossipMemberIndex()
	for _, m := range members {
		index.upsert(m)
	}
	c.gossip.setMemberIndex(index)
}

func raftServerIDs(t *testing.T, c *Cluster) []string {
	t.Helper()
	cfg := c.raft.raft.GetConfiguration()
	if err := cfg.Error(); err != nil {
		t.Fatalf("GetConfiguration: %v", err)
	}
	out := make([]string, 0, len(cfg.Configuration().Servers))
	for _, srv := range cfg.Configuration().Servers {
		out = append(out, string(srv.ID))
	}
	return out
}

// MaxServerTierNodes is checked by topology/placement validation, but that
// rejects an oversized tier AFTER the surplus nodes have already joined and
// started receiving the log and FSM. The membership mutator is the only place
// that can actually bound replication, so the cap has to hold there.
func TestRaftReplicaAdmissionEnforcesServerTierBudget(t *testing.T) {
	c, cleanup := newReplicaBudgetCluster(t, "srv-000")
	defer cleanup()

	// A dedicated-tier fleet: 10 servers, plus workers and ingress to put the
	// live count above MaxMixedClusterNodes.
	members := []Member{{NodeID: "srv-000", Role: config.NodeRoleServer, Alive: true, RaftAddr: "127.0.0.1:1"}}
	for i := 1; i < 10; i++ {
		members = append(members, Member{
			NodeID:   fmt.Sprintf("srv-%03d", i),
			Role:     config.NodeRoleServer,
			Alive:    true,
			RaftAddr: fmt.Sprintf("127.0.0.1:%d", 19000+i),
			APIURL:   fmt.Sprintf("http://127.0.0.1:%d", 18000+i),
		})
	}
	for i := range 2 {
		members = append(members, Member{NodeID: fmt.Sprintf("wrk-%03d", i), Role: config.NodeRoleWorker, Alive: true})
	}
	members = append(members, Member{NodeID: "ing-000", Role: config.NodeRoleIngress, Alive: true})
	seedGossipView(t, c, members)

	if err := LargeClusterTopologyError(members); err == nil {
		t.Fatal("topology validation accepted ten dedicated servers; the fixture no longer models the reported fleet")
	}

	for i := 1; i < 10; i++ {
		c.handleMemberJoin(fmt.Sprintf("srv-%03d", i))
	}

	got := raftServerIDs(t, c)
	if len(got) > MaxServerTierNodes {
		t.Fatalf("raft configuration holds %d replicas (%v); the advertised limit is %d and every replica carries the whole placement FSM",
			len(got), got, MaxServerTierNodes)
	}
	if len(got) != MaxServerTierNodes {
		t.Fatalf("raft configuration holds %d replicas (%v); admission should fill the budget exactly", len(got), got)
	}
	if raftReplicaAdmissionRefused.Value() == 0 {
		t.Fatal("refusals were not counted; operators need the signal to know surplus servers must be re-roled")
	}
}

// The <=MaxMixedClusterNodes topology is explicitly supported and every mixed
// node is server-role, so the dedicated-tier budget must not apply to it.
func TestRaftReplicaAdmissionKeepsSmallMixedTopology(t *testing.T) {
	c, cleanup := newReplicaBudgetCluster(t, "mix-000")
	defer cleanup()

	members := []Member{{NodeID: "mix-000", Role: config.NodeRoleMixed, Alive: true, RaftAddr: "127.0.0.1:1"}}
	for i := 1; i < MaxMixedClusterNodes; i++ {
		members = append(members, Member{
			NodeID:   fmt.Sprintf("mix-%03d", i),
			Role:     config.NodeRoleMixed,
			Alive:    true,
			RaftAddr: fmt.Sprintf("127.0.0.1:%d", 29000+i),
			APIURL:   fmt.Sprintf("http://127.0.0.1:%d", 28000+i),
		})
	}
	seedGossipView(t, c, members)

	if err := LargeClusterTopologyError(members); err != nil {
		t.Fatalf("a %d-node mixed cluster must stay supported: %v", MaxMixedClusterNodes, err)
	}
	for i := 1; i < MaxMixedClusterNodes; i++ {
		c.handleMemberJoin(fmt.Sprintf("mix-%03d", i))
	}

	if got := raftServerIDs(t, c); len(got) != MaxMixedClusterNodes {
		t.Fatalf("small mixed cluster admitted %d of %d replicas (%v); the legacy topology was broken by the dedicated-tier budget",
			len(got), MaxMixedClusterNodes, got)
	}
}

// A gossip-dead configured server must not occupy budget, or the spare slots
// that exist for rolling replacement would never be usable.
func TestRaftReplicaBudgetIgnoresDeadConfiguredServers(t *testing.T) {
	c, cleanup := newReplicaBudgetCluster(t, "srv-a")
	defer cleanup()

	members := []Member{
		{NodeID: "srv-a", Role: config.NodeRoleServer, Alive: true, RaftAddr: "127.0.0.1:1"},
		{NodeID: "srv-dead", Role: config.NodeRoleServer, Alive: false, RaftAddr: "127.0.0.1:2"},
	}
	for i := range 12 {
		members = append(members, Member{NodeID: fmt.Sprintf("wrk-%03d", i), Role: config.NodeRoleWorker, Alive: true})
	}
	seedGossipView(t, c, members)

	f := c.raft.raft.AddNonvoter(raft.ServerID("srv-dead"), raft.ServerAddress("127.0.0.1:2"), 0, c.commitTimeout)
	if err := f.Error(); err != nil {
		t.Fatalf("AddNonvoter(srv-dead): %v", err)
	}

	replicas, ok := c.currentReplicaCount("srv-new")
	if !ok {
		t.Fatal("currentReplicaCount could not read the configuration")
	}
	if replicas != 1 {
		t.Fatalf("replica count = %d, want 1 (the gossip-dead entry is awaiting RemoveServer and must not hold a slot)", replicas)
	}
	if c.raftReplicaAdmissionBlocked("srv-new") {
		t.Fatal("a replacement server was refused while the only other slot holder is gossip-dead")
	}
}

// An already-configured replica changing address or suffrage is not a new
// state carrier and must not be refused when the tier is at budget.
func TestRaftReplicaBudgetAllowsExistingMemberCorrections(t *testing.T) {
	c, cleanup := newReplicaBudgetCluster(t, "srv-self")
	defer cleanup()

	members := []Member{{NodeID: "srv-self", Role: config.NodeRoleServer, Alive: true, RaftAddr: "127.0.0.1:1"}}
	for i := range 12 {
		members = append(members, Member{NodeID: fmt.Sprintf("wrk-%03d", i), Role: config.NodeRoleWorker, Alive: true})
	}
	seedGossipView(t, c, members)

	// Fill the budget with configured replicas that gossip does not know
	// about, so none of them is discounted as dead.
	for i := range MaxServerTierNodes - 1 {
		id := fmt.Sprintf("srv-filler-%d", i)
		if err := c.raft.raft.AddNonvoter(raft.ServerID(id), raft.ServerAddress(fmt.Sprintf("127.0.0.1:%d", 31000+i)), 0, c.commitTimeout).Error(); err != nil {
			t.Fatalf("AddNonvoter(%s): %v", id, err)
		}
	}
	if !c.raftReplicaAdmissionBlocked("srv-brand-new") {
		t.Fatal("budget is full but a brand-new replica was still admitted")
	}
	if c.raftReplicaAdmissionBlocked("srv-filler-0") {
		t.Fatal("an existing replica was counted against its own admission")
	}
}
