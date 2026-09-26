package cluster

import (
	"fmt"
	"sync"
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

// A gossip-dead configured server DOES occupy budget until its removal is
// committed: it still receives the log and the FSM, and gossip liveness is
// not raft liveness. Discounting it is what let a flapping tier grow past the
// budget, because the returning member then takes the existing-member path
// and never re-checks admission. Rolling replacement trails the eviction the
// dead-owner reconciler performs, rather than racing it.
func TestRaftReplicaBudgetCountsDeadConfiguredServersUntilRemoval(t *testing.T) {
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
	if replicas != 2 {
		t.Fatalf("replica count = %d, want 2 (self plus the gossip-dead entry, which is still configured and still replicated to)", replicas)
	}
	// Below the budget there is still room, so the replacement is admitted.
	if c.raftReplicaAdmissionBlocked("srv-new") {
		t.Fatal("a replacement was refused while the tier is well under its budget")
	}

	// Once the configuration is full of gossip-dead members, the slot only
	// frees when the removal commits.
	for i := range MaxServerTierNodes - 2 {
		id := fmt.Sprintf("srv-filler-dead-%d", i)
		if err := c.raft.raft.AddNonvoter(raft.ServerID(id), raft.ServerAddress(fmt.Sprintf("127.0.0.1:%d", 43000+i)), 0, c.commitTimeout).Error(); err != nil {
			t.Fatalf("AddNonvoter(%s): %v", id, err)
		}
	}
	if !c.raftReplicaAdmissionBlocked("srv-new") {
		t.Fatal("a full configuration admitted another replica because some of its members are gossip-dead")
	}
	if err := c.raft.raft.RemoveServer(raft.ServerID("srv-dead"), 0, c.commitTimeout).Error(); err != nil {
		t.Fatalf("RemoveServer(srv-dead): %v", err)
	}
	if c.raftReplicaAdmissionBlocked("srv-new") {
		t.Fatal("the slot did not free after the removal committed")
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

// NotifyJoin starts a goroutine per join, so the budget only bounds the tier
// if the count and the membership mutation happen under one lock. Before the
// fix, 32 simultaneous joins against a nearly-full configuration all observed
// room and all were admitted (14 replicas observed, 38 under -race), and
// nothing repairs that: an already-configured server skips admission on every
// later reconcile.
func TestRaftReplicaAdmissionBoundedUnderConcurrentJoins(t *testing.T) {
	c, cleanup := newReplicaBudgetCluster(t, "srv-concurrent")
	defer cleanup()

	const joiners = 32
	members := []Member{{NodeID: c.nodeID, Role: config.NodeRoleServer, Alive: true, RaftAddr: "127.0.0.1:1"}}
	for i := range joiners {
		members = append(members, Member{
			NodeID:   fmt.Sprintf("join-%02d", i),
			Role:     config.NodeRoleServer,
			Alive:    true,
			RaftAddr: fmt.Sprintf("127.0.0.1:%d", 33000+i),
		})
	}
	// Put the live count above MaxMixedClusterNodes so the dedicated-tier
	// budget (not the small-cluster allowance) is the one under test.
	for i := range 12 {
		members = append(members, Member{NodeID: fmt.Sprintf("wrk-%03d", i), Role: config.NodeRoleWorker, Alive: true})
	}
	seedGossipView(t, c, members)

	// Fill every slot but one with configured replicas gossip doesn't know
	// about, so none of them is discounted as dead.
	for i := range MaxServerTierNodes - 2 {
		id := fmt.Sprintf("existing-%d", i)
		if err := c.raft.raft.AddNonvoter(raft.ServerID(id), raft.ServerAddress(fmt.Sprintf("127.0.0.1:%d", 34000+i)), 0, c.commitTimeout).Error(); err != nil {
			t.Fatalf("AddNonvoter(%s): %v", id, err)
		}
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range joiners {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			c.handleMemberJoin(fmt.Sprintf("join-%02d", i))
		}(i)
	}
	close(start)
	wg.Wait()

	got := raftServerIDs(t, c)
	if len(got) > MaxServerTierNodes {
		t.Fatalf("%d concurrent joins grew the configuration to %d replicas (%v); the budget is %d and every replica receives the whole log and FSM",
			joiners, len(got), got, MaxServerTierNodes)
	}
	if len(got) != MaxServerTierNodes {
		t.Fatalf("configuration holds %d replicas (%v); the one free slot should still have been filled", len(got), got)
	}
}

// Removal shares the admission lock. hashicorp/raft v1.7.3 gives no usable
// configuration index for a compare-and-set, so if a RemoveServer could land
// between a joiner's replica count and its AddVoter, the count would describe
// a configuration the mutation never sees. Joins and evictions racing each
// other must still leave the tier inside its budget.
func TestRaftMembershipMutationsSerializeWithRemoval(t *testing.T) {
	c, cleanup := newReplicaBudgetCluster(t, "srv-mixed-churn")
	defer cleanup()

	const joiners = 16
	members := []Member{{NodeID: c.nodeID, Role: config.NodeRoleServer, Alive: true, RaftAddr: "127.0.0.1:1"}}
	for i := range joiners {
		members = append(members, Member{
			NodeID:   fmt.Sprintf("churn-%02d", i),
			Role:     config.NodeRoleServer,
			Alive:    true,
			RaftAddr: fmt.Sprintf("127.0.0.1:%d", 36000+i),
		})
	}
	for i := range 12 {
		members = append(members, Member{NodeID: fmt.Sprintf("wrk-%03d", i), Role: config.NodeRoleWorker, Alive: true})
	}
	seedGossipView(t, c, members)

	evictable := make([]string, 0, 3)
	for i := range MaxServerTierNodes - 1 {
		id := fmt.Sprintf("leaving-%d", i)
		if err := c.raft.raft.AddNonvoter(raft.ServerID(id), raft.ServerAddress(fmt.Sprintf("127.0.0.1:%d", 37000+i)), 0, c.commitTimeout).Error(); err != nil {
			t.Fatalf("AddNonvoter(%s): %v", id, err)
		}
		if i < 3 {
			evictable = append(evictable, id)
		}
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range joiners {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			c.handleMemberJoin(fmt.Sprintf("churn-%02d", i))
		}(i)
	}
	for _, id := range evictable {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			c.removeDeadOwnerServer(id)
		}(id)
	}
	close(start)
	wg.Wait()

	if got := raftServerIDs(t, c); len(got) > MaxServerTierNodes {
		t.Fatalf("joins racing evictions left %d replicas (%v); the budget is %d", len(got), got, MaxServerTierNodes)
	}
}

// The unlocked fast path exists so a 2000-node reconcile sweep doesn't queue
// behind a raft round. It must agree with the locked decision, or a settled
// member gets re-offered forever (or, worse, a correction is skipped).
func TestMemberJoinSettledMatchesLockedDecision(t *testing.T) {
	c, cleanup := newReplicaBudgetCluster(t, "srv-settled")
	defer cleanup()

	members := []Member{
		{NodeID: c.nodeID, Role: config.NodeRoleServer, Alive: true, RaftAddr: "127.0.0.1:1"},
		{NodeID: "srv-peer", Role: config.NodeRoleServer, Alive: true, RaftAddr: "127.0.0.1:38001"},
		{NodeID: "wrk-peer", Role: config.NodeRoleWorker, Alive: true, RaftAddr: "127.0.0.1:38002"},
	}
	seedGossipView(t, c, members)

	if c.memberJoinSettled("srv-peer", "127.0.0.1:38001") {
		t.Fatal("an unconfigured member reported as settled; it would never be admitted")
	}
	c.handleMemberJoin("srv-peer")
	if !c.memberJoinSettled("srv-peer", "127.0.0.1:38001") {
		t.Fatal("a member configured exactly as the policy wants is still re-offered on every 5s sweep")
	}
	if c.memberJoinSettled("srv-peer", "127.0.0.1:39999") {
		t.Fatal("an address change reported as settled; the correction would never run")
	}

	c.handleMemberJoin("wrk-peer")
	srv, ok := c.configuredServer("wrk-peer")
	if !ok {
		t.Fatal("worker-role peer was not configured at all")
	}
	if srv.Suffrage != raft.Nonvoter {
		t.Fatalf("worker-role peer got suffrage %v; role-forced non-voters must never become voters", srv.Suffrage)
	}
	if !c.memberJoinSettled("wrk-peer", "127.0.0.1:38002") {
		t.Fatal("a correctly configured non-voter is still re-offered on every sweep")
	}
}

// A gossip-dead replica is still IN the configuration: it still receives the
// log and the FSM, its raft connection may still work (gossip and raft can
// partition independently), and nothing has removed it yet. Discounting it
// hands its slot to a replacement, and when the original comes back before
// the removal grace expires its existing-member path skips admission
// entirely — leaving a configuration permanently above the budget.
func TestRaftReplicaBudgetCountsGossipDeadConfiguredReplicas(t *testing.T) {
	c, cleanup := newReplicaBudgetCluster(t, "srv-flap")
	defer cleanup()

	members := []Member{{NodeID: c.nodeID, Role: config.NodeRoleServer, Alive: true, RaftAddr: "127.0.0.1:1"}}
	// Two replacements want in, and the fleet is big enough that the
	// dedicated-tier budget applies.
	for i := range 2 {
		members = append(members, Member{
			NodeID:   fmt.Sprintf("srv-replacement-%d", i),
			Role:     config.NodeRoleServer,
			Alive:    true,
			RaftAddr: fmt.Sprintf("127.0.0.1:%d", 41000+i),
		})
	}
	for i := range 12 {
		members = append(members, Member{NodeID: fmt.Sprintf("wrk-%03d", i), Role: config.NodeRoleWorker, Alive: true})
	}

	// Fill the tier, then mark two of the configured replicas gossip-dead.
	var flapped []string
	for i := range MaxServerTierNodes - 1 {
		id := fmt.Sprintf("srv-existing-%d", i)
		if err := c.raft.raft.AddNonvoter(raft.ServerID(id), raft.ServerAddress(fmt.Sprintf("127.0.0.1:%d", 42000+i)), 0, c.commitTimeout).Error(); err != nil {
			t.Fatalf("AddNonvoter(%s): %v", id, err)
		}
		if i < 2 {
			flapped = append(flapped, id)
			members = append(members, Member{NodeID: id, Role: config.NodeRoleServer, Alive: false, RaftAddr: fmt.Sprintf("127.0.0.1:%d", 42000+i)})
		}
	}
	seedGossipView(t, c, members)

	for i := range 2 {
		c.handleMemberJoin(fmt.Sprintf("srv-replacement-%d", i))
	}

	got := raftServerIDs(t, c)
	if len(got) > MaxServerTierNodes {
		t.Fatalf("configuration holds %d replicas (%v); two gossip-dead members are still configured state carriers, so their slots are not free",
			len(got), got)
	}

	// The flapped members coming back must not need a slot they never lost.
	for _, id := range flapped {
		c.handleMemberJoin(id)
	}
	if got := raftServerIDs(t, c); len(got) > MaxServerTierNodes {
		t.Fatalf("configuration grew to %d replicas (%v) after the flapped members rejoined", len(got), got)
	}
}
