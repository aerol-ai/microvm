package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// Plan item C7 (invariant I4): opPlace released a reservation's pending load
// at once, so until the worker's next capacity heartbeat the sandbox counted
// nowhere on the leader, and a second reservation for the same room was
// granted. The worker's admitter refused that create, so the node stayed in
// budget, but the client got a 503 for a create another node could have
// taken.
//
// This runs the real leader path: raft, the FSM, and the leader's reservation
// admission. The node has no admitter, so its own lease behaves like a remote
// worker's: it changes only when a heartbeat is stored.
func TestReserveAfterPromoteCountsLoadTheHeartbeatHasNotShown(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	c, cleanup := newTestCluster(t, "c7-lag", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	heartbeat := func(reservedCPU float64) capacity.Snapshot {
		return capacity.Snapshot{
			HostCPUCores: 6, HostMemoryTotalMB: 16384,
			CPUBudget: 6, MemoryBudgetMB: 16384,
			ReservedCPU: reservedCPU, CanAdmit: true,
		}
	}
	c.capacityLeases.set(c.nodeID, heartbeat(0), time.Now())

	ctx := context.Background()
	target := PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL}
	spec := func(cpu float64) *models.CreateSandboxRequest {
		return &models.CreateSandboxRequest{Image: "alpine", CPU: cpu, MemoryMB: 512}
	}
	if err := c.ReserveOnTarget(ctx, "sb-fill", target, spec(4), PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("reserve 4 of 6 CPUs on an empty worker: %v", err)
	}
	// The worker created it and promotes: the FSM stops counting it as
	// pending, and the stored heartbeat is still the empty one.
	if err := c.RecordPlacement(ctx, "sb-fill", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("promote: %v", err)
	}
	err := c.ReserveOnTarget(ctx, "sb-next", target, spec(4), PlacementSecrets{}, time.Minute)
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("reserve 4 more CPUs on the unchanged heartbeat after a promote = %v, want ErrCapacityExceeded (4 of 6 are in use)", err)
	}

	// A heartbeat taken after the promote shows the sandbox. The extra count
	// must go, or the worker would be counted twice and lose room it has.
	c.capacityLeases.set(c.nodeID, heartbeat(4), time.Now())
	if err := c.ReserveOnTarget(ctx, "sb-rest", target, spec(2), PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("reserve the last 2 CPUs once the heartbeat shows the promoted sandbox = %v, want granted (no double count)", err)
	}
}

// A one-node cluster places on itself, and its own lease is re-read from its
// admitter on every placement call. The admitter already holds a sandbox the
// node promoted, so the unreported entry must go on that read; counting it as
// well would refuse room the node has.
func TestSingleNodeClusterCountsItsOwnPromoteOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	c, cleanup := newTestCluster(t, "c7-self", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	giveFreshCapacity(c) // 8 CPUs

	ctx := context.Background()
	target := PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL}
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 4, MemoryMB: 512}
	if err := c.ReserveOnTarget(ctx, "sb-1", target, spec, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// The local create admits it, then promotes.
	c.capacityLeases.admitter.Reserve("sb-1", capacityRequestFromSpec(spec))
	if err := c.RecordPlacement(ctx, "sb-1", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if err := c.ReserveOnTarget(ctx, "sb-2", target, spec, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("reserve the other 4 of 8 CPUs after a local promote = %v, want granted (the admitter already counts sb-1)", err)
	}
}

// unreportedTotals reads every node of a ledger through load, the lookup
// placement uses.
func unreportedTotals(u *unreportedLoad) (map[string]capacity.Request, map[string]map[string]int) {
	u.mu.RLock()
	ids := make([]string, 0, len(u.nodes))
	for id := range u.nodes {
		ids = append(ids, id)
	}
	u.mu.RUnlock()
	pending := make(map[string]capacity.Request, len(ids))
	runtimes := make(map[string]map[string]int, len(ids))
	for _, id := range ids {
		pending[id], runtimes[id], _ = u.load(id)
	}
	return pending, runtimes
}

func TestUnreportedLoadLedger(t *testing.T) {
	cpu := func(v float64) capacity.Request {
		return capacity.Request{CPU: v, MemoryMB: 256, DiskGB: 1, GPUs: 0, Runtime: models.RuntimeDocker}
	}
	cases := []struct {
		name string
		run  func(u *unreportedLoad)
		want map[string]float64
	}{
		{
			name: "a heartbeat requested after the record shows it",
			run: func(u *unreportedLoad) {
				u.record("w1", cpu(2))
				u.reported("w1", u.mark())
			},
			want: map[string]float64{},
		},
		{
			name: "a heartbeat requested before the record may not show it",
			run: func(u *unreportedLoad) {
				mark := u.mark()
				u.record("w1", cpu(2))
				u.reported("w1", mark)
			},
			want: map[string]float64{"w1": 2},
		},
		{
			// 0.1+0.2 then subtracting 0.1 leaves 0.20000000000000004,
			// which refuses a create that fits exactly.
			name: "only the covered prefix goes, and the rest is re-totalled exactly",
			run: func(u *unreportedLoad) {
				u.record("w1", cpu(0.1))
				mark := u.mark()
				u.record("w1", cpu(0.2))
				u.reported("w1", mark)
			},
			want: map[string]float64{"w1": 0.2},
		},
		{
			name: "a heartbeat clears only its own node",
			run: func(u *unreportedLoad) {
				u.record("w1", cpu(1))
				u.record("w2", cpu(3))
				u.reported("w1", u.mark())
				u.reported("unknown", u.mark())
			},
			want: map[string]float64{"w2": 3},
		},
		{
			name: "loads on one node add up",
			run: func(u *unreportedLoad) {
				u.record("w1", cpu(1))
				u.record("w1", cpu(1.5))
				u.record("", cpu(9))
				u.reported("", u.mark())
			},
			want: map[string]float64{"w1": 2.5},
		},
		{
			name: "a node that left the membership is dropped, this server is kept",
			run: func(u *unreportedLoad) {
				u.record("gone", cpu(4))
				u.record("self", cpu(1))
				u.record("w1", cpu(2))
				u.retain(map[string]struct{}{"w1": {}}, "self")
				u.retain(nil, "self") // an empty view is not "everyone left"
			},
			want: map[string]float64{"self": 1, "w1": 2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := newUnreportedLoad()
			tc.run(u)
			got, runtimes := unreportedTotals(u)
			if len(got) != len(tc.want) {
				t.Fatalf("nodes with unreported load = %v, want %v", got, tc.want)
			}
			for id, want := range tc.want {
				if got[id].CPU != want {
					t.Fatalf("%s CPU = %v, want exactly %v", id, got[id].CPU, want)
				}
				if got[id].MemoryMB == 0 || runtimes[id][models.RuntimeDocker] == 0 {
					t.Fatalf("%s lost its memory or runtime count: %+v %v", id, got[id], runtimes[id])
				}
			}
		})
	}
}

// pendingLoad.of adds a node's unreported load to its reservations in flight
// without writing to either source: the runtime maps it returns are shared
// with the FSM's copy and the ledger, and a later record must not change one
// a caller already holds. A nil ledger (a hand-built test cluster) is a no-op
// everywhere.
func TestPendingLoadOfAddsUnreportedToReservations(t *testing.T) {
	u := &unreportedLoad{} // the zero value, as a struct literal makes it
	u.record("both", capacity.Request{CPU: 1, MemoryMB: 100, DiskGB: 2, GPUs: 1, Runtime: models.RuntimeGvisor})
	u.record("promoted", capacity.Request{CPU: 4, Runtime: models.RuntimeDocker})
	fsmRuntimes := map[string]int{models.RuntimeGvisor: 3}
	load := pendingLoad{
		reserved:   map[string]capacity.Request{"both": {CPU: 2, MemoryMB: 50, DiskGB: 1, GPUs: 1}, "reserved": {CPU: 1}},
		runtimes:   map[string]map[string]int{"both": fsmRuntimes, "reserved": {models.RuntimeDocker: 1}},
		unreported: u,
	}
	cases := []struct {
		node     string
		wantCPU  float64
		wantRT   string
		wantSlot int
	}{
		{"both", 3, models.RuntimeGvisor, 4},
		{"promoted", 4, models.RuntimeDocker, 1},
		{"reserved", 1, models.RuntimeDocker, 1},
		{"idle", 0, models.RuntimeDocker, 0},
	}
	for _, tc := range cases {
		got, byRuntime := load.of(tc.node)
		if got.CPU != tc.wantCPU || byRuntime[tc.wantRT] != tc.wantSlot {
			t.Fatalf("%s: of = %+v %v, want CPU %v and %d %s", tc.node, got, byRuntime, tc.wantCPU, tc.wantSlot, tc.wantRT)
		}
	}
	if got, _ := load.of("both"); got.MemoryMB != 150 || got.DiskGB != 3 || got.GPUs != 2 {
		t.Fatalf("both: memory/disk/GPU = %+v, want the reservation and the promote together", got)
	}
	_, held := load.of("promoted")
	u.record("promoted", capacity.Request{CPU: 1, Runtime: models.RuntimeDocker})
	if fsmRuntimes[models.RuntimeGvisor] != 3 || held[models.RuntimeDocker] != 1 {
		t.Fatalf("a lookup or a later record wrote through a shared map: fsm %v, held %v", fsmRuntimes, held)
	}

	var none *unreportedLoad
	none.record("w1", capacity.Request{CPU: 1})
	none.reported("w1", 1)
	none.retain(map[string]struct{}{"w1": {}}, "")
	if _, _, ok := none.load("w1"); ok || none.mark() != 0 {
		t.Fatal("a nil ledger reported load or a mark")
	}
	if got, _ := (pendingLoad{reserved: load.reserved}).of("both"); got.CPU != 2 {
		t.Fatalf("with no ledger of = %+v, want the reservation alone", got)
	}
	var noCache *capacityLeaseCache
	if noCache.unreportedMark() != 0 {
		t.Fatal("a nil lease cache reported a mark")
	}
	noCache.setReported("w1", capacity.Snapshot{}, time.Now(), 1)
}

// Which FSM writes move load out of the pending sums before a heartbeat can
// show it. Everything else must record nothing, or a node would look fuller
// than it is until its next heartbeat.
func TestFSMRecordsUnreportedLoad(t *testing.T) {
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 2, MemoryMB: 512}
	reserve := command{Op: opReserve, SandboxID: "sb", OwnerNodeID: "w1", Spec: spec, IncarnationID: "inc", ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	place := command{Op: opPlace, SandboxID: "sb", OwnerNodeID: "w1", IncarnationID: "inc", ExpectedIncarnationID: "inc"}
	placeFresh := command{Op: opPlace, SandboxID: "sb", OwnerNodeID: "w1", Spec: spec, IncarnationID: "inc"}
	reassign := func(to, cause string) command {
		return command{Op: opReassign, SandboxID: "sb", OwnerNodeID: to, ExpectedIncarnationID: "inc", ReassignCause: cause}
	}
	cases := []struct {
		name  string
		cmds  []command
		wantN string // node holding 2 CPUs of unreported load; "" = none
	}{
		{"promote of a reservation", []command{reserve, place}, "w1"},
		{"a create with no reservation was never pending", []command{placeFresh}, ""},
		{"re-placing a placed row", []command{placeFresh, placeFresh}, ""},
		{"a refused promote", []command{reserve, {Op: opPlace, SandboxID: "sb", OwnerNodeID: "w1", IncarnationID: "x", ExpectedIncarnationID: "x"}}, ""},
		{"failover reassign of a placed sandbox", []command{placeFresh, reassign("w2", reassignCauseFailover)}, "w2"},
		{"failover reassign of a reservation keeps it pending instead", []command{reserve, reassign("w2", reassignCauseFailover)}, ""},
		{"failover reassign to the same owner", []command{placeFresh, reassign("w1", reassignCauseFailover)}, ""},
		{"failover reassign to nobody orphans it", []command{placeFresh, reassign("", reassignCauseFailover)}, ""},
		{"a migrate reassign lands where the sandbox already is", []command{placeFresh, reassign("w2", "")}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPlacementFSM()
			u := newUnreportedLoad()
			f.unreported.Store(u)
			for _, cmd := range tc.cmds {
				applyOp(t, f, cmd)
			}
			got, _ := unreportedTotals(u)
			if tc.wantN == "" {
				if len(got) != 0 {
					t.Fatalf("unreported load = %v, want none", got)
				}
				return
			}
			if len(got) != 1 || got[tc.wantN].CPU != 2 || got[tc.wantN].MemoryMB != 512 {
				t.Fatalf("unreported load = %v, want 2 CPU / 512 MB on %s", got, tc.wantN)
			}
		})
	}
}

// Every server applies every entry, so every server holds the same unreported
// load: a follower that routes creates sees it, and a follower elected leader
// starts with it. Recording never touches replicated state, so a server
// without a ledger ends up with the same placements and the same answers.
func TestUnreportedLoadIsTheSameOnEveryServer(t *testing.T) {
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256}
	log := []command{
		{Op: opReserve, SandboxID: "sb-1", OwnerNodeID: "w1", Spec: spec, IncarnationID: "i1", ExpiresUnix: time.Now().Add(time.Minute).Unix()},
		{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "w1", IncarnationID: "i1", ExpectedIncarnationID: "i1"},
		{Op: opPlace, SandboxID: "sb-2", OwnerNodeID: "w2", Spec: spec, IncarnationID: "i2"},
		{Op: opReassign, SandboxID: "sb-2", OwnerNodeID: "w1", ExpectedIncarnationID: "i2", ReassignCause: reassignCauseFailover},
	}
	leader, follower, plain := newPlacementFSM(), newPlacementFSM(), newPlacementFSM()
	leaderLoad, followerLoad := newUnreportedLoad(), newUnreportedLoad()
	leader.unreported.Store(leaderLoad)
	follower.unreported.Store(followerLoad)
	for i, cmd := range log {
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		entry := &raft.Log{Index: uint64(i + 1), Data: payload}
		a, b, c := leader.Apply(entry), follower.Apply(entry), plain.Apply(entry)
		if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a, c) {
			t.Fatalf("entry %d answered %v / %v / %v; recording must not change an apply result", i+1, a, b, c)
		}
	}
	got, _ := unreportedTotals(leaderLoad)
	again, _ := unreportedTotals(followerLoad)
	if !reflect.DeepEqual(got, again) || got["w1"].CPU != 2 {
		t.Fatalf("leader holds %v, follower %v; want both 2 CPU on w1 (one promote, one failover)", got, again)
	}
	for _, id := range []string{"sb-1", "sb-2"} {
		want, _ := plain.get(id)
		for _, f := range []*placementFSM{leader, follower} {
			p, _ := f.get(id)
			p.CreatedUnix, p.UpdatedUnix = want.CreatedUnix, want.UpdatedUnix
			if !reflect.DeepEqual(p, want) {
				t.Fatalf("%s differs with a ledger installed:\n got  %+v\n want %+v", id, p, want)
			}
		}
	}
}

// unreportedCluster is a leader-side view of workers whose heartbeats were
// stored once, with the FSM recording into the lease cache's ledger as New
// wires it.
func unreportedCluster(workers ...Member) *Cluster {
	c := slotCluster(workers...)
	c.capacityLeases = newCapacityLeaseCache(c.nodeID, nil, 5*time.Second, nil)
	for _, w := range workers {
		c.capacityLeases.set(w.NodeID, w.Capacity, time.Now())
	}
	c.fsm.unreported.Store(c.capacityLeases.unreported)
	return c
}

// What the client sees: after a promote fills a worker, the next create goes
// to the worker with room instead of to the full one and a 503 from its
// admitter.
func TestSelectPlacementPlacesElsewhereAfterPromote(t *testing.T) {
	c := unreportedCluster(
		slotWorker("worker-a", 4, []string{models.RuntimeDocker}),
		slotWorker("worker-b", 4, []string{models.RuntimeDocker}),
	)
	fill := &models.CreateSandboxRequest{Image: "alpine", CPU: 4, MemoryMB: 1024}
	applyOp(t, c.fsm, command{Op: opReserve, SandboxID: "sb-fill", OwnerNodeID: "worker-a", Spec: fill, IncarnationID: "inc", ExpiresUnix: time.Now().Add(time.Minute).Unix()})
	applyOp(t, c.fsm, command{Op: opPlace, SandboxID: "sb-fill", OwnerNodeID: "worker-a", IncarnationID: "inc", ExpectedIncarnationID: "inc"})

	req := capacityRequestFromSpec(fill)
	for i := 0; i < 50; i++ {
		target, err := c.SelectPlacement(req)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if target.NodeID != "worker-b" {
			t.Fatalf("iter %d placed on %s, whose 4 CPUs the promoted sandbox holds; want worker-b", i, target.NodeID)
		}
	}
	err := c.admitReservationCommand(command{Op: opReserve, SandboxID: "sb-late", OwnerNodeID: "worker-a", Spec: fill, IncarnationID: "inc-late"})
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("leader admission onto the filled worker = %v, want ErrCapacityExceeded", err)
	}
}

// Mass failover scored every reassign of a dead node's sandboxes against the
// same heartbeats, so one survivor could be handed more than it can run, and
// the overflow failed its recreates there until it was escalated elsewhere.
func TestFailoverReassignCountsAgainstTheNextPick(t *testing.T) {
	c := unreportedCluster(
		slotWorker("worker-a", 4, []string{models.RuntimeDocker}),
		slotWorker("worker-b", 4, []string{models.RuntimeDocker}),
	)
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 4, MemoryMB: 1024, Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	for _, id := range []string{"sb-1", "sb-2", "sb-3"} {
		applyOp(t, c.fsm, command{Op: opPlace, SandboxID: id, OwnerNodeID: "dead", Spec: spec, IncarnationID: "inc-" + id})
	}
	// The eviction loop: pick a target, commit the reassign, next sandbox.
	used := map[string]bool{}
	for _, id := range []string{"sb-1", "sb-2"} {
		p, _ := c.fsm.get(id)
		target, err := c.selectRecreationTargetFor(p)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if used[target.NodeID] {
			t.Fatalf("%s reassigned to %s, which the previous reassign already filled", id, target.NodeID)
		}
		used[target.NodeID] = true
		applyOp(t, c.fsm, command{Op: opReassign, SandboxID: id, OwnerNodeID: target.NodeID, ExpectedIncarnationID: p.IncarnationID, ReassignCause: reassignCauseFailover})
	}
	p, _ := c.fsm.get("sb-3")
	if target, err := c.selectRecreationTargetFor(p); err == nil {
		t.Fatalf("sb-3 reassigned to %s although both survivors are full; it must stay orphaned", target.NodeID)
	}
}

// inFlightPromoteTransport answers a capacity fetch, running during first:
// a promote this server applies while the request is on the wire.
type inFlightPromoteTransport struct {
	body   []byte
	during func()
}

func (r *inFlightPromoteTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if r.during != nil {
		r.during()
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(r.body)), Header: make(http.Header)}, nil
}

// The heartbeat side of the ledger, through the real fetch path. A promote
// applied before the request went out is in the answer, so it goes; one
// applied while the request was in flight may not be, so it stays until the
// next heartbeat. Clearing by arrival instead would drop it here.
func TestCapacityHeartbeatClearsOnlyWhatItsRequestCovers(t *testing.T) {
	body, err := json.Marshal(capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 8192, CPUBudget: 8, MemoryBudgetMB: 8192, ReservedCPU: 1, CanAdmit: true})
	if err != nil {
		t.Fatal(err)
	}
	leases := newCapacityLeaseCache("server", nil, 5*time.Second, nil)
	u := leases.unreported
	u.record("worker-a", capacity.Request{CPU: 1, Runtime: models.RuntimeDocker})
	rt := &inFlightPromoteTransport{body: body, during: func() {
		u.record("worker-a", capacity.Request{CPU: 2, Runtime: models.RuntimeDocker})
	}}
	c := &Cluster{nodeID: "server", capacityLeases: leases, internalClient: &http.Client{Transport: rt}}
	members := []Member{{NodeID: "worker-a", InternalURL: "https://worker-a", Role: config.NodeRoleWorker, Alive: true}}
	if left := c.runCapacityFetchPhase(context.Background(), members, time.Second, capacityFetchPass{attemptTimeout: time.Second, recordFailures: true}); len(left) != 0 {
		t.Fatalf("the fetch did not land: %d left", len(left))
	}
	if !leases.hasLease("worker-a") {
		t.Fatal("the heartbeat was not stored")
	}
	got, _ := unreportedTotals(u)
	if got["worker-a"].CPU != 2 {
		t.Fatalf("worker-a unreported CPU after the heartbeat = %v, want 2 (only the promote applied mid-request)", got["worker-a"].CPU)
	}
}

// This server's own lease comes from its admitter, read on every placement
// call. A read clears what the admitter already holds, and a read that
// finishes after a newer one must not put the older snapshot back.
func TestCapacityLeaseOwnRefreshAndOutOfOrderReads(t *testing.T) {
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 8192, DiskTotalGB: 100, DiskFreeGB: 100},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1, DiskReservationRatio: 1},
		nil,
	)
	leases := newCapacityLeaseCache("server", admitter, 5*time.Second, nil)
	leases.unreported.record("server", capacity.Request{CPU: 2})
	// The overlay runs after the admitter was read: a promote applied then
	// is not in this snapshot and must survive it.
	leases.SetLocalTemplateIDsProvider(func() ([]string, bool) {
		leases.unreported.record("server", capacity.Request{CPU: 3})
		return nil, false
	})
	leases.refreshLocal(time.Now())
	if got, _ := unreportedTotals(leases.unreported); got["server"].CPU != 3 {
		t.Fatalf("own unreported CPU after an admitter read = %v, want 3 (only the promote applied after the read)", got["server"].CPU)
	}

	newer := leases.unreportedMark() + 2
	leases.setReported("worker-a", capacity.Snapshot{HostCPUCores: 8, ReservedCPU: 4}, time.Now(), newer)
	leases.setReported("worker-a", capacity.Snapshot{HostCPUCores: 8, ReservedCPU: 1}, time.Now(), newer-1)
	leases.mu.RLock()
	kept := leases.leases["worker-a"].snapshot.ReservedCPU
	leases.mu.RUnlock()
	if kept != 4 {
		t.Fatalf("stored ReservedCPU = %v after an older read finished last, want the newer 4", kept)
	}
}

// A node that leaves the membership sends no more heartbeats, so the lease
// loop's retain is what frees its entries.
func TestCapacityLeaseRetainDropsDepartedNodesUnreportedLoad(t *testing.T) {
	leases := newCapacityLeaseCache("server", nil, 5*time.Second, nil)
	leases.unreported.record("gone", capacity.Request{CPU: 4})
	leases.unreported.record("worker-a", capacity.Request{CPU: 1})
	leases.unreported.record("server", capacity.Request{CPU: 1})
	leases.retain(map[string]struct{}{"worker-a": {}})
	got, _ := unreportedTotals(leases.unreported)
	if _, ok := got["gone"]; ok || got["worker-a"].CPU != 1 || got["server"].CPU != 1 {
		t.Fatalf("unreported load after retain = %v, want worker-a and this server only", got)
	}
}
