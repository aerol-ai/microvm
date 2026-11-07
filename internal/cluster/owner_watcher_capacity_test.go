package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// refusingRecreator fails every recreate with err, the way a worker whose
// admitter is full answers a failover recreate.
type refusingRecreator struct {
	err   error
	calls atomic.Int64
}

func (r *refusingRecreator) RecreateSandbox(context.Context, string, models.CreateSandboxRequest, PlacementSecrets, map[int]ExposedPortRoute) error {
	r.calls.Add(1)
	return r.err
}

func recreatePolicySpec(cpu float64) *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{Image: "alpine", CPU: cpu, MemoryMB: 256, Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
}

// Live chaos run UC-478 (2026-11-08): a mass failover assigned more sandboxes
// to the survivors than they had room for, the survivors' admitters refused
// the overflow, and those sandboxes stayed placed on a node that could never
// run them, five minutes later and for good (I6). The owner watcher asked to
// move each one, found no other node with room, and kept retrying where it
// was. A recreate refused for capacity with nowhere else to go must be handed
// back, as the eviction already does for a sandbox it has no target for.
// Any other failure still retries in place: an image pull or a runtime error
// can clear up, and moving would not help.
func TestRecreateRefusedForCapacityIsHandedBack(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	cases := []struct {
		name       string
		err        error
		wantHanded bool
	}{
		{"refused for capacity", fmt.Errorf("recreate: %w: cpu 4.00 of 4.00 reserved", capacity.ErrCapacityExceeded), true},
		{"any other failure", errors.New("recreate: pull alpine: connection reset"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, cleanup := newTestCluster(t, "c7-refused", true, nil)
			defer cleanup()
			waitForLeader(t, c, 10*time.Second)
			rec := &refusingRecreator{err: tc.err}
			c.AttachRecreator(rec)
			ctx := context.Background()
			if err := c.RecordPlacement(ctx, "sb-over", recreatePolicySpec(1), PlacementSecrets{}); err != nil {
				t.Fatalf("place: %v", err)
			}
			// The only node is the one refusing, so there is nowhere else.
			for i := 0; i <= maxRecreateFailuresBeforeReassign; i++ {
				c.recreateOwnedSandboxes(ctx)
			}
			p, ok := c.PlacementOf("sb-over")
			if !ok {
				t.Fatal("the placement is gone; a hand-back keeps it, orphaned")
			}
			handed := p.IsOrphaned() && p.OwnerNodeID == ""
			if handed != tc.wantHanded {
				t.Fatalf("after %d refused recreates owner = %q, orphaned = %v; want handed back = %v",
					rec.calls.Load(), p.OwnerNodeID, p.IsOrphaned(), tc.wantHanded)
			}
			if !tc.wantHanded {
				return
			}
			before := rec.calls.Load()
			c.recreateOwnedSandboxes(ctx)
			if rec.calls.Load() != before {
				t.Fatal("the owner watcher still recreates a sandbox it handed back")
			}
		})
	}
}

// Capacity left gossip for the capacity heartbeat long ago, so a gossip member
// carries none. The stuck-placement path read raw gossip members for a
// sandbox without sealed secrets, so no peer ever fit and a stuck sandbox
// could never move, even to a node with plenty of room. It must see the same
// heartbeats placement does.
func TestStuckReassignSeesHeartbeatCapacity(t *testing.T) {
	worker := func(id string) Member {
		return Member{NodeID: id, APIURL: "http://" + id, Alive: true, Role: config.NodeRoleWorker}
	}
	idx := newGossipMemberIndex()
	idx.replace([]Member{
		{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
		worker("worker-stuck"),
		worker("worker-roomy"),
	})
	leases := newCapacityLeaseCache("server-a", nil, 5*time.Second, nil)
	leases.set("worker-stuck", capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 8192, CPUBudget: 4, MemoryBudgetMB: 8192, ReservedCPU: 4, CanAdmit: true}, time.Now())
	leases.set("worker-roomy", capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 8192, CPUBudget: 4, MemoryBudgetMB: 8192, CanAdmit: true}, time.Now())
	c := &Cluster{nodeID: "server-a", apiURL: "http://server-a", fsm: newPlacementFSM(), gossip: &gossipNode{memberIndex: idx}, capacityLeases: leases}

	p := Placement{SandboxID: "sb", OwnerNodeID: "worker-stuck", Spec: recreatePolicySpec(1)}
	target, err := c.selectRecreationTargetFor(p, "worker-stuck")
	if err != nil || target.NodeID != "worker-roomy" {
		t.Fatalf("stuck reassign target = (%q, %v), want worker-roomy, which reports 4 free CPUs", target.NodeID, err)
	}
}

// The leader's side of a refusal for capacity. A node with room still takes
// the sandbox; only when none has room is it handed back, fenced on the owner
// that refused, so a placement that moved meanwhile is left alone.
func TestHandBackRefusedPlacement(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	full := func(id string) Member { return recreateCandidate(id, config.NodeRoleWorker, 0) }
	cases := []struct {
		name      string
		peers     []Member
		movedTo   string // a newer owner the placement has before the hand-back
		wantOwner string
		wantErr   error
	}{
		{name: "another worker has room", peers: []Member{full("stuck-worker"), recreateCandidate("roomy-worker", config.NodeRoleWorker, 100)}, wantOwner: "roomy-worker"},
		{name: "no worker has room", peers: []Member{full("stuck-worker"), full("full-worker")}, wantOwner: ""},
		{name: "the placement moved meanwhile", peers: []Member{full("stuck-worker"), full("full-worker")}, movedTo: "new-home", wantOwner: "new-home", wantErr: ErrStuckReassignNotOwner},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, cleanup := newTestClusterWithRole(t, fmt.Sprintf("srv-hand-back-%d", i), config.NodeRoleServer, true, nil)
			defer cleanup()
			waitForLeader(t, c, 10*time.Second)
			c.recreateFailures = &recreateFailureTracker{counts: map[string]int{}, permanent: map[string]struct{}{}}
			// Every candidate is full on CPU: AvailableCPU is not what
			// placement reads; the reserved CPU is.
			for j := range tc.peers {
				if tc.peers[j].NodeID != "roomy-worker" {
					tc.peers[j].Capacity.ReservedCPU = tc.peers[j].Capacity.CPUBudget
				}
			}
			seedGossipView(t, c, tc.peers)
			p := placeFailoverPlacement(t, c, "sb-refused", "stuck-worker")
			if tc.movedTo != "" {
				// Same incarnation, new owner, applied before the
				// hand-back's own command reaches the FSM.
				if err := c.applyCommand(context.Background(), command{Op: opReassign, SandboxID: p.SandboxID, OwnerNodeID: tc.movedTo, ExpectedIncarnationID: p.IncarnationID}); err != nil {
					t.Fatalf("move: %v", err)
				}
			}
			err := c.handBackRefusedPlacement(context.Background(), p.SandboxID, p)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("hand back = %v, want %v", err, tc.wantErr)
			}
			after, _ := c.PlacementOf(p.SandboxID)
			if after.OwnerNodeID != tc.wantOwner {
				t.Fatalf("owner = %q, want %q", after.OwnerNodeID, tc.wantOwner)
			}
			if tc.wantOwner == "" && (!after.IsOrphaned() || after.OrphanedOwnerNodeID != "stuck-worker") {
				t.Fatalf("handed back as orphaned = %v from %q; want orphaned from stuck-worker, which never ran it", after.IsOrphaned(), after.OrphanedOwnerNodeID)
			}
		})
	}
}

// A dedicated worker tells the leader when its own admitter refused the
// recreate, and only then: any other failure keeps today's retry in place.
func TestAgentEscalationSaysWhenTheAdmitterRefused(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"admitter refused", fmt.Errorf("create: %w: memory 512 of 512 MB reserved", capacity.ErrCapacityExceeded), true},
		{"network slots full", &capacity.SlotPoolExhaustedError{Pool: capacity.SlotPoolContainerNetns}, true},
		{"image pull failed", errors.New("image pull failed"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []ReassignStuckRequest
			agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case PublicInternalOwnedRecoveryPath:
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(OwnedRecoveryResponse{
						Placements:    []Placement{failoverRecreatePlacement("sb-full", "worker-self")},
						Authoritative: true,
					})
				case PublicInternalReassignStuckPath:
					var req ReassignStuckRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					got = append(got, req)
					w.WriteHeader(http.StatusAccepted)
				default:
					http.NotFound(w, r)
				}
			}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
			agent.recreateFailures = &recreateFailureTracker{counts: map[string]int{}, permanent: map[string]struct{}{}}
			agent.AttachRecreator(&refusingRecreator{err: tc.err})
			for range maxRecreateFailuresBeforeReassign {
				agent.recreateOwnedSandboxes(context.Background())
			}
			if len(got) != 1 || got[0].CapacityRefused != tc.want {
				t.Fatalf("reassign requests = %+v, want one with capacity_refused = %v", got, tc.want)
			}
		})
	}
}

// slotsAdmitter is a worker's admitter with room for a fixed number of
// sandboxes: it runs what fits and refuses the rest for capacity.
type slotsAdmitter struct {
	room    int
	running map[string]bool
}

func (a *slotsAdmitter) RecreateSandbox(_ context.Context, id string, _ models.CreateSandboxRequest, _ PlacementSecrets, _ map[int]ExposedPortRoute) error {
	if a.running[id] {
		return nil
	}
	if len(a.running) >= a.room {
		return fmt.Errorf("recreate %s: %w: cpu %d of %d reserved", id, capacity.ErrCapacityExceeded, len(a.running), a.room)
	}
	a.running[id] = true
	return nil
}

// UC-478 offline. A worker holding 12 recreate-policy sandboxes dies; the
// two survivors have room for 4 each. A capacity heartbeat from each lands
// half way through the eviction, before either has rebuilt anything, so the
// later reassigns see the room the earlier ones took and all 12 are assigned
// (run 2 of the live case, 2026-11-08). Each survivor's admitter runs 4 and
// refuses the rest. By the time the escalations have run, every sandbox must
// either run on its owner or be handed back and run nowhere (I6), and no
// survivor runs more than its room (I4).
func TestMassFailoverOverflowConvergesI6(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	c, cleanup := newTestClusterWithRole(t, "srv-mass", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	c.recreateFailures = &recreateFailureTracker{counts: map[string]int{}, permanent: map[string]struct{}{}}
	const room = 4
	survivor := func(id string) Member {
		return Member{NodeID: id, APIURL: "http://" + id, Alive: true, Role: config.NodeRoleWorker, Capacity: capacity.Snapshot{
			HostCPUCores: room, HostMemoryTotalMB: 16384, CPUBudget: room, MemoryBudgetMB: 16384, CanAdmit: true,
		}}
	}
	survivors := []Member{survivor("worker-2"), survivor("worker-3")}
	seedGossipView(t, c, append([]Member{{NodeID: "worker-1", Alive: false, Role: config.NodeRoleWorker}}, survivors...))
	heartbeat := func(admitters map[string]*slotsAdmitter) {
		for _, s := range survivors {
			snap := s.Capacity
			if a := admitters[s.NodeID]; a != nil {
				snap.ReservedCPU = float64(len(a.running))
			}
			c.capacityLeases.set(s.NodeID, snap, time.Now())
		}
	}

	ctx := context.Background()
	var ids []string
	for i := 0; i < 12; i++ {
		ids = append(ids, placeFailoverPlacement(t, c, fmt.Sprintf("sb-ha-%02d", i), "worker-1").SandboxID)
	}
	// The eviction, as evictDeadOwner runs it: pick, commit, next.
	assigned := 0
	for i, id := range ids {
		if i == len(ids)/2 {
			heartbeat(nil) // nothing rebuilt yet
		}
		p, _ := c.PlacementOf(id)
		target, err := c.selectRecreationTargetFor(p)
		if err != nil {
			continue
		}
		if err := c.applyCommand(ctx, command{Op: opReassign, SandboxID: id, OwnerNodeID: target.NodeID, ExpectedIncarnationID: p.IncarnationID, ReassignCause: reassignCauseFailover}); err != nil {
			t.Fatalf("reassign %s: %v", id, err)
		}
		assigned++
	}
	if assigned != len(ids) {
		t.Fatalf("the eviction assigned %d of %d; this case needs the over-assignment run 2 saw", assigned, len(ids))
	}

	// Each survivor's owner watcher, as a dedicated worker runs it: rebuild
	// what it owns, and after repeated failures ask the leader to move it.
	admitters := map[string]*slotsAdmitter{}
	trackers := map[string]*recreateFailureTracker{}
	for _, s := range survivors {
		admitters[s.NodeID] = &slotsAdmitter{room: room, running: map[string]bool{}}
		trackers[s.NodeID] = &recreateFailureTracker{counts: map[string]int{}, permanent: map[string]struct{}{}}
	}
	for round := 0; round < maxRecreateFailuresBeforeReassign+3; round++ {
		heartbeat(admitters)
		for _, s := range survivors {
			owner := s.NodeID
			deps := ownerRecreateDeps{
				recreator: admitters[owner],
				failures:  trackers[owner],
				logger:    c.logger,
				escalate: func(ctx context.Context, id string, p Placement, cause error) {
					_ = c.ReassignStuckPlacement(ctx, owner, id, p.IncarnationID, refusedForCapacity(cause))
				},
			}
			for id, p := range c.fsm.fullPlacementsForOwner(owner) {
				recreateOwnedPlacement(ctx, deps, id, p)
			}
		}
	}

	landed, unplaced := 0, 0
	for _, id := range ids {
		p, _ := c.PlacementOf(id)
		var runsOn []string
		for node, a := range admitters {
			if a.running[id] {
				runsOn = append(runsOn, node)
			}
		}
		switch {
		case !p.IsOrphaned() && p.OwnerNodeID != "worker-1" && len(runsOn) == 1 && runsOn[0] == p.OwnerNodeID:
			landed++
		case p.IsOrphaned() && len(runsOn) == 0:
			unplaced++
		default:
			t.Errorf("I6 violated: %s is placed on %q (orphaned %v) but runs on %v", id, p.OwnerNodeID, p.IsOrphaned(), runsOn)
		}
	}
	for node, a := range admitters {
		if len(a.running) > room {
			t.Errorf("I4 violated: %s runs %d, room %d", node, len(a.running), room)
		}
	}
	if landed != 2*room || unplaced != len(ids)-2*room {
		t.Fatalf("%d landed and %d handed back of %d; want %d landed (the room) and the rest handed back", landed, unplaced, len(ids), 2*room)
	}
}
