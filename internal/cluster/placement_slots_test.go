package cluster

import (
	"errors"
	"expvar"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression for the bank density ramp (2026-11-01): metal workers stopped at
// 256 containerd and 256 Firecracker sandboxes because their network-slot
// pools were full, while CPU and memory admission still had room. Placement
// kept choosing them, and the creates failed there with "no free slot".

// slotWorker is a worker with plenty of CPU and memory and the given pools.
// cores sizes its budgets, so a bigger host wins plain headroom scoring.
func slotWorker(nodeID string, cores int, runtimes []string, pools ...capacity.SlotPool) Member {
	return Member{
		NodeID: nodeID,
		APIURL: "http://" + nodeID,
		Alive:  true,
		Role:   config.NodeRoleWorker,
		Capacity: capacity.Snapshot{
			HostCPUCores:      cores,
			HostMemoryTotalMB: cores * 4096,
			CPUBudget:         float64(cores),
			MemoryBudgetMB:    cores * 4096,
			SupportedRuntimes: runtimes,
			CanAdmit:          true,
			SlotPools:         pools,
		},
	}
}

func netnsPool(total, free int) capacity.SlotPool {
	return capacity.SlotPool{Name: capacity.SlotPoolContainerNetns, Runtimes: []string{models.RuntimeDocker, models.RuntimeGvisor}, Total: total, Free: free}
}

func tapPool(total, free int) capacity.SlotPool {
	return capacity.SlotPool{Name: capacity.SlotPoolFirecrackerTap, Runtimes: []string{models.RuntimeFirecracker}, Total: total, Free: free}
}

func slotCluster(members ...Member) *Cluster {
	index := newGossipMemberIndex()
	index.replace(append([]Member{{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer}}, members...))
	return &Cluster{nodeID: "server-a", apiURL: "http://server-a", fsm: newPlacementFSM(), gossip: &gossipNode{memberIndex: index}}
}

var containerAndFC = []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeFirecracker}

func TestSelectPlacementSkipsNodeWhoseSlotPoolIsFull(t *testing.T) {
	// metal has 12x the CPU and memory, so headroom scoring alone always
	// picks it; its netns pool is full, its TAP pool is not.
	metal := slotWorker("worker-metal", 48, containerAndFC, netnsPool(256, 0), tapPool(256, 10))
	small := slotWorker("worker-small", 4, containerAndFC, netnsPool(256, 200), tapPool(256, 0))
	c := slotCluster(metal, small)
	cases := []struct {
		runtime string
		want    string
	}{
		{models.RuntimeDocker, "worker-small"},
		// gVisor shares the containerd netns pool with runc.
		{models.RuntimeGvisor, "worker-small"},
		{models.RuntimeFirecracker, "worker-metal"},
	}
	for _, tc := range cases {
		for i := 0; i < 50; i++ {
			target, err := c.SelectPlacement(capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: tc.runtime})
			if err != nil {
				t.Fatalf("%s iter %d: %v", tc.runtime, i, err)
			}
			if target.NodeID != tc.want {
				t.Fatalf("%s placed on %s, want %s (the other node's pool for it is full)", tc.runtime, target.NodeID, tc.want)
			}
		}
	}
}

func TestSelectPlacementAllSlotPoolsFullIsClusterAtCapacity(t *testing.T) {
	c := slotCluster(
		slotWorker("worker-a", 48, containerAndFC, netnsPool(256, 0), tapPool(256, 0)),
		slotWorker("worker-b", 48, containerAndFC, netnsPool(256, 0), tapPool(256, 0)),
	)
	before := expvarCount(schedulerCandidateRejects.Get("network_slots"))
	_, err := c.SelectPlacement(capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeFirecracker})
	if !errors.Is(err, ErrClusterAtCapacity) {
		t.Fatalf("every pool full = %v, want ErrClusterAtCapacity", err)
	}
	// Every existing ErrNoPlacementTarget mapping (503 + Retry-After) still
	// applies, and the message says capacity so a client can tell.
	if !errors.Is(err, ErrNoPlacementTarget) || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("err = %q: must stay an ErrNoPlacementTarget and say capacity", err)
	}
	if after := expvarCount(schedulerCandidateRejects.Get("network_slots")); after != before+2 {
		t.Fatalf("network_slots rejects = %d, want %d (two workers turned away)", after, before+2)
	}
}

func expvarCount(v expvar.Var) int64 {
	if v == nil {
		return 0
	}
	n, _ := strconv.ParseInt(v.String(), 10, 64)
	return n
}

func candidateIDs(cands []Member) map[string]bool {
	out := make(map[string]bool, len(cands))
	for _, m := range cands {
		out[m.NodeID] = true
	}
	return out
}

func TestSelectPlacementBudgetFullIsClusterAtCapacity(t *testing.T) {
	full := slotWorker("worker-a", 4, []string{models.RuntimeDocker})
	full.Capacity.ReservedCPU = 4
	_, err := slotCluster(full).SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 128, Runtime: models.RuntimeDocker})
	if !errors.Is(err, ErrClusterAtCapacity) {
		t.Fatalf("CPU budget spent = %v, want ErrClusterAtCapacity", err)
	}
	notAdmitting := slotWorker("worker-b", 4, []string{models.RuntimeDocker})
	notAdmitting.Capacity.CanAdmit = false
	notAdmitting.Capacity.Reasons = []string{"live memory floor breached"}
	if _, err := slotCluster(notAdmitting).SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 128, Runtime: models.RuntimeDocker}); !errors.Is(err, ErrClusterAtCapacity) {
		t.Fatalf("host not admitting = %v, want ErrClusterAtCapacity", err)
	}
}

// "At capacity" must not be claimed when no worker can run the request at all:
// waiting will not help, and the message would send the client the wrong way.
func TestSelectPlacementIncompatibleIsNotAtCapacity(t *testing.T) {
	c := slotCluster(slotWorker("worker-a", 48, []string{models.RuntimeDocker}, netnsPool(256, 0)))
	_, err := c.SelectPlacement(capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeFirecracker})
	if !errors.Is(err, ErrNoPlacementTarget) || errors.Is(err, ErrClusterAtCapacity) {
		t.Fatalf("no firecracker worker = %v, want plain ErrNoPlacementTarget", err)
	}
	gpu := slotWorker("worker-g", 48, []string{models.RuntimeDocker})
	if _, err := slotCluster(gpu).SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 128, Runtime: models.RuntimeDocker, GPUs: 1}); errors.Is(err, ErrClusterAtCapacity) {
		t.Fatalf("no GPU anywhere reported as capacity: %v", err)
	}
}

// Reserved creates have not taken their slot yet, so the heartbeat cannot show
// them: placement subtracts them, counting every runtime the pool serves.
func TestSelectPlacementCountsPendingReservationsAgainstSlots(t *testing.T) {
	metal := slotWorker("worker-metal", 48, containerAndFC, netnsPool(256, 2), tapPool(256, 1))
	small := slotWorker("worker-small", 4, containerAndFC, netnsPool(256, 100), tapPool(256, 100))
	c := slotCluster(metal, small)
	live := time.Now().Add(time.Minute).Unix()
	applyOp(t, c.fsm, command{Op: opReserve, SandboxID: "sb-1", OwnerNodeID: "worker-metal", Spec: &models.CreateSandboxRequest{CPU: 0.25, MemoryMB: 128}, ExpiresUnix: live})
	// A pending firecracker create holds a TAP, not a netns.
	applyOp(t, c.fsm, command{Op: opReserve, SandboxID: "sb-fc", OwnerNodeID: "worker-metal", Spec: &models.CreateSandboxRequest{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeFirecracker}, ExpiresUnix: live})

	// One netns slot left on metal after sb-1, so it is still a candidate
	// (scoring then prefers the node with more slots left). A pending gVisor
	// create then takes that last slot.
	_, cands, err := c.SelectPlacementWithCandidates(capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeDocker})
	if err != nil {
		t.Fatal(err)
	}
	if !candidateIDs(cands)["worker-metal"] {
		t.Fatalf("candidates = %v; metal has one netns slot left after its pending reservation", candidateIDs(cands))
	}
	applyOp(t, c.fsm, command{Op: opReserve, SandboxID: "sb-2", OwnerNodeID: "worker-metal", Spec: &models.CreateSandboxRequest{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeGvisor}, ExpiresUnix: live})
	for _, rt := range []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeFirecracker} {
		for i := 0; i < 50; i++ {
			target, err := c.SelectPlacement(capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: rt})
			if err != nil {
				t.Fatalf("%s: %v", rt, err)
			}
			if target.NodeID != "worker-small" {
				t.Fatalf("%s placed on %s; metal's pending reservations already hold its last slots", rt, target.NodeID)
			}
		}
	}
}

// A peer that predates SlotPools (rolling upgrade) and a runtime with no
// bounded pool are not gated: placement behaves exactly as before.
func TestSelectPlacementUnknownSlotPoolIsNotGated(t *testing.T) {
	legacy := slotWorker("worker-legacy", 8, []string{models.RuntimeDocker, models.RuntimeIsolate})
	c := slotCluster(legacy)
	for _, rt := range []string{models.RuntimeDocker, models.RuntimeIsolate} {
		if target, err := c.SelectPlacement(capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: rt}); err != nil || target.NodeID != "worker-legacy" {
			t.Fatalf("%s on a peer without SlotPools = (%v, %v), want placed", rt, target.NodeID, err)
		}
	}
	if !slotsFit(legacy, capacity.Request{Runtime: models.RuntimeDocker}, map[string]int{models.RuntimeDocker: 1000}) {
		t.Fatal("pending reservations alone must not gate a peer that reports no pool")
	}
}

func TestPlacementScoreAddsTheSlotAxis(t *testing.T) {
	req := capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeDocker}
	nearlyFull := slotWorker("a", 8, containerAndFC, netnsPool(256, 2))
	roomy := slotWorker("b", 8, containerAndFC, netnsPool(256, 250))
	if placementScore(nearlyFull, req, capacity.Request{}, nil) >= placementScore(roomy, req, capacity.Request{}, nil) {
		t.Fatal("with equal CPU and memory, the node with more free slots must score higher")
	}
	// Pending reservations count on the slot axis too.
	if placementScore(roomy, req, capacity.Request{}, map[string]int{models.RuntimeGvisor: 200}) >= placementScore(roomy, req, capacity.Request{}, nil) {
		t.Fatal("pending creates on the shared pool must lower the score")
	}
	// Without a pool for the runtime the score is headroomScore's.
	noPool := slotWorker("c", 8, containerAndFC)
	if got, want := placementScore(noPool, req, capacity.Request{}, nil), headroomScore(noPool, req, capacity.Request{}); got != want {
		t.Fatalf("placementScore without a pool = %v, want headroomScore %v", got, want)
	}
	unknown := Member{NodeID: "u"}
	if got := placementScore(unknown, req, capacity.Request{}, nil); got != 0.5 {
		t.Fatalf("unknown-capacity peer score = %v, want the neutral 0.5", got)
	}
	withDisk := slotWorker("d", 8, containerAndFC, netnsPool(256, 256))
	withDisk.Capacity.DiskBudgetGB = 100
	if s := placementScore(withDisk, req, capacity.Request{}, nil); s <= 0 || s > 1 {
		t.Fatalf("score with disk and slot axes = %v, want in (0,1]", s)
	}
}

// The leader's re-check before the Raft propose counts pending slots and the
// earlier reservations of the same batch.
func TestAdmitReservationCommandsChecksNetworkSlots(t *testing.T) {
	worker := slotWorker("worker-a", 48, containerAndFC, netnsPool(256, 1))
	reserve := func(id, rt string) reservationCommand {
		return reservationCommand{SandboxID: id, OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{CPU: 0.25, MemoryMB: 128, Runtime: rt}}
	}
	if err := admitReservationCommands([]Member{worker}, nil, nil, nil, 0, []reservationCommand{reserve("sb-1", models.RuntimeDocker)}); err != nil {
		t.Fatalf("one create into the last slot: %v", err)
	}
	err := admitReservationCommands([]Member{worker}, nil, nil, nil, 0, []reservationCommand{reserve("sb-1", models.RuntimeDocker), reserve("sb-2", models.RuntimeGvisor)})
	if !errors.Is(err, ErrCapacityExceeded) || !strings.Contains(err.Error(), "network slot") {
		t.Fatalf("two creates into one slot = %v, want ErrCapacityExceeded naming the network slot", err)
	}
	err = admitReservationCommands([]Member{worker}, nil, map[string]map[string]int{"worker-a": {models.RuntimeGvisor: 1}}, nil, 0, []reservationCommand{reserve("sb-3", models.RuntimeDocker)})
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("a pending gVisor create already holds the last netns: %v, want ErrCapacityExceeded", err)
	}
	// A firecracker create does not draw on the netns pool.
	if err := admitReservationCommands([]Member{worker}, nil, map[string]map[string]int{"worker-a": {models.RuntimeGvisor: 1}}, nil, 0, []reservationCommand{reserve("sb-4", models.RuntimeFirecracker)}); err != nil {
		t.Fatalf("firecracker create against a full netns pool: %v", err)
	}
}

// Failover recreation picks among recipients with the same rule: a recipient
// whose pool is full for the sandbox's runtime is not a target.
func TestSelectRecreationTargetSkipsSlotFullRecipient(t *testing.T) {
	roomy := slotWorker("worker-roomy", 4, containerAndFC, netnsPool(256, 50))
	full := slotWorker("worker-full", 48, containerAndFC, netnsPool(256, 0))
	c := slotCluster(roomy, full)
	p := Placement{Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 0.25, MemoryMB: 128}}
	target, ok := c.selectRecreationTarget(p, "dead-owner")
	if !ok || target.NodeID != "worker-roomy" {
		t.Fatalf("recreation target = (%q, %t), want worker-roomy (worker-full has no netns slot)", target.NodeID, ok)
	}
	c = slotCluster(full)
	if _, ok := c.selectRecreationTarget(p, "dead-owner"); ok {
		t.Fatal("the only candidate has no slot; there is no recreation target")
	}
}

func TestNodeFitVerdict(t *testing.T) {
	base := slotWorker("w", 4, []string{models.RuntimeDocker})
	cases := []struct {
		name string
		edit func(*Member)
		req  capacity.Request
		want fitVerdict
	}{
		{"fits", func(*Member) {}, capacity.Request{CPU: 1, Runtime: models.RuntimeDocker}, fitOK},
		{"stale", func(m *Member) { m.CapacityStale = true }, capacity.Request{CPU: 1}, fitIncompatible},
		{"runtime missing", func(*Member) {}, capacity.Request{CPU: 1, Runtime: models.RuntimeFirecracker}, fitIncompatible},
		// Incompatible wins over full: a node that cannot run the request is
		// not "at capacity" for it.
		{"runtime missing and full", func(m *Member) { m.Capacity.ReservedCPU = 4 }, capacity.Request{CPU: 1, Runtime: models.RuntimeWasm}, fitIncompatible},
		{"gpu vendor", func(m *Member) { m.Capacity.GPUCount, m.Capacity.GPUVendor = 1, "amd" }, capacity.Request{GPUs: 1, GPUVendor: "nvidia"}, fitIncompatible},
		{"template absent", func(m *Member) { m.Capacity.LocalTemplateInventoryKnown = true }, capacity.Request{TemplateID: "tpl"}, fitIncompatible},
		{"module absent", func(m *Member) { m.Capacity.LocalWasmModuleInventoryKnown = true }, capacity.Request{Runtime: models.RuntimeWasm, ModuleRef: "m"}, fitIncompatible},
		{"cpu", func(m *Member) { m.Capacity.ReservedCPU = 4 }, capacity.Request{CPU: 1}, fitNoRoom},
		{"memory", func(m *Member) { m.Capacity.ReservedMemoryMB = m.Capacity.MemoryBudgetMB }, capacity.Request{MemoryMB: 1}, fitNoRoom},
		{"disk", func(m *Member) { m.Capacity.DiskBudgetGB, m.Capacity.ReservedDiskGB = 10, 10 }, capacity.Request{DiskGB: 1}, fitNoRoom},
	}
	for _, tc := range cases {
		m := base
		m.Capacity.SupportedRuntimes = []string{models.RuntimeDocker}
		tc.edit(&m)
		if got := nodeFitVerdict(m, tc.req, capacity.Request{}); got != tc.want {
			t.Fatalf("%s: verdict = %d, want %d", tc.name, got, tc.want)
		}
		if nodeFits(m, tc.req, capacity.Request{}) != (tc.want == fitOK) {
			t.Fatalf("%s: nodeFits disagrees with the verdict", tc.name)
		}
	}
}
