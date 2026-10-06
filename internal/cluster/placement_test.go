package cluster

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestNodeFitsRespectsBudget asserts that a peer whose post-reservation
// budget would be exceeded is rejected by nodeFits.
func TestNodeFitsRespectsBudget(t *testing.T) {
	tight := Member{
		NodeID: "tight",
		APIURL: "http://t",
		Alive:  true,
		Capacity: capacity.Snapshot{
			HostCPUCores:      4,
			HostMemoryTotalMB: 8000,
			CPUBudget:         4,
			MemoryBudgetMB:    8000,
			ReservedCPU:       3.5,
			ReservedMemoryMB:  7800,
		},
	}
	if nodeFits(tight, capacity.Request{CPU: 1, MemoryMB: 1024}, capacity.Request{}) {
		t.Fatal("tight node should not fit a 1-core/1G request")
	}
	if !nodeFits(tight, capacity.Request{CPU: 0.1, MemoryMB: 100}, capacity.Request{}) {
		t.Fatal("tight node should still fit a small request that fits in remaining budget")
	}
}

// TestNodeFitsRejectsUnknownCapacity asserts that a peer with no capacity
// heartbeat is not a candidate. Forwarding unknown-capacity creates causes
// avoidable remote 503s and retry storms.
func TestNodeFitsRejectsUnknownCapacity(t *testing.T) {
	unknown := Member{NodeID: "u", APIURL: "http://u", Alive: true}
	if nodeFits(unknown, capacity.Request{CPU: 1, MemoryMB: 1024}, capacity.Request{}) {
		t.Fatal("unknown-capacity node should not be treated as candidate")
	}
}

func TestNodeFitsRejectsStaleCapacityHeartbeat(t *testing.T) {
	stale := Member{
		NodeID:        "stale",
		APIURL:        "http://stale",
		Alive:         true,
		CapacityStale: true,
		Capacity: capacity.Snapshot{
			HostCPUCores: 8, HostMemoryTotalMB: 8000,
			CPUBudget: 8, MemoryBudgetMB: 8000,
		},
	}
	if nodeFits(stale, capacity.Request{CPU: 1, MemoryMB: 1024}, capacity.Request{}) {
		t.Fatal("stale-capacity node should not be treated as candidate")
	}
}

func TestCanOwnSandboxRole(t *testing.T) {
	for _, tc := range []struct {
		role string
		want bool
	}{
		{"", true},
		{"mixed", true},
		{"worker", true},
		{"ingress,worker", true},
		{"server,worker", true},
		{"server", false},
		{"ingress", false},
		{"server,ingress", false},
		{"controller", false},
	} {
		if got := CanOwnSandboxRole(tc.role); got != tc.want {
			t.Fatalf("role %q CanOwnSandboxRole = %v, want %v", tc.role, got, tc.want)
		}
	}
}

// TestHeadroomScorePrefersEmptier checks the scoring monotonicity that
// power-of-two-choices relies on.
func TestHeadroomScorePrefersEmptier(t *testing.T) {
	full := Member{Capacity: capacity.Snapshot{
		HostCPUCores: 4, HostMemoryTotalMB: 8000,
		CPUBudget: 4, MemoryBudgetMB: 8000,
		ReservedCPU: 3.0, ReservedMemoryMB: 6000,
	}}
	empty := Member{Capacity: capacity.Snapshot{
		HostCPUCores: 4, HostMemoryTotalMB: 8000,
		CPUBudget: 4, MemoryBudgetMB: 8000,
		ReservedCPU: 0.5, ReservedMemoryMB: 1000,
	}}
	req := capacity.Request{CPU: 0.5, MemoryMB: 500}
	if headroomScore(full, req, capacity.Request{}) >= headroomScore(empty, req, capacity.Request{}) {
		t.Fatal("emptier node should score higher")
	}
}

// TestPickTwoDistinct ensures pickTwo never picks the same index twice when
// the candidate slice has more than one element. This is the property
// power-of-two-choices depends on for actually being two choices.
func TestPickTwoDistinct(t *testing.T) {
	members := []Member{
		{NodeID: "a"}, {NodeID: "b"}, {NodeID: "c"}, {NodeID: "d"},
	}
	for i := 0; i < 200; i++ {
		x, y := pickTwo(members)
		if x.NodeID == y.NodeID {
			t.Fatalf("pickTwo returned identical members on iter %d: %v / %v", i, x, y)
		}
	}
}

// TestNodeFitsRejectsDiskOverflow asserts the disk-budget filter — placement
// must skip a peer whose remaining disk budget cannot hold the request, even
// when CPU and memory would otherwise fit. Without this, a sandbox lands on
// the peer and ENOSPCs at create time, leaking partial state.
func TestNodeFitsRejectsDiskOverflow(t *testing.T) {
	tight := Member{
		NodeID: "tight",
		APIURL: "http://t",
		Alive:  true,
		Capacity: capacity.Snapshot{
			HostCPUCores: 16, HostMemoryTotalMB: 32000, HostDiskTotalGB: 100,
			CPUBudget: 16, MemoryBudgetMB: 32000, DiskBudgetGB: 100,
			ReservedCPU: 1, ReservedMemoryMB: 1024, ReservedDiskGB: 95,
		},
	}
	if nodeFits(tight, capacity.Request{CPU: 1, MemoryMB: 1024, DiskGB: 10}, capacity.Request{}) {
		t.Fatal("tight-disk node should not fit a 10 GB ask with only 5 GB free")
	}
	if !nodeFits(tight, capacity.Request{CPU: 1, MemoryMB: 1024, DiskGB: 5}, capacity.Request{}) {
		t.Fatal("tight-disk node should still fit an exactly-sized ask")
	}
}

// TestNodeFitsRejectsGPULessHost: a GPU sandbox must not be forwarded to a
// peer that has no GPUs. The remote admitter would 503 anyway, but doing
// the filter at placement time avoids the wasted forward and the noisy log.
func TestNodeFitsRejectsGPULessHost(t *testing.T) {
	gpuLess := Member{NodeID: "g0", APIURL: "http://g", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
	}}
	if nodeFits(gpuLess, capacity.Request{CPU: 1, MemoryMB: 100, GPUs: 1, GPUVendor: "nvidia"}, capacity.Request{}) {
		t.Fatal("GPU sandbox should be rejected from GPU-less host")
	}
}

// TestNodeFitsRejectsGPUVendorMismatch: NVIDIA request must not land on AMD.
func TestNodeFitsRejectsGPUVendorMismatch(t *testing.T) {
	amd := Member{NodeID: "amd", APIURL: "http://a", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		GPUCount: 4, GPUVendor: "amd",
	}}
	if nodeFits(amd, capacity.Request{CPU: 1, MemoryMB: 100, GPUs: 1, GPUVendor: "nvidia"}, capacity.Request{}) {
		t.Fatal("NVIDIA request must not fit on AMD host")
	}
	if !nodeFits(amd, capacity.Request{CPU: 1, MemoryMB: 100, GPUs: 1, GPUVendor: "amd"}, capacity.Request{}) {
		t.Fatal("matching vendor must fit")
	}
}

// TestNodeFitsRejectsUnsupportedRuntime: gvisor request must not land on a
// docker-only host. Empty SupportedRuntimes (legacy peer) is treated as
// "unknown, allow" — exercised in a separate test.
func TestNodeFitsRejectsUnsupportedRuntime(t *testing.T) {
	dockerOnly := Member{NodeID: "d", APIURL: "http://d", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		SupportedRuntimes: []string{"docker"},
	}}
	if nodeFits(dockerOnly, capacity.Request{CPU: 1, MemoryMB: 100, Runtime: "gvisor"}, capacity.Request{}) {
		t.Fatal("gvisor request must not fit on docker-only host")
	}
	if !nodeFits(dockerOnly, capacity.Request{CPU: 1, MemoryMB: 100, Runtime: "docker"}, capacity.Request{}) {
		t.Fatal("docker request must fit on docker-only host")
	}
}

func TestSelectPlacementSkipsDockerOnlyWorkersForFirecrackerAt100Nodes(t *testing.T) {
	index := newGossipMemberIndex()
	var members []Member
	for i := 0; i < 3; i++ {
		members = append(members, Member{
			NodeID: "server-" + string(rune('a'+i)),
			APIURL: "http://server",
			Alive:  true,
			Role:   config.NodeRoleServer,
		})
	}
	for i := 0; i < 10; i++ {
		members = append(members, Member{
			NodeID: "ingress-" + string(rune('a'+i)),
			APIURL: "http://ingress",
			Alive:  true,
			Role:   config.NodeRoleIngress,
		})
	}
	for i := 0; i < 30; i++ {
		members = append(members, runtimeWorker("docker-worker-", i, []string{models.RuntimeDocker}))
	}
	for i := 0; i < 57; i++ {
		members = append(members, runtimeWorker("fc-worker-", i, []string{models.RuntimeDocker, models.RuntimeFirecracker}))
	}
	index.replace(members)

	c := &Cluster{
		nodeID: "server-a",
		apiURL: "http://server-a",
		fsm:    newPlacementFSM(),
		gossip: &gossipNode{memberIndex: index},
	}

	for i := 0; i < 200; i++ {
		target, err := c.SelectPlacement(capacity.Request{
			CPU: 1, MemoryMB: 100,
			Runtime: models.RuntimeFirecracker,
		})
		if err != nil {
			t.Fatalf("SelectPlacement iteration %d: %v", i, err)
		}
		if !strings.HasPrefix(target.NodeID, "fc-worker-") {
			t.Fatalf("SelectPlacement chose %q, want only firecracker-capable workers", target.NodeID)
		}
	}
}

// TestNodeFitsLegacyEmptyRuntimesAllowsAny: a peer that pre-dates the
// SupportedRuntimes field (empty list, but with a fresh non-zero capacity
// heartbeat) must remain a candidate for any runtime — otherwise a rolling
// upgrade would freeze placements.
func TestNodeFitsLegacyEmptyRuntimesAllowsAny(t *testing.T) {
	legacy := Member{NodeID: "l", APIURL: "http://l", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
		// SupportedRuntimes intentionally empty
	}}
	if !nodeFits(legacy, capacity.Request{CPU: 1, MemoryMB: 100, Runtime: "gvisor"}, capacity.Request{}) {
		t.Fatal("legacy (empty SupportedRuntimes) peer must accept any runtime")
	}
}

// TestHeadroomScoreIncludesDiskWhenReported: when a peer reports a disk
// budget, the score must drop relative to a peer with more free disk. This
// is the property power-of-two-choices uses to prefer the emptier peer.
func TestHeadroomScoreIncludesDiskWhenReported(t *testing.T) {
	full := Member{Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000, HostDiskTotalGB: 100,
		CPUBudget: 8, MemoryBudgetMB: 8000, DiskBudgetGB: 100,
		ReservedCPU: 1, ReservedMemoryMB: 1024, ReservedDiskGB: 90,
	}}
	empty := Member{Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000, HostDiskTotalGB: 100,
		CPUBudget: 8, MemoryBudgetMB: 8000, DiskBudgetGB: 100,
		ReservedCPU: 1, ReservedMemoryMB: 1024, ReservedDiskGB: 5,
	}}
	req := capacity.Request{CPU: 1, MemoryMB: 100, DiskGB: 5}
	if headroomScore(full, req, capacity.Request{}) >= headroomScore(empty, req, capacity.Request{}) {
		t.Fatal("disk-emptier node should score higher when both report disk")
	}
}

// TestCapacityRequestFromSpecMatchesCreatePath pins the invariant the
// capacityRequestFromSpec helper exists to enforce: a CreateSandboxRequest
// that flows through capacityRequestFromCreate (placement on create) must
// produce the same capacity.Request as the spec going through
// capacityRequestFromSpec (placement on failover-recreate). Drift here
// would mean a recreated GPU/disk sandbox loses its hard constraints.
func TestCapacityRequestFromSpecPopulatesAllAxes(t *testing.T) {
	spec := &models.CreateSandboxRequest{
		CPU: 2, MemoryMB: 4096, DiskGB: 50, Runtime: "gvisor",
		GPUs: &models.GPURequest{Vendor: models.GPUVendorNVIDIA, Count: 2},
	}
	got := capacityRequestFromSpec(spec)
	want := capacity.Request{CPU: 2, MemoryMB: 4096, DiskGB: 50, Runtime: "gvisor", GPUs: 2, GPUVendor: "nvidia"}
	if got != want {
		t.Fatalf("capacityRequestFromSpec drift: got %+v want %+v", got, want)
	}
}

func TestCapacityRequestFromSpecDefaultsRuntimeToDocker(t *testing.T) {
	got := capacityRequestFromSpec(&models.CreateSandboxRequest{})
	if got.Runtime != models.RuntimeDocker {
		t.Fatalf("Runtime = %q, want docker", got.Runtime)
	}
}

// TestCapacityRequestFromSpecGPUCountDefaults pins the documented GPU.Count
// semantics: 0 means "default 1", -1 ("all") is normalized to 1 for
// placement scoring (we can't gossip "all" cleanly, and any GPU host with
// at least one card satisfies the intent).
func TestCapacityRequestFromSpecGPUCountDefaults(t *testing.T) {
	for _, tc := range []struct{ in, want int }{{0, 1}, {-1, 1}, {3, 3}} {
		spec := &models.CreateSandboxRequest{
			CPU: 1, MemoryMB: 100, DiskGB: 10,
			GPUs: &models.GPURequest{Vendor: models.GPUVendorNVIDIA, Count: tc.in},
		}
		if got := capacityRequestFromSpec(spec).GPUs; got != tc.want {
			t.Fatalf("GPU.Count=%d: got %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestHeadroomScoreSymmetricNeutral verifies the scoring helper's defensive
// unknown-capacity path returns a neutral 0.5. SelectPlacement filters unknown
// capacity before scoring; this keeps direct helper use deterministic.
func TestHeadroomScoreSymmetricNeutral(t *testing.T) {
	unknown := Member{}
	score := headroomScore(unknown, capacity.Request{CPU: 1, MemoryMB: 1024}, capacity.Request{})
	if math.Abs(score-0.5) > 1e-9 {
		t.Fatalf("expected neutral 0.5 score for unknown capacity, got %v", score)
	}
}

func TestAdmitReservationCommandsRejectsMissingCapacityHeartbeat(t *testing.T) {
	err := admitReservationCommands([]Member{
		{NodeID: "worker-a", APIURL: "http://worker-a", Alive: true, Role: "worker"},
	}, nil, nil, 32, []reservationCommand{
		{SandboxID: "sb1", OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{CPU: 1, MemoryMB: 128}},
	})
	if !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("admitReservationCommands error = %v, want ErrNoPlacementTarget", err)
	}
}

func TestAdmitReservationCommandsAppliesPerWorkerBackpressure(t *testing.T) {
	err := admitReservationCommands([]Member{
		{NodeID: "worker-a", APIURL: "http://worker-a", Alive: true, Role: "worker", Capacity: capacity.Snapshot{
			HostCPUCores: 16, HostMemoryTotalMB: 32000,
			CPUBudget: 16, MemoryBudgetMB: 32000,
		}},
	}, nil, map[string]int{"worker-a": 2}, 2, []reservationCommand{
		{SandboxID: "sb1", OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{CPU: 1, MemoryMB: 128}},
	})
	if !errors.Is(err, ErrCreateBackpressure) {
		t.Fatalf("admitReservationCommands error = %v, want ErrCreateBackpressure", err)
	}
}

func TestAdmitReservationCommandsAccountsForBatchCapacity(t *testing.T) {
	err := admitReservationCommands([]Member{
		{NodeID: "worker-a", APIURL: "http://worker-a", Alive: true, Role: "worker", Capacity: capacity.Snapshot{
			HostCPUCores: 4, HostMemoryTotalMB: 4096,
			CPUBudget: 2, MemoryBudgetMB: 4096,
		}},
	}, nil, nil, 32, []reservationCommand{
		{SandboxID: "sb1", OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{CPU: 1, MemoryMB: 128}},
		{SandboxID: "sb2", OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{CPU: 1.5, MemoryMB: 128}},
	})
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("admitReservationCommands error = %v, want ErrCapacityExceeded", err)
	}
}

// TestNodeFitsTemplatePresent: a peer that reports the requested
// template in its inventory passes. The clone boots locally against
// already-cached artifacts and inherits the <100ms fast-boot property.
func TestNodeFitsTemplatePresent(t *testing.T) {
	hot := Member{NodeID: "hot", APIURL: "http://h", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
		LocalTemplateInventoryKnown: true,
		LocalTemplateIDs:            []string{"tpl-a", "tpl-b", "tpl-c"},
	}}
	if !nodeFits(hot, capacity.Request{CPU: 1, MemoryMB: 100, TemplateID: "tpl-b"}, capacity.Request{}) {
		t.Fatal("node with the template should fit")
	}
}

// TestNodeFitsTemplateAbsentRejected: a peer with a non-empty inventory
// missing the requested template is rejected. This is the authoritative
// "no" arm — the peer reported its inventory and the template isn't
// in it, so placing here would force the consumer-side puller to fetch
// from AOCR and lose the fast-boot property.
func TestNodeFitsTemplateAbsentRejected(t *testing.T) {
	cold := Member{NodeID: "cold", APIURL: "http://c", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
		LocalTemplateInventoryKnown: true,
		LocalTemplateIDs:            []string{"tpl-a"},
	}}
	if nodeFits(cold, capacity.Request{CPU: 1, MemoryMB: 100, TemplateID: "tpl-z"}, capacity.Request{}) {
		t.Fatal("node missing the template should be rejected when inventory is non-empty")
	}
}

// TestNodeFitsTemplateUnknownAllowOnEmpty: a peer with unknown template
// inventory (legacy node mid-rolling-upgrade, or just-joined node that
// hasn't reported yet) must remain a candidate. Gating here would
// strand creates on fresh clusters; the consumer-side puller is the
// safety net when the placement misses. Mirrors SupportedRuntimes'
// unknown-allow rule.
func TestNodeFitsTemplateUnknownAllowOnEmpty(t *testing.T) {
	legacy := Member{NodeID: "l", APIURL: "http://l", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
		// LocalTemplateInventoryKnown intentionally false
	}}
	if !nodeFits(legacy, capacity.Request{CPU: 1, MemoryMB: 100, TemplateID: "tpl-x"}, capacity.Request{}) {
		t.Fatal("legacy (empty LocalTemplateIDs) peer must accept any template")
	}
}

func TestNodeFitsKnownEmptyTemplateInventoryRejected(t *testing.T) {
	empty := Member{NodeID: "empty", APIURL: "http://e", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
		LocalTemplateInventoryKnown: true,
	}}
	if nodeFits(empty, capacity.Request{CPU: 1, MemoryMB: 100, TemplateID: "tpl-x"}, capacity.Request{}) {
		t.Fatal("authoritative empty template inventory should reject template-bound create")
	}
}

// TestNodeFitsNoTemplateRequestSkipsGate: a request without a template
// (a non-Firecracker create) must not be filtered by LocalTemplateIDs
// at all — empty TemplateID means "any host." Without this guard a
// docker sandbox could be falsely rejected because the peer's
// inventory doesn't list its (non-existent) template.
func TestNodeFitsRejectsCanAdmitFalseWithReasons(t *testing.T) {
	full := Member{NodeID: "full", APIURL: "http://full", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
		CanAdmit: false,
		Reasons:  []string{"at capacity"},
	}}
	if nodeFits(full, capacity.Request{CPU: 0.1, MemoryMB: 100}, capacity.Request{}) {
		t.Fatal("node with CanAdmit=false and reasons should not fit")
	}
}

func TestNodeFitsWasmModuleInventoryKnown(t *testing.T) {
	withModule := Member{NodeID: "wasm-hot", APIURL: "http://w", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
		LocalWasmModuleInventoryKnown: true,
		LocalWasmModuleIDs:            []string{"mod-a"},
	}}
	req := capacity.Request{CPU: 1, MemoryMB: 100, Runtime: models.RuntimeWasm, ModuleRef: "mod-a"}
	if !nodeFits(withModule, req, capacity.Request{}) {
		t.Fatal("node with cached wasm module should fit wasm request")
	}
	if nodeFits(withModule, capacity.Request{CPU: 1, MemoryMB: 100, Runtime: models.RuntimeWasm, ModuleRef: "mod-b"}, capacity.Request{}) {
		t.Fatal("node missing wasm module should reject wasm request when inventory is known")
	}

	legacy := Member{NodeID: "wasm-legacy", APIURL: "http://l", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
	}}
	if !nodeFits(legacy, capacity.Request{CPU: 1, MemoryMB: 100, Runtime: models.RuntimeWasm, ModuleRef: "mod-x"}, capacity.Request{}) {
		t.Fatal("unknown wasm inventory should allow wasm request")
	}
}

func TestNodeFitsNoTemplateRequestSkipsGate(t *testing.T) {
	docker := Member{NodeID: "d", APIURL: "http://d", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
		LocalTemplateIDs: []string{"tpl-a"},
	}}
	if !nodeFits(docker, capacity.Request{CPU: 1, MemoryMB: 100}, capacity.Request{}) {
		t.Fatal("non-template request must skip the template gate")
	}
}

// TestCapacityRequestFromSpecCarriesTemplateID pins the wiring
// invariant: a Firecracker create flowing through capacityRequestFromSpec
// (failover-recreate) must carry the TemplateID so the recreated
// placement targets a node that has the template. Drift here would mean
// a failed-over Firecracker sandbox loses its template-locality
// guarantee on the recreate, paying the docker-pull cost on every
// failover.
func TestCapacityRequestFromSpecCarriesTemplateID(t *testing.T) {
	spec := &models.CreateSandboxRequest{
		CPU: 1, MemoryMB: 512, DiskGB: 5,
		Runtime: models.RuntimeFirecracker, TemplateID: "tpl-fc-1",
	}
	got := capacityRequestFromSpec(spec)
	if got.TemplateID != "tpl-fc-1" {
		t.Fatalf("capacityRequestFromSpec.TemplateID = %q, want %q", got.TemplateID, "tpl-fc-1")
	}
}

func TestCapacityRequestFromSpecFirecrackerOverlayCountsAsDisk(t *testing.T) {
	got := capacityRequestFromSpec(&models.CreateSandboxRequest{
		CPU: 1, MemoryMB: 512, DiskGB: 5,
		Runtime:       models.RuntimeFirecracker,
		OverlaySizeGB: 20,
	})
	if got.DiskGB != 25 {
		t.Fatalf("capacityRequestFromSpec DiskGB = %d, want 25", got.DiskGB)
	}
}

func TestCapacityRequestFromSpecTemplateIDImpliesFirecracker(t *testing.T) {
	spec := &models.CreateSandboxRequest{
		CPU: 1, MemoryMB: 512, DiskGB: 5,
		TemplateID: " tpl-fc-1 ",
	}
	got := capacityRequestFromSpec(spec)
	if got.Runtime != models.RuntimeFirecracker || got.TemplateID != "tpl-fc-1" {
		t.Fatalf("capacityRequestFromSpec = %+v, want runtime=firecracker template_id=tpl-fc-1", got)
	}

	dockerOnly := Member{NodeID: "docker-only", APIURL: "http://d", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
		SupportedRuntimes: []string{models.RuntimeDocker},
	}}
	if nodeFits(dockerOnly, got, capacity.Request{}) {
		t.Fatal("template-backed Firecracker request must not fit on a docker-only host")
	}
}

func runtimeWorker(prefix string, i int, runtimes []string) Member {
	return Member{
		NodeID: prefix + strconv.Itoa(i),
		APIURL: "http://" + prefix + strconv.Itoa(i),
		Alive:  true,
		Role:   config.NodeRoleWorker,
		Capacity: capacity.Snapshot{
			HostCPUCores:      16,
			HostMemoryTotalMB: 65536,
			CPUBudget:         16,
			MemoryBudgetMB:    65536,
			AvailableCPU:      16,
			AvailableMemoryMB: 65536,
			SupportedRuntimes: runtimes,
			CanAdmit:          true,
		},
	}
}

// heteroPlacementCluster builds an offline *Cluster whose gossip view mirrors
// the cluster-hetero integration topology: a dedicated control-plane server and
// ingress (neither may own a sandbox) plus multi-runtime workers. x/y/w each
// advertise docker+gvisor+wasm; z also advertises firecracker. It is the offline
// guard for routing bugs (creates must land on a worker that advertises the
// requested runtime). Returns the cluster plus runtime->allowed-worker sets.
func heteroPlacementCluster() (*Cluster, map[string][]string) {
	workers := map[string][]string{
		models.RuntimeDocker:      {"worker-x", "worker-y", "worker-w", "worker-z"},
		models.RuntimeWasm:        {"worker-x", "worker-y", "worker-w", "worker-z"},
		models.RuntimeGvisor:      {"worker-x", "worker-y", "worker-w", "worker-z"},
		models.RuntimeFirecracker: {"worker-z"},
	}
	members := []Member{
		{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "ingress-a", APIURL: "http://ingress-a", Alive: true, Role: config.NodeRoleIngress},
		heteroWorker("worker-x", []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeWasm}),
		heteroWorker("worker-y", []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeWasm}),
		heteroWorker("worker-w", []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeWasm}),
		heteroWorker("worker-z", []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeWasm, models.RuntimeFirecracker}),
	}
	index := newGossipMemberIndex()
	index.replace(members)
	c := &Cluster{
		nodeID: "server-a",
		apiURL: "http://server-a",
		fsm:    newPlacementFSM(),
		gossip: &gossipNode{memberIndex: index},
	}
	return c, workers
}

func heteroWorker(nodeID string, runtimes []string) Member {
	return Member{
		NodeID: nodeID,
		APIURL: "http://" + nodeID,
		Alive:  true,
		Role:   config.NodeRoleWorker,
		Capacity: capacity.Snapshot{
			HostCPUCores:      16,
			HostMemoryTotalMB: 65536,
			CPUBudget:         16,
			MemoryBudgetMB:    65536,
			AvailableCPU:      16,
			AvailableMemoryMB: 65536,
			SupportedRuntimes: runtimes,
			CanAdmit:          true,
		},
	}
}

// allowedWorker reports whether nodeID is in the hetero worker allow-list.
func allowedWorker(allowed []string, nodeID string) bool {
	for _, id := range allowed {
		if id == nodeID {
			return true
		}
	}
	return false
}

// TestSelectPlacementHeteroRoutesSpecializedRuntimeToCapableWorker pins the core
// hetero scheduler invariant: a create that names a specialized runtime is
// placed only on a worker that advertises it. Firecracker is singleton (z);
// wasm/gvisor may land on any multi-runtime peer.
func TestSelectPlacementHeteroRoutesSpecializedRuntimeToCapableWorker(t *testing.T) {
	c, workers := heteroPlacementCluster()
	for _, runtimeName := range []string{models.RuntimeWasm, models.RuntimeFirecracker, models.RuntimeGvisor} {
		allowed := workers[runtimeName]
		for i := 0; i < 100; i++ {
			target, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 100, Runtime: runtimeName})
			if err != nil {
				t.Fatalf("runtime %q: SelectPlacement iter %d: %v", runtimeName, i, err)
			}
			if !allowedWorker(allowed, target.NodeID) {
				t.Fatalf("runtime %q placed on %q, want one of %v (regression: create routed to a worker that does not run this runtime)",
					runtimeName, target.NodeID, allowed)
			}
		}
	}
}

// TestSelectPlacementHeteroDockerStaysOnDockerCapableWorker asserts a docker
// create only lands on a worker that advertises docker (all multi-runtime peers).
func TestSelectPlacementHeteroDockerStaysOnDockerCapableWorker(t *testing.T) {
	c, workers := heteroPlacementCluster()
	allowed := workers[models.RuntimeDocker]
	for i := 0; i < 200; i++ {
		target, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 100, Runtime: models.RuntimeDocker})
		if err != nil {
			t.Fatalf("SelectPlacement iter %d: %v", i, err)
		}
		if !allowedWorker(allowed, target.NodeID) {
			t.Fatalf("docker create placed on %q, want one of %v", target.NodeID, allowed)
		}
	}
}

// TestSelectPlacementHeteroUnspecifiedRuntimeDefaultsToDockerWorker is the
// offline guard for the cluster-hetero default-runtime routing bug: a create
// that omits runtime must not reach server/ingress roles and must land on a
// worker that advertises docker.
func TestSelectPlacementHeteroUnspecifiedRuntimeDefaultsToDockerWorker(t *testing.T) {
	c, workers := heteroPlacementCluster()
	allowed := workers[models.RuntimeDocker]
	req := capacityRequestFromSpec(&models.CreateSandboxRequest{CPU: 1, MemoryMB: 100})
	if req.Runtime != models.RuntimeDocker {
		t.Fatalf("capacityRequestFromSpec defaulted runtime to %q, want docker", req.Runtime)
	}
	for i := 0; i < 200; i++ {
		target, err := c.SelectPlacement(req)
		if err != nil {
			t.Fatalf("SelectPlacement iter %d: %v", i, err)
		}
		if !allowedWorker(allowed, target.NodeID) {
			t.Fatalf("unspecified-runtime create placed on %q, want one of %v", target.NodeID, allowed)
		}
	}
}

// TestSelectPlacementRejectsRuntimeWithNoCapableWorker pins the "503, don't
// misplace" contract: when no live worker advertises the requested runtime,
// SelectPlacement returns ErrNoPlacementTarget rather than silently forwarding
// to an incapable node (which would 5xx at create time after a wasted hop).
func TestSelectPlacementRejectsRuntimeWithNoCapableWorker(t *testing.T) {
	members := []Member{
		{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
		runtimeWorker("docker-worker-", 0, []string{models.RuntimeDocker}),
	}
	index := newGossipMemberIndex()
	index.replace(members)
	c := &Cluster{
		nodeID: "server-a",
		apiURL: "http://server-a",
		fsm:    newPlacementFSM(),
		gossip: &gossipNode{memberIndex: index},
	}

	if _, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 100, Runtime: models.RuntimeWasm}); !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("SelectPlacement for wasm with no wasm worker = %v, want ErrNoPlacementTarget", err)
	}
}

// T19 S5 regression (UC-80): a template that just became ready is in the
// replicated catalogue but not yet in any gossiped LocalTemplateIDs. The
// template filter must not read that as an authoritative "no" on the node the
// catalogue names, or a create from a fresh template has no target at all.
func TestCatalogueTemplateHolderPassesTheTemplateFilter(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-tpl-holder", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	if err := publishWholeCatalog(context.Background(), c, ArtifactKindTemplate, "fc-1", "inc-1", 1, catalogRows("", "tpl-fresh")); err != nil {
		t.Fatalf("publish: %v", err)
	}

	snap := func(ids ...string) capacity.Snapshot {
		return capacity.Snapshot{
			HostCPUCores: 8, HostMemoryTotalMB: 8000, CPUBudget: 8, MemoryBudgetMB: 8000,
			LocalTemplateInventoryKnown: true, LocalTemplateIDs: ids,
		}
	}
	gossipIDs := []string{"tpl-old"}
	members := []Member{
		{NodeID: "fc-1", APIURL: "http://fc-1", Alive: true, Capacity: snap(gossipIDs...)},
		{NodeID: "fc-2", APIURL: "http://fc-2", Alive: true, Capacity: snap("tpl-old")},
		{NodeID: "fc-unknown", APIURL: "http://fc-u", Alive: true, Capacity: capacity.Snapshot{
			HostCPUCores: 8, HostMemoryTotalMB: 8000, CPUBudget: 8, MemoryBudgetMB: 8000}},
	}
	req := capacity.Request{CPU: 1, MemoryMB: 100, TemplateID: "tpl-fresh"}

	if nodeFits(members[0], req, capacity.Request{}) {
		t.Fatal("precondition: gossip alone must reject the fresh template on fc-1")
	}
	got := c.withCatalogueTemplateHolders(members, req.TemplateID)

	tests := []struct {
		node string
		want bool
	}{
		{node: "fc-1", want: true},       // catalogue holder: admitted
		{node: "fc-2", want: false},      // authoritative inventory, not a holder: still rejected
		{node: "fc-unknown", want: true}, // unknown inventory: "unknown, allow" as before
	}
	byID := map[string]Member{}
	for _, m := range got {
		byID[m.NodeID] = m
	}
	for _, tc := range tests {
		if fits := nodeFits(byID[tc.node], req, capacity.Request{}); fits != tc.want {
			t.Errorf("nodeFits(%s) = %v, want %v", tc.node, fits, tc.want)
		}
	}

	// The gossip snapshot the caller passed in must not be mutated.
	if len(members[0].Capacity.LocalTemplateIDs) != 1 || len(gossipIDs) != 1 {
		t.Fatalf("input member inventory mutated: %v", members[0].Capacity.LocalTemplateIDs)
	}
	// Unknown inventory keeps its nil slice: the merge runs only for
	// authoritative lists.
	if byID["fc-unknown"].Capacity.LocalTemplateIDs != nil {
		t.Fatalf("unknown inventory gained a list: %v", byID["fc-unknown"].Capacity.LocalTemplateIDs)
	}

	// Admission re-checks the chosen owner with the same filter; with the
	// catalogue applied, the reservation placement picked must be admitted.
	spec := &models.CreateSandboxRequest{CPU: 1, MemoryMB: 100, TemplateID: "tpl-fresh"}
	res := []reservationCommand{{SandboxID: "sb-1", OwnerNodeID: "fc-1", Spec: spec}}
	if err := admitReservationCommands(members, nil, map[string]int{}, 0, res); err == nil {
		t.Fatal("precondition: admission on gossip alone must reject fc-1")
	}
	if err := admitReservationCommands(got, nil, map[string]int{}, 0, res); err != nil {
		t.Fatalf("admission with the catalogue applied rejected the holder: %v", err)
	}

	// No template, or one the catalogue doesn't know: members pass through.
	if out := c.withCatalogueTemplateHolders(members, "", "tpl-nobody"); &out[0] != &members[0] {
		t.Fatal("no holders should return the input slice untouched")
	}
}

// warmFilledWorker is the node cluster-mixed-benchmark-with-obs left behind:
// an 18-CPU budget with 17 reserved, 8 of them parked warm-pool slots its
// admitter reclaims for a real sandbox.
func warmFilledWorker(parkedCPU float64, parkedMemMB, parkedDiskGB int) Member {
	return Member{
		NodeID: "w1", APIURL: "http://w1", Role: "mixed", Alive: true,
		Capacity: capacity.Snapshot{
			HostCPUCores: 2, HostMemoryTotalMB: 7820,
			CPUBudget: 18, MemoryBudgetMB: 66470, DiskBudgetGB: 180,
			ReservedCPU: 17, ReservedMemoryMB: 17408, ReservedDiskGB: 170,
			ParkedCPU: parkedCPU, ParkedMemoryMB: parkedMemMB, ParkedDiskGB: parkedDiskGB,
			CanAdmit: true,
		},
	}
}

// Parked warm slots must not make a node look full. Counting them is what
// stopped UC-95 density at 9 sandboxes a node and sent UC-104's isolate
// creates to "capacity exceeded" on idle nodes. A peer that predates the
// Parked* fields reads as zero parked and keeps the old answer.
func TestNodeFitsTreatsParkedWarmSlotsAsFree(t *testing.T) {
	two := capacity.Request{CPU: 1, MemoryMB: 1024, DiskGB: 10}
	cases := []struct {
		name  string
		node  Member
		extra capacity.Request
		want  bool
	}{
		{"parked slots leave room", warmFilledWorker(8, 8192, 80), capacity.Request{}, true},
		{"in-flight reservations still count", warmFilledWorker(8, 8192, 80), capacity.Request{CPU: 9}, false},
		{"legacy peer without parked fields", warmFilledWorker(0, 0, 0), capacity.Request{CPU: 1}, false},
		{"parked larger than reserved floors at zero", warmFilledWorker(40, 8192, 80), capacity.Request{CPU: 17}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeFits(tc.node, two, tc.extra); got != tc.want {
				t.Fatalf("nodeFits = %v, want %v", got, tc.want)
			}
		})
	}

	// The leader's reservation check (run before the Raft propose, never in
	// FSM apply) reads the same fit, so a reservation against the node is
	// admitted rather than refused with ErrCapacityExceeded.
	err := admitReservationCommands([]Member{warmFilledWorker(8, 8192, 80)}, nil, nil, 0,
		[]reservationCommand{{SandboxID: "sb-1", OwnerNodeID: "w1"}})
	if err != nil {
		t.Fatalf("reservation against a warm-filled worker = %v, want admitted", err)
	}

	// Scoring still counts parked capacity: a node with genuinely free room
	// must outscore one that would have to give up warm slots.
	free := warmFilledWorker(0, 0, 0)
	free.Capacity.ReservedCPU, free.Capacity.ReservedMemoryMB, free.Capacity.ReservedDiskGB = 9, 9216, 90
	if headroomScore(free, two, capacity.Request{}) <= headroomScore(warmFilledWorker(8, 8192, 80), two, capacity.Request{}) {
		t.Fatal("a node with free room scored no better than one full of warm slots")
	}
}

// egressPlacementCluster is heteroPlacementCluster's shape for capability-aware
// egress placement (plans/egress-domain-filtering.md CEO D20): a control-plane
// server plus docker workers whose gateway readiness the test controls. A nil
// entry in ready models a legacy peer that omits egress_gateway_ready.
func egressPlacementCluster(ready map[string]bool) *Cluster {
	members := []Member{{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer}}
	for _, id := range []string{"worker-a", "worker-b", "worker-c"} {
		m := heteroWorker(id, []string{models.RuntimeDocker})
		m.Capacity.EgressGatewayReady = ready[id]
		members = append(members, m)
	}
	index := newGossipMemberIndex()
	index.replace(members)
	return &Cluster{
		nodeID: "server-a",
		apiURL: "http://server-a",
		fsm:    newPlacementFSM(),
		gossip: &gossipNode{memberIndex: index},
	}
}

// TestSelectPlacementRoutesGatewayModeToReadyNodes pins CEO D20: a
// hostname-filtered create (and its failover recreate, which goes through
// the same request builder) only lands on a node advertising a ready egress
// gateway, and a plain create still uses every node.
func TestSelectPlacementRoutesGatewayModeToReadyNodes(t *testing.T) {
	c := egressPlacementCluster(map[string]bool{"worker-b": true})
	gw := capacityRequestFromSpec(&models.CreateSandboxRequest{CPU: 1, MemoryMB: 100, NetworkAllowOut: []string{"pypi.org"}})
	if !gw.NeedsEgressGateway {
		t.Fatal("a hostname allow list must mark the request gateway-mode")
	}
	for i := 0; i < 200; i++ {
		target, err := c.SelectPlacement(gw)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if target.NodeID != "worker-b" {
			t.Fatalf("gateway-mode create placed on %q, want worker-b (the only ready gateway)", target.NodeID)
		}
	}
	seen := map[string]bool{}
	plain := capacityRequestFromSpec(&models.CreateSandboxRequest{CPU: 1, MemoryMB: 100, NetworkAllowOut: []string{"10.0.0.0/8"}})
	if plain.NeedsEgressGateway {
		t.Fatal("a CIDR-only allow list stays on netrules, not the gateway")
	}
	for i := 0; i < 300; i++ {
		target, err := c.SelectPlacement(plain)
		if err != nil {
			t.Fatalf("plain iter %d: %v", i, err)
		}
		seen[target.NodeID] = true
	}
	if len(seen) < 2 {
		t.Fatalf("plain creates must not be narrowed to gateway nodes, saw %v", seen)
	}
}

// TestSelectPlacementGatewayModeNoReadyNode: with no ready gateway anywhere
// (including legacy peers that never send the field), a gateway-mode create
// fails with the specific sentinel, which is still an ErrNoPlacementTarget so
// every 503 mapping holds. Never a fall back to an incapable node.
func TestSelectPlacementGatewayModeNoReadyNode(t *testing.T) {
	c := egressPlacementCluster(nil)
	req := capacity.Request{CPU: 1, MemoryMB: 100, Runtime: models.RuntimeDocker, NeedsEgressGateway: true}
	_, err := c.SelectPlacement(req)
	if !errors.Is(err, ErrNoEgressGatewayTarget) || !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("err = %v, want ErrNoEgressGatewayTarget wrapping ErrNoPlacementTarget", err)
	}
	// A cluster that is simply full answers the generic sentinel, even for a
	// gateway-mode request: the gateway was not why it failed.
	full := egressPlacementCluster(map[string]bool{"worker-a": true, "worker-b": true, "worker-c": true})
	_, err = full.SelectPlacement(capacity.Request{CPU: 999, MemoryMB: 100, Runtime: models.RuntimeDocker, NeedsEgressGateway: true})
	if !errors.Is(err, ErrNoPlacementTarget) || errors.Is(err, ErrNoEgressGatewayTarget) {
		t.Fatalf("full cluster err = %v, want plain ErrNoPlacementTarget", err)
	}
}

// TestCapacityRequestFromSpecEgressGateway covers which creates need the
// gateway: hostnames on a container runtime only. WASM and isolate filter in
// their own mediators; Firecracker joins in Phase 4; block-all redirects
// nothing; a list that doesn't compile is left to the target's 400.
func TestCapacityRequestFromSpecEgressGateway(t *testing.T) {
	cases := []struct {
		name string
		spec models.CreateSandboxRequest
		want bool
	}{
		{"docker hostname", models.CreateSandboxRequest{NetworkAllowOut: []string{"*.github.com"}}, true},
		{"gvisor hostname", models.CreateSandboxRequest{Runtime: models.RuntimeGvisor, NetworkAllowOut: []string{"pypi.org:8443"}}, true},
		{"mixed with deny cidr", models.CreateSandboxRequest{NetworkAllowOut: []string{"pypi.org"}, NetworkDenyOut: []string{"0.0.0.0/0"}}, true},
		{"wasm hostname", models.CreateSandboxRequest{Runtime: models.RuntimeWasm, NetworkAllowOut: []string{"pypi.org"}}, false},
		{"isolate hostname", models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, NetworkAllowOut: []string{"pypi.org"}}, false},
		{"firecracker hostname", models.CreateSandboxRequest{Runtime: models.RuntimeFirecracker, NetworkAllowOut: []string{"pypi.org"}}, false},
		{"block-all wins", models.CreateSandboxRequest{NetworkBlockAll: true, NetworkAllowOut: []string{"pypi.org"}}, false},
		{"cidr only", models.CreateSandboxRequest{NetworkAllowOut: []string{"10.0.0.0/8"}}, false},
		{"deny only", models.CreateSandboxRequest{NetworkDenyOut: []string{"10.0.0.0/8"}}, false},
		{"invalid", models.CreateSandboxRequest{NetworkAllowOut: []string{"bad host!"}}, false},
	}
	for _, tc := range cases {
		spec := tc.spec
		if got := capacityRequestFromSpec(&spec).NeedsEgressGateway; got != tc.want {
			t.Errorf("%s: NeedsEgressGateway = %v, want %v", tc.name, got, tc.want)
		}
	}
}
