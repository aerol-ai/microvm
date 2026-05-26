package cluster

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

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
		LocalTemplateIDs: []string{"tpl-a", "tpl-b", "tpl-c"},
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
		LocalTemplateIDs: []string{"tpl-a"},
	}}
	if nodeFits(cold, capacity.Request{CPU: 1, MemoryMB: 100, TemplateID: "tpl-z"}, capacity.Request{}) {
		t.Fatal("node missing the template should be rejected when inventory is non-empty")
	}
}

// TestNodeFitsTemplateUnknownAllowOnEmpty: a peer with an empty
// inventory (legacy node mid-rolling-upgrade, or just-joined node that
// hasn't reported yet) must remain a candidate. Gating here would
// strand creates on fresh clusters; the consumer-side puller is the
// safety net when the placement misses. Mirrors SupportedRuntimes'
// unknown-allow rule.
func TestNodeFitsTemplateUnknownAllowOnEmpty(t *testing.T) {
	legacy := Member{NodeID: "l", APIURL: "http://l", Alive: true, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 8000,
		CPUBudget: 8, MemoryBudgetMB: 8000,
		// LocalTemplateIDs intentionally empty
	}}
	if !nodeFits(legacy, capacity.Request{CPU: 1, MemoryMB: 100, TemplateID: "tpl-x"}, capacity.Request{}) {
		t.Fatal("legacy (empty LocalTemplateIDs) peer must accept any template")
	}
}

// TestNodeFitsNoTemplateRequestSkipsGate: a request without a template
// (a non-Firecracker create) must not be filtered by LocalTemplateIDs
// at all — empty TemplateID means "any host." Without this guard a
// docker sandbox could be falsely rejected because the peer's
// inventory doesn't list its (non-existent) template.
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
