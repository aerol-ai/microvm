package cluster

import (
	"math"
	"testing"

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

// TestNodeFitsUnknownCapacity asserts that a peer with no advertised capacity
// snapshot is treated as candidate (better to forward and be rejected by the
// remote admitter than to skip a viable node).
func TestNodeFitsUnknownCapacity(t *testing.T) {
	unknown := Member{NodeID: "u", APIURL: "http://u", Alive: true}
	if !nodeFits(unknown, capacity.Request{CPU: 1, MemoryMB: 1024}, capacity.Request{}) {
		t.Fatal("unknown-capacity node should be treated as candidate")
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

// TestNodeFitsLegacyEmptyRuntimesAllowsAny: a peer that pre-dates the
// SupportedRuntimes field (empty list, but non-zero CPU/memory so the
// "unknown capacity" early-return doesn't fire) must remain a candidate
// for any runtime — otherwise a rolling upgrade would freeze placements.
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

// TestHeadroomScoreSymmetricNeutral verifies the unknown-capacity path
// returns a neutral 0.5 score so it ties with peers that haven't reported.
func TestHeadroomScoreSymmetricNeutral(t *testing.T) {
	unknown := Member{}
	score := headroomScore(unknown, capacity.Request{CPU: 1, MemoryMB: 1024}, capacity.Request{})
	if math.Abs(score-0.5) > 1e-9 {
		t.Fatalf("expected neutral 0.5 score for unknown capacity, got %v", score)
	}
}
