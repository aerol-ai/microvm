package capacity

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestParkReservationID(t *testing.T) {
	if got := ParkReservationID("park-abc"); got != "park:park-abc" {
		t.Fatalf("id = %q", got)
	}
}

func TestParkGateCanParkGuardBand(t *testing.T) {
	a := New(HostInfo{CPUCores: 2, MemoryTotalMB: 2048}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	shape := dockerpool.ParkShape{
		CPU:      1,
		MemoryMB: 1024,
		Runtime:  models.RuntimeDocker,
	}
	gate := &ParkGate{
		Admitter: a,
		GuardShape: Request{
			CPU:      1,
			MemoryMB: 1024,
			Runtime:  models.RuntimeDocker,
		},
	}
	if !gate.CanPark(shape) {
		t.Fatal("expected first park to fit with guard band")
	}
	if err := gate.ParkReservation("slot-1", shape); err != nil {
		t.Fatalf("park reservation: %v", err)
	}
	if gate.CanPark(shape) {
		t.Fatal("expected guard band to block second park")
	}
	gate.ReleasePark("slot-1")
	if !gate.CanPark(shape) {
		t.Fatal("expected capacity after release")
	}
}

func TestReleaseParkReservation(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	shape := dockerpool.ParkShape{CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker}
	gate := &ParkGate{Admitter: a}
	if err := gate.ParkReservation("slot-x", shape); err != nil {
		t.Fatalf("park: %v", err)
	}
	ReleaseParkReservation(a, "slot-x")
	if snap := a.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("active = %d after transfer release", snap.SandboxesActive)
	}
}

// reclaimHost is a 4-CPU, 4 GB host with every slot of it parked: four
// warm slots of 1 CPU / 1 GB, and a reclaimer that frees them oldest first
// the way the pool does (Release, without the admitter lock held).
func reclaimHost(t *testing.T) (*Admitter, *[]int) {
	t.Helper()
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	gate := &ParkGate{Admitter: a}
	parked := []string{"s1", "s2", "s3", "s4"}
	for _, id := range parked {
		if err := gate.ParkReservation(id, dockerpool.ParkShape{CPU: 1, MemoryMB: 1024, Runtime: models.RuntimeDocker}); err != nil {
			t.Fatalf("park %s: %v", id, err)
		}
	}
	var calls []int
	a.SetParkReclaimer(func(slots int) int {
		calls = append(calls, slots)
		freed := 0
		for freed < slots && len(parked) > 0 {
			gate.ReleasePark(parked[0])
			parked = parked[1:]
			freed++
		}
		return freed
	})
	return a, &calls
}

// A host full of warm slots must still admit a real sandbox: the slots are
// speculative, and keeping them made every non-pooled create (isolate,
// gvisor, another image) fail with "cpu reservation exceeded" on an idle
// node (UC-104 on cluster-mixed-benchmark-with-obs, density 38 -> 27).
func TestAdmitReclaimsParkedSlotsForARealSandbox(t *testing.T) {
	a, calls := reclaimHost(t)

	snap := a.Snapshot()
	if snap.ParkedSlots != 4 || snap.ParkedCPU != 4 || snap.ParkedMemoryMB != 4096 {
		t.Fatalf("parked = %d slots / %.0f CPU / %d MB, want 4 / 4 / 4096", snap.ParkedSlots, snap.ParkedCPU, snap.ParkedMemoryMB)
	}
	if !snap.CanAdmit {
		t.Fatalf("a host holding only parked slots reported can_admit=false (%v): placement would skip it", snap.Reasons)
	}

	if err := a.Admit("sb-real", Request{CPU: 2, MemoryMB: 1024, Runtime: models.RuntimeDocker}); err != nil {
		t.Fatalf("Admit with parked slots to reclaim = %v", err)
	}
	if len(*calls) != 1 || (*calls)[0] != 2 {
		t.Fatalf("reclaim calls = %v, want one call for exactly the 2 slots the shortfall needs", *calls)
	}
	after := a.Snapshot()
	if after.ReservedCPU != 4 || after.ParkedSlots != 2 {
		t.Fatalf("after reclaim: reserved %.0f CPU with %d parked, want 4 CPU with 2 parked", after.ReservedCPU, after.ParkedSlots)
	}
}

func TestAdmitDoesNotReclaim(t *testing.T) {
	cases := []struct {
		name    string
		id      string
		req     Request
		wantErr bool
	}{
		{
			name: "the create fits without it",
			id:   "sb-small",
			req:  Request{CPU: 0, MemoryMB: 0, Runtime: models.RuntimeDocker},
		},
		{
			name:    "a park never reclaims another park",
			id:      ParkReservationID("s5"),
			req:     Request{CPU: 1, MemoryMB: 1024, Runtime: models.RuntimeDocker},
			wantErr: true,
		},
		{
			name:    "a non-budget failure cannot be fixed by reclaim",
			id:      "sb-gpu",
			req:     Request{CPU: 1, MemoryMB: 1024, GPUs: 1},
			wantErr: true,
		},
		{
			name:    "parked capacity is smaller than the shortfall",
			id:      "sb-huge",
			req:     Request{CPU: 5, MemoryMB: 1024, Runtime: models.RuntimeDocker},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, calls := reclaimHost(t)
			err := a.Admit(tc.id, tc.req)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Admit err = %v, wantErr %v", err, tc.wantErr)
			}
			if len(*calls) != 0 {
				t.Fatalf("reclaim called %v; it must only run for a real create that parked capacity can rescue", *calls)
			}
			if got := a.Snapshot().ParkedSlots; got != 4 {
				t.Fatalf("parked slots = %d, want all 4 kept", got)
			}
		})
	}
}

// A pool that frees nothing (every slot mid-adopt) must not loop the create.
func TestAdmitReclaimIsBounded(t *testing.T) {
	a, _ := reclaimHost(t)
	calls := 0
	a.SetParkReclaimer(func(int) int { calls++; return 0 })
	if err := a.Admit("sb-real", Request{CPU: 1, MemoryMB: 1024}); err == nil {
		t.Fatal("Admit succeeded with nothing reclaimed")
	}
	if calls != 1 {
		t.Fatalf("reclaim calls = %d, want 1 (stop as soon as the pool frees nothing)", calls)
	}

	// A pool whose freed room is taken again before the retry gets two
	// rounds, then the create fails.
	a2, _ := reclaimHost(t)
	rounds := 0
	a2.SetParkReclaimer(func(slots int) int { rounds++; return slots })
	if err := a2.Admit("sb-real", Request{CPU: 1, MemoryMB: 1024}); err == nil {
		t.Fatal("Admit succeeded although the reclaimed room was never freed")
	}
	if rounds != 2 {
		t.Fatalf("reclaim rounds = %d, want 2", rounds)
	}
}

// The refill gate must keep counting parked slots, or the pool would park
// past the budget into capacity its own slots already hold.
func TestCanAdmitRequestCountsParkedSlots(t *testing.T) {
	a, _ := reclaimHost(t)
	if ok, _ := a.CanAdmitRequest(Request{CPU: 1, MemoryMB: 1024}); ok {
		t.Fatal("CanAdmitRequest admitted into capacity parked slots hold")
	}
}

// Release and Reserve keep the parked share in step with the totals.
func TestParkedShareTracksReserveAndRelease(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{}, nil)
	a.Reserve(ParkReservationID("p1"), Request{CPU: 1, MemoryMB: 512, DiskGB: 10})
	a.Reserve(ParkReservationID("p1"), Request{CPU: 2, MemoryMB: 512, DiskGB: 10}) // re-reserve replaces
	a.Reserve("sb-1", Request{CPU: 1, MemoryMB: 256})
	snap := a.Snapshot()
	if snap.ParkedSlots != 1 || snap.ParkedCPU != 2 || snap.ParkedDiskGB != 10 || snap.ReservedCPU != 3 {
		t.Fatalf("snapshot = parked %d/%.0f CPU/%d GB, reserved %.0f CPU", snap.ParkedSlots, snap.ParkedCPU, snap.ParkedDiskGB, snap.ReservedCPU)
	}
	a.Release(ParkReservationID("p1"))
	a.Release("sb-1")
	if snap := a.Snapshot(); snap.ParkedSlots != 0 || snap.ParkedCPU != 0 || snap.ReservedCPU != 0 {
		t.Fatalf("after release: parked %d / %.0f CPU, reserved %.0f CPU, want all zero", snap.ParkedSlots, snap.ParkedCPU, snap.ReservedCPU)
	}
}
