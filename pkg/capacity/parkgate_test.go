package capacity

import (
	"context"
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

// parkedHost is a 4-CPU, 4 GB host with every slot of it parked: four warm
// slots of 1 CPU / 1 GB, each marked ready the way its pool does once the
// container is up.
func parkedHost(t *testing.T) (*Admitter, *ParkGate, *[]string) {
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
		gate.MarkParkReady(id, true)
	}
	return a, gate, &parked
}

// reclaimHost adds a reclaimer that frees ready slots oldest first, the way
// the pool does (Release, without the admitter lock held).
func reclaimHost(t *testing.T) (*Admitter, *[]int) {
	t.Helper()
	a, gate, parked := parkedHost(t)
	var calls []int
	a.AddParkReclaimer(func(slots int) int {
		calls = append(calls, slots)
		freed := 0
		for freed < slots && len(*parked) > 0 {
			gate.ReleasePark((*parked)[0])
			*parked = (*parked)[1:]
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
	a, _, _ := parkedHost(t)
	calls := 0
	a.AddParkReclaimer(func(int) int { calls++; return 0 })
	if err := a.Admit("sb-real", Request{CPU: 1, MemoryMB: 1024}); err == nil {
		t.Fatal("Admit succeeded with nothing reclaimed")
	}
	if calls != 1 {
		t.Fatalf("reclaim calls = %d, want 1 (stop as soon as the pool frees nothing)", calls)
	}

	// A pool whose freed room is taken again before the retry gets two
	// rounds, then the create fails.
	a2, _, _ := parkedHost(t)
	rounds := 0
	a2.AddParkReclaimer(func(slots int) int { rounds++; return slots })
	if err := a2.Admit("sb-real", Request{CPU: 1, MemoryMB: 1024}); err == nil {
		t.Fatal("Admit succeeded although the reclaimed room was never freed")
	}
	if rounds != 2 {
		t.Fatalf("reclaim rounds = %d, want 2", rounds)
	}
}

// Two pools on one admitter (the docker pool is not gated on the engine): the
// second must still be asked when the first has nothing to give, or the
// first pool registered silently owns reclaim and the other's slots, still
// reported to placement as free, refuse every create sent to the node.
func TestAdmitAsksEveryReclaimer(t *testing.T) {
	a, gate, parked := parkedHost(t)
	var asked []string
	a.AddParkReclaimer(func(int) int { asked = append(asked, "empty"); return 0 })
	a.AddParkReclaimer(func(slots int) int {
		asked = append(asked, "full")
		gate.ReleasePark((*parked)[0])
		*parked = (*parked)[1:]
		return 1
	})
	if err := a.Admit("sb-real", Request{CPU: 1, MemoryMB: 1024}); err != nil {
		t.Fatalf("Admit = %v, want the second pool to free a slot", err)
	}
	if len(asked) != 2 || asked[0] != "empty" || asked[1] != "full" {
		t.Fatalf("reclaimers asked = %v, want both in order", asked)
	}
}

// Only a slot ready in its pool is reclaimable. One still spawning (its park
// reservation is taken before the container starts) or acquired by a create
// that is adopting it cannot be freed, so it must count as used, not as the
// free room placement would send a create to.
func TestParkedShareCountsOnlyReadySlots(t *testing.T) {
	a := New(HostInfo{CPUCores: 2, MemoryTotalMB: 2048}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	gate := &ParkGate{Admitter: a}
	shape := dockerpool.ParkShape{CPU: 1, MemoryMB: 1024, Runtime: models.RuntimeDocker}
	for _, id := range []string{"spawning", "ready"} {
		if err := gate.ParkReservation(id, shape); err != nil {
			t.Fatalf("park %s: %v", id, err)
		}
	}
	gate.MarkParkReady("ready", true)
	gate.MarkParkReady("ready", true) // a repeated notice changes nothing
	if snap := a.Snapshot(); snap.ParkedSlots != 1 || snap.ParkedCPU != 1 || snap.ReservedCPU != 2 {
		t.Fatalf("parked %d / %.0f CPU of %.0f reserved, want 1 / 1 of 2", snap.ParkedSlots, snap.ParkedCPU, snap.ReservedCPU)
	}

	// Acquired for adoption: no longer reclaimable.
	gate.MarkParkReady("ready", false)
	if snap := a.Snapshot(); snap.ParkedSlots != 0 || snap.CanAdmit {
		t.Fatalf("after acquire: parked %d, can_admit %v; want 0 and a full host", snap.ParkedSlots, snap.CanAdmit)
	}

	// A notice for a slot already released, or for a non-park ID, is ignored.
	gate.ReleasePark("spawning")
	gate.MarkParkReady("spawning", true)
	a.SetParkReclaimable("sb-1", true)
	if snap := a.Snapshot(); snap.ParkedSlots != 0 || snap.ReservedCPU != 1 {
		t.Fatalf("stale notices moved the books: parked %d, reserved %.0f", snap.ParkedSlots, snap.ReservedCPU)
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

// Release and re-Reserve keep the parked share in step with the totals.
func TestParkedShareTracksReserveAndRelease(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{}, nil)
	a.Reserve(ParkReservationID("p1"), Request{CPU: 1, MemoryMB: 512, DiskGB: 10})
	a.SetParkReclaimable(ParkReservationID("p1"), true)
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
	// A slot re-parked under the same ID starts out not ready.
	a.Reserve(ParkReservationID("p1"), Request{CPU: 1})
	if got := a.Snapshot().ParkedSlots; got != 0 {
		t.Fatalf("a released slot's ready state survived: parked %d", got)
	}
}

// End to end with the real pool: refill-shaped parks, the pool's notifier
// and reclaimer wired as pkg/daemon does, and a real create that only fits by
// reclaiming. The acquired slot is skipped, and the pool shrinks by exactly
// what admission took.
func TestAdmitReclaimsFromARealPool(t *testing.T) {
	a := New(HostInfo{CPUCores: 3, MemoryTotalMB: 3072}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	gate := &ParkGate{Admitter: a}
	pool := dockerpool.New(nil)
	pool.SetDefaultDepth(3)
	pool.SetParkReleaser(gate.ReleasePark)
	pool.SetParkReadyNotifier(gate.MarkParkReady)
	a.AddParkReclaimer(pool.Reclaim)

	key := dockerpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker}
	pool.NoteTarget(key)
	shape := dockerpool.ParkShape{CPU: 1, MemoryMB: 1024, Runtime: models.RuntimeDocker}
	for _, id := range []string{"p1", "p2", "p3"} {
		if err := gate.ParkReservation(id, shape); err != nil {
			t.Fatalf("park %s: %v", id, err)
		}
		pool.RecordLoaded(&dockerpool.ParkedSlot{ID: id, Key: key, Handle: aliveHandle{}})
	}
	// One slot is mid-adopt: acquired, its reservation not yet transferred.
	acquired, err := pool.Acquire(context.Background(), key, "")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if snap := a.Snapshot(); snap.ParkedSlots != 2 || snap.ReservedCPU != 3 {
		t.Fatalf("parked %d of %.0f reserved, want 2 ready of 3", snap.ParkedSlots, snap.ReservedCPU)
	}

	if err := a.Admit("sb-real", Request{CPU: 2, MemoryMB: 2048}); err != nil {
		t.Fatalf("Admit = %v, want both ready slots reclaimed", err)
	}
	if pool.HasReady(key) {
		t.Fatal("the pool still holds a ready slot it should have given up")
	}
	if snap := a.Snapshot(); snap.ReservedCPU != 3 || snap.ParkedSlots != 0 {
		t.Fatalf("after reclaim: reserved %.0f CPU, parked %d; want the sandbox's 2 plus the acquired slot's 1", snap.ReservedCPU, snap.ParkedSlots)
	}
	ReleaseParkReservation(a, acquired.ID) // the adopt completes
	if snap := a.Snapshot(); snap.ReservedCPU != 2 {
		t.Fatalf("after adopt: reserved %.0f CPU, want 2", snap.ReservedCPU)
	}
}

type aliveHandle struct{}

func (aliveHandle) Alive() bool                                         { return true }
func (aliveHandle) Adopt(context.Context, string, string, string) error { return nil }
func (aliveHandle) Close() error                                        { return nil }
