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
