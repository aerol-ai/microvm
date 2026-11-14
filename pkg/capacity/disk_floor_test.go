package capacity

import (
	"errors"
	"expvar"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeDisk is a sandbox volume whose free space a test can change.
type fakeDisk struct {
	total uint64
	free  atomic.Uint64
	err   error
}

func newFakeDisk(total, free uint64) *fakeDisk {
	d := &fakeDisk{total: total}
	d.free.Store(free)
	return d
}

func (d *fakeDisk) DiskUsage() (uint64, uint64, error) {
	if d.err != nil {
		return 0, 0, d.err
	}
	return d.total, d.free.Load(), nil
}

const gib = uint64(1) << 30

// C27: new creates are refused while the sandbox volume is under the floor.
func TestDiskFloor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ratio  float64
		disk   DiskProbe // nil: no probe installed
		refuse bool
	}{
		{name: "above the floor", ratio: 0.10, disk: newFakeDisk(100*gib, 50*gib)},
		{name: "exactly at the floor admits", ratio: 0.10, disk: newFakeDisk(100*gib, 10*gib)},
		{name: "one byte under the floor refuses", ratio: 0.10, disk: newFakeDisk(100*gib, 10*gib-1), refuse: true},
		{name: "a full volume refuses", ratio: 0.10, disk: newFakeDisk(100*gib, 0), refuse: true},
		{name: "no floor: a full volume admits", ratio: 0, disk: newFakeDisk(100*gib, 0)},
		{name: "no probe: the floor is off", ratio: 0.10},
		{name: "a probe error allows", ratio: 0.10, disk: &fakeDisk{err: errors.New("statfs boom")}},
		{name: "a zero-size volume reads as unknown", ratio: 0.10, disk: newFakeDisk(0, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{DiskFloorRatio: tc.ratio}, fakeProbe{free: 16384})
			if tc.disk != nil {
				a.SetDiskProbe(tc.disk)
			}
			err := a.Admit("sb-1", Request{CPU: 1, MemoryMB: 512, DiskGB: 5})
			ok, reasons := a.CanAdmitRequest(Request{CPU: 1, MemoryMB: 512})
			if !tc.refuse {
				if err != nil || !ok {
					t.Fatalf("Admit = %v, CanAdmitRequest = %v %v; want admitted", err, ok, reasons)
				}
				return
			}
			if !errors.Is(err, ErrCapacityExceeded) || !strings.Contains(err.Error(), "disk floor breached") {
				t.Fatalf("Admit = %v, want a disk floor refusal", err)
			}
			if ok || len(reasons) != 1 || !strings.HasPrefix(reasons[0], "disk floor breached") {
				t.Fatalf("CanAdmitRequest = %v %v, want one disk floor reason", ok, reasons)
			}
			if a.Snapshot().SandboxesActive != 0 {
				t.Fatal("a refused create kept a reservation")
			}
		})
	}
}

// The floor reads the disk on every admission, so freeing space lets the
// next create in without a restart.
func TestDiskFloorIsLive(t *testing.T) {
	disk := newFakeDisk(100*gib, 5*gib)
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{DiskFloorRatio: 0.10}, nil)
	a.SetDiskProbe(disk)
	if err := a.Admit("sb-1", Request{CPU: 1}); err == nil {
		t.Fatal("admitted under the floor")
	}
	disk.free.Store(20 * gib)
	if err := a.Admit("sb-1", Request{CPU: 1}); err != nil {
		t.Fatalf("still refused after space was freed: %v", err)
	}
	a.SetDiskProbe(nil)
	disk.free.Store(0)
	if err := a.Admit("sb-2", Request{CPU: 1}); err != nil {
		t.Fatalf("refused with the probe removed: %v", err)
	}
}

// A sandbox already holding a reservation keeps it, and may resize, under
// the floor: refusing it would not stop one byte being written.
func TestDiskFloorSparesHeldReservations(t *testing.T) {
	disk := newFakeDisk(100*gib, 50*gib)
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{DiskFloorRatio: 0.10}, nil)
	a.SetDiskProbe(disk)
	if err := a.Admit("sb-1", Request{CPU: 1, MemoryMB: 512}); err != nil {
		t.Fatal(err)
	}
	disk.free.Store(1 * gib)
	if err := a.Admit("sb-1", Request{CPU: 2, MemoryMB: 1024}); err != nil {
		t.Fatalf("resize under the floor: %v", err)
	}
	if owned, err := a.AdmitOwned("sb-1", Request{CPU: 2, MemoryMB: 1024}); err != nil || owned {
		t.Fatalf("AdmitOwned of a held ID = %v %v, want kept and not owned", owned, err)
	}
	if owned, err := a.AdmitOwned("sb-2", Request{CPU: 1}); err == nil || owned {
		t.Fatalf("a new create under the floor = %v %v, want refused", owned, err)
	}
	a.Release("sb-1")
	if err := a.Admit("sb-1", Request{CPU: 1}); err == nil {
		t.Fatal("a stopped sandbox started under the floor")
	}
}

// A disk floor refusal is not a budget a warm slot can give back, so it must
// not reclaim parked slots for nothing.
func TestDiskFloorDoesNotReclaimParkedSlots(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{CPUReservationRatio: 1, DiskFloorRatio: 0.10}, nil)
	a.SetDiskProbe(newFakeDisk(100*gib, 1*gib))
	if err := a.Admit(parkReservationPrefix+"slot-1", Request{CPU: 8}); err == nil {
		t.Fatal("a park was admitted under the floor")
	}
	a.SetDiskProbe(nil)
	if err := a.Admit(parkReservationPrefix+"slot-1", Request{CPU: 8}); err != nil {
		t.Fatalf("park: %v", err)
	}
	a.SetParkReclaimable(parkReservationPrefix+"slot-1", true)
	var reclaims atomic.Int32
	a.AddParkReclaimer(func(int) int { reclaims.Add(1); return 1 })
	a.SetDiskProbe(newFakeDisk(100*gib, 1*gib))
	if err := a.Admit("sb-1", Request{CPU: 8}); err == nil {
		t.Fatal("admitted under the floor")
	}
	if n := reclaims.Load(); n != 0 {
		t.Fatalf("%d reclaims for a disk floor refusal, want 0", n)
	}
}

// The snapshot carries the floor and the volume's live numbers, says it
// cannot admit (so placement skips the node), and the gauges follow.
func TestSnapshotReportsSandboxDisk(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384, DiskFreeGB: 999}, Limits{DiskFloorRatio: 0.10}, nil)
	if snap := a.Snapshot(); snap.DiskFloorRatio != 0 || snap.SandboxDiskTotalMB != 0 || snap.SandboxDiskFreeMB != 0 {
		t.Fatalf("no probe: %+v, want the disk floor fields empty", snap)
	}

	a.SetDiskProbe(newFakeDisk(200*gib, 8*gib))
	snap := a.Snapshot()
	if snap.DiskFloorRatio != 0.10 || snap.SandboxDiskTotalMB != 200*1024 || snap.SandboxDiskFreeMB != 8*1024 {
		t.Fatalf("snapshot = ratio %v total %d free %d", snap.DiskFloorRatio, snap.SandboxDiskTotalMB, snap.SandboxDiskFreeMB)
	}
	if snap.HostDiskFreeGB != 8 {
		t.Fatalf("HostDiskFreeGB = %d, want 8 from the probe", snap.HostDiskFreeGB)
	}
	if snap.CanAdmit || len(snap.Reasons) == 0 || !strings.HasPrefix(snap.Reasons[0], "disk floor breached") {
		t.Fatalf("CanAdmit = %v %v, want a disk floor refusal", snap.CanAdmit, snap.Reasons)
	}
	if got := expvar.Get("aerolvm_host_pressure_sandbox_disk_free_mb").String(); got != "8192" {
		t.Fatalf("free gauge = %s, want 8192", got)
	}
	if got := expvar.Get("aerolvm_host_pressure_sandbox_disk_total_mb").String(); got != "204800" {
		t.Fatalf("total gauge = %s, want 204800", got)
	}

	// A probe that fails leaves the boot-time free value and no live numbers.
	a.SetDiskProbe(&fakeDisk{err: errors.New("statfs boom")})
	if snap := a.Snapshot(); snap.HostDiskFreeGB != 999 || snap.SandboxDiskTotalMB != 0 || !snap.CanAdmit {
		t.Fatalf("probe error: free %d total %d can_admit %v", snap.HostDiskFreeGB, snap.SandboxDiskTotalMB, snap.CanAdmit)
	}
}

func TestStatfsDiskProbe(t *testing.T) {
	total, free, err := NewStatfsDiskProbe(t.TempDir()).DiskUsage()
	if err != nil || total == 0 || free > total {
		t.Fatalf("DiskUsage = %d %d %v, want a real volume", total, free, err)
	}
	if _, _, err := NewStatfsDiskProbe(filepath.Join(t.TempDir(), "missing")).DiskUsage(); err == nil {
		t.Fatal("a missing path read without error")
	}
}
