package capacity

import (
	"testing"
)

func TestDryRunRejectsDiskGPUAndRSS(t *testing.T) {
	rss := fakeRSS{total: 9000, ready: true}
	a := NewWithRSSSource(
		HostInfo{CPUCores: 8, MemoryTotalMB: 10000, DiskTotalGB: 10, GPUCount: 1, GPUVendor: "nvidia"},
		Limits{
			CPUReservationRatio:    1.0,
			MemoryReservationRatio: 1.0,
			DiskReservationRatio:   1.0,
			RSSWatermarkRatio:      0.5,
		},
		fakeProbe{free: 100},
		rss,
	)
	a.Reserve("full", Request{CPU: 8, MemoryMB: 9000, DiskGB: 10, GPUs: 1})

	snap := a.Snapshot()
	if snap.CanAdmit {
		t.Fatalf("expected CanAdmit=false on saturated host, got %+v", snap)
	}
	if len(snap.Reasons) == 0 {
		t.Fatal("expected rejection reasons")
	}
}

func TestDryRunRejectsRuntimeAndGPUVendor(t *testing.T) {
	a := New(
		HostInfo{CPUCores: 4, MemoryTotalMB: 4096, GPUCount: 2, GPUVendor: "nvidia", SupportedRuntimes: []string{"docker"}},
		Limits{CPUReservationRatio: 1.0, MemoryReservationRatio: 1.0},
		nil,
	)
	can, reasons := a.dryRun(Request{Runtime: "wasm", GPUs: 1, GPUVendor: "amd"})
	if can || len(reasons) < 2 {
		t.Fatalf("dryRun = (%v, %v), want false with runtime + vendor reasons", can, reasons)
	}
}

func TestDryRunMemoryFloorRejects(t *testing.T) {
	a := New(
		HostInfo{CPUCores: 4, MemoryTotalMB: 4096},
		Limits{CPUReservationRatio: 1.0, MemoryReservationRatio: 1.0, MemoryFloorRatio: 0.5},
		fakeProbe{free: 1000},
	)
	can, reasons := a.dryRun(Request{CPU: 0.1, MemoryMB: 500})
	if can {
		t.Fatalf("dryRun should reject when free-memory floor breached: %v", reasons)
	}
}

func TestBytesToGBAndDetectDiskGB(t *testing.T) {
	if got := bytesToGB(0); got != 0 {
		t.Fatalf("bytesToGB(0) = %d, want 0", got)
	}
	if got := bytesToGB(512 * 1024 * 1024); got != 1 {
		t.Fatalf("bytesToGB(half GiB) = %d, want 1", got)
	}
	if got := bytesToGB(5 * 1024 * 1024 * 1024); got != 5 {
		t.Fatalf("bytesToGB(5GiB) = %d, want 5", got)
	}

	total, free, err := detectDiskGB("/")
	if err != nil {
		t.Fatalf("detectDiskGB(/): %v", err)
	}
	if total <= 0 || free < 0 {
		t.Fatalf("detectDiskGB returned total=%d free=%d", total, free)
	}

	if _, _, err := detectDiskGB(""); err != nil {
		t.Fatalf("detectDiskGB empty path: %v", err)
	}

	_ = defaultDiskPath()
}
