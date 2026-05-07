package capacity

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

type fakeProbe struct {
	free int
	err  error
}

func (f fakeProbe) FreeMB() (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.free, nil
}

func TestAdmitUnderLimitsAccepts(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    0.9,
		MemoryReservationRatio: 0.85,
		MemoryFloorRatio:       0.0625, // 1024 MB on a 16384 MB host
	}, fakeProbe{free: 8000})

	if err := a.Admit("a", Request{CPU: 1, MemoryMB: 1024}); err != nil {
		t.Fatalf("admit: %v", err)
	}
	snap := a.Snapshot()
	if snap.SandboxesActive != 1 || snap.ReservedCPU != 1 || snap.ReservedMemoryMB != 1024 {
		t.Fatalf("snapshot: %+v", snap)
	}
}

// TestAdmitNoCountCap exercises the design choice that admission is
// pure-math — a host with very small per-sandbox requests should accept
// arbitrarily many sandboxes as long as CPU/memory budgets allow.
func TestAdmitNoCountCap(t *testing.T) {
	a := New(HostInfo{CPUCores: 100, MemoryTotalMB: 100_000}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	for i := range 200 {
		id := fmt.Sprintf("s-%d", i)
		// Each sandbox asks for the smallest unit that still passes ints.
		if err := a.Admit(id, Request{CPU: 0, MemoryMB: 100}); err != nil {
			t.Fatalf("admit %s: %v", id, err)
		}
	}
	if snap := a.Snapshot(); snap.SandboxesActive != 200 {
		t.Fatalf("expected 200 active, got %d", snap.SandboxesActive)
	}
}

func TestAdmitCPUReservationRatio(t *testing.T) {
	// 4 cores * 0.5 = budget of 2 CPU.
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    0.5,
		MemoryReservationRatio: 1.0,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 2, MemoryMB: 100})
	if err := a.Admit("b", Request{CPU: 1, MemoryMB: 100}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected cpu rejection, got %v", err)
	}
}

func TestAdmitMemoryReservationRatio(t *testing.T) {
	a := New(HostInfo{CPUCores: 16, MemoryTotalMB: 1000}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 0.8, // budget = 800 MB
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 1, MemoryMB: 700})
	if err := a.Admit("b", Request{CPU: 1, MemoryMB: 200}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected mem rejection, got %v", err)
	}
}

func TestAdmitMemoryFloorBlocks(t *testing.T) {
	// 2000 MB floor on a 16384 MB host = 0.122 ratio.
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		MemoryFloorRatio: 2000.0 / 16384.0,
	}, fakeProbe{free: 2500})

	// 2500 - 1000 = 1500 < 2000 floor → reject.
	err := a.Admit("a", Request{CPU: 1, MemoryMB: 1000})
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected floor rejection, got %v", err)
	}
}

func TestAdmitMemoryFloorProbeErrorAllows(t *testing.T) {
	// Probe error is treated as "unknown, allow". Otherwise a transient
	// /proc/meminfo glitch would 503 every request. Ratio of 1.0 means floor
	// equals total host memory — guaranteed to fail if probe were consulted.
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		MemoryFloorRatio: 1.0,
	}, fakeProbe{err: errors.New("probe boom")})

	if err := a.Admit("a", Request{CPU: 1, MemoryMB: 100}); err != nil {
		t.Fatalf("expected admit on probe error, got %v", err)
	}
}

func TestReleaseFreesBudget(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio: 1.0,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 4, MemoryMB: 100})
	if err := a.Admit("b", Request{CPU: 1, MemoryMB: 100}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected rejection before release, got %v", err)
	}
	a.Release("a")
	if err := a.Admit("b", Request{CPU: 1, MemoryMB: 100}); err != nil {
		t.Fatalf("expected admit after release, got %v", err)
	}
}

func TestAdmitIdempotentForSameID(t *testing.T) {
	// Re-admitting the same ID overwrites; this is what ResizeSandbox uses.
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio: 1.0,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 2, MemoryMB: 100})
	mustAdmit(t, a, "a", Request{CPU: 4, MemoryMB: 100})
	snap := a.Snapshot()
	if snap.ReservedCPU != 4 || snap.SandboxesActive != 1 {
		t.Fatalf("snapshot after re-admit: %+v", snap)
	}
}

func TestReserveBypassesAdmit(t *testing.T) {
	// Replay path must overcommit if persistent state demands it; the
	// admitter must reflect reality, not what its limits say.
	a := New(HostInfo{CPUCores: 1, MemoryTotalMB: 100}, Limits{
		CPUReservationRatio: 0.5,
	}, nil)

	a.Reserve("a", Request{CPU: 8, MemoryMB: 8000})
	a.Reserve("b", Request{CPU: 8, MemoryMB: 8000})
	snap := a.Snapshot()
	if snap.SandboxesActive != 2 || snap.ReservedCPU != 16 {
		t.Fatalf("replay should not be gated: %+v", snap)
	}
	// And the next Admit sees the overcommit.
	if err := a.Admit("c", Request{CPU: 1, MemoryMB: 1}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected rejection after replay, got %v", err)
	}
}

func TestAdmitConcurrentCorrectness(t *testing.T) {
	// 100 goroutines each try to reserve 1 CPU on a host with budget = 10.
	// Exactly 10 must succeed.
	a := New(HostInfo{CPUCores: 10, MemoryTotalMB: 1_000_000}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)

	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := string(rune('a'+i%26)) + string(rune('A'+i/26))
			if err := a.Admit(id, Request{CPU: 1, MemoryMB: 1}); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if accepted != 10 {
		t.Fatalf("expected exactly 10 accepted, got %d", accepted)
	}
}

func TestSnapshotCanAdmit(t *testing.T) {
	// Tiny host: 1 core, 100 MB, full ratios. After admitting 1 CPU + 1 MB,
	// there's no headroom for the dryRun probe ask, so CanAdmit must flip.
	a := New(HostInfo{CPUCores: 1, MemoryTotalMB: 100}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	if snap := a.Snapshot(); !snap.CanAdmit {
		t.Fatalf("empty admitter should accept: %+v", snap)
	}
	mustAdmit(t, a, "a", Request{CPU: 1, MemoryMB: 1})
	if snap := a.Snapshot(); snap.CanAdmit {
		t.Fatalf("full admitter should reject: %+v", snap)
	}
}

func mustAdmit(t *testing.T, a *Admitter, id string, req Request) {
	t.Helper()
	if err := a.Admit(id, req); err != nil {
		t.Fatalf("admit %q: %v", id, err)
	}
}
