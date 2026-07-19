package capacity

import (
	"errors"
	"fmt"
	"strings"
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

func TestSnapshotPublishesHostPressureMetrics(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096, DiskTotalGB: 100, GPUCount: 2}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		DiskReservationRatio:   1.0,
	}, fakeProbe{free: 2048})
	a.Reserve("sb-pressure", Request{CPU: 1.5, MemoryMB: 512, DiskGB: 10, GPUs: 1})

	snap := a.Snapshot()
	if snap.ReservedGPUs != 1 {
		t.Fatalf("ReservedGPUs = %d, want 1", snap.ReservedGPUs)
	}
	if got := hostPressureSandboxes.Value(); got != 1 {
		t.Fatalf("host pressure sandboxes = %d, want 1", got)
	}
	if got := hostPressureReservedCPU.Value(); got != 1500 {
		t.Fatalf("reserved cpu millicores = %d, want 1500", got)
	}
	if got := hostPressureReservedMemory.Value(); got != 512 {
		t.Fatalf("reserved memory = %d, want 512", got)
	}
	if got := hostPressureReservedGPUs.Value(); got != 1 {
		t.Fatalf("reserved gpus = %d, want 1", got)
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

// TestAdmitFractionalCPU exercises the design choice that CPU is fractional
// — eight 0.5-core sandboxes on a 4-core host with full ratio fits exactly,
// the ninth must be rejected.
func TestAdmitFractionalCPU(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)

	for i := range 8 {
		id := fmt.Sprintf("s-%d", i)
		if err := a.Admit(id, Request{CPU: 0.5, MemoryMB: 1}); err != nil {
			t.Fatalf("admit %s: %v", id, err)
		}
	}
	if err := a.Admit("overflow", Request{CPU: 0.1, MemoryMB: 1}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected fractional overflow rejection, got %v", err)
	}
	if snap := a.Snapshot(); snap.ReservedCPU != 4.0 {
		t.Fatalf("ReservedCPU = %v, want 4.0", snap.ReservedCPU)
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

// TestAdmitCPUOverProvisionFactor verifies the factor multiplies the budget.
// 4 cores × 1.0 ratio × 10× factor = 40 CPU budget — twenty 2-CPU sandboxes
// must fit, the twenty-first overflows.
func TestAdmitCPUOverProvisionFactor(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 1_000_000}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		CPUOverProvisionFactor: 10.0,
	}, nil)

	for i := range 20 {
		id := fmt.Sprintf("s-%d", i)
		if err := a.Admit(id, Request{CPU: 2, MemoryMB: 1}); err != nil {
			t.Fatalf("admit %s: %v", id, err)
		}
	}
	if err := a.Admit("overflow", Request{CPU: 0.1, MemoryMB: 1}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected overcommit ceiling, got %v", err)
	}
	snap := a.Snapshot()
	if snap.CPUBudget != 40 {
		t.Fatalf("CPUBudget = %v, want 40", snap.CPUBudget)
	}
	if snap.CPUOverProvisionFactor != 10.0 {
		t.Fatalf("CPUOverProvisionFactor = %v, want 10", snap.CPUOverProvisionFactor)
	}
}

// TestAdmitMemoryOverProvisionFactor mirrors the CPU test for memory.
func TestAdmitMemoryOverProvisionFactor(t *testing.T) {
	a := New(HostInfo{CPUCores: 1000, MemoryTotalMB: 1000}, Limits{
		CPUReservationRatio:       1.0,
		MemoryReservationRatio:    1.0,
		MemoryOverProvisionFactor: 10.0,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 1, MemoryMB: 9000})
	mustAdmit(t, a, "b", Request{CPU: 1, MemoryMB: 1000})
	if err := a.Admit("c", Request{CPU: 1, MemoryMB: 1}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected overcommit ceiling, got %v", err)
	}
}

// TestOverProvisionFactorClampedToOne checks the zero/sub-1 clamp so existing
// callers (and tests) that don't set the factor keep prior behaviour.
func TestOverProvisionFactorClampedToOne(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 1000}, Limits{
		CPUReservationRatio:       1.0,
		MemoryReservationRatio:    1.0,
		CPUOverProvisionFactor:    0,   // unset
		MemoryOverProvisionFactor: 0.5, // sub-1, must clamp up
	}, nil)
	snap := a.Snapshot()
	if snap.CPUBudget != 4 || snap.MemoryBudgetMB != 1000 {
		t.Fatalf("clamp failed: %+v", snap)
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

// TestReleaseUnknownIDIsNoOp pins down the contract used by every Release
// call site (Stop, Destroy, die-event, reconcile-stopped-branch): release on
// an ID that was never reserved must be a silent no-op, not a panic or a
// negative-counter corruption. Without this the lifecycle code would have to
// guard every Release with a "did we Admit?" check.
func TestReleaseUnknownIDIsNoOp(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)

	a.Release("never-existed")
	snap := a.Snapshot()
	if snap.SandboxesActive != 0 || snap.ReservedCPU != 0 || snap.ReservedMemoryMB != 0 {
		t.Fatalf("release of unknown id mutated state: %+v", snap)
	}
}

// TestReleaseIdempotent: two Releases of the same ID must leave the admitter
// in the post-first-release state. Stop → die event will both fire Release
// in normal operation.
func TestReleaseIdempotent(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 2, MemoryMB: 1024})
	a.Release("a")
	a.Release("a") // second release is the regression — must not double-subtract
	snap := a.Snapshot()
	if snap.SandboxesActive != 0 || snap.ReservedCPU != 0 || snap.ReservedMemoryMB != 0 {
		t.Fatalf("double release corrupted state: %+v", snap)
	}
	// And the freed budget is fully reusable.
	mustAdmit(t, a, "b", Request{CPU: 4, MemoryMB: 4000})
}

// TestReserveOverwritesPriorReserve covers the replay → out-of-band-start
// path. ReplayReservations sets initial state; if a sandbox then comes back
// online with different specs (resize-while-stopped is a future feature, but
// the safety property must hold today), the second Reserve must overwrite, not
// stack.
func TestReserveOverwritesPriorReserve(t *testing.T) {
	a := New(HostInfo{CPUCores: 16, MemoryTotalMB: 32_000}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)

	a.Reserve("a", Request{CPU: 2, MemoryMB: 1024})
	a.Reserve("a", Request{CPU: 8, MemoryMB: 16_000})
	snap := a.Snapshot()
	if snap.SandboxesActive != 1 {
		t.Fatalf("Reserve must overwrite, got %d active", snap.SandboxesActive)
	}
	if snap.ReservedCPU != 8 || snap.ReservedMemoryMB != 16_000 {
		t.Fatalf("Reserve overwrite footprint wrong: %+v", snap)
	}
}

// TestAdmitFailurePreservesPriorReservation: a rejected Admit must leave the
// existing reservation intact. The bug we'd see otherwise is a resize that
// fails to fit and silently zeroes out the original CPU/mem booking, which
// would then let a *third* sandbox slip in over the host budget.
func TestAdmitFailurePreservesPriorReservation(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 2, MemoryMB: 1024})
	// Re-admit asking for the entire host; with one slot already reserved this
	// must fail.
	if err := a.Admit("a", Request{CPU: 8, MemoryMB: 8192}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected re-admit overflow, got %v", err)
	}
	snap := a.Snapshot()
	if snap.SandboxesActive != 1 || snap.ReservedCPU != 2 || snap.ReservedMemoryMB != 1024 {
		t.Fatalf("rejected re-admit corrupted prior reservation: %+v", snap)
	}
}

// TestAdmitDownsizeReleasesDelta: re-Admit with a *smaller* footprint must
// give back the difference so the freed budget is immediately admittable.
// Mirror image of TestAdmitFailurePreservesPriorReservation but for the
// success branch.
func TestAdmitDownsizeReleasesDelta(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 4, MemoryMB: 4096})
	// Now host is fully reserved by "a". Downsize "a" and admit a second.
	mustAdmit(t, a, "a", Request{CPU: 1, MemoryMB: 1024})
	mustAdmit(t, a, "b", Request{CPU: 3, MemoryMB: 3072})
	snap := a.Snapshot()
	if snap.SandboxesActive != 2 || snap.ReservedCPU != 4 || snap.ReservedMemoryMB != 4096 {
		t.Fatalf("downsize delta accounting wrong: %+v", snap)
	}
}

// TestAdmitUpsizeOverflowKeepsOriginal pairs with Downsize: an upsize that
// pushes total over budget must reject AND leave the original reservation
// untouched (no half-applied state).
func TestAdmitUpsizeOverflowKeepsOriginal(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 2, MemoryMB: 1024})
	mustAdmit(t, a, "b", Request{CPU: 2, MemoryMB: 1024})
	// Host is at 4 CPU / 2048 MB. Upsizing "a" by 1 CPU would put us at 5 — reject.
	if err := a.Admit("a", Request{CPU: 3, MemoryMB: 1024}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected upsize overflow, got %v", err)
	}
	snap := a.Snapshot()
	if snap.SandboxesActive != 2 || snap.ReservedCPU != 4 || snap.ReservedMemoryMB != 2048 {
		t.Fatalf("upsize-overflow leaked state: %+v", snap)
	}
}

// TestMemoryFloorDisabledWhenRatioZero: the floor check must short-circuit
// on the zero-ratio config even if a probe is wired in. Useful so test setups
// that don't care about the floor don't accidentally trigger it.
func TestMemoryFloorDisabledWhenRatioZero(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		MemoryFloorRatio:       0,
	}, fakeProbe{free: 0}) // probe says zero free; admit must still succeed

	if err := a.Admit("a", Request{CPU: 1, MemoryMB: 1024}); err != nil {
		t.Fatalf("floor=0 should bypass probe entirely, got %v", err)
	}
}

// TestMemoryFloorExactBoundary: free-req == floor must reject. The condition
// is `free-req < floor`, so equality is the boundary case the operator
// expects to *pass*.
func TestMemoryFloorExactBoundary(t *testing.T) {
	// Floor: 1000 MB on a 16384 MB host = ~0.061.
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		MemoryFloorRatio: 1000.0 / 16384.0,
	}, fakeProbe{free: 1500})

	// 1500 - 500 = 1000 — exactly at floor, must NOT reject.
	if err := a.Admit("a", Request{CPU: 1, MemoryMB: 500}); err != nil {
		t.Fatalf("admit at exact floor boundary rejected: %v", err)
	}
	a.Release("a")
	// 1500 - 501 = 999 — below floor, must reject.
	if err := a.Admit("a", Request{CPU: 1, MemoryMB: 501}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("admit one MB below floor accepted: %v", err)
	}
}

// TestSnapshotReportsBudgetAndFloor: operators rely on /capacity to debug
// "why was I rejected." The snapshot must surface the derived budgets and
// floor the admitter uses internally.
func TestSnapshotReportsBudgetAndFloor(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 10_000}, Limits{
		CPUReservationRatio:       0.5,
		MemoryReservationRatio:    0.8,
		MemoryFloorRatio:          0.1, // 1000 MB
		CPUOverProvisionFactor:    2.0,
		MemoryOverProvisionFactor: 1.5,
	}, fakeProbe{free: 5000})

	snap := a.Snapshot()
	if snap.CPUBudget != 8*0.5*2.0 {
		t.Fatalf("CPUBudget = %v, want %v", snap.CPUBudget, 8*0.5*2.0)
	}
	if snap.MemoryBudgetMB != int(float64(10_000)*0.8*1.5) {
		t.Fatalf("MemoryBudgetMB = %d, want %d", snap.MemoryBudgetMB, int(float64(10_000)*0.8*1.5))
	}
	if snap.MemoryFloorMB != 1000 {
		t.Fatalf("MemoryFloorMB = %d, want 1000", snap.MemoryFloorMB)
	}
	if snap.LiveMemoryFreeMB != 5000 {
		t.Fatalf("LiveMemoryFreeMB = %d, want 5000 (probe value)", snap.LiveMemoryFreeMB)
	}
}

// TestZeroReservationRatiosAreUnlimited: documented contract for the zero
// values of CPUReservationRatio and MemoryReservationRatio. With both at zero
// every Admit must succeed regardless of host size — this is what hosted
// development setups use to disable admission entirely.
func TestZeroReservationRatiosAreUnlimited(t *testing.T) {
	a := New(HostInfo{CPUCores: 1, MemoryTotalMB: 100}, Limits{
		CPUReservationRatio:    0,
		MemoryReservationRatio: 0,
	}, nil)

	for i := range 50 {
		id := fmt.Sprintf("s-%d", i)
		if err := a.Admit(id, Request{CPU: 100, MemoryMB: 1_000_000}); err != nil {
			t.Fatalf("admit %s on unlimited admitter: %v", id, err)
		}
	}
}

// TestReleaseIsolatedBetweenSandboxes: releasing one sandbox must not affect
// the reservation of another, even when both have identical CPU/mem footprints.
// Map-based Release means this should be obvious, but it pins down the
// invariant the lifecycle code depends on.
func TestReleaseIsolatedBetweenSandboxes(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 1, MemoryMB: 1024})
	mustAdmit(t, a, "b", Request{CPU: 1, MemoryMB: 1024})
	mustAdmit(t, a, "c", Request{CPU: 1, MemoryMB: 1024})

	a.Release("b")
	snap := a.Snapshot()
	if snap.SandboxesActive != 2 {
		t.Fatalf("Release of b leaked: %+v", snap)
	}
	if snap.ReservedCPU != 2 || snap.ReservedMemoryMB != 2048 {
		t.Fatalf("Release accounting wrong after isolating b: %+v", snap)
	}
	// The freed slot is exactly b-sized; refilling it brings us back to 3 reservations
	// at 3/4 cores, then the next request must respect the remaining budget.
	mustAdmit(t, a, "d", Request{CPU: 1, MemoryMB: 1024})
	if err := a.Admit("e", Request{CPU: 2, MemoryMB: 1024}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected CPU rejection, only 1 core free: %v", err)
	}
}

// TestAdmitDiskReservationRatio mirrors the CPU/memory budget test: a host
// with a 100 GB declared disk and 0.8 ratio rejects beyond 80 GB total
// reservation. Without this, the placement scheduler can ship a sandbox to
// a peer that physically can't hold its --storage-opt size.
func TestAdmitDiskReservationRatio(t *testing.T) {
	a := New(HostInfo{CPUCores: 16, MemoryTotalMB: 16384, DiskTotalGB: 100}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		DiskReservationRatio:   0.8,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 1, MemoryMB: 100, DiskGB: 50})
	mustAdmit(t, a, "b", Request{CPU: 1, MemoryMB: 100, DiskGB: 30})
	if err := a.Admit("c", Request{CPU: 1, MemoryMB: 100, DiskGB: 1}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected disk rejection at 81 GB on 80 GB budget, got %v", err)
	}
	a.Release("a")
	mustAdmit(t, a, "c", Request{CPU: 1, MemoryMB: 100, DiskGB: 50})
}

// TestAdmitDiskDisabledWhenRatioZero: matches the existing zero-ratio
// contract for CPU/memory. With DiskReservationRatio=0 the admitter must
// not reject even when DiskGB is huge — operators that don't opt in keep
// today's "no disk admission" behavior.
func TestAdmitDiskDisabledWhenRatioZero(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 8000, DiskTotalGB: 10}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		// DiskReservationRatio: 0
	}, nil)
	if err := a.Admit("a", Request{CPU: 1, MemoryMB: 100, DiskGB: 1_000_000}); err != nil {
		t.Fatalf("disk ratio=0 must bypass disk check, got %v", err)
	}
}

// TestAdmitGPURejectsWhenHostHasNone exercises the contract that placement
// scheduling depends on: a GPU sandbox forwarded to a GPU-less node will
// 503, so the placement layer (and the local admitter as the source-of-
// truth) must say no.
func TestAdmitGPURejectsWhenHostHasNone(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 8000}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	err := a.Admit("a", Request{CPU: 1, MemoryMB: 100, GPUs: 1, GPUVendor: "nvidia"})
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected GPU rejection on GPU-less host, got %v", err)
	}
}

// TestAdmitGPUVendorMismatch: a host advertising AMD must reject a sandbox
// asking for NVIDIA. Otherwise placement will land an NVIDIA sandbox on an
// AMD node where docker --gpus would surface a confusing low-level error.
func TestAdmitGPUVendorMismatch(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 8000, GPUCount: 4, GPUVendor: "amd"}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	err := a.Admit("a", Request{CPU: 1, MemoryMB: 100, GPUs: 1, GPUVendor: "nvidia"})
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected GPU vendor mismatch rejection, got %v", err)
	}
	if err := a.Admit("a", Request{CPU: 1, MemoryMB: 100, GPUs: 1, GPUVendor: "amd"}); err != nil {
		t.Fatalf("matching vendor must admit, got %v", err)
	}
}

// TestAdmitGPUExhaustsCount tracks reservations: on a 2-GPU host the third
// 1-GPU sandbox must be rejected, then accepted once a slot is released.
func TestAdmitGPUExhaustsCount(t *testing.T) {
	a := New(HostInfo{CPUCores: 16, MemoryTotalMB: 16000, GPUCount: 2, GPUVendor: "nvidia"}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	mustAdmit(t, a, "a", Request{CPU: 1, MemoryMB: 100, GPUs: 1, GPUVendor: "nvidia"})
	mustAdmit(t, a, "b", Request{CPU: 1, MemoryMB: 100, GPUs: 1, GPUVendor: "nvidia"})
	if err := a.Admit("c", Request{CPU: 1, MemoryMB: 100, GPUs: 1, GPUVendor: "nvidia"}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected GPU exhaustion, got %v", err)
	}
	a.Release("a")
	mustAdmit(t, a, "c", Request{CPU: 1, MemoryMB: 100, GPUs: 1, GPUVendor: "nvidia"})
}

// TestAdmitRuntimeUnsupported: a host that advertises only "docker" must
// reject a request asking for "gvisor". Empty SupportedRuntimes (legacy
// peer / pre-D snapshot) is a separate test because that is "any allowed."
func TestAdmitRuntimeUnsupported(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 8000, SupportedRuntimes: []string{"docker"}}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	err := a.Admit("a", Request{CPU: 1, MemoryMB: 100, Runtime: "gvisor"})
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected runtime rejection, got %v", err)
	}
	if err := a.Admit("a", Request{CPU: 1, MemoryMB: 100, Runtime: "docker"}); err != nil {
		t.Fatalf("supported runtime must admit, got %v", err)
	}
}

// TestRuntimeUnsupportedSurfacesHostList: the rejection reason must echo the
// declared SupportedRuntimes so an operator debugging "why was my gvisor
// sandbox 503'd" can see "this host only has [docker]" in the response.
func TestRuntimeUnsupportedSurfacesHostList(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 8000, SupportedRuntimes: []string{"docker"}}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)
	err := a.Admit("a", Request{CPU: 1, MemoryMB: 100, Runtime: "gvisor"})
	if err == nil || !strings.Contains(err.Error(), `"gvisor"`) || !strings.Contains(err.Error(), "docker") {
		t.Fatalf("rejection message must mention requested + supported runtimes, got %v", err)
	}
}

// TestEmptySupportedRuntimesAllowsAny pins the rolling-upgrade contract: a
// snapshot from a peer that pre-dates SupportedRuntimes must not have its
// placements skipped. New(host) defaults the field to ["docker"], but Admit
// itself uses runtimeSupported which returns true on empty for callers that
// build an Admitter directly with an empty list — important for tests and
// for runtime metadata wired in from raw gossip after JSON round-trip.
func TestEmptySupportedRuntimesAllowsAny(t *testing.T) {
	a := &Admitter{
		host:         HostInfo{CPUCores: 8, MemoryTotalMB: 8000},
		limits:       Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		reservations: map[string]Request{},
	}
	if err := a.Admit("a", Request{CPU: 1, MemoryMB: 100, Runtime: "anything"}); err != nil {
		t.Fatalf("empty SupportedRuntimes must allow any runtime, got %v", err)
	}
}

// TestNewDefaultsSupportedRuntimes verifies the docker default applied when
// the operator doesn't set SB_HOST_RUNTIMES — without this default, the
// first build that flips the gate would 503 every gvisor request even on
// hosts that have always supported docker.
func TestNewDefaultsSupportedRuntimes(t *testing.T) {
	a := New(HostInfo{CPUCores: 1, MemoryTotalMB: 100}, Limits{}, nil)
	snap := a.Snapshot()
	if len(snap.SupportedRuntimes) != 1 || snap.SupportedRuntimes[0] != "docker" {
		t.Fatalf("expected default [docker], got %v", snap.SupportedRuntimes)
	}
}

// TestSnapshotReportsDiskGPURuntime: placement scoring on a peer reads these
// fields off capacity heartbeats, so they must round-trip through Snapshot
// accurately.
func TestSnapshotReportsDiskGPURuntime(t *testing.T) {
	a := New(HostInfo{
		CPUCores: 8, MemoryTotalMB: 8000,
		DiskTotalGB:       200,
		GPUCount:          4,
		GPUVendor:         "nvidia",
		SupportedRuntimes: []string{"docker", "gvisor"},
	}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		DiskReservationRatio:   0.5, // budget = 100 GB
	}, nil)
	mustAdmit(t, a, "a", Request{CPU: 1, MemoryMB: 100, DiskGB: 30, GPUs: 2, GPUVendor: "nvidia"})

	snap := a.Snapshot()
	if snap.HostDiskTotalGB != 200 || snap.DiskBudgetGB != 100 || snap.ReservedDiskGB != 30 {
		t.Fatalf("disk fields wrong: %+v", snap)
	}
	if snap.AvailableDiskGB != 70 {
		t.Fatalf("AvailableDiskGB = %d, want 70", snap.AvailableDiskGB)
	}
	if snap.AvailableCPU != 7 || snap.AvailableMemoryMB != 7900 || snap.AvailableGPUs != 2 {
		t.Fatalf("available fields wrong: %+v", snap)
	}
	if snap.GPUCount != 4 || snap.GPUVendor != "nvidia" {
		t.Fatalf("gpu inventory wrong: %+v", snap)
	}
	if len(snap.SupportedRuntimes) != 2 {
		t.Fatalf("runtimes wrong: %+v", snap.SupportedRuntimes)
	}
}

// TestSnapshotIsPointInTime: Snapshot() returns a copy, not a live view —
// later mutations on the admitter must not affect a previously-captured
// Snapshot. /capacity callers depend on this for stable response bodies.
func TestSnapshotIsPointInTime(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
	}, nil)

	mustAdmit(t, a, "a", Request{CPU: 1, MemoryMB: 1024})
	before := a.Snapshot()

	mustAdmit(t, a, "b", Request{CPU: 2, MemoryMB: 2048})
	a.Release("a")

	if before.SandboxesActive != 1 || before.ReservedCPU != 1 || before.ReservedMemoryMB != 1024 {
		t.Fatalf("captured snapshot mutated by later ops: %+v", before)
	}
	now := a.Snapshot()
	if now.SandboxesActive != 1 || now.ReservedCPU != 2 || now.ReservedMemoryMB != 2048 {
		t.Fatalf("live snapshot wrong: %+v", now)
	}
}

// fakeRSS is the test double for the Phase 5 sampler. Mirrors the
// shape of fakeProbe above — a value type with exported fields so each
// test can dial it without a constructor.
type fakeRSS struct {
	total int
	ready bool
}

func (f fakeRSS) TotalRSSMB() int { return f.total }
func (f fakeRSS) Ready() bool     { return f.ready }

// TestAdmitRSSWatermarkRejects exercises the Phase 5 effective-memory
// floor: nominal accounting allows the request, but actual RSS leaves
// less than the watermark free after admit. The reject reason must
// name the watermark axis so /capacity dashboards can attribute the
// 503 correctly.
func TestAdmitRSSWatermarkRejects(t *testing.T) {
	// 16 GB host, 10% watermark = 1638 MB must stay free of RSS+req.
	// Existing RSS already sits at 14000 MB, so only 2384 MB of effective
	// free remains. A 1024 MB request leaves 1360 MB — below the 1638 MB
	// floor.
	a := NewWithRSSSource(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		RSSWatermarkRatio:      0.10,
	}, nil, fakeRSS{total: 14000, ready: true})

	err := a.Admit("rss-reject", Request{CPU: 1, MemoryMB: 1024})
	if err == nil {
		t.Fatal("admit accepted but RSS watermark should have rejected")
	}
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("err = %v, want wrapping ErrCapacityExceeded", err)
	}
	if !strings.Contains(err.Error(), "rss watermark") {
		t.Fatalf("err missing rss watermark reason: %v", err)
	}
}

// TestAdmitRSSWatermarkAccepts is the positive twin of the reject
// test — same host and ratio, but RSS is low enough that effective
// free comfortably clears the watermark.
func TestAdmitRSSWatermarkAccepts(t *testing.T) {
	a := NewWithRSSSource(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		RSSWatermarkRatio:      0.10,
	}, nil, fakeRSS{total: 2000, ready: true})

	if err := a.Admit("rss-ok", Request{CPU: 1, MemoryMB: 1024}); err != nil {
		t.Fatalf("admit: %v", err)
	}
}

// TestAdmitRSSWatermarkSkippedWhenSamplerNotReady guards the cold-
// start case: a brand-new daemon would have rss.TotalRSSMB()==0
// before the first tick. Without the Ready() gate, that looks like
// "host is empty" and admits unbounded — or, with a watermark set
// against a host that legitimately is empty, would still admit. The
// gate flips that to "fall back to nominal accounting until we have
// real data".
func TestAdmitRSSWatermarkSkippedWhenSamplerNotReady(t *testing.T) {
	// Constructed so the RSS check would FAIL if it ran: 0 RSS means
	// effective=full host, but with a watermark of 1.0 (the entire host
	// must stay free of RSS+req) any non-zero request would breach.
	a := NewWithRSSSource(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		RSSWatermarkRatio:      1.0,
	}, nil, fakeRSS{total: 0, ready: false})

	if err := a.Admit("cold-start", Request{CPU: 1, MemoryMB: 1024}); err != nil {
		t.Fatalf("admit on !Ready sampler must skip the RSS check: %v", err)
	}
}

// TestAdmitRSSWatermarkDisabledWhenRatioZero confirms that the
// default (RSSWatermarkRatio=0, the opt-in switch) keeps admission
// behaviour byte-identical to pre-Phase-5 even with a wired-in
// sampler.
func TestAdmitRSSWatermarkDisabledWhenRatioZero(t *testing.T) {
	a := NewWithRSSSource(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		// RSSWatermarkRatio defaults to 0
	}, nil, fakeRSS{total: 16000, ready: true}) // RSS would otherwise breach

	if err := a.Admit("disabled", Request{CPU: 1, MemoryMB: 1024}); err != nil {
		t.Fatalf("admit must succeed when watermark is disabled: %v", err)
	}
}

// TestAdmitRSSWatermarkSkippedWhenNoSource is the docker-only-host
// case: capacity.New leaves rss as nil, and the gate must skip the
// check rather than panic on a nil interface deref.
func TestAdmitRSSWatermarkSkippedWhenNoSource(t *testing.T) {
	a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		RSSWatermarkRatio:      0.50, // even an aggressive ratio must be a no-op
	}, nil)

	if err := a.Admit("no-source", Request{CPU: 1, MemoryMB: 1024}); err != nil {
		t.Fatalf("admit must succeed when no RSS source is wired: %v", err)
	}
}

// TestSnapshotRSSFields verifies that the cluster-heartbeat snapshot
// surfaces the Phase 5 axis. Placement on a peer uses these to score
// remote nodes; if Snapshot lied about effective-free, the local
// admitter could accept a forward the remote will then 503.
func TestSnapshotRSSFields(t *testing.T) {
	a := NewWithRSSSource(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		RSSWatermarkRatio:      0.10,
	}, nil, fakeRSS{total: 4096, ready: true})

	snap := a.Snapshot()
	if snap.ActualRSSMB != 4096 {
		t.Fatalf("ActualRSSMB = %d, want 4096", snap.ActualRSSMB)
	}
	if snap.EffectiveMemoryFreeMB != 16384-4096 {
		t.Fatalf("EffectiveMemoryFreeMB = %d, want %d", snap.EffectiveMemoryFreeMB, 16384-4096)
	}
	if snap.RSSWatermarkMB != 1638 /* 16384 * 0.10 */ {
		t.Fatalf("RSSWatermarkMB = %d, want %d", snap.RSSWatermarkMB, 1638 /* 16384 * 0.10 */)
	}
	if snap.RSSWatermarkRatio != 0.10 {
		t.Fatalf("RSSWatermarkRatio = %v, want 0.10", snap.RSSWatermarkRatio)
	}
}

// TestSnapshotRSSFieldsZeroBeforeReady covers the pre-tick window.
// Even with a wired sampler, the snapshot must report 0 for the
// observation-derived fields so peers running new code don't take a
// cold-start "0 RSS" reading as truth.
func TestSnapshotRSSFieldsZeroBeforeReady(t *testing.T) {
	a := NewWithRSSSource(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		RSSWatermarkRatio:      0.10,
	}, nil, fakeRSS{total: 5000, ready: false}) // !Ready masks total

	snap := a.Snapshot()
	if snap.ActualRSSMB != 0 {
		t.Fatalf("ActualRSSMB = %d, want 0 before Ready", snap.ActualRSSMB)
	}
	if snap.EffectiveMemoryFreeMB != 0 {
		t.Fatalf("EffectiveMemoryFreeMB = %d, want 0 before Ready", snap.EffectiveMemoryFreeMB)
	}
	// Watermark MB is config-derived, not observation-derived — it can
	// be reported even before the first sample.
	if snap.RSSWatermarkMB != 1638 /* 16384 * 0.10 */ {
		t.Fatalf("RSSWatermarkMB = %d, want %d", snap.RSSWatermarkMB, 1638 /* 16384 * 0.10 */)
	}
}

// TestSnapshotSandboxesByRuntime covers the per-isolation live-sandbox gauge:
// Snapshot aggregates reservations by runtime, the expvar map mirrors it, and a
// runtime that drops to zero is removed (no stale value lingers).
func TestSnapshotSandboxesByRuntime(t *testing.T) {
	a := New(HostInfo{CPUCores: 16, MemoryTotalMB: 16384, DiskTotalGB: 200}, Limits{
		CPUReservationRatio:    1.0,
		MemoryReservationRatio: 1.0,
		DiskReservationRatio:   1.0,
	}, fakeProbe{free: 8192})
	a.Reserve("sb-c1", Request{CPU: 1, MemoryMB: 128, Runtime: "docker"})
	a.Reserve("sb-c2", Request{CPU: 1, MemoryMB: 128, Runtime: "docker"})
	a.Reserve("sb-w1", Request{CPU: 1, MemoryMB: 128, Runtime: "wasm"})
	a.Reserve("sb-any", Request{CPU: 1, MemoryMB: 128}) // no runtime -> "unspecified"

	snap := a.Snapshot()
	if snap.SandboxesActive != 4 {
		t.Fatalf("SandboxesActive = %d, want 4", snap.SandboxesActive)
	}
	for rt, want := range map[string]int{"docker": 2, "wasm": 1, "unspecified": 1} {
		if got := snap.SandboxesByRuntime[rt]; got != want {
			t.Fatalf("SandboxesByRuntime[%s] = %d, want %d", rt, got, want)
		}
	}
	if v := sandboxesByRuntime.Get("docker"); v == nil || v.String() != "2" {
		t.Fatalf("aerolvm_sandboxes_by_runtime{key=docker} = %v, want 2", v)
	}
	// Releasing the sole wasm sandbox must remove its key on the next snapshot.
	a.Release("sb-w1")
	_ = a.Snapshot()
	if v := sandboxesByRuntime.Get("wasm"); v != nil {
		t.Fatalf("sandboxes_by_runtime{key=wasm} should be deleted after release, got %v", v)
	}
}
