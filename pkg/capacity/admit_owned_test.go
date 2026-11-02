package capacity

import (
	"errors"
	"sync"
	"testing"
)

// AdmitOwned is how a create learns whether the reservation is its own to
// release: an ID that already holds one keeps it untouched.
func TestAdmitOwned(t *testing.T) {
	tests := []struct {
		name      string
		prior     *Request // a reservation the ID already holds
		req       Request
		wantOwned bool
		wantErr   error
		wantCPU   float64
		wantCount int
	}{
		{name: "a free id is admitted and owned", req: Request{CPU: 2, MemoryMB: 1024}, wantOwned: true, wantCPU: 2, wantCount: 1},
		{name: "a held id keeps its holder's reservation", prior: &Request{CPU: 2, MemoryMB: 1024}, req: Request{CPU: 1, MemoryMB: 512}, wantOwned: false, wantCPU: 2, wantCount: 1},
		{name: "a held id is not budget-checked", prior: &Request{CPU: 4, MemoryMB: 1024}, req: Request{CPU: 64, MemoryMB: 1 << 20}, wantOwned: false, wantCPU: 4, wantCount: 1},
		{name: "over budget is refused, nothing owned", req: Request{CPU: 64, MemoryMB: 1024}, wantErr: ErrCapacityExceeded, wantCount: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 8192}, Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1}, nil)
			if tt.prior != nil {
				a.Reserve("sb-1", *tt.prior)
			}
			owned, err := a.AdmitOwned("sb-1", tt.req)
			if owned != tt.wantOwned || !errors.Is(err, tt.wantErr) {
				t.Fatalf("AdmitOwned = %v, %v; want %v, %v", owned, err, tt.wantOwned, tt.wantErr)
			}
			snap := a.Snapshot()
			if snap.SandboxesActive != tt.wantCount || snap.ReservedCPU != tt.wantCPU {
				t.Fatalf("snapshot active=%d cpu=%v, want %d, %v", snap.SandboxesActive, snap.ReservedCPU, tt.wantCount, tt.wantCPU)
			}
		})
	}
}

// Two creates of one ID admitting at once: exactly one owns the reservation,
// so exactly one release can free it.
func TestAdmitOwnedConcurrentOneOwner(t *testing.T) {
	for round := 0; round < 50; round++ {
		a := New(HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1}, nil)
		var wg sync.WaitGroup
		var mu sync.Mutex
		owners := 0
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				owned, err := a.AdmitOwned("sb-1", Request{CPU: 1, MemoryMB: 512})
				if err != nil {
					t.Error(err)
				}
				if owned {
					mu.Lock()
					owners++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if owners != 1 {
			t.Fatalf("round %d: %d creates own one id's reservation", round, owners)
		}
		if snap := a.Snapshot(); snap.SandboxesActive != 1 || snap.ReservedCPU != 1 {
			t.Fatalf("round %d: snapshot %+v", round, snap)
		}
	}
}
