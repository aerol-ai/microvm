package cluster

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// fillFSMWithPlacements seeds an FSM with `n` placements, each owned by a
// round-robin node and exposing one raw-TCP host port that's unique across
// the set. Returns the FSM ready for further opAddExposedPort applies.
func fillFSMWithPlacements(t testing.TB, fsm *placementFSM, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("scale-%07d", i)
		place, _ := encodeCommand(command{
			Op:          opPlace,
			SandboxID:   id,
			OwnerNodeID: fmt.Sprintf("node-%03d", i%32),
			OwnerAPIURL: fmt.Sprintf("http://10.0.%d.%d:21212", (i/256)%256, i%256),
			Spec:        &models.CreateSandboxRequest{Image: "img"},
		})
		if got := fsm.Apply(&raft.Log{Index: uint64(i + 1), Data: place}); got != nil {
			t.Fatalf("seed place %d: %v", i, got)
		}
		add, _ := encodeCommand(command{
			Op:        opAddExposedPort,
			SandboxID: id,
			Port:      22000 + i,
			Protocol:  models.ExposedPortProtocolTCP,
			HostPort:  40000 + i,
		})
		if got := fsm.Apply(&raft.Log{Index: uint64(n + i + 1), Data: add}); got != nil {
			t.Fatalf("seed expose %d: %v", i, got)
		}
	}
}

// TestFSMValidateHostPortAt10K is the B6 scale claim for the FSM's port-
// availability index. With 10K placements each holding a distinct TCP host
// port, an opAddExposedPort that doesn't conflict MUST succeed, and one that
// reuses an existing host port MUST be rejected with ErrHostPortReserved.
// Regressions that reintroduce placement-map scans will show up as ballooning
// wall clock here and in the benchmark.
func TestFSMValidateHostPortAt10K(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped under -short")
	}
	fsm := newPlacementFSM()
	const n = 10_000
	fillFSMWithPlacements(t, fsm, n)

	// Place a fresh sandbox we'll mutate with new port adds.
	newID := "scale-target"
	place, _ := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   newID,
		OwnerNodeID: "node-target",
		OwnerAPIURL: "http://10.99.0.1:21212",
		Spec:        &models.CreateSandboxRequest{Image: "img"},
	})
	if got := fsm.Apply(&raft.Log{Index: uint64(2*n + 1), Data: place}); got != nil {
		t.Fatalf("place target: %v", got)
	}

	// Non-conflicting add: host port well above the seeded range. Must
	// succeed and walk the entire placement map without false-positive.
	t0 := time.Now()
	okAdd, _ := encodeCommand(command{
		Op:        opAddExposedPort,
		SandboxID: newID,
		Port:      55555,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  60000,
	})
	if got := fsm.Apply(&raft.Log{Index: uint64(2*n + 2), Data: okAdd}); got != nil {
		t.Fatalf("expose-non-conflicting after %d placements returned %v", n, got)
	}
	okElapsed := time.Since(t0)

	// Conflicting add: reuse a host port from the seeded set. Must surface
	// ErrHostPortReserved — without this, two TCP exposures would race to
	// the same kernel port across the fleet and one would silently lose at
	// bind time on the new owner.
	t1 := time.Now()
	dupHostPort := 40000 + (n / 2) // owned by scale-{n/2}
	dupAdd, _ := encodeCommand(command{
		Op:        opAddExposedPort,
		SandboxID: newID,
		Port:      55556,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  dupHostPort,
	})
	got := fsm.Apply(&raft.Log{Index: uint64(2*n + 3), Data: dupAdd})
	conflictElapsed := time.Since(t1)
	err, _ := got.(error)
	if err == nil || !errors.Is(err, ErrHostPortReserved) {
		t.Fatalf("expose-conflicting after %d placements returned %v, want ErrHostPortReserved", n, got)
	}
	t.Logf("validateHostPortAvailableLocked at %d placements: ok=%s, conflict=%s",
		n, okElapsed, conflictElapsed)
}

func TestFSMHostPortIndexReleasesOnRemoveAndDelete(t *testing.T) {
	fsm := newPlacementFSM()
	for _, id := range []string{"owner", "next"} {
		place, _ := encodeCommand(command{
			Op:          opPlace,
			SandboxID:   id,
			OwnerNodeID: "node-a",
			Spec:        &models.CreateSandboxRequest{Image: "img"},
		})
		if got := fsm.Apply(&raft.Log{Index: uint64(len(id)), Data: place}); got != nil {
			t.Fatalf("place %s: %v", id, got)
		}
	}
	add, _ := encodeCommand(command{
		Op:        opAddExposedPort,
		SandboxID: "owner",
		Port:      5432,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  45432,
	})
	if got := fsm.Apply(&raft.Log{Index: 10, Data: add}); got != nil {
		t.Fatalf("add owner tcp: %v", got)
	}
	dup, _ := encodeCommand(command{
		Op:        opAddExposedPort,
		SandboxID: "next",
		Port:      5432,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  45432,
	})
	if got := fsm.Apply(&raft.Log{Index: 11, Data: dup}); !errors.Is(got.(error), ErrHostPortReserved) {
		t.Fatalf("duplicate host port = %v, want ErrHostPortReserved", got)
	}
	remove, _ := encodeCommand(command{Op: opRemoveExposedPort, SandboxID: "owner", Port: 5432})
	if got := fsm.Apply(&raft.Log{Index: 12, Data: remove}); got != nil {
		t.Fatalf("remove owner tcp: %v", got)
	}
	if got := fsm.Apply(&raft.Log{Index: 13, Data: dup}); got != nil {
		t.Fatalf("host port not released after remove: %v", got)
	}
	del, _ := encodeCommand(command{Op: opDelete, SandboxID: "next"})
	if got := fsm.Apply(&raft.Log{Index: 14, Data: del}); got != nil {
		t.Fatalf("delete next: %v", got)
	}
	if got := fsm.Apply(&raft.Log{Index: 15, Data: add}); got != nil {
		t.Fatalf("host port not released after delete: %v", got)
	}
}

// BenchmarkFSMValidateHostPortAt10K measures the steady-state cost of one
// opAddExposedPort against a 10K-placement FSM. Operators can track this to
// notice if a future port-allocator change regresses the O(1) host-port index
// back into an FSM-wide scan.
func BenchmarkFSMValidateHostPortAt10K(b *testing.B) {
	fsm := newPlacementFSM()
	const n = 10_000
	fillFSMWithPlacements(b, fsm, n)
	newID := "bench-target"
	place, _ := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   newID,
		OwnerNodeID: "node-bench",
		Spec:        &models.CreateSandboxRequest{Image: "img"},
	})
	fsm.Apply(&raft.Log{Index: uint64(2*n + 1), Data: place})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		add, _ := encodeCommand(command{
			Op:        opAddExposedPort,
			SandboxID: newID,
			Port:      55555,
			// Walk distinct non-conflicting host ports so each iteration
			// triggers the full scan (a re-add of the same route would
			// short-circuit via the same-route no-op branch).
			Protocol: models.ExposedPortProtocolTCP,
			HostPort: 60000 + i,
		})
		fsm.Apply(&raft.Log{Index: uint64(2*n + 2 + i), Data: add})
	}
}
