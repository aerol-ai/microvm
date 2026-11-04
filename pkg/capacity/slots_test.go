package capacity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSlotPoolExhaustedIsACapacityRefusal(t *testing.T) {
	sentinel := NewSlotPoolExhausted(" container netns pool ")
	cases := []struct {
		name string
		err  error
	}{
		{"bare", sentinel},
		{"wrapped once", fmt.Errorf("provision netns: %w", sentinel)},
		{"wrapped twice", fmt.Errorf("create: %w", fmt.Errorf("provision netns: %w", sentinel))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, ErrCapacityExceeded) {
				t.Fatalf("errors.Is(%v, ErrCapacityExceeded) = false", tc.err)
			}
			if !errors.Is(tc.err, sentinel) {
				t.Fatalf("errors.Is(%v, sentinel) = false; pools compare their own value by identity", tc.err)
			}
			pool, ok := SlotPoolExhausted(tc.err)
			if !ok || pool != "container netns pool" {
				t.Fatalf("SlotPoolExhausted = (%q, %t), want (container netns pool, true)", pool, ok)
			}
			msg := tc.err.Error()
			if !strings.Contains(msg, "container netns pool: no free slot") || !strings.Contains(msg, ErrCapacityExceeded.Error()) {
				t.Fatalf("message %q must name the pool and say host capacity exceeded", msg)
			}
		})
	}
}

func TestSlotPoolExhaustedRejectsOtherErrors(t *testing.T) {
	for _, err := range []error{nil, errors.New("container netns pool: no free slot"), ErrCapacityExceeded} {
		if pool, ok := SlotPoolExhausted(err); ok {
			t.Fatalf("SlotPoolExhausted(%v) = (%q, true), want false", err, pool)
		}
	}
	// Two pools are distinct values even though both are capacity refusals.
	a, b := NewSlotPoolExhausted("a"), NewSlotPoolExhausted("b")
	if errors.Is(a, b) {
		t.Fatal("two pools' sentinels must not match each other")
	}
	var nilErr *SlotPoolExhaustedError
	if got := nilErr.Error(); !strings.HasPrefix(got, "slot pool: no free slot") {
		t.Fatalf("nil error message = %q", got)
	}
	if got := NewSlotPoolExhausted("").Error(); !strings.HasPrefix(got, "slot pool: no free slot") {
		t.Fatalf("unnamed pool message = %q", got)
	}
}

func TestSnapshotSlotPoolFor(t *testing.T) {
	snap := Snapshot{SlotPools: []SlotPool{
		{Name: SlotPoolContainerNetns, Runtimes: []string{"docker", "gvisor"}, Total: 256, Free: 3},
		{Name: SlotPoolFirecrackerTap, Runtimes: []string{"firecracker"}, Total: 256, Free: 0},
	}}
	cases := []struct {
		runtime  string
		wantOK   bool
		wantName string
		wantFree int
	}{
		{"docker", true, SlotPoolContainerNetns, 3},
		{"gvisor", true, SlotPoolContainerNetns, 3},
		{"firecracker", true, SlotPoolFirecrackerTap, 0},
		{"wasm", false, "", 0},
		{"", false, "", 0},
	}
	for _, tc := range cases {
		pool, ok := snap.SlotPoolFor(tc.runtime)
		if ok != tc.wantOK || pool.Name != tc.wantName || pool.Free != tc.wantFree {
			t.Fatalf("SlotPoolFor(%q) = (%+v, %t), want name=%q free=%d ok=%t", tc.runtime, pool, ok, tc.wantName, tc.wantFree, tc.wantOK)
		}
	}
	if _, ok := (Snapshot{}).SlotPoolFor("docker"); ok {
		t.Fatal("a snapshot without SlotPools (an older peer) must report no pool")
	}
}

// The heartbeat is JSON over /v1/capacity. A snapshot without pools must not
// grow the payload, and one with pools must round-trip.
func TestSnapshotSlotPoolsWireShape(t *testing.T) {
	raw, err := json.Marshal(Snapshot{HostCPUCores: 4})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "slot_pools") {
		t.Fatalf("empty SlotPools must be omitted: %s", raw)
	}
	in := Snapshot{HostCPUCores: 4, SlotPools: []SlotPool{{Name: SlotPoolFirecrackerTap, Runtimes: []string{"firecracker"}, Total: 256, Free: 17}}}
	raw, err = json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Snapshot
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.SlotPools) != 1 || out.SlotPools[0].Free != 17 || !out.SlotPools[0].Serves("firecracker") {
		t.Fatalf("round trip lost the pool: %s -> %+v", raw, out.SlotPools)
	}
}
