package wasm

import "testing"

// ManagedCount feeds the capacity heartbeat's WASM instance pool under
// SB_WASM_MAX_INSTANCES; it must count without probing each worker.
func TestManagedCountCountsHeldInstances(t *testing.T) {
	d := New(Config{}, nil)
	if got := d.ManagedCount(); got != 0 {
		t.Fatalf("empty driver count = %d", got)
	}
	d.byID["sb-1"] = &sandboxInstance{}
	d.byID["sb-2"] = &sandboxInstance{}
	if got := d.ManagedCount(); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
}
