package netns

import (
	"context"
	"errors"
	"expvar"
	"testing"
	"time"
)

// The containerd netns pool counts its claims (hit or miss) and its refills,
// under its own aerolvm_containerd_netns_pool_* names (TODOS.md: the
// containerd pools exported no metrics).
func TestNetnsPoolCountersFollowClaimsAndRefills(t *testing.T) {
	ctx := context.Background()
	p := testPool(t, 3)
	host := NewFakeHost()
	h := NewRuntimeHandoff(p, host)

	read := func() map[string]int64 {
		out := map[string]int64{}
		for _, name := range []string{
			"aerolvm_containerd_netns_pool_hits_total",
			"aerolvm_containerd_netns_pool_misses_total",
			"aerolvm_containerd_netns_pool_refills_total",
			"aerolvm_containerd_netns_pool_refill_failures_total",
		} {
			v, ok := expvar.Get(name).(*expvar.Int)
			if !ok {
				t.Fatalf("expvar %s is not registered", name)
			}
			out[name] = v.Value()
		}
		return out
	}
	before := read()

	// One miss (nothing prewarmed), one refill, one hit on that refill, and
	// one refill that fails in CNI ADD.
	if _, _, err := h.Provision(ctx, "sb-miss"); err != nil {
		t.Fatal(err)
	}
	if err := p.Prewarm(ctx, host, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.Provision(ctx, "sb-hit"); err != nil {
		t.Fatal(err)
	}
	host.SetRealizeError(errors.New("cni boom"))
	if err := p.Prewarm(ctx, host, time.Now().UTC()); err == nil {
		t.Fatal("prewarm with a failing CNI ADD: want error")
	}

	after := read()
	want := map[string]int64{
		"aerolvm_containerd_netns_pool_hits_total":            1,
		"aerolvm_containerd_netns_pool_misses_total":          1,
		"aerolvm_containerd_netns_pool_refills_total":         1,
		"aerolvm_containerd_netns_pool_refill_failures_total": 1,
	}
	for name, delta := range want {
		if got := after[name] - before[name]; got != delta {
			t.Errorf("%s delta = %d, want %d", name, got, delta)
		}
	}
}
