package isolate

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestIdleReaperTearsDownIdleGroup(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	d.cfg.IdleTTL = time.Minute
	ctx := context.Background()

	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	if sup.spawnCount() != 1 {
		t.Fatalf("spawned %d", sup.spawnCount())
	}

	// Force lastUsed into the past and sweep.
	d.groupsMu.Lock()
	for _, g := range d.groups {
		g.lastUsed = time.Now().Add(-2 * time.Minute)
	}
	d.groupsMu.Unlock()

	d.reapIdleGroups(time.Minute)

	d.groupsMu.Lock()
	left := len(d.groups)
	d.groupsMu.Unlock()
	if left != 0 {
		t.Fatalf("groups left = %d, want 0 after idle reap", left)
	}
	if !sup.hosts[0].stopped {
		t.Fatal("host was not Stop()'d by idle reaper")
	}
	d.mu.Lock()
	rec := d.byID["sb-1"]
	d.mu.Unlock()
	if rec == nil || rec.state.Status != models.SandboxStatusStopped || !rec.needsReload {
		t.Fatalf("sandbox record after reap = %+v", rec)
	}
}

func TestIdleReaperDisabledWhenTTLZero(t *testing.T) {
	d := New(Config{IdleTTL: 0}, nil)
	// Must not panic / hang.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.RunIdleReaper(ctx)
}

func TestRunIdleReaperTicks(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	d.cfg.IdleTTL = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	d.groupsMu.Lock()
	for _, g := range d.groups {
		g.lastUsed = time.Now().Add(-5 * time.Minute)
	}
	d.groupsMu.Unlock()

	done := make(chan struct{})
	go func() {
		d.RunIdleReaper(ctx)
		close(done)
	}()
	// Tick interval is max(ttl/2, 1s) — wait for one sweep after idle threshold.
	time.Sleep(1500 * time.Millisecond)
	cancel()
	<-done

	d.groupsMu.Lock()
	n := len(d.groups)
	d.groupsMu.Unlock()
	if n != 0 {
		t.Fatalf("reaper left %d groups", n)
	}
}

func TestReapIdleGroupsEdgeCases(t *testing.T) {
	d := New(Config{}, nil)
	d.reapIdleGroups(0) // ttl disabled

	d.groupsMu.Lock()
	d.groups["ghost"] = nil
	d.groupsMu.Unlock()
	d.reapIdleGroups(time.Minute) // nil group skipped

	sup := &fakeSupervisor{}
	d2 := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d2.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	// Zero lastUsed gets initialized and group survives one sweep.
	d2.reapIdleGroups(time.Minute)
	if sup.spawnCount() != 1 || sup.hosts[0].stopped {
		t.Fatal("fresh group should survive first reap with initialized lastUsed")
	}
}
