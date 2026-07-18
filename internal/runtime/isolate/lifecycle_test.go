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
