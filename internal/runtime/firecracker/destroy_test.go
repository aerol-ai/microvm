package firecracker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestDestroy_NilSandboxIsNoop matches the Docker driver's contract:
// the service's rollback paths may call Destroy on a half-built sandbox
// (nil pointer); the call must not panic or surface a spurious error.
func TestDestroy_NilSandboxIsNoop(t *testing.T) {
	d := New(Config{}, nil)
	if err := d.Destroy(context.Background(), nil); err != nil {
		t.Fatalf("Destroy(nil) should be no-op; got %v", err)
	}
}

// TestDestroy_HappyPath confirms a Destroy after a successful Create
// unwinds every resource: VMM shut down, host TAP removed, pool slot
// released, runDir cleaned, registry entries dropped.
func TestDestroy_HappyPath(t *testing.T) {
	f := newDriverFixture(t)
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-destroy", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-destroy"}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if !f.vmm.shutdown {
		t.Error("vmm.Shutdown not called")
	}
	if !f.vmm.cleaned {
		t.Error("vmm.Cleanup not called")
	}
	if f.tapHost.removeCalls != 1 {
		t.Errorf("tap.Remove calls = %d, want 1", f.tapHost.removeCalls)
	}
	if f.pool.release != 1 {
		t.Errorf("pool.Release calls = %d, want 1", f.pool.release)
	}
	// Registry maps should be empty after Destroy.
	if _, ok := f.driver.vmms["sb-destroy"]; ok {
		t.Error("vmm registry not cleared")
	}
	if _, ok := f.driver.clients["sb-destroy"]; ok {
		t.Error("client registry not cleared")
	}
}

// TestDestroy_UnknownSandboxStillReleasesPool exercises the
// reconcile-after-restart path: the driver's in-memory map is empty
// (daemon restarted) but the pool still has the row. Destroy must
// release the slot even when there's no VMM handle to shut down.
func TestDestroy_UnknownSandboxStillReleasesPool(t *testing.T) {
	f := newDriverFixture(t)
	// Manually pre-seed the pool as if a prior Create succeeded.
	_, err := f.pool.Allocate(context.Background(), "sb-orphan", time.Time{})
	if err != nil {
		t.Fatalf("pre-seed allocate: %v", err)
	}
	releasesBefore := f.pool.release

	if err := f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-orphan"}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if f.pool.release != releasesBefore+1 {
		t.Errorf("pool.Release not invoked; got %d, want %d", f.pool.release, releasesBefore+1)
	}
	// TAP Remove called because the slot was known to the pool.
	if f.tapHost.removeCalls != 1 {
		t.Errorf("tap.Remove calls = %d, want 1", f.tapHost.removeCalls)
	}
}

// TestDestroy_SurfacesFirstErrorButContinues confirms a failure in one
// cleanup step doesn't abort the rest. The error returned is the first
// failure (so callers see "shutdown failed" rather than the secondary
// "tap remove failed"); the secondaries still happen so the next
// daemon-restart doesn't leak.
func TestDestroy_SurfacesFirstErrorButContinues(t *testing.T) {
	f := newDriverFixture(t)
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-err-during-destroy", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.vmm.shutdownErr = errors.New("vmm: SIGTERM rejected")
	f.tapHost.removeErr = errors.New("ip: device busy")

	err = f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-err-during-destroy"})
	if err == nil {
		t.Fatal("expected error from Destroy")
	}
	// Must have walked through every step despite the errors.
	if !f.vmm.cleaned {
		t.Error("Cleanup should run even after Shutdown error")
	}
	if f.pool.release != 1 {
		t.Errorf("pool.Release should run even after tap.Remove error; release=%d", f.pool.release)
	}
}
