package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestDriverImplementsRuntime is the assertion that justifies landing the
// skeleton at all: the Runtime interface (the contract the service layer
// relies on) holds with a second implementation. If a future change to
// runtime.Runtime forgets to add the matching method here, this fails to
// compile — which is the right place to catch the drift.
func TestDriverImplementsRuntime(t *testing.T) {
	var _ runtime.Runtime = (*Driver)(nil)
}

// TestPing confirms the binary-existence checks behave as expected:
//   - empty paths -> immediate error
//   - bogus paths -> os.Stat error wrapped
//   - real files -> nil error
//
// Ping is the cheapest end-to-end check the driver has today and the
// daemon's /healthz hangs off it; getting it right matters.
func TestPing(t *testing.T) {
	dir := t.TempDir()
	fcBin := filepath.Join(dir, "firecracker")
	jailerBin := filepath.Join(dir, "jailer")
	for _, p := range []string{fcBin, jailerBin} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	t.Run("missing fc binary path", func(t *testing.T) {
		d := New(Config{JailerBinary: jailerBin}, nil)
		if err := d.Ping(context.Background()); err == nil {
			t.Fatal("expected error for empty FirecrackerBinary")
		}
	})

	t.Run("missing jailer binary path", func(t *testing.T) {
		d := New(Config{FirecrackerBinary: fcBin}, nil)
		if err := d.Ping(context.Background()); err == nil {
			t.Fatal("expected error for empty JailerBinary")
		}
	})

	t.Run("bogus firecracker binary", func(t *testing.T) {
		d := New(Config{FirecrackerBinary: "/nonexistent/firecracker", JailerBinary: jailerBin}, nil)
		if err := d.Ping(context.Background()); err == nil {
			t.Fatal("expected stat error")
		}
	})

	t.Run("happy path", func(t *testing.T) {
		d := New(Config{FirecrackerBinary: fcBin, JailerBinary: jailerBin}, nil)
		if err := d.Ping(context.Background()); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})

	t.Run("happy path with kernel", func(t *testing.T) {
		kernel := filepath.Join(dir, "vmlinux")
		if err := os.WriteFile(kernel, []byte{}, 0o644); err != nil {
			t.Fatalf("write kernel: %v", err)
		}
		d := New(Config{FirecrackerBinary: fcBin, JailerBinary: jailerBin, KernelImage: kernel}, nil)
		if err := d.Ping(context.Background()); err != nil {
			t.Fatalf("expected nil with kernel set, got %v", err)
		}
	})
}

// TestSkeletonMethodsReturnNotImplemented walks the methods that remain
// skeleton stubs after Phase 1. Phase 1 lands Create/Destroy/Stop/Inspect
// /ListManaged for cold-boot sandboxes; the remaining methods stay
// not-implemented (Start-from-stopped is Phase 2, CreateSnapshot is Phase
// 3, Resize is post-Phase-1, the network-rule shims share their TAP-side
// implementation with the firewall package that hasn't landed yet).
//
// When a method graduates, the corresponding case here must be removed
// (or the test loop will fail), forcing the author to acknowledge the
// surface change.
func TestSkeletonMethodsReturnNotImplemented(t *testing.T) {
	d := New(Config{}, nil)
	ctx := context.Background()

	type call struct {
		name string
		run  func() error
	}
	calls := []call{
		{"Start", func() error {
			_, err := d.Start(ctx, "id")
			return err
		}},
		{"CreateSnapshot", func() error {
			_, err := d.CreateSnapshot(ctx, "id", "img")
			return err
		}},
		{"Resize", func() error { return d.Resize(ctx, "id", models.ResizeSandboxRequest{}) }},
		{"RemoveImage", func() error { return d.RemoveImage(ctx, "img") }},
		{"PushAllowedPorts", func() error { return d.PushAllowedPorts(ctx, "1.2.3.4", "tok", nil) }},
		{"ClearNetworkRules", func() error { return d.ClearNetworkRules("1.2.3.4") }},
		{"ApplyNetworkBlockAll", func() error { return d.ApplyNetworkBlockAll("1.2.3.4") }},
		{"ApplyNetworkBlockIngress", func() error { return d.ApplyNetworkBlockIngress("1.2.3.4") }},
		{"ClearNetworkBlockIngress", func() error { return d.ClearNetworkBlockIngress("1.2.3.4") }},
		{"ClearNetworkBlockEgress", func() error { return d.ClearNetworkBlockEgress("1.2.3.4") }},
	}

	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			err := c.run()
			if !errors.Is(err, models.ErrRuntimeNotImplemented) {
				t.Fatalf("%s: expected ErrRuntimeNotImplemented, got %v", c.name, err)
			}
		})
	}
}

// TestStopUnknownSandboxIsNoop confirms Stop on an unregistered sandbox
// is a no-op rather than an error. Reconcile may call Stop on rows it
// has just learned of from a different node; returning an error would
// look like a real failure in logs.
func TestStopUnknownSandboxIsNoop(t *testing.T) {
	d := New(Config{}, nil)
	if err := d.Stop(context.Background(), "unknown-id"); err != nil {
		t.Fatalf("Stop on unknown sandbox should be no-op; got %v", err)
	}
}

func TestStopRegisteredSandboxNotImplementedDoesNotShutdown(t *testing.T) {
	d := New(Config{}, nil)
	v := &fakeVMM{}
	d.vmms["known-id"] = v

	err := d.Stop(context.Background(), "known-id")
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("Stop registered sandbox error = %v, want ErrRuntimeNotImplemented", err)
	}
	if v.shutdown {
		t.Fatal("Stop should not kill a Firecracker VMM until start/stop semantics are implemented")
	}
}

// TestInspectUnknownSandboxReturnsNil mirrors the Docker driver's
// contract: a sandbox that isn't in the driver's registry returns
// (nil, nil) rather than an error.
func TestInspectUnknownSandboxReturnsNil(t *testing.T) {
	d := New(Config{}, nil)
	state, err := d.Inspect(context.Background(), "unknown-id")
	if err != nil {
		t.Fatalf("Inspect on unknown sandbox should not error; got %v", err)
	}
	if state != nil {
		t.Fatalf("Inspect on unknown sandbox should return nil state; got %+v", state)
	}
}

// TestDestroyNilSandboxIsNoop matches the Docker driver's contract: cleanup
// paths may invoke Destroy on a half-built sandbox with a nil pointer. The
// runtime must not panic, and it must not surface ErrRuntimeNotImplemented
// for the no-op case — otherwise the service's rollback paths would log
// spurious failures.
func TestDestroyNilSandboxIsNoop(t *testing.T) {
	d := New(Config{}, nil)
	if err := d.Destroy(context.Background(), nil); err != nil {
		t.Fatalf("Destroy(nil): expected nil error, got %v", err)
	}
}

// TestListManagedEmptyOK confirms that until Create lands, the driver
// truthfully reports zero managed VMMs rather than not-implemented. The
// service's reconcile loop calls ListManaged on every tick; returning an
// error here would noisily break reconcile on a host that has Firecracker
// wired but no sandboxes on it yet.
func TestListManagedEmptyOK(t *testing.T) {
	d := New(Config{}, nil)
	got, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(got))
	}
}
