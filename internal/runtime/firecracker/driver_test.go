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

// TestSkeletonMethodsReturnNotImplemented walks every method we expect to
// still be a skeleton stub. The point isn't to test the message — it's to
// flag the day a method graduates: when the real implementation lands,
// the corresponding case here must be removed (or the test loop will
// fail), forcing the author to acknowledge the surface change.
func TestSkeletonMethodsReturnNotImplemented(t *testing.T) {
	d := New(Config{}, nil)
	ctx := context.Background()

	type call struct {
		name string
		run  func() error
	}
	calls := []call{
		{"Create", func() error {
			_, err := d.Create(ctx, models.CreateSandboxRequest{}, "id", "tok", nil)
			return err
		}},
		{"Start", func() error {
			_, err := d.Start(ctx, "id")
			return err
		}},
		{"Stop", func() error { return d.Stop(ctx, "id") }},
		{"Destroy", func() error { return d.Destroy(ctx, &models.Sandbox{ID: "id"}) }},
		{"CreateSnapshot", func() error {
			_, err := d.CreateSnapshot(ctx, "id", "img")
			return err
		}},
		{"Resize", func() error { return d.Resize(ctx, "id", models.ResizeSandboxRequest{}) }},
		{"Inspect", func() error {
			_, err := d.Inspect(ctx, "id")
			return err
		}},
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
