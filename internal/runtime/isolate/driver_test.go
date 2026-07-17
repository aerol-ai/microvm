package isolate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	rt "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The load-bearing property of the whole tier (plans/isolate-runtime.md §1):
// the driver is a Runtime, and deliberately NOT a ContainerRuntime — isolates
// never get an IP, so there is nothing for iptables to pin. If someone adds a
// network-rule method to the driver this test breaks the build conversation.
func TestDriverIsRuntimeButNotContainerRuntime(t *testing.T) {
	var r rt.Runtime = New(Config{}, nil)
	if _, ok := rt.AsContainerRuntime(r); ok {
		t.Fatal("isolate driver must not satisfy ContainerRuntime (host-mediated networking, §4)")
	}
}

// Phase-1 skeleton: every lifecycle method rejects with
// ErrRuntimeNotImplemented so a stray dispatch is an actionable 4xx, never a
// panic or a generic 500.
func TestSkeletonMethodsReturnNotImplemented(t *testing.T) {
	d := New(Config{}, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{name: "create", call: func() error {
			_, err := d.Create(ctx, models.CreateSandboxRequest{}, "sb-1", "token", nil)
			return err
		}},
		{name: "start", call: func() error {
			_, err := d.Start(ctx, "sb-1")
			return err
		}},
		{name: "stop", call: func() error { return d.Stop(ctx, "sb-1") }},
		{name: "destroy_non_nil", call: func() error {
			return d.Destroy(ctx, &models.Sandbox{ID: "sb-1"})
		}},
		{name: "create_snapshot", call: func() error {
			_, err := d.CreateSnapshot(ctx, "sb-1", "img")
			return err
		}},
		{name: "resize", call: func() error {
			return d.Resize(ctx, "sb-1", models.ResizeSandboxRequest{})
		}},
		{name: "remove_image", call: func() error { return d.RemoveImage(ctx, "img") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if !errors.Is(err, models.ErrRuntimeNotImplemented) {
				t.Fatalf("%s = %v, want ErrRuntimeNotImplemented", tc.name, err)
			}
		})
	}
}

func TestDestroyNilIsNoOp(t *testing.T) {
	d := New(Config{}, nil)
	if err := d.Destroy(context.Background(), nil); err != nil {
		t.Fatalf("Destroy(nil) = %v, want nil (Runtime contract)", err)
	}
}

func TestInspectUnknownReturnsNil(t *testing.T) {
	d := New(Config{}, nil)
	state, err := d.Inspect(context.Background(), "sb-missing")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if state != nil {
		t.Fatalf("Inspect unknown = %+v, want nil", state)
	}
}

// Reconcile calls ListManaged on every registered runtime; an empty (not
// nil-error) result is what lets restart reconcile terminal-ize stray isolate
// rows instead of wedging the sweep.
func TestListManagedEmpty(t *testing.T) {
	d := New(Config{}, nil)
	managed, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(managed) != 0 {
		t.Fatalf("ListManaged = %d entries, want 0", len(managed))
	}
}

func TestInspectAndListManagedSeeRegisteredState(t *testing.T) {
	d := New(Config{}, nil)
	want := &models.SandboxRuntimeState{SandboxID: "sb-1", Status: models.SandboxStatusStarted}
	d.mu.Lock()
	d.byID["sb-1"] = want
	d.mu.Unlock()

	state, err := d.Inspect(context.Background(), "sb-1")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if state != want {
		t.Fatalf("Inspect = %+v, want the registered state", state)
	}
	managed, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(managed) != 1 || managed["sb-1"] != want {
		t.Fatalf("ListManaged = %+v, want the registered state under sb-1", managed)
	}
}

func TestPing(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing_binary_errors", func(t *testing.T) {
		d := New(Config{WorkerdPath: filepath.Join(dir, "missing-workerd")}, nil)
		if err := d.Ping(context.Background()); err == nil {
			t.Fatal("expected error for missing workerd binary")
		}
	})

	t.Run("directory_errors", func(t *testing.T) {
		d := New(Config{WorkerdPath: dir}, nil)
		if err := d.Ping(context.Background()); err == nil {
			t.Fatal("expected error for directory workerd path")
		}
	})

	t.Run("existing_binary_ok", func(t *testing.T) {
		bin := filepath.Join(dir, "workerd")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
		d := New(Config{WorkerdPath: bin}, nil)
		if err := d.Ping(context.Background()); err != nil {
			t.Fatalf("Ping = %v, want nil", err)
		}
	})
}

type stubResolver struct{}

func (stubResolver) Resolve(ctx context.Context, ref string) (ResolvedBundle, error) {
	return ResolvedBundle{Ref: ref}, nil
}

type stubPool struct{}

func (stubPool) Acquire(ctx context.Context) (WarmHost, bool) { return WarmHost{}, false }

func TestSetters(t *testing.T) {
	d := New(Config{}, nil)
	d.SetBundleResolver(stubResolver{})
	if d.resolver == nil {
		t.Fatal("SetBundleResolver did not wire the resolver")
	}
	d.SetWarmPool(stubPool{})
	if d.warmPool == nil {
		t.Fatal("SetWarmPool did not wire the pool")
	}
}

func TestFromDaemonConfig(t *testing.T) {
	cfg := config.Config{
		IsolateWorkerdPath:      "/opt/workerd",
		IsolateRunDir:           "/run/iso",
		IsolateGroupGranularity: config.IsolateGroupPerSandbox,
		IsolateUseJail:          true,
		IsolateJailChrootBase:   "/srv/jail",
		IsolateJailUID:          1234,
		IsolateJailGID:          1235,
		IsolateJitless:          true,
	}
	got := FromDaemonConfig(cfg)
	want := Config{
		WorkerdPath:      "/opt/workerd",
		RunDir:           "/run/iso",
		GroupGranularity: GroupPerSandbox,
		UseJail:          true,
		JailChrootBase:   "/srv/jail",
		JailUID:          1234,
		JailGID:          1235,
		Jitless:          true,
	}
	if got != want {
		t.Fatalf("FromDaemonConfig = %+v, want %+v", got, want)
	}
}
