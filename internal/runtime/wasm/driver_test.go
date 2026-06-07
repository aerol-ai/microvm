package wasm

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSkeletonMethodsReturnNotImplemented(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		run  func() error
	}{
		{"Create", func() error {
			_, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, "id", "tok", nil)
			return err
		}},
		{"Start", func() error {
			_, err := d.Start(ctx, "id")
			return err
		}},
		{"Stop", func() error { return d.Stop(ctx, "id") }},
		{"CreateSnapshot", func() error {
			_, err := d.CreateSnapshot(ctx, "id", "img")
			return err
		}},
		{"Resize", func() error { return d.Resize(ctx, "id", models.ResizeSandboxRequest{}) }},
		{"RemoveImage", func() error { return d.RemoveImage(ctx, "img") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, models.ErrRuntimeNotImplemented) {
				t.Fatalf("expected ErrRuntimeNotImplemented, got %v", err)
			}
		})
	}
}

func TestDestroyNilSandboxIsNoop(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	if err := d.Destroy(context.Background(), nil); err != nil {
		t.Fatalf("Destroy(nil): %v", err)
	}
}

func TestListManagedEmptyOK(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	got, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map, got %d", len(got))
	}
}

func TestInspectUnknownSandboxReturnsNil(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	state, err := d.Inspect(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if state != nil {
		t.Fatalf("expected nil state, got %+v", state)
	}
}

func TestPingRequiresModulesDir(t *testing.T) {
	d := New(Config{}, nil)
	if err := d.Ping(context.Background()); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("Ping without modules dir: %v", err)
	}
}
