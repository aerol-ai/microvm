package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// A node that cannot keep a mount where the sandbox is built (a Kubernetes
// worker pod with external storage off, F13) refuses a create with mounts
// before any work: nothing reaches the runtime and nothing is stored, so the
// sandbox never writes to local disk in place of the store. A request that
// is wrong stays the caller's 4xx, checked first; a create without mounts is
// untouched.
func TestCreateSandboxRefusesMountsWhenTheNodeCannotServeThem(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir:     filepath.Join(t.TempDir(), "mounts"),
		CredDir:     filepath.Join(t.TempDir(), "cred"),
		Unavailable: "external storage is off on this Kubernetes worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)
	svc.mounts = mgr

	s3 := []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://bucket", Target: "/data"}}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", Mounts: s3}); !errors.Is(err, mounts.ErrMountsUnavailable) {
		t.Fatalf("CreateSandbox = %v, want ErrMountsUnavailable", err)
	}
	if rt.createCalls != 0 {
		t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
	}
	if rows, err := st.List(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("stored rows = %d (%v), want 0", len(rows), err)
	}

	bad := []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://bucket", Target: "/proc"}}
	if err := svc.validateCreateMounts(ctx, bad, "sb-bad"); err == nil || errors.Is(err, mounts.ErrMountsUnavailable) {
		t.Fatalf("a wrong request = %v, want the caller's own error first", err)
	}
	if err := svc.validateCreateMounts(ctx, nil, "sb-none"); err != nil {
		t.Fatalf("a create without mounts = %v, want nil", err)
	}

	// A platform volume is a mount: refused before any storage work.
	pv := enabledVolumeService(t)
	pv.mounts = mgr
	req := models.CreateSandboxRequest{Image: "alpine", PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}}}
	if _, err := pv.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); !errors.Is(err, mounts.ErrMountsUnavailable) {
		t.Fatalf("resolvePlatformVolumes = %v, want ErrMountsUnavailable", err)
	}
}
