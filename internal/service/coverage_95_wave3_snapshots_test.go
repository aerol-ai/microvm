package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCreateSnapshotWithOwnershipWave3 covers the success path (including
// kickSnapshotPushReconciler), idempotent same-sandbox return, runtime failure,
// and cross-sandbox name conflict via the ownership-aware entry point.
func TestCreateSnapshotWithOwnershipWave3(t *testing.T) {
	ctx := context.Background()

	t.Run("success with pending push kick", func(t *testing.T) {
		st := openImageDistributionStore(t)
		defer st.Close()

		now := time.Now().UTC()
		if err := st.Create(ctx, seedSnapshotSandbox("sb-snap-kick", now)); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}

		rt := &fakeSnapshotRuntime{imageID: "sha256:kick"}
		svc := &Service{
			store:  st,
			docker: rt,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		patPath := writePATFile(t, "token")
		pusher, err := NewSnapshotPusher(SnapshotPushConfig{
			Enabled: true, Host: "aocr.test", ClusterID: "cluster-kick", PATPath: patPath,
		}, &fakeSnapshotPushDocker{}, svc.logger)
		if err != nil {
			t.Fatalf("NewSnapshotPusher: %v", err)
		}
		rec := newTestReconciler(t, st, &fakeSnapshotPushDocker{})
		svc.AttachSnapshotPusher(pusher, rec)

		snap, created, err := svc.CreateSnapshotWithOwnership(ctx, "sb-snap-kick",
			models.CreateSandboxSnapshotRequest{Name: "e2b/sb-snap-kick:default"})
		if err != nil {
			t.Fatalf("CreateSnapshotWithOwnership: %v", err)
		}
		if !created {
			t.Fatal("first create should report created=true")
		}
		if snap.PushState != models.SnapshotPushStatePending {
			t.Fatalf("push state = %q, want pending when pusher is wired", snap.PushState)
		}
		if snap.ImageDistributionMode != models.ImageDistributionLocalOnly {
			t.Fatalf("distribution mode = %q, want local_only", snap.ImageDistributionMode)
		}
		if rt.hits != 1 {
			t.Fatalf("runtime CreateSnapshot hits = %d, want 1", rt.hits)
		}
		time.Sleep(25 * time.Millisecond) // kickSnapshotPushReconciler goroutine
	})

	t.Run("same sandbox idempotent", func(t *testing.T) {
		st := openImageDistributionStore(t)
		defer st.Close()
		now := time.Now().UTC()
		if err := st.Create(ctx, seedSnapshotSandbox("sb-snap-idem", now)); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		rt := &fakeSnapshotRuntime{imageID: "sha256:idem"}
		svc := &Service{store: st, docker: rt, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

		first, created, err := svc.CreateSnapshotWithOwnership(ctx, "sb-snap-idem",
			models.CreateSandboxSnapshotRequest{Name: "snapshots/shared:idem"})
		if err != nil || !created {
			t.Fatalf("first = (%v, %v), want success created=true", first, created)
		}
		second, created, err := svc.CreateSnapshotWithOwnership(ctx, "sb-snap-idem",
			models.CreateSandboxSnapshotRequest{Name: "snapshots/shared:idem"})
		if err != nil {
			t.Fatalf("second CreateSnapshotWithOwnership: %v", err)
		}
		if created {
			t.Fatal("second call should report created=false")
		}
		if rt.hits != 1 {
			t.Fatalf("runtime hits = %d, want 1 (idempotent)", rt.hits)
		}
		if second.Name != first.Name {
			t.Fatalf("second name = %q, want %q", second.Name, first.Name)
		}
	})

	t.Run("runtime CreateSnapshot error", func(t *testing.T) {
		st := openImageDistributionStore(t)
		defer st.Close()
		now := time.Now().UTC()
		if err := st.Create(ctx, seedSnapshotSandbox("sb-snap-err", now)); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		rt := &fakeSnapshotRuntime{err: errors.New("docker commit failed")}
		svc := &Service{store: st, docker: rt, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

		_, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb-snap-err",
			models.CreateSandboxSnapshotRequest{Name: "snapshots/fail:v1"})
		if err == nil || !strings.Contains(err.Error(), "docker commit failed") {
			t.Fatalf("error = %v, want runtime failure", err)
		}
		if _, getErr := st.GetSnapshot(ctx, "snapshots/fail:v1"); !errors.Is(getErr, store.ErrNotFound) {
			t.Fatalf("snapshot row leaked after runtime failure: %v", getErr)
		}
	})

	t.Run("cross sandbox conflict", func(t *testing.T) {
		st := openImageDistributionStore(t)
		defer st.Close()
		now := time.Now().UTC()
		for _, id := range []string{"sb-snap-a", "sb-snap-b"} {
			if err := st.Create(ctx, seedSnapshotSandbox(id, now)); err != nil {
				t.Fatalf("seed %s: %v", id, err)
			}
		}
		rt := &fakeSnapshotRuntime{imageID: "sha256:conflict"}
		svc := &Service{store: st, docker: rt, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

		if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb-snap-a",
			models.CreateSandboxSnapshotRequest{Name: "snapshots/shared:conflict"}); err != nil {
			t.Fatalf("first create: %v", err)
		}
		_, created, err := svc.CreateSnapshotWithOwnership(ctx, "sb-snap-b",
			models.CreateSandboxSnapshotRequest{Name: "snapshots/shared:conflict"})
		if !errors.Is(err, store.ErrSnapshotNameConflict) {
			t.Fatalf("error = %v, want ErrSnapshotNameConflict", err)
		}
		if created {
			t.Fatal("conflict path should report created=false")
		}
		if rt.hits != 1 {
			t.Fatalf("runtime hits = %d, want 1", rt.hits)
		}
	})

	t.Run("empty name rejected", func(t *testing.T) {
		svc := &Service{store: openImageDistributionStore(t), docker: &fakeSnapshotRuntime{}}
		t.Cleanup(func() { _ = svc.store.Close() })
		_, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb-x", models.CreateSandboxSnapshotRequest{Name: "  "})
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("error = %v, want name required", err)
		}
	})
}

func seedSnapshotSandbox(id string, now time.Time) *models.Sandbox {
	return &models.Sandbox{
		ID: id, Image: "ubuntu:22.04", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-" + id, ContainerIP: "10.0.0.10",
		CPU: 1, MemoryMB: 1024, DiskGB: 10, OSUser: "root",
		Env: map[string]string{}, ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		Runtime: models.RuntimeDocker,
	}
}
