package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// On a containerd node a snapshot's image is in containerd's store (from a
// containerd sandbox, or a Firecracker one), so deleting the snapshot must
// remove it there, not only from Docker.
func TestDeleteSnapshotRemovesTheImageFromEveryEngine(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	snapshot := &models.SandboxSnapshot{
		Name: "fc-app", Image: "aerolvm-snapshot/abc:latest", ImageID: "sha256:abc",
		SourceSandboxID: "sb-fc", CreatedAt: time.Now().UTC().Round(0),
	}
	if err := st.CreateSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	dockerRT, containerdRT := &fakeSnapshotRuntime{}, &fakeSnapshotRuntime{}
	svc := &Service{store: st, docker: dockerRT, containerd: containerdRT, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := svc.DeleteSnapshot(ctx, snapshot.Name); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	for name, rt := range map[string]*fakeSnapshotRuntime{"docker": dockerRT, "containerd": containerdRT} {
		if rt.removeHits != 1 || rt.lastRemoved != snapshot.Image {
			t.Errorf("%s RemoveImage hits %d ref %q, want 1 %q", name, rt.removeHits, rt.lastRemoved, snapshot.Image)
		}
	}
}

func TestDeleteSnapshotKeepsTheRowWhenAnEngineCannotRemove(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	snapshot := &models.SandboxSnapshot{
		Name: "fc-app", Image: "aerolvm-snapshot/abc:latest", ImageID: "sha256:abc",
		SourceSandboxID: "sb-fc", CreatedAt: time.Now().UTC().Round(0),
	}
	if err := st.CreateSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	svc := &Service{store: st, docker: &fakeSnapshotRuntime{}, containerd: &fakeSnapshotRuntime{removeErr: errors.New("containerd down")},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := svc.DeleteSnapshot(ctx, snapshot.Name); err == nil {
		t.Fatal("DeleteSnapshot succeeded although containerd kept the image")
	}
	if _, err := st.GetSnapshot(ctx, snapshot.OwnerRef, snapshot.Name); err != nil {
		t.Fatalf("the row went although its image is still there (a retry could not find it): %v", err)
	}
}
