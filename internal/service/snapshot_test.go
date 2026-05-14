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
	"github.com/aerol-ai/microvm/pkg/mounts"
)

type fakeSnapshotRuntime struct {
	imageID string
	hits    int
	lastRef string
	lastImg string
	err     error
}

func (f *fakeSnapshotRuntime) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	panic("unexpected Create")
}
func (f *fakeSnapshotRuntime) CreateSnapshot(_ context.Context, containerRef, imageRef string) (string, error) {
	f.hits++
	f.lastRef = containerRef
	f.lastImg = imageRef
	if f.err != nil {
		return "", f.err
	}
	return f.imageID, nil
}
func (f *fakeSnapshotRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("unexpected Start")
}
func (f *fakeSnapshotRuntime) Stop(context.Context, string) error { panic("unexpected Stop") }
func (f *fakeSnapshotRuntime) Destroy(context.Context, *models.Sandbox) error {
	panic("unexpected Destroy")
}
func (f *fakeSnapshotRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	panic("unexpected Resize")
}
func (f *fakeSnapshotRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("unexpected Inspect")
}
func (f *fakeSnapshotRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	panic("unexpected ListManaged")
}
func (f *fakeSnapshotRuntime) Ping(context.Context) error { panic("unexpected Ping") }
func (f *fakeSnapshotRuntime) RemoveImage(context.Context, string) error {
	panic("unexpected RemoveImage")
}
func (f *fakeSnapshotRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	panic("unexpected PushAllowedPorts")
}
func (f *fakeSnapshotRuntime) ClearNetworkRules(string) error    { return nil }
func (f *fakeSnapshotRuntime) ApplyNetworkBlockAll(string) error { return nil }

func TestCreateSnapshotIdempotentByName(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	sandbox := &models.Sandbox{
		ID:             "sb-snap-idem",
		Image:          "ubuntu:22.04",
		Status:         models.SandboxStatusStarted,
		ContainerID:    "ctr-snap-idem",
		ContainerIP:    "10.0.0.10",
		CPU:            1,
		MemoryMB:       1024,
		DiskGB:         10,
		OSUser:         "root",
		Env:            map[string]string{},
		ToolboxEnabled: true,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
		LastActiveAt:   time.Now().UTC(),
		Runtime:        models.RuntimeDocker,
	}
	if err := st.Create(ctx, sandbox); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	rt := &fakeSnapshotRuntime{imageID: "sha256:snapshot-1"}
	svc := &Service{store: st, docker: rt, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	first, err := svc.CreateSnapshot(ctx, sandbox.ID, models.CreateSandboxSnapshotRequest{Name: "snapshots/demo:v1"})
	if err != nil {
		t.Fatalf("first CreateSnapshot() error = %v", err)
	}
	second, err := svc.CreateSnapshot(ctx, sandbox.ID, models.CreateSandboxSnapshotRequest{Name: "snapshots/demo:v1"})
	if err != nil {
		t.Fatalf("second CreateSnapshot() error = %v", err)
	}
	if rt.hits != 1 {
		t.Fatalf("CreateSnapshot runtime hits = %d, want 1", rt.hits)
	}
	if first.ImageID != rt.imageID || second.ImageID != rt.imageID {
		t.Fatalf("unexpected image ids: first=%q second=%q want=%q", first.ImageID, second.ImageID, rt.imageID)
	}
	if first.Name != second.Name || first.SourceSandboxID != sandbox.ID {
		t.Fatalf("unexpected snapshots: first=%+v second=%+v", first, second)
	}
	if rt.lastRef != sandbox.ContainerID {
		t.Fatalf("runtime container ref = %q, want %q", rt.lastRef, sandbox.ContainerID)
	}
}

func TestCreateSnapshotConflictsAcrossSandboxes(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	for _, sandbox := range []*models.Sandbox{
		{
			ID: "sb-snap-one", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted,
			ContainerID: "ctr-one", CPU: 1, MemoryMB: 1024, DiskGB: 10, OSUser: "root",
			Env: map[string]string{}, ToolboxEnabled: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), LastActiveAt: time.Now().UTC(), Runtime: models.RuntimeDocker,
		},
		{
			ID: "sb-snap-two", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted,
			ContainerID: "ctr-two", CPU: 1, MemoryMB: 1024, DiskGB: 10, OSUser: "root",
			Env: map[string]string{}, ToolboxEnabled: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), LastActiveAt: time.Now().UTC(), Runtime: models.RuntimeDocker,
		},
	} {
		if err := st.Create(ctx, sandbox); err != nil {
			t.Fatalf("seed sandbox %s: %v", sandbox.ID, err)
		}
	}

	rt := &fakeSnapshotRuntime{imageID: "sha256:snapshot-1"}
	svc := &Service{store: st, docker: rt, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	if _, err := svc.CreateSnapshot(ctx, "sb-snap-one", models.CreateSandboxSnapshotRequest{Name: "snapshots/shared:v1"}); err != nil {
		t.Fatalf("first CreateSnapshot() error = %v", err)
	}
	if _, err := svc.CreateSnapshot(ctx, "sb-snap-two", models.CreateSandboxSnapshotRequest{Name: "snapshots/shared:v1"}); !errors.Is(err, store.ErrSnapshotNameConflict) {
		t.Fatalf("expected ErrSnapshotNameConflict, got %v", err)
	}
	if rt.hits != 1 {
		t.Fatalf("CreateSnapshot runtime hits = %d, want 1", rt.hits)
	}
}
