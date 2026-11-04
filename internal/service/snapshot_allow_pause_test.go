package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// allow_pause: false means "never pause my sandbox for this snapshot". A
// sandbox that is not stopped is refused with a 409 before any runtime work,
// on every runtime; a stopped one is snapshotted; omitting the field keeps
// the default (pause briefly).

func allowPauseService(t *testing.T, status models.SandboxStatus, runtime string) (*Service, *fakeSnapshotRuntime, string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID: "sb-allow-pause", Image: "alpine:3.20", Status: status, ContainerID: "ctr-allow-pause",
		CPU: 1, MemoryMB: 1024, DiskGB: 10, OSUser: "root", Env: map[string]string{}, ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now, Runtime: runtime,
	}
	if err := st.Create(ctx, sandbox); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	rt := &fakeSnapshotRuntime{imageID: "sha256:allow-pause"}
	svc := &Service{store: st, docker: rt, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return svc, rt, sandbox.ID
}

func TestCreateSnapshotAllowPause(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     models.SandboxStatus
		allowPause *bool
		refused    bool
	}{
		{"running, default", models.SandboxStatusStarted, nil, false},
		{"running, allowed", models.SandboxStatusStarted, boolPtr(true), false},
		{"running, not allowed", models.SandboxStatusStarted, boolPtr(false), true},
		{"creating, not allowed", models.SandboxStatusCreating, boolPtr(false), true},
		{"error, not allowed", models.SandboxStatusError, boolPtr(false), true},
		{"stopped, not allowed", models.SandboxStatusStopped, boolPtr(false), false},
		{"passivated, not allowed", models.SandboxStatusPassivated, boolPtr(false), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, rt, id := allowPauseService(t, tc.status, models.RuntimeDocker)
			snap, err := svc.CreateSnapshot(context.Background(), id,
				models.CreateSandboxSnapshotRequest{Name: "allow-pause", AllowPause: tc.allowPause})
			if tc.refused {
				if !errors.Is(err, models.ErrSnapshotSourceNotReady) || !strings.Contains(err.Error(), "allow_pause is false") {
					t.Fatalf("err = %v, want a 409 naming allow_pause", err)
				}
				if rt.hits != 0 {
					t.Fatal("the runtime was asked to snapshot a sandbox the caller said must not pause")
				}
				if _, getErr := svc.GetSnapshot(context.Background(), "allow-pause"); getErr == nil {
					t.Fatal("a refused snapshot left a catalogue row")
				}
				return
			}
			if err != nil || snap == nil || rt.hits != 1 {
				t.Fatalf("CreateSnapshot = %+v, %v (runtime hits %d), want it taken", snap, err, rt.hits)
			}
		})
	}
}

// A retry of a snapshot that already exists pauses nothing, so allow_pause
// does not turn it into a refusal.
func TestCreateSnapshotAllowPauseReplaysAnExistingSnapshot(t *testing.T) {
	svc, rt, id := allowPauseService(t, models.SandboxStatusStarted, models.RuntimeDocker)
	ctx := context.Background()
	first, err := svc.CreateSnapshot(ctx, id, models.CreateSandboxSnapshotRequest{Name: "replayed"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := svc.CreateSnapshot(ctx, id, models.CreateSandboxSnapshotRequest{Name: "replayed", AllowPause: boolPtr(false)})
	if err != nil || again.ImageID != first.ImageID || rt.hits != 1 {
		t.Fatalf("retry with allow_pause false = %+v, %v (hits %d), want the stored snapshot", again, err, rt.hits)
	}
}

// The facades send no allow_pause, so they get the default on every
// runtime, Firecracker included.
func TestCreateSnapshotWithAliasUsesTheDefaultPause(t *testing.T) {
	svc, rt, id := allowPauseService(t, models.SandboxStatusStarted, models.RuntimeDocker)
	snap, created, err := svc.CreateSnapshotWithAlias(context.Background(), id,
		models.CreateSandboxSnapshotRequest{Name: "facade-snap"},
		models.SnapshotAlias{Alias: "facade-alias", Facade: models.FacadeE2B})
	if err != nil || !created || snap == nil || rt.hits != 1 {
		t.Fatalf("CreateSnapshotWithAlias on a running sandbox = %+v, %v, %v (hits %d)", snap, created, err, rt.hits)
	}
}
