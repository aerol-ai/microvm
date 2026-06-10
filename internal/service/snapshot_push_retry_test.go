package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fakePushStore covers only the surface SnapshotPushReconciler needs.
// Concurrent-safe so the reconciler's bounded fan-out doesn't race the
// test.
type fakePushStore struct {
	mu           sync.Mutex
	rows         map[string]*models.SandboxSnapshot
	stateUpdates atomic.Int64
	distUpdates  atomic.Int64
	listErr      error
	stateErr     map[string]error
	distErr      error
}

func newFakePushStore() *fakePushStore {
	return &fakePushStore{rows: map[string]*models.SandboxSnapshot{}}
}

func (f *fakePushStore) seed(snap *models.SandboxSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *snap
	f.rows[snap.Name] = &cp
}

func (f *fakePushStore) ListSnapshotsPendingPush(_ context.Context) ([]*models.SandboxSnapshot, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*models.SandboxSnapshot, 0)
	for _, r := range f.rows {
		if r.PushState == models.SnapshotPushStatePending || r.PushState == models.SnapshotPushStateError {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakePushStore) SetSnapshotPushState(_ context.Context, name, state, errMsg string) error {
	f.stateUpdates.Add(1)
	if f.stateErr != nil {
		if err := f.stateErr[state]; err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[name]
	if !ok {
		return errors.New("not found")
	}
	r.PushState = state
	r.PushError = errMsg
	return nil
}

func (f *fakePushStore) UpdateSnapshotImageDistribution(_ context.Context, name, mode, ref, digest string) error {
	f.distUpdates.Add(1)
	if f.distErr != nil {
		return f.distErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[name]
	if !ok {
		return errors.New("not found")
	}
	r.ImageDistributionMode = mode
	r.ImageRegistryRef = ref
	r.ImageDigest = digest
	return nil
}

func (f *fakePushStore) get(name string) *models.SandboxSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[name]
	if !ok {
		return nil
	}
	cp := *r
	return &cp
}

func newTestReconciler(t *testing.T, store SnapshotPushStore, fakeDocker SnapshotPushDocker) *SnapshotPushReconciler {
	t.Helper()
	patPath := writePATFile(t, "token")
	pusher, err := NewSnapshotPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.test",
		ClusterID: "cluster-1",
		PATPath:   patPath,
	}, fakeDocker, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewSnapshotPusher: %v", err)
	}
	return NewSnapshotPushReconciler(pusher, store, slog.New(slog.NewTextHandler(io.Discard, nil)), 2)
}

func TestReconciler_NoPendingIsNoop(t *testing.T) {
	store := newFakePushStore()
	store.seed(&models.SandboxSnapshot{
		Name:                  "done",
		Image:                 "img:1",
		PushState:             models.SnapshotPushStateActive,
		ImageDistributionMode: models.ImageDistributionAOCR,
	})
	rec := newTestReconciler(t, store, &fakeSnapshotPushDocker{})

	stats, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Scanned != 0 {
		t.Fatalf("Scanned = %d, want 0", stats.Scanned)
	}
	if store.distUpdates.Load() != 0 || store.stateUpdates.Load() != 0 {
		t.Fatalf("unexpected writes: dist=%d state=%d",
			store.distUpdates.Load(), store.stateUpdates.Load())
	}
}

func TestReconciler_PendingToActive(t *testing.T) {
	store := newFakePushStore()
	store.seed(&models.SandboxSnapshot{
		Name:                  "snap",
		Image:                 "aerolvm-build/abc:latest",
		PushState:             models.SnapshotPushStatePending,
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	})
	rec := newTestReconciler(t, store, &fakeSnapshotPushDocker{})

	stats, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Succeeded != 1 || stats.Failed != 0 {
		t.Fatalf("stats = %+v", stats)
	}

	row := store.get("snap")
	if row.PushState != models.SnapshotPushStateActive {
		t.Fatalf("PushState = %q, want active", row.PushState)
	}
	if row.ImageDistributionMode != models.ImageDistributionAOCR {
		t.Fatalf("ImageDistributionMode = %q, want aocr", row.ImageDistributionMode)
	}
	wantRef := "aocr.test/cluster/cluster-1/snapshots/snap:latest"
	if row.ImageRegistryRef != wantRef {
		t.Fatalf("ImageRegistryRef = %q, want %q", row.ImageRegistryRef, wantRef)
	}
}

func TestReconciler_PendingToErrorEligibleNextTick(t *testing.T) {
	store := newFakePushStore()
	store.seed(&models.SandboxSnapshot{
		Name:                  "snap",
		Image:                 "aerolvm-build/abc:latest",
		PushState:             models.SnapshotPushStatePending,
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	})
	docker := &fakeSnapshotPushDocker{err: errors.New("registry 500")}
	rec := newTestReconciler(t, store, docker)

	stats, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Failed != 1 || stats.Succeeded != 0 {
		t.Fatalf("stats = %+v", stats)
	}

	row := store.get("snap")
	if row.PushState != models.SnapshotPushStateError {
		t.Fatalf("PushState = %q, want error", row.PushState)
	}
	if row.PushError == "" {
		t.Fatal("PushError should carry the registry error")
	}
	if row.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("ImageDistributionMode flipped to %q on failure", row.ImageDistributionMode)
	}

	// Second tick must still pick the row up (error → retry-eligible).
	docker.err = nil
	if _, err := rec.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	row = store.get("snap")
	if row.PushState != models.SnapshotPushStateActive {
		t.Fatalf("after recovery PushState = %q, want active", row.PushState)
	}
}

func TestReconciler_SkipsNonLocalRow(t *testing.T) {
	// A row whose distribution mode is already remote (e.g. someone
	// re-registered with an existing registry ref) but whose push_state
	// is still 'pending' for whatever reason. The reconciler should
	// recognize there's nothing to push and flip state to active without
	// calling the docker daemon.
	store := newFakePushStore()
	store.seed(&models.SandboxSnapshot{
		Name:                  "remote",
		Image:                 "ghcr.io/org/img:latest",
		PushState:             models.SnapshotPushStatePending,
		ImageDistributionMode: models.ImageDistributionExternalRegistry,
	})
	docker := &fakeSnapshotPushDocker{}
	rec := newTestReconciler(t, store, docker)

	stats, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Skipped != 1 {
		t.Fatalf("stats = %+v, want Skipped=1", stats)
	}
	if len(docker.calls) != 0 {
		t.Fatalf("docker called %d times for a non-local row", len(docker.calls))
	}
	row := store.get("remote")
	if row.PushState != models.SnapshotPushStateActive {
		t.Fatalf("non-local row left in PushState=%q", row.PushState)
	}
}

func TestReconciler_NewReconcilerNilWhenPusherNil(t *testing.T) {
	store := newFakePushStore()
	rec := NewSnapshotPushReconciler(nil, store, nil, 0)
	if rec != nil {
		t.Fatal("nil pusher must produce nil reconciler")
	}
}

func TestReconcilerEdgeBranches(t *testing.T) {
	ctx := context.Background()

	if rec := NewSnapshotPushReconciler(nil, nil, nil, 0); rec != nil {
		t.Fatal("nil pusher/store should produce nil reconciler")
	}

	t.Run("list error", func(t *testing.T) {
		store := newFakePushStore()
		store.listErr = errors.New("list failed")
		rec := newTestReconciler(t, store, &fakeSnapshotPushDocker{})
		if _, err := rec.RunOnce(ctx); err == nil || !strings.Contains(err.Error(), "list failed") {
			t.Fatalf("RunOnce list error = %v", err)
		}
	})

	t.Run("claim failure", func(t *testing.T) {
		store := newFakePushStore()
		store.seed(&models.SandboxSnapshot{
			Name:                  "snap-claim",
			Image:                 "img:1",
			PushState:             models.SnapshotPushStatePending,
			ImageDistributionMode: models.ImageDistributionLocalOnly,
		})
		store.stateErr = map[string]error{
			models.SnapshotPushStatePushing: errors.New("claim failed"),
		}
		rec := newTestReconciler(t, store, &fakeSnapshotPushDocker{})
		stats, err := rec.RunOnce(ctx)
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if stats.Failed != 1 {
			t.Fatalf("stats = %+v, want 1 failed", stats)
		}
		row := store.get("snap-claim")
		if row.PushState != models.SnapshotPushStatePending {
			t.Fatalf("PushState = %q, want pending after claim failure", row.PushState)
		}
	})

	t.Run("metadata failure", func(t *testing.T) {
		store := newFakePushStore()
		store.seed(&models.SandboxSnapshot{
			Name:                  "snap-meta",
			Image:                 "img:2",
			PushState:             models.SnapshotPushStatePending,
			ImageDistributionMode: models.ImageDistributionLocalOnly,
		})
		store.distErr = errors.New("metadata failed")
		rec := newTestReconciler(t, store, &fakeSnapshotPushDocker{})
		stats, err := rec.RunOnce(ctx)
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if stats.Failed != 1 {
			t.Fatalf("stats = %+v, want 1 failed", stats)
		}
		row := store.get("snap-meta")
		if row.PushState != models.SnapshotPushStateError {
			t.Fatalf("PushState = %q, want error", row.PushState)
		}
	})

	t.Run("state clear failure", func(t *testing.T) {
		store := newFakePushStore()
		store.seed(&models.SandboxSnapshot{
			Name:                  "snap-clear",
			Image:                 "img:3",
			PushState:             models.SnapshotPushStatePending,
			ImageDistributionMode: models.ImageDistributionLocalOnly,
		})
		store.stateErr = map[string]error{
			models.SnapshotPushStateActive: errors.New("clear failed"),
		}
		rec := newTestReconciler(t, store, &fakeSnapshotPushDocker{})
		stats, err := rec.RunOnce(ctx)
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if stats.Failed != 1 {
			t.Fatalf("stats = %+v, want 1 failed", stats)
		}
		row := store.get("snap-clear")
		if row.PushState != models.SnapshotPushStatePushing {
			t.Fatalf("PushState = %q, want pushing after clear failure", row.PushState)
		}
	})

	t.Run("nil snapshot skipped", func(t *testing.T) {
		store := newFakePushStore()
		rec := newTestReconciler(t, store, &fakeSnapshotPushDocker{})
		if got := rec.pushOne(ctx, nil); got != snapshotPushSkipped {
			t.Fatalf("pushOne(nil) = %v, want skipped", got)
		}
	})
}
