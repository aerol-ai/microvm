package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeTemplatePushStore covers only the surface
// TemplateArtifactPushReconciler needs. Concurrent-safe so the
// reconciler's bounded fan-out doesn't race the test. Mirrors
// fakePushStore in shape.
type fakeTemplatePushStore struct {
	mu           sync.Mutex
	rows         map[string]*models.Template
	stateUpdates atomic.Int64
	distUpdates  atomic.Int64
	stateErr     map[string]error
}

func newFakeTemplatePushStore() *fakeTemplatePushStore {
	return &fakeTemplatePushStore{rows: map[string]*models.Template{}}
}

func (f *fakeTemplatePushStore) seed(tpl *models.Template) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *tpl
	f.rows[tpl.ID] = &cp
}

func (f *fakeTemplatePushStore) ListTemplatesPendingPush(_ context.Context) ([]*models.Template, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*models.Template, 0)
	for _, r := range f.rows {
		if (r.PushState == models.TemplatePushStatePending || r.PushState == models.TemplatePushStateError) &&
			r.Status == models.TemplateStatusReady {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeTemplatePushStore) SetTemplatePushState(_ context.Context, id, state, errMsg string) error {
	f.stateUpdates.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stateErr != nil {
		if err := f.stateErr[state]; err != nil {
			return err
		}
	}
	r, ok := f.rows[id]
	if !ok {
		return errors.New("not found")
	}
	r.PushState = state
	r.PushError = errMsg
	return nil
}

func (f *fakeTemplatePushStore) UpdateTemplatePushDistribution(_ context.Context, id, ref, digest string) error {
	f.distUpdates.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[id]
	if !ok {
		return errors.New("not found")
	}
	r.RegistryRef = ref
	r.PushDigest = digest
	return nil
}

func (f *fakeTemplatePushStore) get(id string) *models.Template {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[id]
	if !ok {
		return nil
	}
	cp := *r
	return &cp
}

// seedArtifactsOnDisk creates the three artifact files the pusher
// expects under templatesDir/<id>/ and returns the absolute paths
// suitable for stamping into the Template row.
func seedArtifactsOnDisk(t *testing.T, templatesDir, id string) (rootfsPath, memPath, statePath string) {
	t.Helper()
	dir := filepath.Join(templatesDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rootfsPath = filepath.Join(dir, templateRootfsFilename)
	memPath = filepath.Join(dir, snapshotMemoryFilename)
	statePath = filepath.Join(dir, snapshotStateFilename)
	for _, p := range []string{rootfsPath, memPath, statePath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return rootfsPath, memPath, statePath
}

func newTestTemplateReconciler(t *testing.T, store TemplateArtifactPushStore, dk TemplateArtifactPushDocker) (*TemplateArtifactPushReconciler, string) {
	t.Helper()
	templatesDir := t.TempDir()
	patPath := writePATFile(t, "token")
	pusher, err := NewTemplateArtifactPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.test",
		ClusterID: "cluster-1",
		PATPath:   patPath,
	}, dk, templatesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewTemplateArtifactPusher: %v", err)
	}
	return NewTemplateArtifactPushReconciler(pusher, store, slog.New(slog.NewTextHandler(io.Discard, nil)), 2), templatesDir
}

func TestTemplatePushReconciler_NoPendingIsNoop(t *testing.T) {
	store := newFakeTemplatePushStore()
	store.seed(&models.Template{
		ID:        "tpl-done",
		Image:     "img:1",
		Status:    models.TemplateStatusReady,
		PushState: models.TemplatePushStateActive,
	})
	rec, _ := newTestTemplateReconciler(t, store, &fakeTemplatePushDocker{})

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

// TestTemplatePushReconciler_PendingToActive pins the happy-path state
// machine: pending → pushing (claim) → active (with registry_ref +
// digest stamped). The dist update lands BEFORE the state-clear so a
// crash between them leaves the row pointing at AOCR (consumers can
// still find the bytes) rather than in 'active' with no ref.
func TestTemplatePushReconciler_PendingToActive(t *testing.T) {
	store := newFakeTemplatePushStore()
	dk := &fakeTemplatePushDocker{digest: "sha256:deadbeef"}
	rec, templatesDir := newTestTemplateReconciler(t, store, dk)

	id := "tpl-ok"
	rootfs, mem, state := seedArtifactsOnDisk(t, templatesDir, id)
	store.seed(&models.Template{
		ID: id, Image: "img:1", Status: models.TemplateStatusReady,
		PushState:          models.TemplatePushStatePending,
		RootfsPath:         rootfs,
		SnapshotMemoryPath: mem,
		SnapshotStatePath:  state,
	})

	stats, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Succeeded != 1 || stats.Failed != 0 || stats.Skipped != 0 {
		t.Fatalf("stats = %+v", stats)
	}

	row := store.get(id)
	if row.PushState != models.TemplatePushStateActive {
		t.Errorf("PushState = %q, want active", row.PushState)
	}
	if row.PushError != "" {
		t.Errorf("PushError = %q, want empty after success", row.PushError)
	}
	wantRef := testHostAOCRRef("aocr.test/cluster/cluster-1/templates/tpl-ok:latest")
	if row.RegistryRef != wantRef {
		t.Errorf("RegistryRef = %q, want %q", row.RegistryRef, wantRef)
	}
	if row.PushDigest != "sha256:deadbeef" {
		t.Errorf("PushDigest = %q, want sha256:deadbeef", row.PushDigest)
	}
	if len(dk.pushCalls) != 1 {
		t.Errorf("PushImage calls = %d, want 1", len(dk.pushCalls))
	}
}

// TestTemplatePushReconciler_PendingToErrorEligibleNextTick pins the
// recovery loop: a transient push failure leaves push_state='error'
// with push_error populated, and the next tick (after the underlying
// issue clears) re-picks the row and drives it to active. Without
// this, an AOCR blip would permanently strand the template on its
// origin node.
func TestTemplatePushReconciler_PendingToErrorEligibleNextTick(t *testing.T) {
	store := newFakeTemplatePushStore()
	dk := &fakeTemplatePushDocker{pushErr: errors.New("registry 500")}
	rec, templatesDir := newTestTemplateReconciler(t, store, dk)

	id := "tpl-retry"
	rootfs, mem, state := seedArtifactsOnDisk(t, templatesDir, id)
	store.seed(&models.Template{
		ID: id, Image: "img:1", Status: models.TemplateStatusReady,
		PushState:          models.TemplatePushStatePending,
		RootfsPath:         rootfs,
		SnapshotMemoryPath: mem,
		SnapshotStatePath:  state,
	})

	stats, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Failed != 1 || stats.Succeeded != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	row := store.get(id)
	if row.PushState != models.TemplatePushStateError {
		t.Fatalf("PushState = %q, want error", row.PushState)
	}
	if row.PushError == "" {
		t.Fatal("PushError must carry the failure reason")
	}
	if row.RegistryRef != "" {
		t.Errorf("RegistryRef = %q, want empty on failure", row.RegistryRef)
	}

	// Next tick after AOCR recovers must re-pick the row.
	dk.pushErr = nil
	if _, err := rec.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	row = store.get(id)
	if row.PushState != models.TemplatePushStateActive {
		t.Fatalf("after recovery PushState = %q, want active", row.PushState)
	}
	if row.RegistryRef == "" {
		t.Error("RegistryRef empty after recovery")
	}
}

// TestTemplatePushReconciler_SkipsNonReadyRow pins the defensive
// guard. If the scanner saw a row in `ready` + `pending` but it
// transitioned to `unhealthy` (Phase 6 PR-A corruption path) before
// the goroutine ran, we MUST NOT push — the rebuild path owns the
// re-mark.
func TestTemplatePushReconciler_SkipsNonReadyRow(t *testing.T) {
	store := newFakeTemplatePushStore()
	dk := &fakeTemplatePushDocker{}
	rec, _ := newTestTemplateReconciler(t, store, dk)

	// Bypass the list filter by seeding the row at pending+unhealthy,
	// then injecting it through ListTemplatesPendingPush's filter is
	// not the test target — we want pushOne's defensive guard.
	// Simulate the race by seeding pending+ready then mutating to
	// unhealthy between scan and push. Easier: call pushOne directly.
	store.seed(&models.Template{
		ID: "tpl-race", Image: "img:1", Status: models.TemplateStatusUnhealthy,
		PushState: models.TemplatePushStatePending,
	})
	tpl := store.get("tpl-race")

	outcome := rec.pushOne(context.Background(), tpl)
	if outcome != templatePushSkipped {
		t.Errorf("outcome = %d, want templatePushSkipped (%d)", outcome, templatePushSkipped)
	}
	if len(dk.importCalls) != 0 || len(dk.pushCalls) != 0 {
		t.Errorf("docker called for non-ready row: import=%d push=%d", len(dk.importCalls), len(dk.pushCalls))
	}
	row := store.get("tpl-race")
	if row.PushState != models.TemplatePushStateActive {
		t.Errorf("PushState = %q, want active (skip should clear pending)", row.PushState)
	}
}

// TestTemplatePushReconciler_NewReconcilerNilWhenPusherNil documents
// the nil-pusher short-circuit so callers can wire the reconciler
// unconditionally and let it no-op when push is disabled.
func TestTemplatePushReconciler_NewReconcilerNilWhenPusherNil(t *testing.T) {
	store := newFakeTemplatePushStore()
	rec := NewTemplateArtifactPushReconciler(nil, store, nil, 0)
	if rec != nil {
		t.Fatal("nil pusher must produce nil reconciler")
	}
}

// TestTemplatePushReconciler_MetadataUpdateFailureRollsToError pins
// the post-success failure arm: if UpdateTemplatePushDistribution
// fails after the push succeeded (rare: disk error), the row must be
// stamped 'error' so the next tick retries — the push is registry-
// idempotent so the retry is safe.
func TestTemplatePushReconciler_MetadataUpdateFailureRollsToError(t *testing.T) {
	store := &flakyTemplatePushStore{
		fakeTemplatePushStore: newFakeTemplatePushStore(),
		distErr:               errors.New("disk full"),
	}
	dk := &fakeTemplatePushDocker{}
	rec, templatesDir := newTestTemplateReconciler(t, store, dk)

	id := "tpl-meta-fail"
	rootfs, mem, state := seedArtifactsOnDisk(t, templatesDir, id)
	store.seed(&models.Template{
		ID: id, Image: "img:1", Status: models.TemplateStatusReady,
		PushState:          models.TemplatePushStatePending,
		RootfsPath:         rootfs,
		SnapshotMemoryPath: mem,
		SnapshotStatePath:  state,
	})

	stats, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Failed != 1 {
		t.Fatalf("stats = %+v, want Failed=1", stats)
	}
	row := store.get(id)
	if row.PushState != models.TemplatePushStateError {
		t.Errorf("PushState = %q, want error after metadata-update failure", row.PushState)
	}
	if row.PushError == "" {
		t.Error("PushError must carry the metadata error")
	}
}

func TestTemplatePushReconcilerConstructorAndCancellationBranches(t *testing.T) {
	if rec := NewTemplateArtifactPushReconciler(nil, newFakeTemplatePushStore(), nil, 0); rec != nil {
		t.Fatal("nil pusher must produce nil reconciler")
	}
	if rec := NewTemplateArtifactPushReconciler(&TemplateArtifactPusher{}, nil, nil, 0); rec != nil {
		t.Fatal("nil store must produce nil reconciler")
	}

	rec := NewTemplateArtifactPushReconciler(&TemplateArtifactPusher{}, newFakeTemplatePushStore(), nil, 0)
	if rec == nil {
		t.Fatal("expected reconciler")
	}
	if rec.maxInFlight != 2 {
		t.Fatalf("maxInFlight = %d, want default 2", rec.maxInFlight)
	}

	var nilRec *TemplateArtifactPushReconciler
	stats, err := nilRec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("nil receiver RunOnce error = %v", err)
	}
	if stats != (TemplateArtifactPushStats{}) {
		t.Fatalf("nil receiver stats = %+v, want zero value", stats)
	}

	store := newFakeTemplatePushStore()
	store.seed(&models.Template{
		ID:        "tpl-cancel",
		Image:     "img:1",
		Status:    models.TemplateStatusReady,
		PushState: models.TemplatePushStatePending,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec, _ = newTestTemplateReconciler(t, store, &fakeTemplatePushDocker{})
	if _, err := rec.RunOnce(ctx); err == nil {
		t.Fatal("canceled context should abort RunOnce")
	}

	store = newFakeTemplatePushStore()
	store.stateErr = map[string]error{
		models.TemplatePushStateActive: errors.New("clear failed"),
	}
	rec, templatesDir := newTestTemplateReconciler(t, store, &fakeTemplatePushDocker{})
	rootfs, mem, state := seedArtifactsOnDisk(t, templatesDir, "tpl-clear-fail")
	store.seed(&models.Template{
		ID:                 "tpl-clear-fail",
		Image:              "img:2",
		Status:             models.TemplateStatusReady,
		PushState:          models.TemplatePushStatePending,
		RootfsPath:         rootfs,
		SnapshotMemoryPath: mem,
		SnapshotStatePath:  state,
	})
	if _, err := rec.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce state-clear failure: %v", err)
	}
	row := store.get("tpl-clear-fail")
	if row.PushState != models.TemplatePushStatePushing {
		t.Fatalf("PushState = %q, want pushing after state-clear failure", row.PushState)
	}
}

type flakyTemplatePushStore struct {
	*fakeTemplatePushStore
	distErr error
}

func (f *flakyTemplatePushStore) UpdateTemplatePushDistribution(ctx context.Context, id, ref, digest string) error {
	if f.distErr != nil {
		return f.distErr
	}
	return f.fakeTemplatePushStore.UpdateTemplatePushDistribution(ctx, id, ref, digest)
}
