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
	"time"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeTemplatePushStore covers only the surface
// TemplateArtifactPushReconciler needs, with the store's claim protocol.
// Concurrent-safe so the reconciler's bounded fan-out doesn't race the
// test. Mirrors fakePushStore in shape.
type fakeTemplatePushStore struct {
	mu        sync.Mutex
	rows      map[string]*models.Template
	stamps    map[string]time.Time
	seq       int64
	claims    atomic.Int64
	completes atomic.Int64
	releases  atomic.Int64

	claimErr    error
	completeErr error
	releaseErr  map[string]error
	retirements []storepkg.SnapshotRegistryRetirement
	retireErr   error
}

func newFakeTemplatePushStore() *fakeTemplatePushStore {
	return &fakeTemplatePushStore{rows: map[string]*models.Template{}, stamps: map[string]time.Time{}}
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

func (f *fakeTemplatePushStore) ClaimTemplatePush(_ context.Context, id string) (*models.Template, time.Time, bool, error) {
	if f.claimErr != nil {
		return nil, time.Time{}, false, f.claimErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[id]
	if !ok || (r.PushState != models.TemplatePushStatePending && r.PushState != models.TemplatePushStateError) {
		return nil, time.Time{}, false, nil
	}
	f.seq++
	stamp := time.Unix(0, f.seq)
	f.stamps[id] = stamp
	r.PushState, r.PushError = models.TemplatePushStatePushing, ""
	f.claims.Add(1)
	cp := *r
	return &cp, stamp, true, nil
}

func (f *fakeTemplatePushStore) holds(id string, claimedAt time.Time) (*models.Template, bool) {
	r, ok := f.rows[id]
	if !ok || r.PushState != models.TemplatePushStatePushing || !f.stamps[id].Equal(claimedAt) {
		return nil, false
	}
	return r, true
}

func (f *fakeTemplatePushStore) CompleteTemplatePush(_ context.Context, id string, claimedAt time.Time, ref, digest string) (bool, error) {
	if f.completeErr != nil {
		return false, f.completeErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.holds(id, claimedAt)
	if !ok {
		return false, nil
	}
	r.RegistryRef, r.PushDigest = ref, digest
	r.PushState, r.PushError = models.TemplatePushStateActive, ""
	f.completes.Add(1)
	return true, nil
}

func (f *fakeTemplatePushStore) ReleaseTemplatePush(_ context.Context, id string, claimedAt time.Time, state, errMsg string) (bool, error) {
	if err := f.releaseErr[state]; err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.holds(id, claimedAt)
	if !ok {
		return false, nil
	}
	r.PushState, r.PushError = state, errMsg
	f.releases.Add(1)
	return true, nil
}

func (f *fakeTemplatePushStore) writes() int64 {
	return f.claims.Load() + f.completes.Load() + f.releases.Load()
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
	if store.writes() != 0 {
		t.Fatalf("unexpected writes: %d", store.writes())
	}
}

// TestTemplatePushReconciler_PendingToActive pins the happy-path state
// machine: pending → pushing (claim) → active, with registry_ref and
// digest stamped in the same fenced write, so no reader ever sees
// 'active' with no ref or a ref under 'pushing'.
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
// the post-success failure arm: if CompleteTemplatePush
// fails after the push succeeded (rare: disk error), the row must be
// stamped 'error' so the next tick retries — the push is registry-
// idempotent so the retry is safe.
func TestTemplatePushReconciler_MetadataUpdateFailureRollsToError(t *testing.T) {
	store := newFakeTemplatePushStore()
	store.completeErr = errors.New("disk full")
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

	// Completion and release both fail: the row stays 'pushing' and the
	// claim's lease is what brings it back.
	store = newFakeTemplatePushStore()
	store.completeErr = errors.New("metadata failed")
	store.releaseErr = map[string]error{models.TemplatePushStateError: errors.New("db gone")}
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

// Two template sweeps that list the same row before either claims it push
// it once: the claim, not the listing, decides who owns the row.
func TestTemplatePushSweepsNeverDoublePushARow(t *testing.T) {
	store := newFakeTemplatePushStore()
	dk := &fakeTemplatePushDocker{}
	rec, templatesDir := newTestTemplateReconciler(t, store, dk)
	rec.slots = make(chan struct{}, 1)
	rootfs, mem, state := seedArtifactsOnDisk(t, templatesDir, "tpl-race2")
	store.seed(&models.Template{
		ID: "tpl-race2", Image: "img:1", Status: models.TemplateStatusReady,
		PushState: models.TemplatePushStatePending, RootfsPath: rootfs,
		SnapshotMemoryPath: mem, SnapshotStatePath: state,
	})
	var listed sync.WaitGroup
	listed.Add(2)
	rec.testAfterList = func() {
		listed.Done()
		listed.Wait()
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = rec.sweep(context.Background())
		}()
	}
	wg.Wait()
	if len(dk.pushCalls) != 1 || store.completes.Load() != 1 {
		t.Fatalf("pushes = %d completions = %d, want one each", len(dk.pushCalls), store.completes.Load())
	}
}

// Single flight, kick and worker loop, as for snapshots.
func TestTemplatePushWorkerKickAndSingleFlight(t *testing.T) {
	store := newFakeTemplatePushStore()
	dk := &fakeTemplatePushDocker{}
	rec, templatesDir := newTestTemplateReconciler(t, store, dk)
	rootfs, mem, state := seedArtifactsOnDisk(t, templatesDir, "tpl-kick")
	store.seed(&models.Template{
		ID: "tpl-kick", Image: "img:1", Status: models.TemplateStatusReady,
		PushState: models.TemplatePushStatePending, RootfsPath: rootfs,
		SnapshotMemoryPath: mem, SnapshotStatePath: state,
	})

	// A RunOnce that meets a running sweep coalesces into it.
	if !rec.gate.enter() {
		t.Fatal("gate")
	}
	if stats, err := rec.RunOnce(context.Background()); err != nil || !stats.Coalesced {
		t.Fatalf("RunOnce beside a sweep = %+v, %v", stats, err)
	}
	if !rec.gate.again(false) {
		t.Fatal("the coalesced request was lost")
	}
	if rec.gate.again(false) {
		t.Fatal("one request ran twice")
	}

	ctx, cancel := context.WithCancel(context.Background())
	sweeps := make(chan TemplateArtifactPushStats, 4)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		rec.Run(ctx, time.Hour, func(stats TemplateArtifactPushStats, _ error) { sweeps <- stats })
	}()
	svc := &Service{templateArtifactPushReconciler: rec}
	svc.kickTemplateArtifactPushReconciler("tpl-kick")
	select {
	case stats := <-sweeps:
		if stats.Succeeded != 1 {
			t.Fatalf("kicked sweep = %+v", stats)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Kick did not wake the template worker")
	}
	cancel()
	<-stopped

	var nilRec *TemplateArtifactPushReconciler
	nilRec.Kick()
	nilRec.Run(context.Background(), time.Hour, nil)
	(&Service{}).kickTemplateArtifactPushReconciler("x")
}

// fencedTemplatePushStore loses every completion, as when a newer claim
// took the template over while the push ran.
type fencedTemplatePushStore struct{ *fakeTemplatePushStore }

func (fencedTemplatePushStore) CompleteTemplatePush(context.Context, string, time.Time, string, string) (bool, error) {
	return false, nil
}

func TestTemplatePushFencedCompletionWritesNothing(t *testing.T) {
	inner := newFakeTemplatePushStore()
	dk := &fakeTemplatePushDocker{}
	rec, templatesDir := newTestTemplateReconciler(t, fencedTemplatePushStore{inner}, dk)
	rootfs, mem, state := seedArtifactsOnDisk(t, templatesDir, "tpl-fenced")
	inner.seed(&models.Template{
		ID: "tpl-fenced", Image: "img:1", Status: models.TemplateStatusReady,
		PushState: models.TemplatePushStatePending, RootfsPath: rootfs,
		SnapshotMemoryPath: mem, SnapshotStatePath: state,
	})
	if got := rec.pushOne(context.Background(), inner.get("tpl-fenced")); got != templatePushSkipped {
		t.Fatalf("pushOne = %v, want the fenced push as a skip", got)
	}
	if row := inner.get("tpl-fenced"); row.RegistryRef != "" || row.PushState != models.TemplatePushStatePushing {
		t.Fatalf("a fenced push wrote the row: %+v", row)
	}
}

func (f *fakeTemplatePushStore) ScheduleSnapshotRegistryRetirement(_ context.Context, r storepkg.SnapshotRegistryRetirement) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.retireErr != nil {
		return f.retireErr
	}
	f.retirements = append(f.retirements, r)
	return nil
}
