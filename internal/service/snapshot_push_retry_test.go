package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakePushStore covers only the surface SnapshotPushReconciler needs, with
// the store's claim protocol: a claim matches only a queued row, and a
// completion or release only the claim it was given. Concurrent-safe so the
// reconciler's bounded fan-out doesn't race the test.
type fakePushStore struct {
	mu        sync.Mutex
	rows      map[string]*models.SandboxSnapshot
	stamps    map[string]time.Time
	seq       int64
	claims    atomic.Int64
	completes atomic.Int64
	releases  atomic.Int64

	listErr     error
	claimErr    error
	completeErr error
	releaseErr  map[string]error

	// The retirement ledger, keyed ref@digest, with its failure knobs.
	retirements    map[string]store.SnapshotRegistryRetirement
	scheduleErr    error
	listRetireErr  error
	inUseErr       error
	deferErr       error
	dropRetireErr  error
	deferredCount  int
	droppedRetires []string
}

func newFakePushStore() *fakePushStore {
	return &fakePushStore{
		rows:        map[string]*models.SandboxSnapshot{},
		stamps:      map[string]time.Time{},
		retirements: map[string]store.SnapshotRegistryRetirement{},
	}
}

func (f *fakePushStore) ScheduleSnapshotRegistryRetirement(_ context.Context, r store.SnapshotRegistryRetirement) error {
	if f.scheduleErr != nil {
		return f.scheduleErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.RegistryRef + "@" + r.Digest
	if _, ok := f.retirements[key]; !ok && r.RegistryRef != "" && r.Digest != "" {
		f.retirements[key] = r
	}
	return nil
}

func (f *fakePushStore) ListDueSnapshotRegistryRetirements(_ context.Context, _ time.Time, limit int) ([]store.SnapshotRegistryRetirement, error) {
	if f.listRetireErr != nil {
		return nil, f.listRetireErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.SnapshotRegistryRetirement
	for _, r := range f.retirements {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b store.SnapshotRegistryRetirement) int { return strings.Compare(a.Digest, b.Digest) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakePushStore) SnapshotRegistryCopyInUse(_ context.Context, ref, digest, _, name string) (bool, bool, error) {
	if f.inUseErr != nil {
		return false, false, f.inUseErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var inUse, pending bool
	for _, r := range f.rows {
		if r.ImageRegistryRef == ref && r.ImageDigest == digest {
			inUse = true
		}
		if r.Name == name && r.PushState != models.SnapshotPushStateActive {
			pending = true
		}
	}
	return inUse, pending, nil
}

func (f *fakePushStore) DeferSnapshotRegistryRetirement(_ context.Context, ref, digest, failure string) error {
	if f.deferErr != nil {
		return f.deferErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deferredCount++
	key := ref + "@" + digest
	if r, ok := f.retirements[key]; ok && failure != "" {
		r.Attempts++
		r.LastError = failure
		f.retirements[key] = r
	}
	return nil
}

func (f *fakePushStore) DeleteSnapshotRegistryRetirement(_ context.Context, ref, digest string) error {
	if f.dropRetireErr != nil {
		return f.dropRetireErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.retirements, ref+"@"+digest)
	f.droppedRetires = append(f.droppedRetires, ref+"@"+digest)
	return nil
}

func (f *fakePushStore) retirement(ref, digest string) (store.SnapshotRegistryRetirement, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.retirements[ref+"@"+digest]
	return r, ok
}

func (f *fakePushStore) seed(snap *models.SandboxSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *snap
	f.rows[snap.Name] = &cp
}

func (f *fakePushStore) ListSnapshotsPendingPushPage(_ context.Context, after store.SnapshotPushCursor, limit int) ([]*models.SandboxSnapshot, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*models.SandboxSnapshot
	for _, r := range f.rows {
		if r.PushState != models.SnapshotPushStatePending && r.PushState != models.SnapshotPushStateError {
			continue
		}
		if r.Name <= after.Name {
			continue
		}
		cp := *r
		out = append(out, &cp)
	}
	slices.SortFunc(out, func(a, b *models.SandboxSnapshot) int { return strings.Compare(a.Name, b.Name) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakePushStore) ClaimSnapshotPush(_ context.Context, _, name string) (*models.SandboxSnapshot, time.Time, bool, error) {
	if f.claimErr != nil {
		return nil, time.Time{}, false, f.claimErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[name]
	if !ok || (r.PushState != models.SnapshotPushStatePending && r.PushState != models.SnapshotPushStateError) {
		return nil, time.Time{}, false, nil
	}
	f.seq++
	stamp := time.Unix(0, f.seq)
	f.stamps[name] = stamp
	r.PushState, r.PushError = models.SnapshotPushStatePushing, ""
	f.claims.Add(1)
	cp := *r
	return &cp, stamp, true, nil
}

// holds reports whether claimedAt is the live claim on name. Caller holds mu.
func (f *fakePushStore) holds(name string, claimedAt time.Time) (*models.SandboxSnapshot, bool) {
	r, ok := f.rows[name]
	if !ok || r.PushState != models.SnapshotPushStatePushing || !f.stamps[name].Equal(claimedAt) {
		return nil, false
	}
	return r, true
}

func (f *fakePushStore) CompleteSnapshotPush(_ context.Context, _, name string, claimedAt time.Time, mode, ref, digest string) (bool, error) {
	if f.completeErr != nil {
		return false, f.completeErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.holds(name, claimedAt)
	if !ok {
		return false, nil
	}
	r.ImageDistributionMode, r.ImageRegistryRef, r.ImageDigest = mode, ref, digest
	r.PushState, r.PushError = models.SnapshotPushStateActive, ""
	f.completes.Add(1)
	return true, nil
}

func (f *fakePushStore) ReleaseSnapshotPush(_ context.Context, _, name string, claimedAt time.Time, state, errMsg string) (bool, error) {
	if err := f.releaseErr[state]; err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.holds(name, claimedAt)
	if !ok {
		return false, nil
	}
	r.PushState, r.PushError = state, errMsg
	f.releases.Add(1)
	return true, nil
}

func (f *fakePushStore) writes() int64 {
	return f.claims.Load() + f.completes.Load() + f.releases.Load()
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
	return newTestReconcilerN(t, store, fakeDocker, 2)
}

func newTestReconcilerN(t *testing.T, store SnapshotPushStore, fakeDocker SnapshotPushDocker, maxInFlight int) *SnapshotPushReconciler {
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
	return NewSnapshotPushReconciler(pusher, store, slog.New(slog.NewTextHandler(io.Discard, nil)), maxInFlight)
}

func pendingLocal(name string) *models.SandboxSnapshot {
	return &models.SandboxSnapshot{
		Name:                  name,
		Image:                 "aerolvm-build/" + name + ":latest",
		SourceSandboxID:       "sb-src",
		CreatedAt:             time.Now().UTC(),
		PushState:             models.SnapshotPushStatePending,
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	}
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
	if store.writes() != 0 {
		t.Fatalf("unexpected writes: %d", store.writes())
	}
}

func TestReconciler_PendingToActive(t *testing.T) {
	store := newFakePushStore()
	store.seed(pendingLocal("snap"))
	rec := newTestReconciler(t, store, &fakeSnapshotPushDocker{digest: "sha256:pushed"})

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
	wantRef := "aocr.test/cluster/cluster-1/snapshots/snap:latest" + archTagSuffix(hostSnapshotArch())
	if row.ImageRegistryRef != wantRef || row.ImageDigest != "sha256:pushed" {
		t.Fatalf("registry copy = %q %q, want %q sha256:pushed", row.ImageRegistryRef, row.ImageDigest, wantRef)
	}
}

func TestReconciler_PendingToErrorEligibleNextTick(t *testing.T) {
	store := newFakePushStore()
	store.seed(pendingLocal("snap"))
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
		// A failed sweep releases the gate: the next one runs.
		store.listErr = nil
		if stats, err := rec.RunOnce(ctx); err != nil || stats.Coalesced {
			t.Fatalf("RunOnce after a failed sweep = %+v, %v", stats, err)
		}
	})

	cases := []struct {
		name      string
		set       func(*fakePushStore, *fakeSnapshotPushDocker)
		wantStats SnapshotPushReconcileStats
		wantState string
	}{
		{
			name:      "claim error leaves the row queued",
			set:       func(s *fakePushStore, _ *fakeSnapshotPushDocker) { s.claimErr = errors.New("claim failed") },
			wantStats: SnapshotPushReconcileStats{Scanned: 1, Failed: 1}, wantState: models.SnapshotPushStatePending,
		},
		{
			name:      "metadata failure releases to error",
			set:       func(s *fakePushStore, _ *fakeSnapshotPushDocker) { s.completeErr = errors.New("metadata failed") },
			wantStats: SnapshotPushReconcileStats{Scanned: 1, Failed: 1}, wantState: models.SnapshotPushStateError,
		},
		{
			name: "metadata and release both fail: the lease recovers it",
			set: func(s *fakePushStore, _ *fakeSnapshotPushDocker) {
				s.completeErr = errors.New("metadata failed")
				s.releaseErr = map[string]error{models.SnapshotPushStateError: errors.New("db gone")}
			},
			wantStats: SnapshotPushReconcileStats{Scanned: 1, Failed: 1}, wantState: models.SnapshotPushStatePushing,
		},
		{
			name: "push and release both fail",
			set: func(s *fakePushStore, d *fakeSnapshotPushDocker) {
				d.err = errors.New("registry 500")
				s.releaseErr = map[string]error{models.SnapshotPushStateError: errors.New("db gone")}
			},
			wantStats: SnapshotPushReconcileStats{Scanned: 1, Failed: 1}, wantState: models.SnapshotPushStatePushing,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakePushStore()
			store.seed(pendingLocal("snap"))
			dk := &fakeSnapshotPushDocker{}
			tc.set(store, dk)
			rec := newTestReconciler(t, store, dk)
			stats, err := rec.RunOnce(ctx)
			if err != nil || stats != tc.wantStats {
				t.Fatalf("RunOnce = %+v, %v; want %+v", stats, err, tc.wantStats)
			}
			if got := store.get("snap").PushState; got != tc.wantState {
				t.Fatalf("PushState = %q, want %q", got, tc.wantState)
			}
		})
	}

	t.Run("non-local row whose release fails", func(t *testing.T) {
		store := newFakePushStore()
		remote := pendingLocal("remote")
		remote.ImageDistributionMode = models.ImageDistributionExternalRegistry
		store.seed(remote)
		store.releaseErr = map[string]error{models.SnapshotPushStateActive: errors.New("db gone")}
		rec := newTestReconciler(t, store, &fakeSnapshotPushDocker{})
		if got := rec.pushOne(ctx, remote); got != snapshotPushSkipped {
			t.Fatalf("pushOne = %v, want skipped", got)
		}
	})

	t.Run("nil snapshot skipped", func(t *testing.T) {
		store := newFakePushStore()
		rec := newTestReconciler(t, store, &fakeSnapshotPushDocker{})
		if got := rec.pushOne(ctx, nil); got != snapshotPushSkipped {
			t.Fatalf("pushOne(nil) = %v, want skipped", got)
		}
	})

	t.Run("a row another worker holds is skipped", func(t *testing.T) {
		store := newFakePushStore()
		store.seed(pendingLocal("held"))
		if _, _, ok, _ := store.ClaimSnapshotPush(ctx, "", "held"); !ok {
			t.Fatal("claim")
		}
		dk := &fakeSnapshotPushDocker{}
		rec := newTestReconciler(t, store, dk)
		if got := rec.pushOne(ctx, pendingLocal("held")); got != snapshotPushSkipped || len(dk.calls) != 0 {
			t.Fatalf("pushOne = %v with %d pushes, want a skip and none", got, len(dk.calls))
		}
	})
}

func TestSnapshotPushReconcilerConstructorAndCancellationBranches(t *testing.T) {
	if rec := NewSnapshotPushReconciler(nil, newFakePushStore(), nil, 0); rec != nil {
		t.Fatal("nil pusher must produce nil reconciler")
	}
	if rec := NewSnapshotPushReconciler(&SnapshotPusher{}, nil, nil, 0); rec != nil {
		t.Fatal("nil store must produce nil reconciler")
	}

	rec := NewSnapshotPushReconciler(&SnapshotPusher{}, newFakePushStore(), nil, 0)
	if rec == nil {
		t.Fatal("expected reconciler")
	}
	if rec.maxInFlight != 2 || cap(rec.slots) != 2 {
		t.Fatalf("maxInFlight = %d slots %d, want default 2", rec.maxInFlight, cap(rec.slots))
	}

	var nilRec *SnapshotPushReconciler
	stats, err := nilRec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("nil receiver RunOnce error = %v", err)
	}
	if stats != (SnapshotPushReconcileStats{}) {
		t.Fatalf("nil receiver stats = %+v, want zero value", stats)
	}
	nilRec.Kick()
	nilRec.Run(context.Background(), time.Hour, nil)
	// A zero reconciler (attached in accessor tests) is inert too.
	(&SnapshotPushReconciler{}).Kick()
	if stats, err := (&SnapshotPushReconciler{}).RunOnce(context.Background()); err != nil || stats != (SnapshotPushReconcileStats{}) {
		t.Fatalf("zero reconciler RunOnce = %+v, %v", stats, err)
	}

	store := newFakePushStore()
	store.seed(pendingLocal("snap-cancel"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec = newTestReconciler(t, store, &fakeSnapshotPushDocker{})
	if _, err := rec.RunOnce(ctx); err == nil {
		t.Fatal("canceled context should abort RunOnce")
	}
	if got := store.get("snap-cancel").PushState; got != models.SnapshotPushStatePending {
		t.Fatalf("a cancelled sweep claimed the row: %q", got)
	}
}

// blockingPushDocker holds every push until release is closed, and records
// how many pushes were in flight at once.
type blockingPushDocker struct {
	started  chan string
	release  chan struct{}
	inFlight atomic.Int64
	peak     atomic.Int64
	pushes   atomic.Int64
	onPush   func(dest string)
}

func newBlockingPushDocker() *blockingPushDocker {
	return &blockingPushDocker{started: make(chan string, 64), release: make(chan struct{})}
}

func (b *blockingPushDocker) PushImage(ctx context.Context, req docker.PushImageRequest) (string, error) {
	n := b.inFlight.Add(1)
	defer b.inFlight.Add(-1)
	for {
		peak := b.peak.Load()
		if n <= peak || b.peak.CompareAndSwap(peak, n) {
			break
		}
	}
	b.pushes.Add(1)
	if b.onPush != nil {
		b.onPush(req.DestRef)
	}
	b.started <- req.DestRef
	select {
	case <-b.release:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if req.OnDigest != nil {
		req.OnDigest("sha256:" + strings.Repeat("a", 64))
	}
	return req.DestRef, nil
}

func openPushStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, path
}

// The double-claim regression: two sweeps that list the same pending row
// before either claims it. The store's claim lets exactly one of them push;
// the other sees the claim match nothing and walks away.
func TestSnapshotPushSweepsNeverDoublePushARow(t *testing.T) {
	ctx := context.Background()
	st, _ := openPushStore(t)
	if err := st.CreateSnapshot(ctx, pendingLocal("snap-race")); err != nil {
		t.Fatal(err)
	}
	dk := &fakeSnapshotPushDocker{digest: "sha256:race"}
	rec := newTestReconcilerN(t, st, dk, 1)

	// Both sweeps hold their page before either goes on to claim.
	var listed sync.WaitGroup
	listed.Add(2)
	rec.testAfterList = func() {
		listed.Done()
		listed.Wait()
	}
	var wg sync.WaitGroup
	results := make([]SnapshotPushReconcileStats, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// sweep, not RunOnce: this pins the claim itself, below the
			// single-flight gate that normally keeps sweeps apart.
			results[i], _ = rec.sweep(ctx)
		}(i)
	}
	wg.Wait()

	if len(dk.calls) != 1 {
		t.Fatalf("the row was pushed %d times, want once", len(dk.calls))
	}
	total := results[0]
	total.add(results[1])
	if total.Scanned != 2 || total.Succeeded != 1 || total.Skipped != 1 {
		t.Fatalf("stats = %+v + %+v, want one push and one skip", results[0], results[1])
	}
	row, err := st.GetSnapshot(ctx, "", "snap-race")
	if err != nil || row.PushState != models.SnapshotPushStateActive || row.ImageDigest != "sha256:race" {
		t.Fatalf("row = %+v, %v", row, err)
	}
}

// A push that finishes after its claim was taken over must not write: the
// newer claim owns the row. Here the lease runs out mid-push and another
// worker claims the row; the first worker's completion is fenced off.
func TestSnapshotPushStaleClaimCompletionIsFenced(t *testing.T) {
	ctx := context.Background()
	st, path := openPushStore(t)
	if err := st.CreateSnapshot(ctx, pendingLocal("snap-fence")); err != nil {
		t.Fatal(err)
	}
	dk := newBlockingPushDocker()
	close(dk.release)
	var takeover time.Time
	dk.onPush = func(string) {
		cb96SQL(t, path, `UPDATE sandbox_snapshots SET push_claimed_at = '2000-01-01 00:00:00+00:00' WHERE name = 'snap-fence'`)
		_, stamp, ok, err := st.ClaimSnapshotPush(ctx, "", "snap-fence")
		if err != nil || !ok {
			t.Errorf("takeover claim = %v, %v", ok, err)
		}
		takeover = stamp
	}
	rec := newTestReconcilerN(t, st, dk, 1)
	stats, err := rec.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Succeeded != 0 || stats.Skipped != 1 {
		t.Fatalf("stats = %+v, want the fenced push as a skip", stats)
	}
	row, _ := st.GetSnapshot(ctx, "", "snap-fence")
	if row.PushState != models.SnapshotPushStatePushing || row.ImageRegistryRef != "" {
		t.Fatalf("the stale push wrote the row: %+v", row)
	}
	// The newer claim can still complete.
	if applied, err := st.CompleteSnapshotPush(ctx, "", "snap-fence", takeover, models.ImageDistributionAOCR, "ref", "sha256:new"); err != nil || !applied {
		t.Fatalf("takeover completion = %v, %v", applied, err)
	}
}

// RunOnce is single-flight: a call that arrives while a sweep runs does not
// sweep beside it. It returns at once (Coalesced) and the running sweep goes
// round again, so a row created meanwhile is still pushed.
func TestSnapshotPushRunOnceIsSingleFlight(t *testing.T) {
	ctx := context.Background()
	st, _ := openPushStore(t)
	if err := st.CreateSnapshot(ctx, pendingLocal("snap-a")); err != nil {
		t.Fatal(err)
	}
	dk := newBlockingPushDocker()
	rec := newTestReconcilerN(t, st, dk, 4)

	done := make(chan SnapshotPushReconcileStats)
	go func() {
		stats, _ := rec.RunOnce(ctx)
		done <- stats
	}()
	<-dk.started // the first sweep is pushing snap-a

	if err := st.CreateSnapshot(ctx, pendingLocal("snap-b")); err != nil {
		t.Fatal(err)
	}
	second, err := rec.RunOnce(ctx)
	if err != nil || !second.Coalesced || second.Scanned != 0 {
		t.Fatalf("concurrent RunOnce = %+v, %v; want coalesced", second, err)
	}
	close(dk.release)
	first := <-done
	if first.Succeeded != 2 || dk.pushes.Load() != 2 {
		t.Fatalf("first RunOnce = %+v with %d pushes; want it to go round again for snap-b", first, dk.pushes.Load())
	}
}

// maxInFlight bounds pushes on the node, not per sweep: even two sweeps
// running at once (below the gate) share one set of slots.
func TestSnapshotPushInFlightBoundIsNodeWide(t *testing.T) {
	ctx := context.Background()
	st, _ := openPushStore(t)
	for _, name := range []string{"n1", "n2", "n3", "n4", "n5", "n6"} {
		if err := st.CreateSnapshot(ctx, pendingLocal(name)); err != nil {
			t.Fatal(err)
		}
	}
	dk := newBlockingPushDocker()
	rec := newTestReconcilerN(t, st, dk, 2)
	rec.pageSize = 2 // several pages per sweep

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = rec.sweep(ctx)
		}()
	}
	// Let the first two pushes start, then confirm nothing else squeezes in.
	<-dk.started
	<-dk.started
	select {
	case dest := <-dk.started:
		t.Fatalf("a third push started (%s) with maxInFlight 2", dest)
	case <-time.After(100 * time.Millisecond):
	}
	close(dk.release)
	wg.Wait()
	if dk.peak.Load() != 2 || dk.pushes.Load() != 6 {
		t.Fatalf("peak %d pushes %d, want 2 and every row once", dk.peak.Load(), dk.pushes.Load())
	}
}

// The worker: Kick wakes it without waiting for the tick, a burst of kicks
// collapses, and it stops with its context.
func TestSnapshotPushWorkerRunsOnKick(t *testing.T) {
	st, _ := openPushStore(t)
	if err := st.CreateSnapshot(context.Background(), pendingLocal("snap-kick")); err != nil {
		t.Fatal(err)
	}
	dk := &fakeSnapshotPushDocker{}
	rec := newTestReconcilerN(t, st, dk, 1)
	ctx, cancel := context.WithCancel(context.Background())
	sweeps := make(chan SnapshotPushReconcileStats, 8)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		rec.Run(ctx, time.Hour, func(stats SnapshotPushReconcileStats, err error) {
			if err != nil {
				t.Errorf("sweep: %v", err)
			}
			sweeps <- stats
		})
	}()
	for range 5 {
		rec.Kick()
	}
	select {
	case stats := <-sweeps:
		if stats.Succeeded != 1 {
			t.Fatalf("kicked sweep = %+v", stats)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Kick did not wake the worker")
	}
	cancel()
	<-stopped
	if len(dk.calls) != 1 {
		t.Fatalf("pushes = %d, want 1", len(dk.calls))
	}
}

// The service's create path wakes the worker rather than sweeping itself.
func TestKickSnapshotPushReconcilerWakesTheWorker(t *testing.T) {
	rec := NewSnapshotPushReconciler(&SnapshotPusher{}, newFakePushStore(), nil, 1)
	svc := &Service{snapshotPushReconciler: rec}
	svc.kickSnapshotPushReconciler(&models.SandboxSnapshot{PushState: models.SnapshotPushStateActive})
	if len(rec.gate.wake) != 0 {
		t.Fatal("an active snapshot woke the worker")
	}
	svc.kickSnapshotPushReconciler(&models.SandboxSnapshot{PushState: models.SnapshotPushStatePending})
	svc.kickSnapshotPushReconciler(&models.SandboxSnapshot{PushState: models.SnapshotPushStatePending})
	if len(rec.gate.wake) != 1 {
		t.Fatalf("pending wake-ups = %d, want them collapsed into 1", len(rec.gate.wake))
	}
}

// Paging walks the whole backlog once, a page at a time.
func TestSnapshotPushSweepPagesThroughTheBacklog(t *testing.T) {
	ctx := context.Background()
	st, _ := openPushStore(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i, name := range []string{"p1", "p2", "p3", "p4", "p5"} {
		snap := pendingLocal(name)
		snap.CreatedAt = base.Add(time.Duration(i) * time.Second)
		if err := st.CreateSnapshot(ctx, snap); err != nil {
			t.Fatal(err)
		}
	}
	dk := &fakeSnapshotPushDocker{}
	rec := newTestReconcilerN(t, st, dk, 2)
	rec.pageSize = 2
	stats, err := rec.RunOnce(ctx)
	if err != nil || stats.Scanned != 5 || stats.Succeeded != 5 || len(dk.calls) != 5 {
		t.Fatalf("RunOnce = %+v, %v with %d pushes", stats, err, len(dk.calls))
	}
}
