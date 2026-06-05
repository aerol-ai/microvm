package vmm

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

// newTestPool opens a fresh on-disk SQLite store and wraps it in a
// Pool. Same pattern internal/store uses (t.TempDir to keep tests
// hermetic, t.Cleanup to close the DB) — the policy layer's tests
// exercise the same store the daemon ships with, no in-memory fake.
func newTestPool(t *testing.T) (*Pool, *store.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, nil), st
}

func TestPool_RecordSpawningAndLoaded(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	if err := p.RecordSpawning(ctx, "vmms-a", "tpl-a", now); err != nil {
		t.Fatalf("record spawning: %v", err)
	}
	// While 'spawning', the slot is not claimable.
	if _, err := p.Acquire(ctx, "tpl-a", "sb1", now); !errors.Is(err, ErrNoLoadedSlot) {
		t.Fatalf("expected ErrNoLoadedSlot for spawning-only pool, got %v", err)
	}

	if err := p.RecordLoaded(ctx, "vmms-a", "/run/x/api.sock", "/run/x", 7, now); err != nil {
		t.Fatalf("record loaded: %v", err)
	}
	slot, err := p.Acquire(ctx, "tpl-a", "sb1", now)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if slot.Status != StatusAllocated || slot.SandboxID != "sb1" {
		t.Fatalf("post-acquire slot = %+v", slot)
	}
	if slot.VsockCID != 7 || slot.APISocket == "" {
		t.Fatalf("acquired slot missing artifact fields: %+v", slot)
	}
}

func TestPool_RecordFailed_DropsToReleased(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	if err := p.RecordSpawning(ctx, "vmms-x", "tpl-a", now); err != nil {
		t.Fatalf("record spawning: %v", err)
	}
	if err := p.RecordFailed(ctx, "vmms-x", "spawner kaboom", now); err != nil {
		t.Fatalf("record failed: %v", err)
	}
	// The slot is released — invisible to Acquire and absent from the
	// refill-list.
	if _, err := p.Acquire(ctx, "tpl-a", "sb1", now); !errors.Is(err, ErrNoLoadedSlot) {
		t.Fatalf("expected ErrNoLoadedSlot, got %v", err)
	}
	got, err := p.ListNonReleased(ctx, "tpl-a")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("released slot still in non-released list: %+v", got)
	}
}

func TestPool_Acquire_IdempotentBySandbox(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()
	if err := p.RecordSpawning(ctx, "vmms-a", "tpl-a", now); err != nil {
		t.Fatalf("spawning: %v", err)
	}
	if err := p.RecordLoaded(ctx, "vmms-a", "/api", "/dir", 3, now); err != nil {
		t.Fatalf("loaded: %v", err)
	}
	// Two more loaded slots so we'd have something else to pick if the
	// idempotency check were broken.
	for _, id := range []string{"vmms-b", "vmms-c"} {
		if err := p.RecordSpawning(ctx, id, "tpl-a", now); err != nil {
			t.Fatalf("spawning %s: %v", id, err)
		}
		if err := p.RecordLoaded(ctx, id, "/api/"+id, "/dir/"+id, 4, now); err != nil {
			t.Fatalf("loaded %s: %v", id, err)
		}
	}

	first, err := p.Acquire(ctx, "tpl-a", "sb1", now)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	again, err := p.Acquire(ctx, "tpl-a", "sb1", now.Add(time.Second))
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	if again.ID != first.ID {
		t.Fatalf("re-acquire returned a different slot: %s vs %s", again.ID, first.ID)
	}
}

func TestPool_TemplateIsolation(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	// One loaded slot per template.
	for _, tpl := range []string{"tpl-a", "tpl-b"} {
		id := "vmms-" + tpl
		if err := p.RecordSpawning(ctx, id, tpl, now); err != nil {
			t.Fatalf("spawn %s: %v", id, err)
		}
		if err := p.RecordLoaded(ctx, id, "/api/"+id, "/dir/"+id, 3, now); err != nil {
			t.Fatalf("load %s: %v", id, err)
		}
	}

	slot, err := p.Acquire(ctx, "tpl-a", "sb1", now)
	if err != nil {
		t.Fatalf("acquire tpl-a: %v", err)
	}
	if slot.TemplateID != "tpl-a" {
		t.Fatalf("crossed lineage: got %s, want tpl-a", slot.TemplateID)
	}
	// Exhausting tpl-a must not steal from tpl-b.
	if _, err := p.Acquire(ctx, "tpl-a", "sb2", now); !errors.Is(err, ErrNoLoadedSlot) {
		t.Fatalf("expected ErrNoLoadedSlot for tpl-a exhaustion, got %v", err)
	}
}

func TestPool_Release_NoRecycling(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()
	if err := p.RecordSpawning(ctx, "vmms-a", "tpl-a", now); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	if err := p.RecordLoaded(ctx, "vmms-a", "/api", "/dir", 3, now); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := p.Acquire(ctx, "tpl-a", "sb1", now); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := p.Release(ctx, "sb1", now); err != nil {
		t.Fatalf("release: %v", err)
	}

	// After release, the slot is NOT back in 'loaded' — the state
	// machine never moves backwards. Acquire must return the sentinel,
	// not the freshly-released slot.
	if _, err := p.Acquire(ctx, "tpl-a", "sb2", now); !errors.Is(err, ErrNoLoadedSlot) {
		t.Fatalf("released slot incorrectly recycled to loaded: got %v", err)
	}

	// Release a sandbox that never claimed a slot — must be a no-op.
	if err := p.Release(ctx, "sb-never", now); err != nil {
		t.Fatalf("release of never-claimed sandbox: %v", err)
	}
}

func TestPool_ConcurrentAcquire(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	// 3 loaded slots for tpl-a.
	for i, cid := range []uint32{3, 4, 5} {
		id := fmt.Sprintf("vmms-%d", i)
		if err := p.RecordSpawning(ctx, id, "tpl-a", now); err != nil {
			t.Fatalf("spawn %s: %v", id, err)
		}
		if err := p.RecordLoaded(ctx, id, "/api/"+id, "/dir/"+id, cid, now); err != nil {
			t.Fatalf("load %s: %v", id, err)
		}
	}

	// 10 racing acquirers — exactly 3 must win.
	const n = 10
	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		wins       int
		exhausted  int
		otherErrs  []error
		claimedIDs = map[string]struct{}{}
	)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			slot, err := p.Acquire(ctx, "tpl-a", fmt.Sprintf("sb-%d", i), now)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
				if _, dup := claimedIDs[slot.ID]; dup {
					otherErrs = append(otherErrs, fmt.Errorf("duplicate slot id %s", slot.ID))
				}
				claimedIDs[slot.ID] = struct{}{}
			case errors.Is(err, ErrNoLoadedSlot):
				exhausted++
			default:
				otherErrs = append(otherErrs, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if len(otherErrs) > 0 {
		t.Fatalf("unexpected errors: %v", otherErrs)
	}
	if wins != 3 || exhausted != n-3 {
		t.Fatalf("wins=%d exhausted=%d, want 3/%d", wins, exhausted, n-3)
	}
	if len(claimedIDs) != 3 {
		t.Fatalf("distinct claimed ids = %d, want 3", len(claimedIDs))
	}
}

func TestPool_StatsByStatus(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	// Build: 1 spawning + 1 loaded + 1 allocated + 1 released for
	// tpl-a; 1 loaded for tpl-b (visibility-by-template check).
	if err := p.RecordSpawning(ctx, "vmms-spawning", "tpl-a", now); err != nil {
		t.Fatal(err)
	}
	for id, cid := range map[string]uint32{"vmms-loaded": 3, "vmms-claimed": 4, "vmms-failed": 5} {
		if err := p.RecordSpawning(ctx, id, "tpl-a", now); err != nil {
			t.Fatal(err)
		}
		// vmms-failed never gets loaded — it goes straight to released
		// via RecordFailed below.
		if id == "vmms-failed" {
			continue
		}
		if err := p.RecordLoaded(ctx, id, "/api/"+id, "/dir/"+id, cid, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.RecordFailed(ctx, "vmms-failed", "boom", now); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Acquire(ctx, "tpl-a", "sb-c", now); err != nil {
		t.Fatal(err)
	}
	// tpl-b's slot stays loaded.
	if err := p.RecordSpawning(ctx, "vmms-b", "tpl-b", now); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordLoaded(ctx, "vmms-b", "/api/b", "/dir/b", 6, now); err != nil {
		t.Fatal(err)
	}

	stats, err := p.Stats(ctx, "tpl-a")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	// Either vmms-loaded or vmms-claimed got allocated (tie on
	// loaded_at); either way the count breakdown is 1/1/1/1.
	if stats.Spawning != 1 || stats.Loaded != 1 || stats.Allocated != 1 || stats.Released != 1 {
		t.Fatalf("stats = %+v, want each=1", stats)
	}
	if stats.Total != 4 {
		t.Fatalf("stats.Total = %d, want 4", stats.Total)
	}

	statsB, err := p.Stats(ctx, "tpl-b")
	if err != nil {
		t.Fatalf("stats b: %v", err)
	}
	if statsB.Loaded != 1 || statsB.Total != 1 {
		t.Fatalf("stats b = %+v, want loaded=1 total=1", statsB)
	}
}

func TestPool_ReapReleased(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	// Two released rows at different ages; one loaded survivor that
	// the reap must never touch.
	if err := p.RecordSpawning(ctx, "vmms-old", "tpl-a", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordFailed(ctx, "vmms-old", "old", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordSpawning(ctx, "vmms-new", "tpl-a", now); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordFailed(ctx, "vmms-new", "new", now); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordSpawning(ctx, "vmms-keep", "tpl-a", now); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordLoaded(ctx, "vmms-keep", "/api", "/dir", 3, now); err != nil {
		t.Fatal(err)
	}

	// Reap with cutoff at -1h: only vmms-old should go.
	deleted, err := p.ReapReleased(ctx, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("reaped %d, want 1", deleted)
	}
	stats, err := p.Stats(ctx, "tpl-a")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Loaded != 1 {
		t.Fatalf("loaded survivor lost: %+v", stats)
	}
	if stats.Released != 1 {
		t.Fatalf("vmms-new released row should remain (newer than cutoff): %+v", stats)
	}
}

func TestPool_ReapReleasedKeepsRowWhenShutdownFails(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour)

	if err := p.RecordSpawning(ctx, "vmms-old", "tpl-a", old); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordLoaded(ctx, "vmms-old", "/api", "/dir", 3, old); err != nil {
		t.Fatal(err)
	}
	parent := &fakeSpawner{}
	p.registerHandle("vmms-old", &fakeHandle{
		apiSocket:   "/api",
		runDir:      "/dir",
		parent:      parent,
		shutdownErr: errors.New("shutdown failed"),
	})
	if _, err := p.Acquire(ctx, "tpl-a", "sb1", old); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := p.Release(ctx, "sb1", old); err != nil {
		t.Fatalf("release: %v", err)
	}

	deleted, err := p.ReapReleased(ctx, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("reaped %d rows, want 0 when shutdown fails", deleted)
	}
	if got := parent.shutdownCnt.Load(); got != 1 {
		t.Fatalf("shutdown attempts = %d, want 1", got)
	}
	p.handlesMu.Lock()
	_, ok := p.handles["vmms-old"]
	p.handlesMu.Unlock()
	if !ok {
		t.Fatal("shutdown-failed handle was not restored for retry")
	}
	stats, err := p.Stats(ctx, "tpl-a")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Released != 1 {
		t.Fatalf("released row was dropped after failed shutdown: %+v", stats)
	}
}

func TestPool_ReleaseOrphanedRowsAtStart(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	if err := p.RecordSpawning(ctx, "vmms-spawning", "tpl-a", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordSpawning(ctx, "vmms-loaded", "tpl-a", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordLoaded(ctx, "vmms-loaded", "/api", "/dir", 3, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordSpawning(ctx, "vmms-live", "tpl-a", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordLoaded(ctx, "vmms-live", "/api/live", "/dir/live", 4, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Acquire(ctx, "tpl-a", "sb-live", now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("acquire live slot: %v", err)
	}

	released, err := p.releaseOrphanedRowsAtStart(ctx, now)
	if err != nil {
		t.Fatalf("release orphaned rows: %v", err)
	}
	if released != 2 {
		t.Fatalf("released %d rows, want 2 orphaned warm rows", released)
	}
	stats, err := p.Stats(ctx, "tpl-a")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Allocated != 1 || stats.Released != 2 {
		t.Fatalf("stats after startup repair = %+v, want allocated=1 released=2", stats)
	}
}

func TestPool_DepthConfig(t *testing.T) {
	p, _ := newTestPool(t)
	// Default depth applies to any template without an override.
	p.SetDefaultDepth(2)
	if got := p.DepthFor("tpl-a"); got != 2 {
		t.Fatalf("default DepthFor = %d, want 2", got)
	}
	// Per-template override wins.
	p.SetDepth("tpl-a", 5)
	if got := p.DepthFor("tpl-a"); got != 5 {
		t.Fatalf("override DepthFor = %d, want 5", got)
	}
	// Other templates still get the default.
	if got := p.DepthFor("tpl-b"); got != 2 {
		t.Fatalf("other-template DepthFor = %d, want 2", got)
	}
	// Setting depth=0 is "stop warming" — distinct from "no override".
	p.SetDepth("tpl-a", 0)
	if got := p.DepthFor("tpl-a"); got != 0 {
		t.Fatalf("zeroed DepthFor = %d, want 0", got)
	}
	// Negative depths are clamped to 0.
	p.SetDepth("tpl-c", -3)
	if got := p.DepthFor("tpl-c"); got != 0 {
		t.Fatalf("negative DepthFor = %d, want 0", got)
	}
}

func TestPool_GetBySandbox(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	// No claim yet → nil, nil.
	if got, err := p.Get(ctx, "sb-never"); err != nil || got != nil {
		t.Fatalf("nil-case Get: %v / %+v", err, got)
	}

	if err := p.RecordSpawning(ctx, "vmms-a", "tpl-a", now); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordLoaded(ctx, "vmms-a", "/api", "/dir", 3, now); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Acquire(ctx, "tpl-a", "sb1", now); err != nil {
		t.Fatal(err)
	}
	got, err := p.Get(ctx, "sb1")
	if err != nil || got == nil {
		t.Fatalf("get: %v / %+v", err, got)
	}
	if got.ID != "vmms-a" || got.Status != StatusAllocated {
		t.Fatalf("got = %+v", got)
	}
}

func TestPool_SlotFromStore_Nil(t *testing.T) {
	if got := slotFromStore(nil); got != nil {
		t.Fatalf("slotFromStore(nil) = %+v, want nil", got)
	}
}

func TestPool_SetDefaultDepth_Negative(t *testing.T) {
	p, _ := newTestPool(t)
	p.SetDefaultDepth(-5)
	if got := p.DepthFor("any"); got != 0 {
		t.Fatalf("SetDefaultDepth(-5) → DepthFor = %d, want 0", got)
	}
}

func TestPool_Acquire_WrapsStoreError(t *testing.T) {
	ctx := context.Background()
	p, st := newTestPool(t)
	st.Close()
	_, err := p.Acquire(ctx, "tpl-a", "sb1", time.Now().UTC())
	if err == nil || errors.Is(err, ErrNoLoadedSlot) {
		t.Fatalf("expected wrapped store error, got %v", err)
	}
}

func TestPool_AcquireWithHandle_NonSentinelError(t *testing.T) {
	ctx := context.Background()
	p, st := newTestPool(t)
	st.Close()
	_, _, err := p.AcquireWithHandle(ctx, "tpl-a", "sb1", time.Now().UTC())
	if err == nil || errors.Is(err, ErrNoLoadedSlot) {
		t.Fatalf("expected wrapped store error, got %v", err)
	}
}

func TestPool_Close_ShutdownFailure(t *testing.T) {
	p, _ := newTestPool(t)
	fs := &fakeSpawner{}
	shutErr := errors.New("process busy")
	p.registerHandle("vmms-h1", &fakeHandle{apiSocket: "/api", runDir: "/dir", parent: fs, shutdownErr: shutErr})
	p.registerHandle("vmms-h2", &fakeHandle{apiSocket: "/api2", runDir: "/dir2", parent: fs, shutdownErr: shutErr})
	// Both shutdown calls fail — drained should be 0.
	if drained := p.Close(context.Background(), 0); drained != 0 {
		t.Fatalf("Close drained = %d, want 0 when all shutdowns fail", drained)
	}
}

func TestPool_ReleaseOrphanedRowsAtStart_Error(t *testing.T) {
	p, st := newTestPool(t)
	st.Close()
	_, err := p.releaseOrphanedRowsAtStart(context.Background(), time.Now().UTC())
	if err == nil {
		t.Fatal("expected error from closed store")
	}
}

func TestPool_Get_StoreError(t *testing.T) {
	p, st := newTestPool(t)
	st.Close()
	_, err := p.Get(context.Background(), "sb1")
	if err == nil {
		t.Fatal("expected error from closed store")
	}
}

func TestPool_Release_StoreError(t *testing.T) {
	p, st := newTestPool(t)
	st.Close()
	err := p.Release(context.Background(), "sb1", time.Now().UTC())
	if err == nil {
		t.Fatal("expected error from closed store")
	}
}

func TestPool_Stats_StoreError(t *testing.T) {
	p, st := newTestPool(t)
	st.Close()
	_, err := p.Stats(context.Background(), "tpl-a")
	if err == nil {
		t.Fatal("expected error from closed store")
	}
}

func TestPool_ListNonReleased_StoreError(t *testing.T) {
	p, st := newTestPool(t)
	st.Close()
	_, err := p.ListNonReleased(context.Background(), "tpl-a")
	if err == nil {
		t.Fatal("expected error from closed store")
	}
}

func TestPool_ReapReleased_ListError(t *testing.T) {
	p, st := newTestPool(t)
	st.Close()
	_, err := p.ReapReleased(context.Background(), time.Now().UTC())
	if err == nil {
		t.Fatal("expected error from closed store")
	}
}

func TestPool_ReapReleased_ErrNotFound(t *testing.T) {
	// Two concurrent ReapReleased calls: the first deletes the row,
	// the second sees ErrNotFound and silently continues (not an error).
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour)

	if err := p.RecordSpawning(ctx, "vmms-race", "tpl-a", old); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordFailed(ctx, "vmms-race", "boom", old); err != nil {
		t.Fatal(err)
	}

	cutoff := now.Add(-time.Hour)
	var wg sync.WaitGroup
	var total int
	var mu sync.Mutex
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := p.ReapReleased(ctx, cutoff)
			if err != nil {
				// ErrNotFound is swallowed inside ReapReleased, so no
				// error should leak to the caller.
				t.Errorf("unexpected error from ReapReleased: %v", err)
				return
			}
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	}
	wg.Wait()
	// Exactly 1 row was deleted across both goroutines.
	if total != 1 {
		t.Fatalf("total deletions across two concurrent reaps = %d, want 1", total)
	}
}

// dbClosingHandle is a SpawnedHandle whose Shutdown closes the store
// so that the next store call (e.g. DeleteFirecrackerVMMSlot) fails.
type dbClosingHandle struct {
	st        *store.Store
	apiSocket string
	runDir    string
}

func (h *dbClosingHandle) APISocket() string { return h.apiSocket }
func (h *dbClosingHandle) RunDir() string    { return h.runDir }
func (h *dbClosingHandle) Pid() int          { return 0 }
func (h *dbClosingHandle) Shutdown(_ context.Context, _ time.Duration) error {
	h.st.Close()
	return nil
}

func TestPool_ReapReleased_DeleteError(t *testing.T) {
	ctx := context.Background()
	p, st := newTestPool(t)
	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour)

	if err := p.RecordSpawning(ctx, "vmms-del", "tpl-a", old); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordFailed(ctx, "vmms-del", "boom", old); err != nil {
		t.Fatal(err)
	}
	// Register a handle whose Shutdown closes the DB so the subsequent
	// DeleteFirecrackerVMMSlot fails with a non-ErrNotFound error.
	p.registerHandle("vmms-del", &dbClosingHandle{st: st, apiSocket: "/api", runDir: "/dir"})

	_, err := p.ReapReleased(ctx, now.Add(-time.Hour))
	if err == nil {
		t.Fatal("expected error when delete fails after successful list")
	}
}
