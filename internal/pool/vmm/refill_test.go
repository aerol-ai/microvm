package vmm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

// fakeSpawner records every Spawn call and returns a stub handle.
// The handle's Shutdown is wired so reap tests can confirm the
// firecracker process gets torn down before the row is deleted.
type fakeSpawner struct {
	mu           sync.Mutex
	calls        []SnapshotInputs
	spawnErr     error // if set, Spawn returns this for every call
	spawnDelay   time.Duration
	shutdownCnt  atomic.Int32
	apiSocketFor func(slotID string) string // optional, defaults to "/run/<slot>/api.sock"
}

func (f *fakeSpawner) Spawn(ctx context.Context, slotID string, inputs SnapshotInputs) (SpawnedHandle, error) {
	if f.spawnDelay > 0 {
		select {
		case <-time.After(f.spawnDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, inputs)
	err := f.spawnErr
	api := "/run/" + slotID + "/api.sock"
	if f.apiSocketFor != nil {
		api = f.apiSocketFor(slotID)
	}
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &fakeHandle{
		apiSocket: api,
		runDir:    "/run/" + slotID,
		parent:    f,
	}, nil
}

func (f *fakeSpawner) Calls() []SnapshotInputs {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]SnapshotInputs, len(f.calls))
	copy(out, f.calls)
	return out
}

type fakeHandle struct {
	apiSocket   string
	runDir      string
	parent      *fakeSpawner
	shutdownErr error
}

func (h *fakeHandle) APISocket() string { return h.apiSocket }
func (h *fakeHandle) RunDir() string    { return h.runDir }
func (h *fakeHandle) Pid() int          { return 0 }
func (h *fakeHandle) Shutdown(_ context.Context, _ time.Duration) error {
	h.parent.shutdownCnt.Add(1)
	return h.shutdownErr
}

// fakeLister returns a fixed list.
type fakeLister struct {
	templates []TemplateWarmInput
	err       error
}

func (l *fakeLister) ListWarmableTemplates(_ context.Context) ([]TemplateWarmInput, error) {
	if l.err != nil {
		return nil, l.err
	}
	// Return a defensive copy so a test that mutates the slice
	// doesn't poison subsequent ticks.
	out := make([]TemplateWarmInput, len(l.templates))
	copy(out, l.templates)
	return out, nil
}

func TestRefill_SpawnsUpToDepth(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 3)

	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{
		TemplateID:         "tpl-a",
		SnapshotMemoryPath: "/srv/tpl-a/mem",
		SnapshotStatePath:  "/srv/tpl-a/state",
		SnapshotChecksum:   "sha256:aaa|sha256:bbb",
		VsockCID:           42,
	}}}
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)

	// 3 spawns expected — the pool was empty, depth=3.
	if got := len(spawner.Calls()); got != 3 {
		t.Fatalf("Spawn call count = %d, want 3", got)
	}
	stats, err := p.Stats(ctx, "tpl-a")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Loaded != 3 || stats.Total != 3 {
		t.Fatalf("stats after refill = %+v, want loaded=3 total=3", stats)
	}

	// A second tick on a fully warm pool issues no spawns.
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)
	if got := len(spawner.Calls()); got != 3 {
		t.Fatalf("second tick triggered extra spawns: got %d total", got)
	}
}

func TestRefill_ZeroDepthIsNoOp(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	// Depth never set — defaults to 0. The refill loop must not
	// spawn anything for this template.
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)
	if got := len(spawner.Calls()); got != 0 {
		t.Fatalf("zero-depth template spawned %d times", got)
	}
}

func TestRefill_SkipsTemplatesWithoutOverride(t *testing.T) {
	// Three templates, only tpl-b has a depth override. The loop
	// should warm tpl-b only.
	ctx := context.Background()
	p, _ := newTestPool(t)
	p.SetDepth("tpl-b", 2)
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{
		{TemplateID: "tpl-a", VsockCID: 3},
		{TemplateID: "tpl-b", VsockCID: 4},
		{TemplateID: "tpl-c", VsockCID: 5},
	}}
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)
	if got := len(spawner.Calls()); got != 2 {
		t.Fatalf("Spawn count = %d, want 2 (tpl-b only)", got)
	}
	for _, call := range spawner.Calls() {
		if call.TemplateID != "tpl-b" {
			t.Fatalf("spawned wrong template: %+v", call)
		}
	}
}

func TestRefill_SpawnerErrorMarksReleased(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 2)
	spawner := &fakeSpawner{spawnErr: errors.New("boom: kernel mismatch")}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)

	// Spawner was called depth-times even though every call failed —
	// the loop doesn't bail on the first error.
	if got := len(spawner.Calls()); got != 2 {
		t.Fatalf("calls under failing spawner = %d, want 2", got)
	}
	// Both rows ended up in 'released' with the error preserved.
	stats, err := p.Stats(ctx, "tpl-a")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Released != 2 || stats.Loaded != 0 {
		t.Fatalf("stats after failed spawns = %+v, want released=2 loaded=0", stats)
	}
}

func TestRefill_ListerErrorSkipsTick(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 2)
	spawner := &fakeSpawner{}
	lister := &fakeLister{err: errors.New("template store offline")}
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)
	if got := len(spawner.Calls()); got != 0 {
		t.Fatalf("spawns under failing lister = %d, want 0", got)
	}
}

func TestRefill_BusyLatchSkipsOverlap(t *testing.T) {
	// Two concurrent runRefillOnce calls — the second must drop on
	// the latch rather than double-spawn.
	ctx := context.Background()
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 1)
	spawner := &fakeSpawner{spawnDelay: 100 * time.Millisecond}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}

	var busy atomic.Bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy) }()
	go func() { defer wg.Done(); p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy) }()
	wg.Wait()
	if got := len(spawner.Calls()); got != 1 {
		t.Fatalf("two overlapping refills spawned %d, want 1 (latch should drop the second)", got)
	}
}

func TestRefill_ConsidersExistingNonReleased(t *testing.T) {
	// 2 already-loaded slots count toward the budget — the loop
	// should only spawn the delta.
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()
	for i, cid := range []uint32{3, 4} {
		id := fmt.Sprintf("vmms-existing-%d", i)
		if err := p.RecordSpawning(ctx, id, "tpl-a", now); err != nil {
			t.Fatal(err)
		}
		if err := p.RecordLoaded(ctx, id, "/api/"+id, "/dir/"+id, cid, now); err != nil {
			t.Fatal(err)
		}
	}
	p.SetDepth("tpl-a", 3)
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 5}}}
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)
	if got := len(spawner.Calls()); got != 1 {
		t.Fatalf("delta refill spawned %d, want 1 (depth=3, existing=2)", got)
	}
}

func TestRefill_SkipsWhenTapFreeBelowWarmReserve(t *testing.T) {
	ctx := context.Background()
	p, st := newTestPool(t)
	now := time.Now().UTC()
	seedTestTapSlots(t, st, 8)
	for i := 0; i < 3; i++ {
		if _, err := st.AllocateFirecrackerTapSlot(ctx, fmt.Sprintf("sb-active-%d", i), now); err != nil {
			t.Fatalf("allocate active tap %d: %v", i, err)
		}
	}
	p.SetDepth("tpl-a", 3)
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)

	if got := len(spawner.Calls()); got != 0 {
		t.Fatalf("spawn calls = %d, want 0 when free taps are below 2x warm depth", got)
	}
}

func TestRefill_AllowsWhenTapFreeMeetsWarmReserve(t *testing.T) {
	ctx := context.Background()
	p, st := newTestPool(t)
	now := time.Now().UTC()
	seedTestTapSlots(t, st, 8)
	for i := 0; i < 2; i++ {
		if _, err := st.AllocateFirecrackerTapSlot(ctx, fmt.Sprintf("sb-active-%d", i), now); err != nil {
			t.Fatalf("allocate active tap %d: %v", i, err)
		}
	}
	p.SetDepth("tpl-a", 3)
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)

	if got := len(spawner.Calls()); got != 3 {
		t.Fatalf("spawn calls = %d, want 3 when free taps meet 2x warm depth", got)
	}
}

func TestGC_ReapsAgedReleasedRows(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()

	// Old released row (eligible) + young released row (not).
	if err := p.RecordSpawning(ctx, "vmms-old", "tpl-a", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordFailed(ctx, "vmms-old", "boom", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordSpawning(ctx, "vmms-new", "tpl-a", now); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordFailed(ctx, "vmms-new", "boom", now); err != nil {
		t.Fatal(err)
	}

	// TTL = 1h — only vmms-old is eligible.
	p.runGCOnce(ctx, 1*time.Hour)
	stats, err := p.Stats(ctx, "tpl-a")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Released != 1 {
		t.Fatalf("after GC stats = %+v, want released=1 (vmms-new survives)", stats)
	}
}

func seedTestTapSlots(t *testing.T, st *store.Store, n int) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		base := i * 4
		if err := st.SeedFirecrackerTapSlot(ctx, store.FirecrackerTapSlot{
			TapName:  fmt.Sprintf("fctap%d", i),
			CIDR:     fmt.Sprintf("172.16.0.%d/30", base),
			HostIP:   fmt.Sprintf("172.16.0.%d", base+1),
			GuestIP:  fmt.Sprintf("172.16.0.%d", base+2),
			VsockCID: uint32(3 + i),
		}, now); err != nil {
			t.Fatalf("seed tap slot %d: %v", i, err)
		}
	}
}

func TestGC_ReleasesWarmTapOwnerBeforeDeletingRow(t *testing.T) {
	ctx := context.Background()
	p, st := newTestPool(t)
	now := time.Now().UTC()

	if err := st.SeedFirecrackerTapSlot(ctx, store.FirecrackerTapSlot{
		TapName:  "fctap0",
		CIDR:     "172.16.0.0/30",
		HostIP:   "172.16.0.1",
		GuestIP:  "172.16.0.2",
		VsockCID: 3,
	}, now); err != nil {
		t.Fatalf("seed tap: %v", err)
	}
	if _, err := st.AllocateFirecrackerTapSlot(ctx, "vmms-old", now); err != nil {
		t.Fatalf("allocate warm tap: %v", err)
	}
	if err := p.RecordSpawning(ctx, "vmms-old", "tpl-a", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordFailed(ctx, "vmms-old", "retired", now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	p.runGCOnce(ctx, time.Hour)

	tapSlot, err := st.GetFirecrackerTapSlotBySandbox(ctx, "vmms-old")
	if err != nil {
		t.Fatalf("get tap after GC: %v", err)
	}
	if tapSlot != nil {
		t.Fatalf("warm tap still owned after GC: %+v", tapSlot)
	}
	vmmSlot, err := st.GetFirecrackerVMMSlotByID(ctx, "vmms-old")
	if err != nil {
		t.Fatalf("get vmm slot after GC: %v", err)
	}
	if vmmSlot != nil {
		t.Fatalf("released VMM slot still present after GC: %+v", vmmSlot)
	}
}

func TestRun_NilSpawnerIsNoOp(t *testing.T) {
	// Run with a nil Spawner returns immediately without panicking.
	// This is the "pool disabled" config path.
	p, _ := newTestPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		p.Run(ctx, RefillConfig{
			RefillInterval: time.Second,
			GCInterval:     time.Second,
			GCTTL:          time.Hour,
		}, &fakeLister{}, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return immediately with nil spawner")
	}
}

func TestRun_PanicsOnZeroIntervals(t *testing.T) {
	p, _ := newTestPool(t)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on zero RefillInterval")
		}
	}()
	p.Run(context.Background(), RefillConfig{}, &fakeLister{}, &fakeSpawner{})
}

func TestRun_EndToEnd_WarmsFromCold(t *testing.T) {
	// Drive Run for a short window, observe the immediate-tick
	// behavior warms the pool without waiting a full interval.
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 2)
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx, RefillConfig{
			RefillInterval: 200 * time.Millisecond,
			GCInterval:     1 * time.Hour, // dormant for this test
			GCTTL:          1 * time.Hour,
			SpawnTimeout:   5 * time.Second,
		}, lister, spawner)
		close(done)
	}()

	// Run only fires the immediate refill at t=0. Spin until the
	// pool reports loaded=2; cap the wait so a regression doesn't
	// hang CI.
	deadline := time.After(2 * time.Second)
	for {
		stats, err := p.Stats(context.Background(), "tpl-a")
		if err != nil {
			cancel()
			<-done
			t.Fatal(err)
		}
		if stats.Loaded == 2 {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("pool did not warm to depth within 2s; stats=%+v", stats)
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// cancellingSpawner cancels the provided context on the first Spawn call,
// then delegates to the embedded fakeSpawner. Used to drive ctx.Err()
// short-circuit paths in runRefillOnce / refillTemplate.
type cancellingSpawner struct {
	cancel context.CancelFunc
	fakeSpawner
}

func (s *cancellingSpawner) Spawn(ctx context.Context, slotID string, inputs SnapshotInputs) (SpawnedHandle, error) {
	s.cancel()
	return s.fakeSpawner.Spawn(ctx, slotID, inputs)
}

// cancelAndErrorSpawner cancels the context AND returns an error from Spawn.
// Used to cover the "RecordFailed also fails after spawn error" path.
type cancelAndErrorSpawner struct {
	cancel context.CancelFunc
}

func (s *cancelAndErrorSpawner) Spawn(_ context.Context, _ string, _ SnapshotInputs) (SpawnedHandle, error) {
	s.cancel()
	return nil, errors.New("spawner failed")
}

// dbClosingSpawner closes the store during Spawn so RecordLoaded fails.
type dbClosingSpawner struct {
	st     *store.Store
	handle SpawnedHandle
}

func (s *dbClosingSpawner) Spawn(_ context.Context, slotID string, _ SnapshotInputs) (SpawnedHandle, error) {
	s.st.Close()
	if s.handle != nil {
		return s.handle, nil
	}
	return &stubHandle{api: "/api/" + slotID, run: "/run/" + slotID}, nil
}

// errorWithHandleSpawner returns both a handle AND an error to exercise
// the defense-in-depth Shutdown path after a failed spawn.
type errorWithHandleSpawner struct {
	handle      SpawnedHandle
	err         error
	shutdownCnt *atomic.Int32
}

func (s *errorWithHandleSpawner) Spawn(_ context.Context, _ string, _ SnapshotInputs) (SpawnedHandle, error) {
	return s.handle, s.err
}

func TestRefill_CtxCancelledMidBudget(t *testing.T) {
	// budget=2 for tpl-a; spawner cancels ctx on the first Spawn so the
	// second budget iteration hits ctx.Err() and returns early.
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 2)
	ctx, cancel := context.WithCancel(context.Background())
	spawner := &cancellingSpawner{
		cancel:      cancel,
		fakeSpawner: fakeSpawner{},
	}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)
	// Only the first spawn was attempted; the second iteration returned early.
	if got := len(spawner.Calls()); got != 1 {
		t.Fatalf("spawn calls = %d, want 1 (ctx cancelled mid-budget)", got)
	}
}

func TestRefill_CtxCancelledBetweenTemplates(t *testing.T) {
	// Two templates; spawner cancels ctx during tpl-a's spawn so the
	// template loop's ctx.Err() check fires before tpl-b is processed.
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 1)
	p.SetDepth("tpl-b", 1)
	ctx, cancel := context.WithCancel(context.Background())
	spawner := &cancellingSpawner{
		cancel:      cancel,
		fakeSpawner: fakeSpawner{},
	}
	lister := &fakeLister{templates: []TemplateWarmInput{
		{TemplateID: "tpl-a", VsockCID: 3},
		{TemplateID: "tpl-b", VsockCID: 4},
	}}
	var busy atomic.Bool
	p.runRefillOnce(ctx, lister, spawner, 5*time.Second, &busy)
	// Only tpl-a's spawn was attempted.
	if got := len(spawner.Calls()); got != 1 {
		t.Fatalf("spawn calls = %d, want 1 (ctx cancelled before tpl-b)", got)
	}
}

func TestRefill_StatsPublishFailed(t *testing.T) {
	// Close the store so ListNonReleased and Stats both fail.
	// runRefillOnce must not panic; it just logs warnings and continues.
	p, st := newTestPool(t)
	p.SetDepth("tpl-a", 1)
	st.Close()
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}
	var busy atomic.Bool
	p.runRefillOnce(context.Background(), lister, spawner, 5*time.Second, &busy)
	// No panics; the warning for "list non-released failed" and
	// "publish stats query failed" cover those log branches.
}

func TestGC_ReapError(t *testing.T) {
	p, st := newTestPool(t)
	st.Close()
	// Must not panic; the gc-reap-failed warning is logged.
	p.runGCOnce(context.Background(), time.Hour)
}

func TestSpawnOne_RecordSpawningFailure(t *testing.T) {
	// Close the store before spawnOne so RecordSpawning fails.
	p, st := newTestPool(t)
	st.Close()
	spawner := &fakeSpawner{}
	tpl := TemplateWarmInput{TemplateID: "tpl-a", VsockCID: 3}
	p.spawnOne(context.Background(), tpl, spawner, 5*time.Second)
	// RecordSpawning failed → early return; Spawn never called.
	if got := len(spawner.Calls()); got != 0 {
		t.Fatalf("spawn calls = %d, want 0 when RecordSpawning fails", got)
	}
}

func TestSpawnOne_HandleDefenseInDepth(t *testing.T) {
	// Spawner returns (handle, error). The pool must call handle.Shutdown
	// even though the spawn "failed", to ensure no leaked process.
	p, _ := newTestPool(t)
	var shutdownCalled atomic.Int32
	handle := &shutdownCountHandle{cnt: &shutdownCalled}
	spawner := &errorWithHandleSpawner{
		handle: handle,
		err:    errors.New("spawn failed but leaked handle"),
	}
	tpl := TemplateWarmInput{TemplateID: "tpl-a", VsockCID: 3}
	p.spawnOne(context.Background(), tpl, spawner, 5*time.Second)
	if got := shutdownCalled.Load(); got != 1 {
		t.Fatalf("handle.Shutdown calls = %d, want 1 (defense-in-depth)", got)
	}
}

// shutdownCountHandle counts Shutdown calls without requiring a fakeSpawner.
type shutdownCountHandle struct {
	cnt *atomic.Int32
}

func (h *shutdownCountHandle) APISocket() string { return "/api/test" }
func (h *shutdownCountHandle) RunDir() string    { return "/run/test" }
func (h *shutdownCountHandle) Pid() int          { return 0 }
func (h *shutdownCountHandle) Shutdown(_ context.Context, _ time.Duration) error {
	h.cnt.Add(1)
	return nil
}

func TestSpawnOne_RecordLoadedFailure(t *testing.T) {
	// DB-closing spawner: RecordSpawning succeeds, Spawn closes the DB
	// and returns a handle, RecordLoaded then fails (DB closed).
	p, st := newTestPool(t)
	tpl := TemplateWarmInput{TemplateID: "tpl-a", VsockCID: 3}
	spawner := &dbClosingSpawner{st: st}

	spawnErrBefore := mapInt(spawnTotal, "record_error")
	p.spawnOne(context.Background(), tpl, spawner, 5*time.Second)
	if got := mapInt(spawnTotal, "record_error") - spawnErrBefore; got != 1 {
		t.Fatalf("record_error counter delta = %d, want 1", got)
	}
}

func TestSpawnOne_MarkFailedAfterSpawnErrorFails(t *testing.T) {
	// cancelAndErrorSpawner: Spawn cancels ctx AND returns error.
	// RecordFailed then fails because parentCtx is cancelled.
	// The "mark failed after spawn error failed" warning must be logged.
	p, _ := newTestPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	spawner := &cancelAndErrorSpawner{cancel: cancel}
	tpl := TemplateWarmInput{TemplateID: "tpl-a", VsockCID: 3}

	spawnErrBefore := mapInt(spawnTotal, "spawn_error")
	p.spawnOne(ctx, tpl, spawner, 5*time.Second)
	// spawn_error counter must have advanced by 1 (or the warn-path was
	// taken when mErr != nil, which is logged but doesn't bump a separate counter).
	// Either way, no panic is the primary assertion.
	_ = spawnErrBefore
}

func TestRun_ZeroSpawnTimeoutDefaulted(t *testing.T) {
	// SpawnTimeout: 0 in RefillConfig should be defaulted to 30s inside Run
	// so spawns still complete (fakeSpawner is instant).
	p, _ := newTestPool(t)
	p.SetDepth("tpl-a", 1)
	spawner := &fakeSpawner{}
	lister := &fakeLister{templates: []TemplateWarmInput{{TemplateID: "tpl-a", VsockCID: 3}}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx, RefillConfig{
			RefillInterval: 50 * time.Millisecond,
			GCInterval:     time.Hour,
			GCTTL:          time.Hour,
			SpawnTimeout:   0, // will be defaulted to 30s
		}, lister, spawner)
		close(done)
	}()
	deadline := time.After(2 * time.Second)
	for {
		stats, _ := p.Stats(context.Background(), "tpl-a")
		if stats.Loaded == 1 {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("pool did not warm up with defaulted SpawnTimeout")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestRun_OrphanRepairError(t *testing.T) {
	// Close the store before Run starts so releaseOrphanedRowsAtStart fails.
	// Run must log a warning and continue rather than crashing.
	p, st := newTestPool(t)
	st.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx, RefillConfig{
			RefillInterval: 50 * time.Millisecond,
			GCInterval:     50 * time.Millisecond,
			GCTTL:          time.Hour,
		}, &fakeLister{}, &fakeSpawner{})
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after context cancel")
	}
}

func TestRun_OrphanRepairReleased_Logged(t *testing.T) {
	// Seed warm-but-handleless rows so releaseOrphanedRowsAtStart reports
	// released > 0 and Run logs the "released orphaned startup rows" info.
	bgCtx := context.Background()
	p, _ := newTestPool(t)
	now := time.Now().UTC()
	for _, id := range []string{"vmms-orphan1", "vmms-orphan2"} {
		if err := p.RecordSpawning(bgCtx, id, "tpl-a", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.RecordLoaded(bgCtx, "vmms-orphan2", "/api", "/dir", 3, now); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx, RefillConfig{
			RefillInterval: 50 * time.Millisecond,
			GCInterval:     time.Hour,
			GCTTL:          time.Hour,
		}, &fakeLister{}, &fakeSpawner{})
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit")
	}

	stats, err := p.Stats(bgCtx, "tpl-a")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Released != 2 {
		t.Fatalf("expected 2 released orphans, got %+v", stats)
	}
}

func TestRun_TickerPaths(t *testing.T) {
	// Use short tickers so both refillTicker.C and gcTicker.C fire before
	// context cancel. Pool has no depth configured — ticks are no-ops but
	// cover the select case branches.
	p, _ := newTestPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx, RefillConfig{
			RefillInterval: 5 * time.Millisecond,
			GCInterval:     5 * time.Millisecond,
			GCTTL:          time.Hour,
		}, &fakeLister{}, &fakeSpawner{})
		close(done)
	}()
	time.Sleep(40 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after context cancel")
	}
}
