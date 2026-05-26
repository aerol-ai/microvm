package vmm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	apiSocket string
	runDir    string
	parent    *fakeSpawner
}

func (h *fakeHandle) APISocket() string { return h.apiSocket }
func (h *fakeHandle) RunDir() string    { return h.runDir }
func (h *fakeHandle) Pid() int          { return 0 }
func (h *fakeHandle) Shutdown(_ context.Context, _ time.Duration) error {
	h.parent.shutdownCnt.Add(1)
	return nil
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
