package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// fakeRotationStore lets the table-driven tests stage the candidate
// list each tick observes. Mirrors the in-process style used by the
// other reconciler tests in this package.
type fakeRotationStore struct {
	mu         sync.Mutex
	candidates []*templateRotationCandidate
	err        error
	listCalls  int
	lastCutoff time.Time
}

func (f *fakeRotationStore) ListTemplatesReadyBefore(_ context.Context, cutoff time.Time) ([]*templateRotationCandidate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	f.lastCutoff = cutoff
	if f.err != nil {
		return nil, f.err
	}
	// Defensive copy so the test can mutate the staging slice between
	// ticks without breaking referential equality.
	out := make([]*templateRotationCandidate, len(f.candidates))
	copy(out, f.candidates)
	return out, nil
}

// fakeRotationMarker satisfies rotationMarker. Captures every ID +
// reason it's asked to mark so the test can assert ordering and exact
// arguments.
type fakeRotationMarker struct {
	mu        sync.Mutex
	calls     []rotationMarkCall
	returnErr error
}

type rotationMarkCall struct {
	ID     string
	Reason string
}

func (f *fakeRotationMarker) MarkSnapshotCorrupt(_ context.Context, id, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, rotationMarkCall{ID: id, Reason: reason})
	return f.returnErr
}

func newTestRotationReconciler(t *testing.T, cfg TemplateRotationConfig, store TemplateRotationStore, marker rotationMarker) *TemplateRotationReconciler {
	t.Helper()
	r, err := NewTemplateRotationReconciler(cfg, store, marker, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewTemplateRotationReconciler: %v", err)
	}
	if r == nil {
		t.Fatal("NewTemplateRotationReconciler returned nil despite config being enabled")
	}
	return r
}

// TestTemplateRotation_DisabledConfigReturnsNil proves the opt-in
// invariant: cfg.IsEnabled() false must hand back a nil reconciler so
// main.go's `if r == nil { return }` keeps the goroutine off. Without
// this, operators who upgrade past Phase 6 with default config would
// silently start a ticker that scans every interval and finds nothing.
func TestTemplateRotation_DisabledConfigReturnsNil(t *testing.T) {
	for _, tc := range []TemplateRotationConfig{
		{},                                // both zero
		{Interval: time.Hour, MaxAge: 0},  // interval set, max-age unset
		{Interval: 0, MaxAge: time.Hour},  // max-age set, interval unset
		{Interval: -1, MaxAge: time.Hour}, // negative interval (defensive)
		{Interval: time.Hour, MaxAge: -1}, // negative max-age (defensive)
	} {
		r, err := NewTemplateRotationReconciler(tc, &fakeRotationStore{}, &fakeRotationMarker{}, nil)
		if err != nil {
			t.Errorf("config %+v: err = %v, want nil", tc, err)
		}
		if r != nil {
			t.Errorf("config %+v: reconciler = %v, want nil (disabled)", tc, r)
		}
	}
}

// TestTemplateRotation_RejectsNilDepsWhenEnabled pins the validation
// arm. An operator enabling rotation but failing to wire the store or
// marker should surface immediately at boot, not silently no-op every
// tick.
func TestTemplateRotation_RejectsNilDepsWhenEnabled(t *testing.T) {
	cfg := TemplateRotationConfig{Interval: time.Hour, MaxAge: time.Hour}
	if _, err := NewTemplateRotationReconciler(cfg, nil, &fakeRotationMarker{}, nil); err == nil {
		t.Error("nil store accepted")
	}
	if _, err := NewTemplateRotationReconciler(cfg, &fakeRotationStore{}, nil, nil); err == nil {
		t.Error("nil marker accepted")
	}
}

// TestTemplateRotation_MarksEachStaleRow proves the happy path: every
// candidate returned by the store flows through MarkSnapshotCorrupt
// exactly once, with reason="rotation". This is the contract operators
// rely on to grep audit logs for rotation-driven rebuilds.
func TestTemplateRotation_MarksEachStaleRow(t *testing.T) {
	store := &fakeRotationStore{
		candidates: []*templateRotationCandidate{
			{ID: "tpl-a", ReadyAt: time.Now().Add(-40 * 24 * time.Hour)},
			{ID: "tpl-b", ReadyAt: time.Now().Add(-31 * 24 * time.Hour)},
		},
	}
	marker := &fakeRotationMarker{}
	r := newTestRotationReconciler(t,
		TemplateRotationConfig{Interval: time.Hour, MaxAge: 30 * 24 * time.Hour},
		store, marker)

	stats, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Scanned != 2 || stats.Marked != 2 || stats.Skipped != 0 {
		t.Errorf("stats = %+v, want {Scanned:2 Marked:2 Skipped:0}", stats)
	}
	if len(marker.calls) != 2 {
		t.Fatalf("marker.calls = %d, want 2", len(marker.calls))
	}
	for _, c := range marker.calls {
		if c.Reason != "rotation" {
			t.Errorf("MarkSnapshotCorrupt reason = %q, want %q", c.Reason, "rotation")
		}
	}
}

// TestTemplateRotation_EmptyCandidateListIsFastNoop pins the
// steady-state behaviour: a tick with no stale rows must not call
// MarkSnapshotCorrupt at all. Otherwise an operator who set a too-large
// MaxAge would still pay one marker call per tick, eventually flipping
// every template unhealthy for no good reason.
func TestTemplateRotation_EmptyCandidateListIsFastNoop(t *testing.T) {
	store := &fakeRotationStore{candidates: nil}
	marker := &fakeRotationMarker{}
	r := newTestRotationReconciler(t,
		TemplateRotationConfig{Interval: time.Hour, MaxAge: time.Hour},
		store, marker)
	stats, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Scanned != 0 || stats.Marked != 0 {
		t.Errorf("stats = %+v, want zero-marked", stats)
	}
	if len(marker.calls) != 0 {
		t.Errorf("marker called %d times on empty candidate list", len(marker.calls))
	}
}

// TestTemplateRotation_PerRowFailureSkippedNotAborted proves the
// resilience contract: a mark failure on one row must not stop the
// reconciler from trying the next. Without this, a single bad row
// (e.g. store row deleted between scan and mark) could starve rotation
// for every other stale template in the same tick.
func TestTemplateRotation_PerRowFailureSkippedNotAborted(t *testing.T) {
	// We use a marker whose Mark returns an error on EVERY call —
	// the reconciler should record Skipped for each, scan to the end,
	// and return successfully (the per-row error is logged, not
	// returned).
	store := &fakeRotationStore{
		candidates: []*templateRotationCandidate{
			{ID: "tpl-a"},
			{ID: "tpl-b"},
			{ID: "tpl-c"},
		},
	}
	marker := &fakeRotationMarker{returnErr: errors.New("simulated mark failure")}
	r := newTestRotationReconciler(t,
		TemplateRotationConfig{Interval: time.Hour, MaxAge: time.Hour},
		store, marker)

	stats, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if stats.Scanned != 3 || stats.Marked != 0 || stats.Skipped != 3 {
		t.Errorf("stats = %+v, want {Scanned:3 Marked:0 Skipped:3}", stats)
	}
	if len(marker.calls) != 3 {
		t.Errorf("marker.calls = %d, want 3 (every row should be attempted)", len(marker.calls))
	}
}

// TestTemplateRotation_StoreErrorReturnedNotSwallowed pins the inverse
// arm: a store-list failure must propagate. The ticker wrapper in
// main.go logs and waits for the next tick; treating "DB down" as
// "scan returned zero rows" would silently disable rotation.
func TestTemplateRotation_StoreErrorReturnedNotSwallowed(t *testing.T) {
	store := &fakeRotationStore{err: errors.New("db down")}
	marker := &fakeRotationMarker{}
	r := newTestRotationReconciler(t,
		TemplateRotationConfig{Interval: time.Hour, MaxAge: time.Hour},
		store, marker)
	_, err := r.RunOnce(context.Background())
	if err == nil {
		t.Fatal("RunOnce swallowed store error")
	}
	if len(marker.calls) != 0 {
		t.Errorf("marker called %d times despite store failure", len(marker.calls))
	}
}

// TestTemplateRotation_CutoffComputedFromNow proves the time-math
// invariant: the store query cutoff must be now-MaxAge, not now alone
// (which would mark every ready template) and not zero (which would
// mark none). This is the easiest knob to misconfigure; pin it.
func TestTemplateRotation_CutoffComputedFromNow(t *testing.T) {
	fixedNow := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	store := &fakeRotationStore{}
	marker := &fakeRotationMarker{}
	r := newTestRotationReconciler(t,
		TemplateRotationConfig{Interval: time.Hour, MaxAge: 30 * 24 * time.Hour},
		store, marker)
	r.now = func() time.Time { return fixedNow }

	if _, err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	wantCutoff := fixedNow.Add(-30 * 24 * time.Hour)
	if !store.lastCutoff.Equal(wantCutoff) {
		t.Errorf("cutoff = %v, want %v", store.lastCutoff, wantCutoff)
	}
}
