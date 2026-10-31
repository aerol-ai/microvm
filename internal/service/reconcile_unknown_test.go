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

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// unknownClock is a settable clock for the unknown-streak bounds.
type unknownClock struct{ t time.Time }

func newUnknownClock() *unknownClock {
	return &unknownClock{t: time.Date(2026, 10, 31, 14, 58, 47, 0, time.UTC)}
}

func (c *unknownClock) now() time.Time          { return c.t }
func (c *unknownClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func unknownTotal(t *testing.T, label string) int64 {
	return expvarMapInt(t, "aerolvm_reconcile_runtime_unknown_total", label)
}

func unknownMarked() int64 { return reconcileRuntimeUnknownMarkedTotal.Value() }

func unknownStreakOf(s *Service, id string) bool {
	s.reconcileUnknown.mu.Lock()
	defer s.reconcileUnknown.mu.Unlock()
	_, ok := s.reconcileUnknown.streaks[id]
	return ok
}

func TestReconcileUnknownTrackerBounds(t *testing.T) {
	cases := []struct {
		name     string
		step     time.Duration
		passes   int
		markedAt int // 1-based pass that marks; 0 = never
	}{
		// Default 5m reconcile interval: passes at 0, 5m, 10m; the third
		// crosses both bounds.
		{name: "default interval marks on the third pass", step: 5 * time.Minute, passes: 5, markedAt: 3},
		// A tight loop (admin reconciles, a short SB_RECONCILE_INTERVAL)
		// must not mark before ten minutes have passed.
		{name: "fast passes wait for the time bound", step: 10 * time.Second, passes: 61, markedAt: 61},
		// One slow pass must not mark on its own.
		{name: "two slow passes are not enough", step: time.Hour, passes: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newUnknownClock()
			tr := &reconcileUnknownTracker{now: clock.now}
			start := clock.t
			marks := 0
			for pass := 1; pass <= tc.passes; pass++ {
				streak, mark := tr.observe("sb-x")
				if streak.ticks != pass || !streak.since.Equal(start) {
					t.Fatalf("pass %d: streak = %+v", pass, streak)
				}
				if mark {
					marks++
					if pass != tc.markedAt {
						t.Fatalf("marked on pass %d, want %d", pass, tc.markedAt)
					}
				}
				clock.advance(tc.step)
			}
			want := 0
			if tc.markedAt > 0 {
				want = 1
			}
			if marks != want {
				t.Fatalf("marks = %d, want %d (a streak marks at most once)", marks, want)
			}
		})
	}
}

func TestReconcileUnknownTrackerLifecycle(t *testing.T) {
	clock := newUnknownClock()
	tr := &reconcileUnknownTracker{now: clock.now}

	// forget/unmark/retain on an empty tracker are no-ops.
	tr.forget("nobody")
	tr.unmark("nobody")
	tr.retain(map[string]struct{}{})

	for i := 0; i < reconcileUnknownMarkAfterTicks; i++ {
		tr.observe("sb-a")
		clock.advance(reconcileUnknownMarkAfter)
	}
	if _, mark := tr.observe("sb-a"); mark {
		t.Fatal("an already-marked streak marked again")
	}
	tr.unmark("sb-a")
	if _, mark := tr.observe("sb-a"); !mark {
		t.Fatal("unmark did not let the next pass retry the mark")
	}
	if got := reconcileRuntimeUnknownSandboxes.Value(); got != 1 {
		t.Fatalf("unknown_sandboxes gauge = %d, want 1", got)
	}

	tr.observe("sb-b")
	tr.retain(map[string]struct{}{"sb-b": {}})
	if _, ok := tr.streaks["sb-a"]; ok {
		t.Fatal("retain kept a streak for a sandbox with no row")
	}
	tr.forget("sb-b")
	if len(tr.streaks) != 0 || reconcileRuntimeUnknownSandboxes.Value() != 0 {
		t.Fatalf("streaks = %v, gauge = %d after forgetting all", tr.streaks, reconcileRuntimeUnknownSandboxes.Value())
	}

	// A new streak after forget starts from the clock now.
	clock.advance(time.Hour)
	if streak, _ := tr.observe("sb-b"); streak.ticks != 1 || !streak.since.Equal(clock.t) {
		t.Fatalf("restarted streak = %+v", streak)
	}

	var zero reconcileUnknownTracker
	if streak, _ := zero.observe("sb-z"); streak.ticks != 1 || streak.since.IsZero() {
		t.Fatalf("zero-value tracker streak = %+v", streak)
	}
}

func newUnknownMarkService(t *testing.T) (*Service, *store.Store, string, *capacity.Admitter, *fakeReconcileRuntime, *unknownClock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir: filepath.Join(t.TempDir(), "mounts"), CredDir: filepath.Join(t.TempDir(), "cred"), WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)
	rt := &fakeReconcileRuntime{
		managed:               map[string]*models.SandboxRuntimeState{},
		inspectErr:            errors.New(`task status of "sb-stuck": ttrpc: closed`),
		allowPushAllowedPorts: true,
	}
	clock := newUnknownClock()
	svc := &Service{
		cfg:        config.Config{ImageBuildGCEnabled: true},
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:      st,
		docker:     &fakeReconcileRuntime{managed: map[string]*models.SandboxRuntimeState{}},
		containerd: rt,
		caddy:      caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}),
		mounts:     mgr,
		admitter:   admitter,
	}
	svc.reconcileUnknown.now = clock.now
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-stuck", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeGvisor, Engine: models.ContainerEngineContainerd,
		ContainerID: "sb-stuck", ContainerIP: "10.88.0.40", CPU: 1, MemoryMB: 512,
		AuditIncarnationID: "inc-sb-stuck", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	admitter.Reserve("sb-stuck", capacity.Request{CPU: 1, MemoryMB: 512})
	return svc, st, path, admitter, rt, clock
}

// A sandbox its runtime never answers for is recorded as status=error after
// ten minutes and three passes, never deleted. When the runtime lists it
// again, the row heals: its real status, and the reconcile message cleared.
func TestReconcileMarksLongUnknownSandboxError(t *testing.T) {
	ctx := context.Background()
	svc, st, _, admitter, rt, clock := newUnknownMarkService(t)
	totalBefore, markedBefore := unknownTotal(t, "containerd"), unknownMarked()

	for pass := 1; pass <= 2; pass++ {
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile pass %d: %v", pass, err)
		}
		got, err := st.Get(ctx, "sb-stuck")
		if err != nil || got.Status != models.SandboxStatusStarted {
			t.Fatalf("pass %d: row = %+v err = %v, want it kept started", pass, got, err)
		}
		clock.advance(5 * time.Minute)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile pass 3: %v", err)
	}
	got, err := st.Get(ctx, "sb-stuck")
	if err != nil {
		t.Fatalf("an unanswered sandbox was deleted: %v", err)
	}
	if got.Status != models.SandboxStatusError ||
		!strings.HasPrefix(got.LastError, reconcileUnknownErrorPrefix) ||
		!strings.Contains(got.LastError, "containerd") || !strings.Contains(got.LastError, "ttrpc: closed") {
		t.Fatalf("after 10 minutes unanswered: status=%q last_error=%q", got.Status, got.LastError)
	}
	if got.ContainerIP != "10.88.0.40" {
		t.Fatalf("marking error changed the address to %q", got.ContainerIP)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 1 {
		t.Fatalf("marking error released the capacity reservation: %+v", snap)
	}
	if d := unknownTotal(t, "containerd") - totalBefore; d != 3 {
		t.Fatalf("aerolvm_reconcile_runtime_unknown_total{containerd} moved by %d, want 3", d)
	}
	if d := unknownMarked() - markedBefore; d != 1 {
		t.Fatalf("aerolvm_reconcile_runtime_unknown_marked_error_total moved by %d, want 1", d)
	}

	// A fourth unanswered pass does not mark again.
	clock.advance(5 * time.Minute)
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile pass 4: %v", err)
	}
	if d := unknownMarked() - markedBefore; d != 1 {
		t.Fatalf("marked again on pass 4: moved by %d", d)
	}

	// The runtime answers again: the row heals.
	rt.inspectErr = nil
	rt.managed["sb-stuck"] = &models.SandboxRuntimeState{SandboxID: "sb-stuck", ContainerID: "sb-stuck", ContainerIP: "10.88.0.40", Status: models.SandboxStatusStarted}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile after recovery: %v", err)
	}
	got, err = st.Get(ctx, "sb-stuck")
	if err != nil || got.Status != models.SandboxStatusStarted || got.LastError != "" {
		t.Fatalf("after recovery: row = %+v err = %v, want started with last_error cleared", got, err)
	}
	if unknownStreakOf(svc, "sb-stuck") {
		t.Fatal("recovered sandbox still tracked as unknown")
	}
}

// A last_error reconcile did not write (the die event's) survives healing.
func TestReconcileKeepsOtherLastErrorOnHeal(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _, rt, _ := newUnknownMarkService(t)
	if err := st.UpdateStatus(ctx, "sb-stuck", models.SandboxStatusStopped, "container exited with code 128"); err != nil {
		t.Fatal(err)
	}
	rt.inspectErr = nil
	rt.managed["sb-stuck"] = &models.SandboxRuntimeState{SandboxID: "sb-stuck", ContainerID: "sb-stuck", Status: models.SandboxStatusStopped}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got, err := st.Get(ctx, "sb-stuck")
	if err != nil || got.LastError != "container exited with code 128" {
		t.Fatalf("row = %+v err = %v, want the die event's last_error kept", got, err)
	}
}

// A mark the store refuses is retried on the next pass; a row destroyed
// meanwhile ends the streak.
func TestReconcileUnknownMarkFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("store refuses the update", func(t *testing.T) {
		svc, st, path, _, _, clock := newUnknownMarkService(t)
		sb, err := st.Get(ctx, "sb-stuck")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < reconcileUnknownMarkAfterTicks-1; i++ {
			svc.noteReconcileRuntimeUnknown(ctx, sb, errors.New("unavailable"))
			clock.advance(reconcileUnknownMarkAfter)
		}
		cb96SQL(t, path, `CREATE TRIGGER uc320_keep BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT, 'uc320 keep'); END`)
		markedBefore := unknownMarked()
		svc.noteReconcileRuntimeUnknown(ctx, sb, errors.New("unavailable"))
		if unknownMarked() != markedBefore {
			t.Fatal("a refused update counted as marked")
		}
		cb96SQL(t, path, `DROP TRIGGER uc320_keep`)
		svc.noteReconcileRuntimeUnknown(ctx, sb, errors.New("unavailable"))
		got, err := st.Get(ctx, "sb-stuck")
		if err != nil || got.Status != models.SandboxStatusError || unknownMarked()-markedBefore != 1 {
			t.Fatalf("retry did not mark: row = %+v err = %v", got, err)
		}
	})

	t.Run("row destroyed meanwhile", func(t *testing.T) {
		svc, st, _, _, _, clock := newUnknownMarkService(t)
		sb, err := st.Get(ctx, "sb-stuck")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Delete(ctx, "sb-stuck"); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < reconcileUnknownMarkAfterTicks; i++ {
			svc.noteReconcileRuntimeUnknown(ctx, sb, errors.New("unavailable"))
			clock.advance(reconcileUnknownMarkAfter)
		}
		if unknownStreakOf(svc, "sb-stuck") {
			t.Fatal("streak kept for a destroyed sandbox")
		}
	})
}

func TestReconcileRuntimeLabel(t *testing.T) {
	cases := map[string]*models.Sandbox{
		"docker":      {Runtime: models.RuntimeDocker},
		"containerd":  {Runtime: models.RuntimeGvisor, Engine: models.ContainerEngineContainerd},
		"firecracker": {Runtime: models.RuntimeFirecracker},
		"wasm":        {Runtime: models.RuntimeWasm},
		"isolate":     {Runtime: models.RuntimeIsolate},
	}
	for want, sb := range cases {
		if got := reconcileRuntimeLabel(sb); got != want {
			t.Fatalf("reconcileRuntimeLabel(%+v) = %q, want %q", sb, got, want)
		}
	}
}
