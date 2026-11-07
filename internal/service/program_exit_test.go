package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeToolboxHealth serves /health the way toolboxd does, with a main
// program the test sets, and counts and paces the requests.
type fakeToolboxHealth struct {
	mu     sync.Mutex
	body   map[string]any
	status int
	delay  time.Duration
	// guestBehind sets the Date header that far behind the host clock, as
	// a guest whose clock is behind would.
	guestBehind time.Duration
	hits        atomic.Int32
	inflight    atomic.Int32
	peak        atomic.Int32
}

func (f *fakeToolboxHealth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if r.URL.Path != "/health" || r.Header.Get("Authorization") != "" {
		w.WriteHeader(http.StatusTeapot)
		return
	}
	time.Sleep(f.delay)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	if f.guestBehind != 0 {
		w.Header().Set("Date", time.Now().Add(-f.guestBehind).UTC().Format(http.TimeFormat))
	}
	_ = json.NewEncoder(w).Encode(f.body)
}

func (f *fakeToolboxHealth) set(mainProgram map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = map[string]any{"status": "ok", "exec_drainers": 0}
	if mainProgram != nil {
		f.body["main_program"] = mainProgram
	}
}

type exitHarness struct {
	svc    *Service
	st     *store.Store
	health *fakeToolboxHealth
	path   string
}

// newExitHarness points sandboxd's toolbox address (ContainerIP:ToolboxPort)
// at a fake toolboxd on 127.0.0.1.
func newExitHarness(t *testing.T) *exitHarness {
	t.Helper()
	health := &fakeToolboxHealth{}
	health.set(map[string]any{"state": "running"})
	srv := httptest.NewServer(health)
	t.Cleanup(srv.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	path := filepath.Join(t.TempDir(), "state.db")
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, path, &recordingRuntime{})
	svc.cfg.ToolboxPort = port
	return &exitHarness{svc: svc, st: st, health: health, path: path}
}

func (h *exitHarness) seed(t *testing.T, id string, status models.SandboxStatus, runtime string, after time.Duration, exitedAt *time.Time) {
	t.Helper()
	now := time.Now().UTC()
	if err := h.st.Create(context.Background(), &models.Sandbox{
		ID: id, Image: "alpine", Runtime: runtime, Status: status, ContainerID: id, ContainerIP: "127.0.0.1",
		CPU: 1, MemoryMB: 256, Lifecycle: models.Lifecycle{DestroyAfterExitFor: after},
		ProgramExitedAt: exitedAt, AuditIncarnationID: "inc-" + id,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

func (h *exitHarness) get(t *testing.T, id string) (*models.Sandbox, bool) {
	t.Helper()
	sb, err := h.st.Get(context.Background(), id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return sb, true
}

// TestDestroyAfterExitRecordsTheExitThenDestroys is L5's required check: the
// main program ends, the sweep stores when and how (status_reason
// program_exited and exit_code, the L2 record), and destroy_after_exit_for
// fires from that stored time.
func TestDestroyAfterExitRecordsTheExitThenDestroys(t *testing.T) {
	ctx := context.Background()
	h := newExitHarness(t)
	h.seed(t, "sb-done", models.SandboxStatusStarted, models.RuntimeDocker, time.Hour, nil)

	h.svc.runLifecycleSweep(ctx)
	if sb, _ := h.get(t, "sb-done"); sb.ProgramExitedAt != nil || sb.StatusReason != "" {
		t.Fatalf("a running program recorded an exit: %v %q", sb.ProgramExitedAt, sb.StatusReason)
	}

	ended := time.Now().UTC().Add(-30 * time.Second)
	h.health.set(map[string]any{"state": "exited", "exit_code": 3, "ended_at": ended.Format(time.RFC3339Nano)})
	h.svc.runLifecycleSweep(ctx)
	sb, ok := h.get(t, "sb-done")
	if !ok {
		t.Fatal("destroyed before its hour")
	}
	wantReason(t, sb, models.SandboxStatusStarted, models.StatusReasonProgramExited, intPtr(3))
	// The reply's Date is the second it was sent, so the stored end is
	// the reported one, late by under that second plus the read.
	if sb.ProgramExitedAt == nil || sb.ProgramExitedAt.Before(ended) || sb.ProgramExitedAt.After(ended.Add(2*time.Second)) {
		t.Fatalf("program_exited_at = %v, want %v (+ under 2 s)", sb.ProgramExitedAt, ended)
	}
	ended = *sb.ProgramExitedAt

	// Recorded once: the next sweep does not ask again.
	hits := h.health.hits.Load()
	h.svc.runLifecycleSweep(ctx)
	if h.health.hits.Load() != hits {
		t.Fatal("asked toolboxd again after the exit was recorded")
	}

	// A stop afterwards names the stop, but the exit and its timer stay.
	if _, err := h.svc.StopSandbox(ctx, "sb-done"); err != nil {
		t.Fatal(err)
	}
	sb, _ = h.get(t, "sb-done")
	if sb.StatusReason != models.StatusReasonUserStop || sb.ProgramExitedAt == nil || !sb.ProgramExitedAt.Equal(ended) {
		t.Fatalf("after a stop: reason %q, exited at %v", sb.StatusReason, sb.ProgramExitedAt)
	}
	// A start runs the program again: the exit is forgotten.
	if _, err := h.svc.StartSandbox(ctx, "sb-done"); err != nil {
		t.Fatal(err)
	}
	if sb, _ = h.get(t, "sb-done"); sb.ProgramExitedAt != nil || sb.StatusReason != "" {
		t.Fatalf("after a start: exited at %v, reason %q", sb.ProgramExitedAt, sb.StatusReason)
	}
}

// TestDestroyAfterExitSurvivesADaemonRestart: an exit stored by the old
// daemon long enough ago is destroyed by the new daemon's first sweep, with
// no toolboxd asked.
func TestDestroyAfterExitSurvivesADaemonRestart(t *testing.T) {
	ctx := context.Background()
	h := newExitHarness(t)
	longAgo := time.Now().UTC().Add(-2 * time.Hour)
	recent := time.Now().UTC().Add(-10 * time.Minute)
	h.seed(t, "sb-due", models.SandboxStatusStarted, models.RuntimeDocker, time.Hour, &longAgo)
	h.seed(t, "sb-wait", models.SandboxStatusStarted, models.RuntimeDocker, time.Hour, &recent)
	h.seed(t, "sb-stopped", models.SandboxStatusStopped, models.RuntimeDocker, time.Hour, &longAgo)

	svc2, _, _ := newServiceRuntimeHarnessAtPath(t, h.path, &recordingRuntime{})
	svc2.cfg.ToolboxPort = h.svc.cfg.ToolboxPort
	svc2.runLifecycleSweep(ctx)
	if _, ok := h.get(t, "sb-due"); ok {
		t.Fatal("sb-due survived its stored timer")
	}
	if _, ok := h.get(t, "sb-stopped"); ok {
		t.Fatal("a sandbox stopped after its program ended kept running its timer past due")
	}
	if _, ok := h.get(t, "sb-wait"); !ok {
		t.Fatal("sb-wait destroyed before its hour")
	}
	if h.health.hits.Load() != 0 {
		t.Fatalf("asked toolboxd %d times for sandboxes with a stored exit", h.health.hits.Load())
	}
}

// TestDestroyAfterExitShortDelayActsInTheSamePass: an exit found in this
// sweep with a delay already past is destroyed in the same sweep.
func TestDestroyAfterExitShortDelayActsInTheSamePass(t *testing.T) {
	h := newExitHarness(t)
	h.seed(t, "sb-quick", models.SandboxStatusStarted, models.RuntimeDocker, time.Second, nil)
	h.health.set(map[string]any{"state": "killed", "exit_code": 137, "signal": "SIGKILL",
		"ended_at": time.Now().UTC().Add(-20 * time.Second).Format(time.RFC3339Nano)})
	h.svc.runLifecycleSweep(context.Background())
	if _, ok := h.get(t, "sb-quick"); ok {
		t.Fatal("not destroyed in the pass that found the exit")
	}
}

// TestProgramExitProbeSelectsAndSurvivesBadAnswers: only started sandboxes
// with the option and no stored exit are asked, on runtimes with a main
// program; an older toolboxd, an error status or no answer records nothing.
func TestProgramExitProbeSelectsAndSurvivesBadAnswers(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name string
		sb   *models.Sandbox
		want bool
	}{
		{"started with the option", &models.Sandbox{Status: models.SandboxStatusStarted, ContainerIP: "x", Runtime: models.RuntimeGvisor, Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Minute}}, true},
		{"firecracker", &models.Sandbox{Status: models.SandboxStatusStarted, ContainerIP: "x", Runtime: models.RuntimeFirecracker, Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Minute}}, true},
		{"no option", &models.Sandbox{Status: models.SandboxStatusStarted, ContainerIP: "x", Runtime: models.RuntimeDocker}, false},
		{"stopped", &models.Sandbox{Status: models.SandboxStatusStopped, ContainerIP: "x", Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Minute}}, false},
		{"already recorded", &models.Sandbox{Status: models.SandboxStatusStarted, ContainerIP: "x", ProgramExitedAt: &now, Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Minute}}, false},
		{"no address", &models.Sandbox{Status: models.SandboxStatusStarted, Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Minute}}, false},
		{"wasm", &models.Sandbox{Status: models.SandboxStatusStarted, ContainerIP: "x", Runtime: models.RuntimeWasm, Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Minute}}, false},
		{"isolate", &models.Sandbox{Status: models.SandboxStatusStarted, ContainerIP: "x", Runtime: models.RuntimeIsolate, Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Minute}}, false},
		{"nil", nil, false},
	} {
		if got := wantsProgramExitProbe(tc.sb); got != tc.want {
			t.Fatalf("%s: wantsProgramExitProbe = %v, want %v", tc.name, got, tc.want)
		}
	}

	for _, tc := range []struct {
		name  string
		setup func(h *exitHarness)
	}{
		{"older toolboxd", func(h *exitHarness) { h.health.set(nil) }},
		{"error status", func(h *exitHarness) { h.health.status = http.StatusServiceUnavailable }},
		{"not json", func(h *exitHarness) { h.health.set(nil); h.health.body = map[string]any{"main_program": "exited"} }},
		{"ended without a code", func(h *exitHarness) { h.health.set(map[string]any{"state": "exited"}) }},
		{"unreachable", func(h *exitHarness) { h.svc.cfg.ToolboxPort = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newExitHarness(t)
			h.seed(t, "sb-x", models.SandboxStatusStarted, models.RuntimeDocker, time.Second, nil)
			tc.setup(h)
			h.svc.runLifecycleSweep(context.Background())
			sb, ok := h.get(t, "sb-x")
			if !ok || sb.ProgramExitedAt != nil {
				t.Fatalf("recorded or destroyed on a bad answer: present=%v", ok)
			}
		})
	}
}

// TestProgramExitProbeConcurrencyIsBounded: many sandboxes are asked at most
// programExitProbeConcurrency at a time.
func TestProgramExitProbeConcurrencyIsBounded(t *testing.T) {
	h := newExitHarness(t)
	h.health.delay = 20 * time.Millisecond
	for i := 0; i < 3*programExitProbeConcurrency; i++ {
		h.seed(t, fmt.Sprintf("sb-%02d", i), models.SandboxStatusStarted, models.RuntimeDocker, time.Hour, nil)
	}
	h.svc.runLifecycleSweep(context.Background())
	if got := h.health.hits.Load(); got != int32(3*programExitProbeConcurrency) {
		t.Fatalf("asked %d sandboxes, want %d", got, 3*programExitProbeConcurrency)
	}
	if peak := h.health.peak.Load(); peak > programExitProbeConcurrency || peak < 2 {
		t.Fatalf("peak concurrent probes %d, want 2..%d", peak, programExitProbeConcurrency)
	}

	// A sweep whose deadline has passed asks nobody.
	h2 := newExitHarness(t)
	h2.seed(t, "sb-late", models.SandboxStatusStarted, models.RuntimeDocker, time.Hour, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h2.svc.probeProgramExits(ctx, []*models.Sandbox{h2.mustGet(t, "sb-late")})
	if h2.health.hits.Load() != 0 {
		t.Fatal("probed after the sweep's deadline")
	}
}

func (h *exitHarness) mustGet(t *testing.T, id string) *models.Sandbox {
	t.Helper()
	sb, ok := h.get(t, id)
	if !ok {
		t.Fatalf("%s missing", id)
	}
	return sb
}

// TestProgramExitTimeIsNeverTooEarly: the stored end is what toolboxd said,
// but never in the future, before the sandbox existed, or further back than
// the sweep could have missed.
func TestProgramExitTimeIsNeverTooEarly(t *testing.T) {
	read := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	old := &models.Sandbox{CreatedAt: read.Add(-24 * time.Hour)}
	young := &models.Sandbox{CreatedAt: read.Add(-30 * time.Second)}
	at := func(d time.Duration) string { return read.Add(d).Format(time.RFC3339Nano) }
	for _, tc := range []struct {
		name      string
		endedAt   string
		hostAhead time.Duration
		dated     bool
		sb        *models.Sandbox
		want      time.Time
	}{
		{"clocks agree", at(-40 * time.Second), 0, true, old, read.Add(-40 * time.Second)},
		// The guest clock is 5 minutes behind: it reports an end 5 m 40 s
		// ago, which really was 40 s ago. Before, this counted from 2
		// minutes ago and the destroy came 80 s early.
		{"guest clock behind", at(-340 * time.Second), 5 * time.Minute, true, old, read.Add(-40 * time.Second)},
		{"guest clock ahead", at(time.Hour - 40*time.Second), -time.Hour, true, old, read.Add(-40 * time.Second)},
		{"moved past the read", at(-10 * time.Second), time.Minute, true, old, read},
		{"no Date header", at(-40 * time.Second), 0, false, old, read},
		{"garbage", "yesterday", 0, true, old, read},
		{"before the sandbox existed", at(-90 * time.Second), 0, true, young, read},
	} {
		p := toolboxMainProgram{EndedAt: tc.endedAt, readAt: read, hostAhead: tc.hostAhead, dated: tc.dated}
		if got := programExitTime(p, tc.sb); !got.Equal(tc.want) {
			t.Fatalf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestProgramExitReadsTheGuestClock: a guest whose clock is behind gets its
// reported end moved onto the host's clock, so the delete is not early.
func TestProgramExitReadsTheGuestClock(t *testing.T) {
	h := newExitHarness(t)
	h.seed(t, "sb-behind", models.SandboxStatusStarted, models.RuntimeDocker, time.Hour, nil)
	h.health.guestBehind = 5 * time.Minute
	reallyEnded := time.Now().UTC().Add(-20 * time.Second)
	h.health.set(map[string]any{"state": "exited", "exit_code": 0, "ended_at": reallyEnded.Add(-5 * time.Minute).Format(time.RFC3339Nano)})
	h.svc.runLifecycleSweep(context.Background())
	sb, ok := h.get(t, "sb-behind")
	if !ok || sb.ProgramExitedAt == nil {
		t.Fatalf("no exit recorded: %+v", sb)
	}
	if sb.ProgramExitedAt.Before(reallyEnded) || sb.ProgramExitedAt.After(reallyEnded.Add(2*time.Second)) {
		t.Fatalf("program_exited_at = %v, want %v (+ under 2 s)", sb.ProgramExitedAt, reallyEnded)
	}
}

// TestDestroyAfterExitRuntimes: WASM and isolate have no main program and
// refuse the option at create and on update; container and Firecracker
// sandboxes take it.
func TestDestroyAfterExitRuntimes(t *testing.T) {
	lc := models.Lifecycle{DestroyAfterExitFor: time.Minute}
	for runtime, ok := range map[string]bool{
		models.RuntimeDocker: true, models.RuntimeGvisor: true, models.RuntimeFirecracker: true, "": true,
		models.RuntimeWasm: false, models.RuntimeIsolate: false,
	} {
		err := validateLifecycleRuntime(lc, runtime)
		if (err == nil) != ok || (err != nil && !strings.Contains(err.Error(), "destroy_after_exit_for is not supported")) {
			t.Fatalf("runtime %q: %v, want ok=%v", runtime, err, ok)
		}
	}
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "mod.wasm", Runtime: models.RuntimeWasm, Lifecycle: &lc}); err == nil ||
		!strings.Contains(err.Error(), "destroy_after_exit_for is not supported") {
		t.Fatalf("wasm create = %v", err)
	}
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-iso", Image: "b", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateLifecycle(ctx, "sb-iso", lc); err == nil {
		t.Fatal("isolate lifecycle update accepted destroy_after_exit_for")
	}
	if err := (models.Lifecycle{DestroyAfterExitFor: -time.Second}).Validate(); err == nil {
		t.Fatal("negative destroy_after_exit_for accepted")
	}
	if err := (models.Lifecycle{DestroyAfterExitFor: 31 * 24 * time.Hour}).Validate(); err == nil {
		t.Fatal("destroy_after_exit_for over 30 days accepted")
	}
	if (models.Lifecycle{DestroyAfterExitFor: time.Minute}).IsZero() {
		t.Fatal("a lifecycle with only destroy_after_exit_for reads as no lifecycle")
	}
}
