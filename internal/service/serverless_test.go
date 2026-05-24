package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// newServerlessHarness builds the minimal Service needed to exercise the
// stop-mode classification + wake-arming logic. Unlike
// newServiceRuntimeHarness/newCapacityHarness it pins
// cfg.EnableServerless=true so the gate is open and the tests can
// observe the wake_armed transitions; tests that need to verify the
// rollout-gate behavior flip the flag back off.
func newServerlessHarness(t *testing.T, runtime *fakeCapacityRuntime) (*Service, *store.Store) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc, _, harnessStore := newCapacityHarness(t, nil, nil)
	// Throw away the harness's store — we want a fresh one we control.
	// The harness stitched it together with everything else, so swap
	// just the fields we need.
	svc.store = st
	svc.docker = runtime
	svc.cfg = config.Config{EnableServerless: true}
	_ = harnessStore

	return svc, st
}

// seedServerlessSandbox writes a started sandbox row with the chosen
// serverless flag. Returns the seeded sandbox so the test can assert
// against the original.
func seedServerlessSandbox(t *testing.T, st *store.Store, id string, serverless bool) *models.Sandbox {
	t.Helper()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:           id,
		Image:        "ubuntu:22.04",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-" + id,
		ContainerIP:  "10.0.0.10",
		CPU:          1,
		MemoryMB:     1024,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
		Lifecycle: models.Lifecycle{
			Serverless:    serverless,
			StopIfIdleFor: 5 * time.Minute,
		},
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	return sb
}

// TestStopSandboxManualClearsWakeArmed: a serverless sandbox that the
// operator manually stops must NOT arm wake. The operator wants the
// sandbox down; an HTTP request must not silently bring it back.
func TestStopSandboxManualClearsWakeArmed(t *testing.T) {
	ctx := context.Background()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	sb := seedServerlessSandbox(t, st, "sb-manual", true)

	// Pre-arm to prove the manual stop actively clears (not just leaves
	// it untouched). Mirrors the realistic sequence: lifecycle stop
	// armed wake, operator now manually stops via API.
	if err := st.SetWakeArmed(ctx, sb.ID, true); err != nil {
		t.Fatalf("pre-arm: %v", err)
	}

	stopped, err := svc.StopSandbox(ctx, sb.ID)
	if err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}
	if stopped.WakeArmed {
		t.Fatalf("manual stop left WakeArmed=true, want false")
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.WakeArmed {
		t.Fatalf("store WakeArmed=true after manual stop, want false")
	}
}

// TestStopSandboxLifecycleArmsServerlessWake: when the lifecycle sweep
// stops a serverless sandbox, wake_armed must be set so the next HTTP
// request resurrects it.
func TestStopSandboxLifecycleArmsServerlessWake(t *testing.T) {
	ctx := context.Background()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	sb := seedServerlessSandbox(t, st, "sb-lifecycle-serverless", true)

	stopped, err := svc.stopSandboxInternal(ctx, sb.ID, stopModeLifecycle)
	if err != nil {
		t.Fatalf("stopSandboxInternal lifecycle: %v", err)
	}
	if !stopped.WakeArmed {
		t.Fatalf("lifecycle stop of serverless sandbox did not arm wake")
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.WakeArmed {
		t.Fatalf("store wake_armed not set after lifecycle stop of serverless sandbox")
	}
}

// TestStopSandboxLifecycleDoesNotArmNonServerless: a non-serverless
// sandbox stopped by the lifecycle sweep must NOT arm wake. The
// wake-aware proxy will then never auto-resume it.
func TestStopSandboxLifecycleDoesNotArmNonServerless(t *testing.T) {
	ctx := context.Background()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	sb := seedServerlessSandbox(t, st, "sb-lifecycle-plain", false)

	stopped, err := svc.stopSandboxInternal(ctx, sb.ID, stopModeLifecycle)
	if err != nil {
		t.Fatalf("stopSandboxInternal lifecycle: %v", err)
	}
	if stopped.WakeArmed {
		t.Fatalf("lifecycle stop of non-serverless sandbox armed wake, want false")
	}
}

// TestStopSandboxEnableServerlessFalseSuppressesArming: with the
// rollout gate off, even a serverless sandbox stopped via lifecycle
// must NOT arm wake. The gate must produce identical behavior to the
// pre-feature codebase so an operator can disable the feature
// host-wide without flipping every Lifecycle row.
func TestStopSandboxEnableServerlessFalseSuppressesArming(t *testing.T) {
	ctx := context.Background()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	svc.cfg.EnableServerless = false
	sb := seedServerlessSandbox(t, st, "sb-gate-off", true)

	stopped, err := svc.stopSandboxInternal(ctx, sb.ID, stopModeLifecycle)
	if err != nil {
		t.Fatalf("stopSandboxInternal: %v", err)
	}
	if stopped.WakeArmed {
		t.Fatalf("gate=off armed wake; want EnableServerless=false to be a no-op")
	}
}

// TestDockerEventInvoluntaryStopArmsServerlessWake: a Docker die event
// for a serverless sandbox we did NOT record an expected stop for
// classifies as involuntary and arms wake.
func TestDockerEventInvoluntaryStopArmsServerlessWake(t *testing.T) {
	ctx := context.Background()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	sb := seedServerlessSandbox(t, st, "sb-involuntary", true)

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: sb.ID,
		Action:    "die",
		ExitCode:  1,
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("handleDockerEvent die: %v", err)
	}

	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("status = %q, want stopped", got.Status)
	}
	if !got.WakeArmed {
		t.Fatalf("involuntary stop of serverless sandbox did not arm wake")
	}
}

// TestDockerEventManualStopDoesNotArmWake: when sandboxd issues a stop
// via the API, the events handler must classify the resulting die
// event as manual (via the expected-stop bookkeeping) and NOT arm
// wake. This is the test that proves the expectedStops map prevents
// the manual stop from being mistaken for a crash.
func TestDockerEventManualStopDoesNotArmWake(t *testing.T) {
	ctx := context.Background()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	sb := seedServerlessSandbox(t, st, "sb-manual-event", true)

	// Simulate the manual stop path recording its expectation. We
	// don't actually call StopSandbox because the fake runtime's
	// Stop() doesn't emit Docker events; instead we record directly
	// then fire the die event the way Docker would have.
	svc.recordExpectedStop(sb.ID, stopModeManual)

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: sb.ID,
		Action:    "die",
		ExitCode:  0,
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("handleDockerEvent die: %v", err)
	}

	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.WakeArmed {
		t.Fatalf("manual stop event armed wake; expected expectation to suppress")
	}
}

// TestDockerEventOOMAlwaysInvoluntary: even when sandboxd had recorded
// an expected stop (e.g. operator issued StopSandbox), an OOM kill
// reaping the container before the stop completed must still classify
// as involuntary so a serverless sandbox can recover on the next
// request. The kernel killed the container, not the operator.
func TestDockerEventOOMAlwaysInvoluntary(t *testing.T) {
	ctx := context.Background()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	sb := seedServerlessSandbox(t, st, "sb-oom", true)

	svc.recordExpectedStop(sb.ID, stopModeManual)

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: sb.ID,
		Action:    "oom",
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("handleDockerEvent oom: %v", err)
	}

	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.WakeArmed {
		t.Fatalf("OOM kill did not arm wake despite serverless flag")
	}
}

// TestConsumeExpectedStopAgeOutTreatsAsInvoluntary: an expectation
// older than expectedStopMaxAge must be ignored so a stale entry
// can't shield a future real involuntary exit from being armed.
func TestConsumeExpectedStopAgeOutTreatsAsInvoluntary(t *testing.T) {
	svc := &Service{
		cfg:           config.Config{EnableServerless: true},
		expectedStops: make(map[string]expectedStopRecord),
	}
	svc.expectedStops["stale"] = expectedStopRecord{
		mode:       stopModeManual,
		recordedAt: time.Now().Add(-expectedStopMaxAge - time.Second),
	}
	if got := svc.consumeExpectedStop("stale"); got != stopModeInvoluntary {
		t.Fatalf("aged expectation = %v, want involuntary", got)
	}
}

// TestRecordExpectedStopSweepsStaleEntries: an entry whose matching
// Docker event never arrived (events stream drop, daemon restart,
// sandbox deleted mid-stop) must be reaped opportunistically so the
// map can't grow unbounded. The next stop on any other sandbox triggers
// the sweep.
func TestRecordExpectedStopSweepsStaleEntries(t *testing.T) {
	svc := &Service{
		cfg:           config.Config{EnableServerless: true},
		expectedStops: make(map[string]expectedStopRecord),
	}
	svc.expectedStops["leaked"] = expectedStopRecord{
		mode:       stopModeLifecycle,
		recordedAt: time.Now().Add(-expectedStopMaxAge - time.Second),
	}
	svc.expectedStops["fresh"] = expectedStopRecord{
		mode:       stopModeLifecycle,
		recordedAt: time.Now(),
	}
	svc.recordExpectedStop("new", stopModeManual)
	if _, ok := svc.expectedStops["leaked"]; ok {
		t.Fatalf("stale entry still present after sweep")
	}
	if _, ok := svc.expectedStops["fresh"]; !ok {
		t.Fatalf("fresh entry was incorrectly reaped")
	}
	if _, ok := svc.expectedStops["new"]; !ok {
		t.Fatalf("new entry was not recorded")
	}
}

// seedSleepingSandbox seeds a stopped + wake_armed=true serverless
// sandbox — the state the wake helper expects to wake. Centralizes
// the field set so every wake test starts from the same baseline.
func seedSleepingSandbox(t *testing.T, st *store.Store, id string) {
	t.Helper()
	sb := seedServerlessSandbox(t, st, id, true)
	sb.Status = models.SandboxStatusStopped
	sb.WakeArmed = true
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("upsert sleeping sandbox: %v", err)
	}
}

// TestEnsureSandboxAwakeForHTTPFastPathStarted: a sandbox already
// in started state must not invoke StartSandbox. The wake helper is
// on the request-serving hot path; an unnecessary store/runtime
// round trip would burn budget on every steady-state request.
func TestEnsureSandboxAwakeForHTTPFastPathStarted(t *testing.T) {
	ctx := context.Background()
	runtime := &fakeCapacityRuntime{}
	svc, st := newServerlessHarness(t, runtime)
	seedServerlessSandbox(t, st, "sb-hot", true) // status=started

	got, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-hot")
	if err != nil {
		t.Fatalf("EnsureSandboxAwakeForHTTP: %v", err)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q, want started", got.Status)
	}
	if runtime.startCount != 0 {
		t.Fatalf("Start called %d times on running sandbox; want 0", runtime.startCount)
	}
}

// TestEnsureSandboxAwakeForHTTPManualStop: a sandbox that the operator
// stopped (wake_armed=false) must return ErrSandboxManuallyStopped so
// the caller surfaces 409 instead of silently resurrecting.
func TestEnsureSandboxAwakeForHTTPManualStop(t *testing.T) {
	ctx := context.Background()
	runtime := &fakeCapacityRuntime{}
	svc, st := newServerlessHarness(t, runtime)
	sb := seedServerlessSandbox(t, st, "sb-manual-down", true)
	sb.Status = models.SandboxStatusStopped
	sb.WakeArmed = false
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	_, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-manual-down")
	if !errors.Is(err, ErrSandboxManuallyStopped) {
		t.Fatalf("err = %v, want ErrSandboxManuallyStopped", err)
	}
	if runtime.startCount != 0 {
		t.Fatalf("Start called %d times on manual-stopped sandbox; want 0", runtime.startCount)
	}
}

// TestEnsureSandboxAwakeForHTTPGateOff: with the rollout gate off,
// the wake helper must be a transparent pass-through — return the
// current sandbox row WITHOUT error and WITHOUT calling Start. The
// caller's existing ToolboxTarget path then produces the same
// "container IP not available" behavior the pre-feature codebase
// did. Returning a new sentinel here would change error semantics
// for non-serverless callers, violating the rollout-gate contract.
func TestEnsureSandboxAwakeForHTTPGateOff(t *testing.T) {
	ctx := context.Background()
	runtime := &fakeCapacityRuntime{}
	svc, st := newServerlessHarness(t, runtime)
	svc.cfg.EnableServerless = false
	seedSleepingSandbox(t, st, "sb-gate-off-wake")

	got, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-gate-off-wake")
	if err != nil {
		t.Fatalf("gate-off should be transparent, got err: %v", err)
	}
	if got == nil || got.ID != "sb-gate-off-wake" {
		t.Fatalf("got = %+v, want sandbox row passed through", got)
	}
	if runtime.startCount != 0 {
		t.Fatalf("Start called %d times with gate off; want 0", runtime.startCount)
	}
}

// TestEnsureSandboxAwakeForHTTPNonServerlessPassthrough: a stopped
// NON-serverless sandbox must be passed through (same rationale as
// gate-off). Only serverless-flagged sandboxes participate in the
// wake state machine.
func TestEnsureSandboxAwakeForHTTPNonServerlessPassthrough(t *testing.T) {
	ctx := context.Background()
	runtime := &fakeCapacityRuntime{}
	svc, st := newServerlessHarness(t, runtime)
	sb := seedServerlessSandbox(t, st, "sb-plain-stopped", false)
	sb.Status = models.SandboxStatusStopped
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-plain-stopped")
	if err != nil {
		t.Fatalf("non-serverless should be transparent, got err: %v", err)
	}
	if got.Lifecycle.Serverless {
		t.Fatalf("returned sandbox marked serverless; seed sets false")
	}
	if runtime.startCount != 0 {
		t.Fatalf("Start called %d times on non-serverless sandbox; want 0", runtime.startCount)
	}
}

// TestEnsureSandboxAwakeForHTTPColdStart: the canonical path —
// stopped + wake_armed serverless sandbox wakes on the first call
// and returns the started sandbox.
func TestEnsureSandboxAwakeForHTTPColdStart(t *testing.T) {
	ctx := context.Background()
	runtime := &fakeCapacityRuntime{
		startResult: &models.SandboxRuntimeState{
			ContainerID: "ctr-cold",
			ContainerIP: "10.0.0.20",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st := newServerlessHarness(t, runtime)
	seedSleepingSandbox(t, st, "sb-cold")

	got, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-cold")
	if err != nil {
		t.Fatalf("EnsureSandboxAwakeForHTTP: %v", err)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q, want started", got.Status)
	}
	if runtime.startCount != 1 {
		t.Fatalf("Start called %d times; want exactly 1 cold start", runtime.startCount)
	}
}

// TestEnsureSandboxAwakeForHTTPSingleFlightCollapses: a burst of
// concurrent wake requests for one sandbox must collapse to a single
// StartSandbox call. Proves the per-sandbox lock works as a
// single-flight, not just a serializer that runs N starts.
func TestEnsureSandboxAwakeForHTTPSingleFlightCollapses(t *testing.T) {
	ctx := context.Background()
	runtime := &fakeCapacityRuntime{
		startResult: &models.SandboxRuntimeState{
			ContainerID: "ctr-burst",
			ContainerIP: "10.0.0.30",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st := newServerlessHarness(t, runtime)
	seedSleepingSandbox(t, st, "sb-burst")

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.EnsureSandboxAwakeForHTTP(ctx, "sb-burst")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if runtime.startCount != 1 {
		t.Fatalf("Start called %d times for %d concurrent wakes; want exactly 1", runtime.startCount, n)
	}
}

// TestEnsureSandboxAwakeForHTTPCircuitOpensAndRecovers: 5
// consecutive cold-start failures within the window must trip the
// per-sandbox breaker; once tripped the next call is rejected with
// ErrWakeCircuitOpen WITHOUT invoking Start. After the open window
// elapses (simulated by rewinding openUntil), the breaker resets and
// the next call attempts a real start again.
func TestEnsureSandboxAwakeForHTTPCircuitOpensAndRecovers(t *testing.T) {
	ctx := context.Background()
	runtime := &fakeCapacityRuntime{
		startErr: errors.New("boom: simulated start failure"),
	}
	svc, st := newServerlessHarness(t, runtime)
	seedSleepingSandbox(t, st, "sb-trip")

	// Drive the threshold-1 attempts; each must call Start.
	for i := 0; i < wakeFailureThreshold; i++ {
		if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-trip"); err == nil {
			t.Fatalf("attempt %d: want error, got nil", i)
		}
		// After a failed Start, StartSandbox set status=error. Reset
		// to stopped+armed so the next attempt actually exercises the
		// wake path (we are testing the breaker, not StartSandbox
		// retries).
		sb, err := st.Get(ctx, "sb-trip")
		if err != nil {
			t.Fatalf("get after attempt %d: %v", i, err)
		}
		sb.Status = models.SandboxStatusStopped
		sb.WakeArmed = true
		if err := st.Upsert(ctx, sb); err != nil {
			t.Fatalf("re-arm after attempt %d: %v", i, err)
		}
	}
	if runtime.startCount != wakeFailureThreshold {
		t.Fatalf("Start called %d times; want %d", runtime.startCount, wakeFailureThreshold)
	}

	// Breaker should now be open: next call rejected without Start.
	_, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-trip")
	if !errors.Is(err, ErrWakeCircuitOpen) {
		t.Fatalf("post-trip err = %v, want ErrWakeCircuitOpen", err)
	}
	if runtime.startCount != wakeFailureThreshold {
		t.Fatalf("Start called during open circuit (count=%d, threshold=%d)", runtime.startCount, wakeFailureThreshold)
	}

	// Rewind openUntil to simulate the 60s window elapsing.
	flight := svc.wakeFlightFor("sb-trip")
	flight.mu.Lock()
	flight.openUntil = time.Now().Add(-time.Second)
	flight.mu.Unlock()

	// Make Start succeed now so the recovery attempt clears state.
	runtime.startErr = nil
	runtime.startResult = &models.SandboxRuntimeState{
		ContainerID: "ctr-recovered",
		ContainerIP: "10.0.0.40",
		Status:      models.SandboxStatusStarted,
	}
	got, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-trip")
	if err != nil {
		t.Fatalf("post-recovery wake: %v", err)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("post-recovery status = %q, want started", got.Status)
	}
	if runtime.startCount != wakeFailureThreshold+1 {
		t.Fatalf("Start called %d times overall; want %d", runtime.startCount, wakeFailureThreshold+1)
	}
}

// TestWakeAwareToolboxTargetManualStopSentinel: the proxy entry
// point must surface ErrSandboxManuallyStopped without falling
// through to ToolboxTarget. apihttp.WriteStoreAwareError then maps
// the sentinel to 409. Verifies the wake-helper sentinel propagates
// instead of being shadowed by "container IP not available" from
// the legacy resolver.
func TestWakeAwareToolboxTargetManualStopSentinel(t *testing.T) {
	ctx := context.Background()
	runtime := &fakeCapacityRuntime{}
	svc, st := newServerlessHarness(t, runtime)
	sb := seedServerlessSandbox(t, st, "sb-wake-target-manual", true)
	sb.Status = models.SandboxStatusStopped
	sb.WakeArmed = false
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	_, err := svc.WakeAwareToolboxTarget(ctx, "sb-wake-target-manual")
	if !errors.Is(err, ErrSandboxManuallyStopped) {
		t.Fatalf("err = %v, want ErrSandboxManuallyStopped", err)
	}
	if runtime.startCount != 0 {
		t.Fatalf("Start called %d times; want 0", runtime.startCount)
	}
}

// TestWakeAwareToolboxTargetWakesAndResolves: a stopped + armed
// serverless sandbox is woken AND the resolver returns a real
// endpoint pointing at the freshly assigned ContainerIP. This is
// the end-to-end happy path the control-plane proxies depend on.
func TestWakeAwareToolboxTargetWakesAndResolves(t *testing.T) {
	ctx := context.Background()
	runtime := &fakeCapacityRuntime{
		startResult: &models.SandboxRuntimeState{
			ContainerID: "ctr-wake-target",
			ContainerIP: "10.0.0.55",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st := newServerlessHarness(t, runtime)
	svc.cfg.ToolboxPort = 21214
	seedSleepingSandbox(t, st, "sb-wake-target")

	endpoint, err := svc.WakeAwareToolboxTarget(ctx, "sb-wake-target")
	if err != nil {
		t.Fatalf("WakeAwareToolboxTarget: %v", err)
	}
	if endpoint.URL != "http://10.0.0.55:21214" {
		t.Fatalf("endpoint URL = %q, want http://10.0.0.55:21214", endpoint.URL)
	}
	if runtime.startCount != 1 {
		t.Fatalf("Start called %d times; want 1", runtime.startCount)
	}
}

func TestL4WakeProxyWakesTCPExposure(t *testing.T) {
	ctx := context.Background()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	upstreamPort := upstream.Addr().(*net.TCPAddr).Port
	upstreamDone := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			upstreamDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			upstreamDone <- err
			return
		}
		if string(buf) != "ping" {
			upstreamDone <- fmt.Errorf("upstream read %q, want ping", string(buf))
			return
		}
		_, err = conn.Write([]byte("pong"))
		upstreamDone <- err
	}()

	runtime := &fakeCapacityRuntime{
		startResult: &models.SandboxRuntimeState{
			ContainerID: "ctr-l4",
			ContainerIP: "127.0.0.1",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st := newServerlessHarness(t, runtime)
	svc.cfg.EnableCaddy = true
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:0"
	svc.cfg.InternalL4WakeDir = t.TempDir()
	svc.caddy = caddy.New(config.Config{EnableCaddy: true, HTTPClientTimeout: time.Second})

	wakeCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	if err := svc.StartL4WakeProxy(wakeCtx); err != nil {
		t.Fatalf("StartL4WakeProxy: %v", err)
	}
	wakeAddr := svc.l4WakeTCP.Addr().String()
	// The listener is the unit under test; route installation during
	// StartSandbox can be a no-op here.
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})

	seedSleepingSandbox(t, st, "sb-l4")
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-l4",
		Port:      upstreamPort,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  40123,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertPort: %v", err)
	}

	conn, err := net.Dial("tcp", wakeAddr)
	if err != nil {
		t.Fatalf("dial wake proxy: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "PROXY TCP4 198.51.100.10 203.0.113.20 50000 40123\r\nping"); err != nil {
		t.Fatalf("write wake proxy: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read wake proxy response: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("wake proxy response = %q, want pong", string(buf))
	}
	if err := <-upstreamDone; err != nil {
		t.Fatalf("upstream handler: %v", err)
	}
	if runtime.startCount != 1 {
		t.Fatalf("Start called %d times; want 1", runtime.startCount)
	}
	got, err := st.Get(ctx, "sb-l4")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.WakeArmed {
		t.Fatalf("WakeArmed=true after L4 wake; want false")
	}
}

func TestL4WakePendingLimitRejectsOverflow(t *testing.T) {
	svc := &Service{cfg: config.Config{
		L4WakeMaxPendingPerSandbox: 1,
		L4WakeMaxPendingGlobal:     2,
	}}

	release, ok := svc.tryAcquireL4Pending("sb-a")
	if !ok {
		t.Fatal("first pending acquire rejected")
	}
	if _, ok := svc.tryAcquireL4Pending("sb-a"); ok {
		t.Fatal("second same-sandbox pending acquire accepted; want rejected")
	}
	release()
	if release, ok := svc.tryAcquireL4Pending("sb-a"); !ok {
		t.Fatal("pending acquire after release rejected")
	} else {
		release()
	}

	releaseA, ok := svc.tryAcquireL4Pending("sb-a")
	if !ok {
		t.Fatal("pending acquire for sb-a rejected")
	}
	defer releaseA()
	releaseB, ok := svc.tryAcquireL4Pending("sb-b")
	if !ok {
		t.Fatal("pending acquire for sb-b rejected")
	}
	defer releaseB()
	if _, ok := svc.tryAcquireL4Pending("sb-c"); ok {
		t.Fatal("global pending overflow accepted; want rejected")
	}
}

func TestL4WakeActiveLimitRejectsOverflow(t *testing.T) {
	svc := &Service{
		cfg: config.Config{
			L4WakeMaxActivePerSandbox: 1,
			L4WakeMaxActiveGlobal:     2,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	release, ok := svc.tryAcquireL4Active("sb-a")
	if !ok {
		t.Fatal("first active acquire rejected")
	}
	if _, ok := svc.tryAcquireL4Active("sb-a"); ok {
		t.Fatal("second same-sandbox active acquire accepted; want rejected")
	}
	release()
	if release, ok := svc.tryAcquireL4Active("sb-a"); !ok {
		t.Fatal("active acquire after release rejected")
	} else {
		release()
	}

	releaseA, ok := svc.tryAcquireL4Active("sb-a")
	if !ok {
		t.Fatal("active acquire for sb-a rejected")
	}
	defer releaseA()
	releaseB, ok := svc.tryAcquireL4Active("sb-b")
	if !ok {
		t.Fatal("active acquire for sb-b rejected")
	}
	defer releaseB()
	if _, ok := svc.tryAcquireL4Active("sb-c"); ok {
		t.Fatal("global active overflow accepted; want rejected")
	}
}

// TestWakeFailureWindowSlides: failures more than wakeFailureWindow
// apart must NOT accumulate — otherwise an hour of one-off blips
// would trip the breaker even though the sandbox is healthy. This is
// the only test that exercises the sliding-window reset rule
// directly; the breaker test above hits the back-to-back path.
func TestWakeFailureWindowSlides(t *testing.T) {
	w := &wakeFlight{}
	now := time.Now()
	w.recordFailure(now)
	w.recordFailure(now.Add(wakeFailureWindow + time.Second))
	if w.failures != 1 {
		t.Fatalf("failures = %d after window-elapsed second failure; want 1", w.failures)
	}
	if !w.openUntil.IsZero() {
		t.Fatalf("breaker tripped on second failure outside the window")
	}
}

// TestWakeCircuitOpenWindowIs60s pins the D3 contract: when the
// breaker trips, the open window is exactly wakeCircuitOpenFor (60s
// per the plan). Locks the duration so we notice if someone changes
// the constant without updating the public Retry-After surface.
func TestWakeCircuitOpenWindowIs60s(t *testing.T) {
	if wakeCircuitOpenFor != 60*time.Second {
		t.Fatalf("wakeCircuitOpenFor = %v, want 60s (D3 contract)", wakeCircuitOpenFor)
	}
	w := &wakeFlight{}
	start := time.Now()
	for i := 0; i < wakeFailureThreshold; i++ {
		w.recordFailure(start.Add(time.Duration(i) * time.Second))
	}
	if w.openUntil.IsZero() {
		t.Fatalf("breaker did not trip after %d failures", wakeFailureThreshold)
	}
	// openUntil is set on the final failure (start + (N-1)s), so the
	// expected close time is start + (N-1)s + wakeCircuitOpenFor.
	wantClose := start.Add(time.Duration(wakeFailureThreshold-1)*time.Second + wakeCircuitOpenFor)
	if !w.openUntil.Equal(wantClose) {
		t.Fatalf("openUntil = %v, want %v (delta %v)", w.openUntil, wantClose, w.openUntil.Sub(wantClose))
	}
}

// TestWakeCircuitTripsOnCapacityErrors: the plan's D3 wording is
// "5 consecutive capacity failures open the circuit." Verify the
// breaker counts capacity.ErrCapacityExceeded the same as any other
// start error — it is the most operationally important failure mode
// to circuit-break against (a host out of CPU/RAM should not be
// hammered by every wake request).
func TestWakeCircuitTripsOnCapacityErrors(t *testing.T) {
	ctx := context.Background()
	runtime := &fakeCapacityRuntime{
		startErr: capacity.ErrCapacityExceeded,
	}
	svc, st := newServerlessHarness(t, runtime)
	seedSleepingSandbox(t, st, "sb-cap-trip")

	for i := 0; i < wakeFailureThreshold; i++ {
		_, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-cap-trip")
		if err == nil {
			t.Fatalf("attempt %d: want capacity error, got nil", i)
		}
		// Re-arm so the next attempt is a real wake (StartSandbox sets
		// status=error on failure).
		sb, getErr := st.Get(ctx, "sb-cap-trip")
		if getErr != nil {
			t.Fatalf("get after attempt %d: %v", i, getErr)
		}
		sb.Status = models.SandboxStatusStopped
		sb.WakeArmed = true
		if err := st.Upsert(ctx, sb); err != nil {
			t.Fatalf("re-arm: %v", err)
		}
	}

	// Sixth call must be rejected by the breaker without another
	// Start invocation (this is the whole point of the breaker
	// versus retrying every request).
	_, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-cap-trip")
	if !errors.Is(err, ErrWakeCircuitOpen) {
		t.Fatalf("post-trip err = %v, want ErrWakeCircuitOpen", err)
	}
	if runtime.startCount != wakeFailureThreshold {
		t.Fatalf("Start called %d times during open circuit; want exactly %d", runtime.startCount, wakeFailureThreshold)
	}
}

// routeFake is a tiny Caddy admin fake that records PATCH (upsert) and
// DELETE (remove) calls per route @id so installHTTPPortRoute /
// removeHTTPPortRoute can be observed without a real Caddy.
type routeFake struct {
	mu      sync.Mutex
	routes  map[string]map[string]any // routeID -> body
	deletes map[string]int            // routeID -> delete count
}

func newRouteFake() *routeFake {
	return &routeFake{
		routes:  map[string]map[string]any{},
		deletes: map[string]int{},
	}
}

func (f *routeFake) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/id/"):
			id := strings.TrimPrefix(r.URL.Path, "/id/")
			body, _ := io.ReadAll(r.Body)
			var parsed map[string]any
			_ = json.Unmarshal(body, &parsed)
			f.mu.Lock()
			defer f.mu.Unlock()
			// Treat PATCH-on-missing as 404 so the upsertRoute fallback
			// runs through PUT — but our minimal fake answers PUT too.
			if _, ok := f.routes[id]; !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			f.routes[id] = parsed
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/config/apps/http/servers/"):
			body, _ := io.ReadAll(r.Body)
			var parsed map[string]any
			_ = json.Unmarshal(body, &parsed)
			f.mu.Lock()
			defer f.mu.Unlock()
			if id, _ := parsed["@id"].(string); id != "" {
				f.routes[id] = parsed
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/id/"):
			id := strings.TrimPrefix(r.URL.Path, "/id/")
			f.mu.Lock()
			defer f.mu.Unlock()
			f.deletes[id]++
			if _, ok := f.routes[id]; !ok {
				// caddy.Client treats 404 as success.
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			delete(f.routes, id)
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	})
}

func (f *routeFake) routeIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, 0, len(f.routes))
	for id := range f.routes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func newRouteTestService(t *testing.T, fake *routeFake, enableServerless bool) *Service {
	t.Helper()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	client := caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	return &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  client,
		cfg: config.Config{
			EnableServerless:    enableServerless,
			InternalIngressAddr: "127.0.0.1:21213",
			Domain:              "sandbox.example.com",
			EnableCaddy:         true,
		},
	}
}

func TestInstallHTTPPortRouteServerlessInstallsWakeAndClearsDirect(t *testing.T) {
	fake := newRouteFake()
	svc := newRouteTestService(t, fake, true)
	sb := &models.Sandbox{
		ID:          "abc",
		ContainerIP: "10.0.0.10",
		Lifecycle:   models.Lifecycle{Serverless: true},
	}
	if err := svc.installHTTPPortRoute(context.Background(), sb, 3000); err != nil {
		t.Fatalf("installHTTPPortRoute: %v", err)
	}
	ids := fake.routeIDs()
	want := []string{"sandbox-abc-port-3000-wake"}
	if !equalSorted(ids, want) {
		t.Fatalf("route ids = %v, want %v", ids, want)
	}
	// Direct delete was attempted (idempotent, 404 absorbed).
	if fake.deletes["sandbox-abc-port-3000"] == 0 {
		t.Fatalf("direct route delete should have been attempted; deletes=%+v", fake.deletes)
	}
}

func TestInstallHTTPPortRouteNonServerlessInstallsDirectAndClearsWake(t *testing.T) {
	fake := newRouteFake()
	svc := newRouteTestService(t, fake, true)
	sb := &models.Sandbox{
		ID:          "abc",
		ContainerIP: "10.0.0.10",
		Lifecycle:   models.Lifecycle{Serverless: false},
	}
	if err := svc.installHTTPPortRoute(context.Background(), sb, 3000); err != nil {
		t.Fatalf("installHTTPPortRoute: %v", err)
	}
	ids := fake.routeIDs()
	want := []string{"sandbox-abc-port-3000"}
	if !equalSorted(ids, want) {
		t.Fatalf("route ids = %v, want %v", ids, want)
	}
	if fake.deletes["sandbox-abc-port-3000-wake"] == 0 {
		t.Fatalf("wake route delete should have been attempted; deletes=%+v", fake.deletes)
	}
}

func TestInstallHTTPPortRouteGateOffIgnoresServerlessFlag(t *testing.T) {
	fake := newRouteFake()
	svc := newRouteTestService(t, fake, false) // gate off
	sb := &models.Sandbox{
		ID:          "abc",
		ContainerIP: "10.0.0.10",
		Lifecycle:   models.Lifecycle{Serverless: true}, // SDK pre-set the flag
	}
	if err := svc.installHTTPPortRoute(context.Background(), sb, 3000); err != nil {
		t.Fatalf("installHTTPPortRoute: %v", err)
	}
	ids := fake.routeIDs()
	want := []string{"sandbox-abc-port-3000"}
	if !equalSorted(ids, want) {
		t.Fatalf("route ids = %v, want %v (gate off must keep legacy direct routes regardless of flag)", ids, want)
	}
}

// TestStopSandboxInternalWakeArmedKeepsWakeRouteLive: stopping a
// serverless sandbox with wake_armed must KEEP a route alive for any
// HTTP exposure — in the wake-aware shape so the ingress proxy can
// resurrect on next request. The direct shape (if any) gets removed.
func TestStopSandboxInternalWakeArmedKeepsWakeRouteLive(t *testing.T) {
	ctx := context.Background()
	fake := newRouteFake()
	// Seed the direct route as if the sandbox had been running.
	fake.routes["sandbox-sb-stop-arm-port-3000"] = map[string]any{"@id": "sandbox-sb-stop-arm-port-3000"}

	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.EnableCaddy = true

	sb := seedServerlessSandbox(t, st, "sb-stop-arm", true)
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID,
		Port:      3000,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed port: %v", err)
	}

	if _, err := svc.stopSandboxInternal(ctx, sb.ID, stopModeLifecycle); err != nil {
		t.Fatalf("stopSandboxInternal: %v", err)
	}

	ids := fake.routeIDs()
	want := []string{"sandbox-sb-stop-arm-port-3000-wake"}
	if !equalSorted(ids, want) {
		t.Fatalf("after stop+arm, routes = %v, want %v", ids, want)
	}
}

// TestGCZombieKeepsWakeRouteForServerlessSandbox: the keep-set must
// include the wake @id for any HTTP exposure on a serverless sandbox so
// the reconcile GC does not delete it between sweeps.
func TestGCZombieKeepsWakeRouteForServerlessSandbox(t *testing.T) {
	fake := newGCCaddyFake()
	fake.httpRouteIDs["sandbox-sl"] = struct{}{}
	fake.httpRouteIDs["sandbox-sl-port-3000-wake"] = struct{}{}
	// Also seed a wake route for a non-serverless sandbox — it must
	// be GC'd because the keep-set excludes wake @ids for those.
	fake.httpRouteIDs["sandbox-plain-port-3000-wake"] = struct{}{}
	fake.httpRouteIDs["sandbox-plain"] = struct{}{}
	fake.httpRouteIDs["sandbox-plain-port-3000"] = struct{}{}

	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy: caddy.New(config.Config{
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			EnableCaddy:       true,
			HTTPClientTimeout: 2 * time.Second,
		}),
		cfg: config.Config{EnableServerless: true},
	}

	serverless := &models.Sandbox{
		ID:        "sl",
		Status:    models.SandboxStatusStopped,
		Lifecycle: models.Lifecycle{Serverless: true},
		WakeArmed: true,
		ExposedPorts: []models.ExposedPort{{
			SandboxID: "sl", Port: 3000, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: time.Now().UTC(),
		}},
	}
	plain := &models.Sandbox{
		ID:     "plain",
		Status: models.SandboxStatusStarted,
		ExposedPorts: []models.ExposedPort{{
			SandboxID: "plain", Port: 3000, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: time.Now().UTC(),
		}},
	}
	svc.gcZombieCaddyEntries(context.Background(), []*models.Sandbox{serverless, plain})

	wantKept := []string{"sandbox-plain", "sandbox-plain-port-3000", "sandbox-sl", "sandbox-sl-port-3000-wake"}
	if got := fake.keys(fake.httpRouteIDs); !equalSorted(got, wantKept) {
		t.Fatalf("after gc: got %v, want %v", got, wantKept)
	}
}

func TestRemoveHTTPPortRouteDeletesBothShapes(t *testing.T) {
	fake := newRouteFake()
	// Seed both shapes so removeHTTPPortRoute has work to do.
	fake.routes["sandbox-abc-port-3000"] = map[string]any{"@id": "sandbox-abc-port-3000"}
	fake.routes["sandbox-abc-port-3000-wake"] = map[string]any{"@id": "sandbox-abc-port-3000-wake"}
	svc := newRouteTestService(t, fake, true)
	if err := svc.removeHTTPPortRoute(context.Background(), "abc", 3000); err != nil {
		t.Fatalf("removeHTTPPortRoute: %v", err)
	}
	if len(fake.routeIDs()) != 0 {
		t.Fatalf("expected all routes deleted; got %v", fake.routeIDs())
	}
}

// TestStopSandboxInternalD5CaddyBeforeStore proves the D5 invariant:
// the Caddy wake-route upsert happens BEFORE wake_armed is flipped
// in the store. The inverse order would leave a window where the
// sandbox is recorded as sleeping with no matching wake route, so
// requests landing in that window would 502 through Caddy. We
// observe the order by reading the store inside the fake Caddy
// admin handler at the moment the wake route is upserted.
func TestStopSandboxInternalD5CaddyBeforeStore(t *testing.T) {
	ctx := context.Background()
	fake := newRouteFake()
	fake.routes["sandbox-sb-d5-port-3000"] = map[string]any{"@id": "sandbox-sb-d5-port-3000"}

	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})

	var (
		wakeRouteSeen         bool
		armedWhenWakeUpserted bool
		captureWakeUpsertMu   sync.Mutex
	)
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// PUT (path: /config/apps/http/servers/...) or PATCH (/id/<id>)
		// is how upsertRoute installs a route. Snapshot the store the
		// moment we see the wake-route id come through.
		if isWakeUpsert(r, "sandbox-sb-d5-port-3000-wake") {
			captureWakeUpsertMu.Lock()
			if !wakeRouteSeen {
				wakeRouteSeen = true
				if sb, err := st.Get(ctx, "sb-d5"); err == nil {
					armedWhenWakeUpserted = sb.WakeArmed
				}
			}
			captureWakeUpsertMu.Unlock()
		}
		fake.handler(t).ServeHTTP(w, r)
	})
	server := httptest.NewServer(wrappedHandler)
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.EnableCaddy = true

	sb := seedServerlessSandbox(t, st, "sb-d5", true)
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID,
		Port:      3000,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed port: %v", err)
	}

	if _, err := svc.stopSandboxInternal(ctx, sb.ID, stopModeLifecycle); err != nil {
		t.Fatalf("stopSandboxInternal: %v", err)
	}

	if !wakeRouteSeen {
		t.Fatalf("wake route was never upserted — test setup broken")
	}
	if armedWhenWakeUpserted {
		t.Fatalf("D5 violation: wake_armed was already true when wake route was being upserted; store flipped before caddy")
	}
	// And after the stop completes, wake_armed must be true (the
	// caddy-first ordering still results in the same final state).
	final, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("get after stop: %v", err)
	}
	if !final.WakeArmed {
		t.Fatalf("after stop, wake_armed = false; expected true on lifecycle stop of serverless sandbox")
	}
}

// TestStopSandboxInternalD5WakeRouteFailureDegradesToNonArm proves
// the D5 fallback: if every wake-route upsert fails, we degrade to
// a non-arm stop so wake_armed and route state never disagree.
func TestStopSandboxInternalD5WakeRouteFailureDegradesToNonArm(t *testing.T) {
	ctx := context.Background()
	fake := newRouteFake()
	fake.routes["sandbox-sb-d5fail-port-3000"] = map[string]any{"@id": "sandbox-sb-d5fail-port-3000"}

	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})

	// Reject every wake-route upsert with 500 so the install loop
	// exhausts all attempts without success.
	failHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWakeUpsert(r, "sandbox-sb-d5fail-port-3000-wake") {
			http.Error(w, "caddy admin down", http.StatusInternalServerError)
			return
		}
		fake.handler(t).ServeHTTP(w, r)
	})
	server := httptest.NewServer(failHandler)
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.EnableCaddy = true

	sb := seedServerlessSandbox(t, st, "sb-d5fail", true)
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID,
		Port:      3000,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed port: %v", err)
	}

	if _, err := svc.stopSandboxInternal(ctx, sb.ID, stopModeLifecycle); err != nil {
		t.Fatalf("stopSandboxInternal: %v", err)
	}
	final, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("get after stop: %v", err)
	}
	if final.WakeArmed {
		t.Fatalf("wake_armed = true after all wake-route upserts failed; should have degraded to non-arm")
	}
}

// TestStopEventPreservesWakeRouteForArmingStop is the P0 regression:
// after stopSandboxInternal installs the wake route and calls docker.Stop,
// the resulting die event must NOT delete the wake route. Pre-fix,
// markSandboxStopped's per-port deleteExposedPortRoute loop nuked the
// wake-aware shape too, so a stopped serverless sandbox lost its only
// ingress and the next inbound HTTP request would 404 through Caddy.
//
// The test simulates the post-stopSandboxInternal state (sandbox row at
// Stopped with WakeArmed=true, wake route installed in Caddy, expectation
// recorded as stopModeLifecycle) and fires the die event. The wake route
// must survive and wake_armed must remain true.
func TestStopEventPreservesWakeRouteForArmingStop(t *testing.T) {
	ctx := context.Background()
	fake := newRouteFake()
	// Post-stopSandboxInternal Caddy state: wake route installed, direct
	// route already removed.
	fake.routes["sandbox-sb-evt-arm-port-3000-wake"] = map[string]any{"@id": "sandbox-sb-evt-arm-port-3000-wake"}

	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.EnableCaddy = true

	// Seed at status=Stopped with WakeArmed=true to mirror the row state
	// stopSandboxInternal would have left behind by the time the die event
	// arrives. ContainerIP empty so the netrules branch is a no-op.
	sb := seedServerlessSandbox(t, st, "sb-evt-arm", true)
	sb.Status = models.SandboxStatusStopped
	sb.WakeArmed = true
	sb.ContainerIP = ""
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("upsert seed: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID,
		Port:      3000,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed port: %v", err)
	}
	// stopSandboxInternal recorded a lifecycle expectation before
	// docker.Stop — replicate that so the event classifier returns
	// stopModeLifecycle and shouldArmWake stays true.
	svc.recordExpectedStop(sb.ID, stopModeLifecycle)

	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{
		SandboxID: sb.ID,
		Action:    "die",
		ExitCode:  0,
		Time:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("handleDockerEvent die: %v", err)
	}

	// The wake route must still be present after the die event.
	ids := fake.routeIDs()
	want := []string{"sandbox-sb-evt-arm-port-3000-wake"}
	if !equalSorted(ids, want) {
		t.Fatalf("after die event, routes = %v, want %v (P0: stop event wiped the wake route)", ids, want)
	}

	// And wake_armed must remain true so EnsureSandboxAwakeForHTTP
	// will actually resurrect on the next request.
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("get after die: %v", err)
	}
	if !got.WakeArmed {
		t.Fatalf("wake_armed = false after die event on serverless lifecycle stop; want true")
	}
}

// isWakeUpsert reports whether r is a PATCH or PUT request that is
// installing the route identified by wakeID. PATCH addresses by
// /id/<id>; PUT carries the body with `"@id": <id>`.
func isWakeUpsert(r *http.Request, wakeID string) bool {
	if r.Method == http.MethodPatch {
		return strings.HasSuffix(r.URL.Path, "/id/"+wakeID)
	}
	if r.Method == http.MethodPut {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return false
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		var parsed map[string]any
		if json.Unmarshal(body, &parsed) != nil {
			return false
		}
		id, _ := parsed["@id"].(string)
		return id == wakeID
	}
	return false
}

// TestReconstructWakeArmedAfterOwnerChange proves D1: a Serverless
// sandbox that landed on a new owner in `stopped + wake_armed=false`
// (typical after cluster failover, where the previous owner's local
// wake_armed bit doesn't migrate) gets its wake route reinstalled and
// the bit flipped on the next reconcile pass.
func TestReconstructWakeArmedAfterOwnerChange(t *testing.T) {
	ctx := context.Background()
	fake := newRouteFake()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.EnableCaddy = true

	sb := seedServerlessSandbox(t, st, "sb-d1", true)
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID,
		Port:      3000,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed port: %v", err)
	}
	// Simulate the post-failover shape: stopped row, wake_armed=false,
	// HTTP exposure carried over from the spec.
	sb.Status = models.SandboxStatusStopped
	sb.WakeArmed = false
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("seed stopped: %v", err)
	}
	reloaded, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	svc.ReconstructWakeArmedIfNeeded(ctx, reloaded)

	if !reloaded.WakeArmed {
		t.Fatalf("in-memory sandbox WakeArmed = false; want true after reconstruction")
	}
	final, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get after reconstruct: %v", err)
	}
	if !final.WakeArmed {
		t.Fatalf("store wake_armed = false after reconstruction; want true")
	}
	ids := fake.routeIDs()
	want := []string{"sandbox-sb-d1-port-3000-wake"}
	if !equalSorted(ids, want) {
		t.Fatalf("wake route not installed; routes = %v, want %v", ids, want)
	}
}

// TestReconstructWakeArmedIsNoOpForNonServerless proves the helper is
// inert for sandboxes that did not opt into serverless: we must never
// flip wake_armed for a plain stopped sandbox.
func TestReconstructWakeArmedIsNoOpForNonServerless(t *testing.T) {
	ctx := context.Background()
	fake := newRouteFake()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.EnableCaddy = true

	sb := seedServerlessSandbox(t, st, "sb-plain", false)
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID,
		Port:      3000,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed port: %v", err)
	}
	sb.Status = models.SandboxStatusStopped
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("seed stopped: %v", err)
	}
	reloaded, _ := st.Get(ctx, sb.ID)

	svc.ReconstructWakeArmedIfNeeded(ctx, reloaded)

	final, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final.WakeArmed {
		t.Fatalf("non-serverless sandbox wake_armed = true after reconstruction; should remain false")
	}
	if len(fake.routeIDs()) != 0 {
		t.Fatalf("no wake routes should be installed for non-serverless; got %v", fake.routeIDs())
	}
}

// TestReconstructWakeArmedReinstallsRoutesWhenAlreadyArmed proves the
// helper re-upserts wake routes even when wake_armed=true is already set.
// Caddy's admin-API routes do not survive a Caddy restart, so the daemon
// must treat wake_armed=true as a goal state to reassert against Caddy
// on every reconcile pass — without this, a Caddy restart between
// auto-stop and the next wake request would leave the wildcard 404
// fallback serving requests forever even though the DB looks correct.
// The store, however, must not be touched (the bit is already true and
// pointless writes churn the row on every reconcile tick).
func TestReconstructWakeArmedReinstallsRoutesWhenAlreadyArmed(t *testing.T) {
	ctx := context.Background()
	fake := newRouteFake()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.EnableCaddy = true

	sb := seedServerlessSandbox(t, st, "sb-armed", true)
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID,
		Port:      3000,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed port: %v", err)
	}
	sb.Status = models.SandboxStatusStopped
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("seed stopped: %v", err)
	}
	if err := st.SetWakeArmed(ctx, sb.ID, true); err != nil {
		t.Fatalf("pre-arm: %v", err)
	}
	reloaded, _ := st.Get(ctx, sb.ID)

	svc.ReconstructWakeArmedIfNeeded(ctx, reloaded)

	ids := fake.routeIDs()
	want := []string{"sandbox-sb-armed-port-3000-wake"}
	if !equalSorted(ids, want) {
		t.Fatalf("already-armed sandbox should still re-install wake route to self-heal Caddy; routes = %v, want %v", ids, want)
	}
	final, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !final.WakeArmed {
		t.Fatalf("wake_armed must remain true after reassert pass")
	}
}

// TestReconstructWakeArmedGateOffIsNoOp proves the rollout gate is
// respected: even a serverless sandbox in stopped state must not have
// wake_armed reconstructed when SB_ENABLE_SERVERLESS is off.
func TestReconstructWakeArmedGateOffIsNoOp(t *testing.T) {
	ctx := context.Background()
	fake := newRouteFake()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = false // explicit gate off

	sb := seedServerlessSandbox(t, st, "sb-gateoff", true)
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID,
		Port:      3000,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed port: %v", err)
	}
	sb.Status = models.SandboxStatusStopped
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("seed stopped: %v", err)
	}
	reloaded, _ := st.Get(ctx, sb.ID)

	svc.ReconstructWakeArmedIfNeeded(ctx, reloaded)

	final, _ := st.Get(ctx, sb.ID)
	if final.WakeArmed {
		t.Fatalf("gate-off must not reconstruct wake_armed")
	}
	if len(fake.routeIDs()) != 0 {
		t.Fatalf("gate-off must not install wake routes; got %v", fake.routeIDs())
	}
}

// TestReconstructWakeArmedSkipsWhenAllInstallsFail proves that if
// every wake-route install fails, we leave wake_armed=false rather
// than claim a wake state we can't serve. Matches the D5 fallback
// inside stopSandboxInternal.
func TestReconstructWakeArmedSkipsWhenAllInstallsFail(t *testing.T) {
	ctx := context.Background()
	fake := newRouteFake()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})

	failHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWakeUpsert(r, "sandbox-sb-d1fail-port-3000-wake") {
			http.Error(w, "caddy admin down", http.StatusInternalServerError)
			return
		}
		fake.handler(t).ServeHTTP(w, r)
	})
	server := httptest.NewServer(failHandler)
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		EnableCaddy:       true,
		HTTPClientTimeout: 2 * time.Second,
	})
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.EnableCaddy = true

	sb := seedServerlessSandbox(t, st, "sb-d1fail", true)
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID,
		Port:      3000,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed port: %v", err)
	}
	sb.Status = models.SandboxStatusStopped
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("seed stopped: %v", err)
	}
	reloaded, _ := st.Get(ctx, sb.ID)

	svc.ReconstructWakeArmedIfNeeded(ctx, reloaded)

	final, _ := st.Get(ctx, sb.ID)
	if final.WakeArmed {
		t.Fatalf("wake_armed flipped despite all wake-route upserts failing; expected non-arm fallback")
	}
}
