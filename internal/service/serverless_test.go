package service

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
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
