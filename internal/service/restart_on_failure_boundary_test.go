package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Review 2 finding 9 (#939, restart on failure): an automatic restart already
// inside the runtime start must not undo a stop that succeeded. These are the
// lifecycle-boundary tests for restart_on_failure.go (lifecycle_boundary.go).

type review923StartRuntime struct {
	*recordingRuntime
	entered chan struct{}
	release chan struct{}
}

func (r *review923StartRuntime) Start(ctx context.Context, id string) (*models.SandboxRuntimeState, error) {
	close(r.entered)
	<-r.release
	return r.recordingRuntime.Start(ctx, id)
}

// TestReview923ManualStopMustWinOverInflightRestart is the reviewer's
// reproducer, moved from review_923_regression_test.go with its assertions.
// A restart on failure is inside the runtime start when a manual stop comes.
// Before: the stop ran at once, succeeded and cancelled the stored restart,
// then the restart finished and wrote "started". Now the stop waits for the
// restart (one lifecycle boundary), then stops the restarted sandbox. The
// reproducer called StopSandbox inline before releasing the start; with the
// stop now waiting for that start, it runs in its own goroutine here, and the
// test also checks that it did wait.
func TestReview923ManualStopMustWinOverInflightRestart(t *testing.T) {
	ctx := context.Background()
	rt := &review923StartRuntime{recordingRuntime: &recordingRuntime{}, entered: make(chan struct{}), release: make(chan struct{})}
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	seedStartedSandbox(t, st, "sb-restart")
	sb, _ := st.Get(ctx, "sb-restart")
	due := time.Now().Add(-time.Second)
	sb.Status, sb.StatusReason, sb.RestartAt = models.SandboxStatusStopped, models.StatusReasonCrashed, &due
	sb.Lifecycle.RestartOnFailure = true
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.ScheduleRestart(ctx, sb.ID, 1, due); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { svc.restartIfDue(ctx, sb.ID); close(done) }()
	select {
	case <-rt.entered:
	case <-done:
		t.Fatal("restart did not reach runtime Start")
	case <-time.After(5 * time.Second):
		t.Fatal("restart did not begin")
	}
	stopped := make(chan error, 1)
	go func() {
		_, err := svc.StopSandbox(ctx, sb.ID)
		stopped <- err
	}()
	select {
	case err := <-stopped:
		t.Fatalf("the stop ran while the restart was inside the runtime start (err=%v)", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(rt.release)
	<-done
	stopErr := <-stopped
	if stopErr != nil {
		t.Fatal(stopErr)
	}
	sb, _ = st.Get(ctx, sb.ID)
	if sb.Status != models.SandboxStatusStopped {
		t.Fatalf("manual stop succeeded but restart left status %s", sb.Status)
	}
	if sb.StatusReason != models.StatusReasonUserStop || sb.RestartAt != nil {
		t.Fatalf("after the stop: reason %q restart_at %v, want user_stop and none", sb.StatusReason, sb.RestartAt)
	}
	if len(rt.stopRefs) != 1 {
		t.Fatalf("runtime stops after the restart = %d, want 1", len(rt.stopRefs))
	}
}

// TestRestartRechecksTheRowAfterTheStart: a sandbox that is not running right
// after its restart (it died at once) keeps the record of that end, not
// "restarted", and the restart still counts for the backoff.
func TestRestartRechecksTheRowAfterTheStart(t *testing.T) {
	h := newRestartHarness(t)
	id := "sb-died-again"
	h.seedRestarting(t, id, models.Lifecycle{})
	h.event(t, id, "die", 3)
	// The runtime reports the container down right after the start.
	h.rt.startState = &models.SandboxRuntimeState{ContainerID: id, ContainerIP: "10.0.0.7", Status: models.SandboxStatusStopped}
	h.clock.advance(time.Minute)
	h.svc.restartIfDue(context.Background(), id)
	row := h.row(t, id)
	wantReason(t, row, models.SandboxStatusStopped, models.StatusReasonCrashed, intPtr(3))
	if row.RestartAt != nil || row.LastRestartedAt == nil {
		t.Fatalf("restart_at %v last_restarted_at %v, want none and set", row.RestartAt, row.LastRestartedAt)
	}
}

// TestRestartGivesUpWhileTheBoundaryStaysBusy: a restart whose wait for the
// boundary outlasts its deadline starts nothing and leaves the restart
// pending, so the sweep arms it again.
func TestRestartGivesUpWhileTheBoundaryStaysBusy(t *testing.T) {
	h := newRestartHarness(t)
	id := "sb-busy-restart"
	h.seedRestarting(t, id, models.Lifecycle{})
	h.event(t, id, "die", 1)
	h.clock.advance(time.Minute)
	unlock, err := h.svc.lifecycleLocks.lockCtx(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	h.svc.restartIfDue(ctx, id)
	cancel()
	unlock()
	if len(h.rt.startRefs) != 0 {
		t.Fatal("started while another step held the boundary")
	}
	if row := h.row(t, id); !restartPending(row) {
		t.Fatalf("the restart was dropped: status %q restart_at %v", row.Status, row.RestartAt)
	}
}

// blockingStopRuntime holds a runtime stop until the test releases it.
type blockingStopRuntime struct {
	*ruleRecordingRuntime
	entered chan struct{}
	release chan struct{}
}

func (r *blockingStopRuntime) Stop(ctx context.Context, ref string) error {
	close(r.entered)
	<-r.release
	return r.recordingRuntime.Stop(ctx, ref)
}

// TestACrashDuringAStopSchedulesNoRestart: the kernel OOM-kills the sandbox
// while a manual stop is inside the runtime stop. The die event waits for
// the stop (the boundary), so it finds the stop's record and schedules no
// restart. Before, the die ran alongside: it could write "out_of_memory"
// first and schedule its restart after the stop had cancelled none, and the
// restart then undid the stop.
func TestACrashDuringAStopSchedulesNoRestart(t *testing.T) {
	ctx := context.Background()
	h := newRestartHarness(t)
	brt := &blockingStopRuntime{ruleRecordingRuntime: h.rt, entered: make(chan struct{}), release: make(chan struct{})}
	h.svc.docker = brt
	id := "sb-oom-stop"
	h.seedRestarting(t, id, models.Lifecycle{})

	stopped := make(chan error, 1)
	go func() {
		_, err := h.svc.StopSandbox(ctx, id)
		stopped <- err
	}()
	<-brt.entered
	h.event(t, id, "oom", 0) // a record only: it does not wait
	died := make(chan error, 1)
	go func() {
		died <- h.svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: id, Action: "die", ExitCode: 137, Time: time.Now().UTC()})
	}()
	select {
	case err := <-died:
		t.Fatalf("the die event ran while the stop held the boundary (err=%v)", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(brt.release)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if err := <-died; err != nil {
		t.Fatal(err)
	}
	row := h.row(t, id)
	if row.Status != models.SandboxStatusStopped || row.StatusReason != models.StatusReasonUserStop || row.RestartAt != nil {
		t.Fatalf("status %q reason %q restart_at %v, want stopped by the user with no restart", row.Status, row.StatusReason, row.RestartAt)
	}
	if n := h.clock.count(); n != 0 {
		t.Fatalf("restart timers armed: %d", n)
	}
}
