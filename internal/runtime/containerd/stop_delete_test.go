package containerd

import (
	"context"
	"errors"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
)

// stillRunning is what runsc answers a delete that comes after the task's
// status left Running but before the sandbox is torn down.
var stillRunning = errors.New("failed to delete task: cannot delete a running container")

func stopWithTask(t *testing.T, task *fakeTask) error {
	t.Helper()
	origDelete, origPoll := stopDeleteTimeout, stopPollInterval
	stopDeleteTimeout, stopPollInterval = 50*time.Millisecond, time.Millisecond
	t.Cleanup(func() { stopDeleteTimeout, stopPollInterval = origDelete, origPoll })
	tr := newFakeTransport()
	tr.containers["sb-stop"] = &fakeContainer{id: "sb-stop", task: task}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	return d.Stop(context.Background(), "sb-stop")
}

// TestStopRetriesTheDeleteUntilGVisorLetsGo is the disk-full drill's
// failure on EKS: the first deletes after the SIGTERM are refused while
// runsc tears the sandbox down. Stop must still succeed, or the service
// records the exit as the sandbox's own.
func TestStopRetriesTheDeleteUntilGVisorLetsGo(t *testing.T) {
	refusals := 3
	task := &fakeTask{status: cntr.Stopped, deleteFn: func(opts int) error {
		if opts != 0 {
			t.Errorf("a retry killed the task (opts=%d); want a plain delete while time remains", opts)
		}
		if refusals > 0 {
			refusals--
			return stillRunning
		}
		return nil
	}}
	if err := stopWithTask(t, task); err != nil {
		t.Fatalf("Stop = %v, want nil once the delete goes through", err)
	}
	if task.deletes != 4 {
		t.Fatalf("deletes = %d, want 4 (3 refused, then done)", task.deletes)
	}
}

// TestStopDeleteEndsWithAKill: refused until the time is up, the last try
// kills what is left and deletes it.
func TestStopDeleteEndsWithAKill(t *testing.T) {
	killed := false
	task := &fakeTask{status: cntr.Stopped, deleteFn: func(opts int) error {
		if opts == 0 {
			return stillRunning
		}
		killed = true
		return nil
	}}
	if err := stopWithTask(t, task); err != nil {
		t.Fatalf("Stop = %v, want nil after the killing delete", err)
	}
	if !killed || task.deletes < 2 {
		t.Fatalf("killed=%v deletes=%d, want plain deletes then one with WithProcessKill", killed, task.deletes)
	}
}

// TestStopDeleteOfAGoneTaskIsDone: a task deleted in between (the events
// path, a retry) is what Stop wanted.
func TestStopDeleteOfAGoneTaskIsDone(t *testing.T) {
	task := &fakeTask{status: cntr.Stopped, deleteFn: func(int) error { return errdefs.ErrNotFound }}
	if err := stopWithTask(t, task); err != nil {
		t.Fatalf("Stop = %v, want nil for a task already gone", err)
	}
	if task.deletes != 1 {
		t.Fatalf("deletes = %d, want 1", task.deletes)
	}
}

// TestStopDeleteThatNeverWorksFails: a delete refused even with the kill is
// still an error the caller sees.
func TestStopDeleteThatNeverWorksFails(t *testing.T) {
	task := &fakeTask{status: cntr.Stopped, deleteFn: func(int) error { return stillRunning }}
	if err := stopWithTask(t, task); !errors.Is(err, stillRunning) {
		t.Fatalf("Stop = %v, want the delete's error", err)
	}
}

// TestStopDeleteStopsWaitingWhenTheCallerGoes: a cancelled stop does not
// sit out the retry window.
func TestStopDeleteStopsWaitingWhenTheCallerGoes(t *testing.T) {
	origDelete, origPoll := stopDeleteTimeout, stopPollInterval
	stopDeleteTimeout, stopPollInterval = time.Minute, 10*time.Millisecond
	t.Cleanup(func() { stopDeleteTimeout, stopPollInterval = origDelete, origPoll })
	ctx, cancel := context.WithCancel(context.Background())
	task := &fakeTask{status: cntr.Stopped, deleteFn: func(int) error { cancel(); return stillRunning }}
	start := time.Now()
	if err := deleteExitedTask(ctx, task); !errors.Is(err, context.Canceled) {
		t.Fatalf("deleteExitedTask = %v, want context.Canceled", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("waited out the retry window after the caller left")
	}
}
