//go:build linux || darwin

package containerd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"golang.org/x/sys/unix"
)

// fifoIOSeams points the task IO at FIFOs under a temp dir instead of
// containerd's /run/containerd/fifo, keeping the real cio copy goroutines.
func fifoIOSeams(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origCreator, origAttach := newTaskIOCreator, newTaskIOAttach
	newTaskIOCreator = func(w io.Writer) cio.Creator {
		return cio.NewCreator(cio.WithStreams(nil, w, w), cio.WithFIFODir(dir))
	}
	t.Cleanup(func() { newTaskIOCreator, newTaskIOAttach = origCreator, origAttach })
	return dir
}

// writeAll plays the shim: it writes n bytes into a task's stdout FIFO and
// reports whether they all went through before the deadline. With nothing
// draining the FIFO, the write blocks once the pipe buffer is full.
func writeAll(t *testing.T, fifo string, n int, within time.Duration) bool {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			done <- err
			return
		}
		defer f.Close()
		_, err = f.Write(bytes.Repeat([]byte("x"), n))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write to %s: %v", fifo, err)
		}
		return true
	case <-time.After(within):
		return false
	}
}

// The cluster-bank-flagship UC-171 hang (2026-11-01): Create released the
// task log when it returned, which closed the file under containerd's copy
// goroutines; the copy stopped, and a sandbox stopped dead after ~128 KiB of
// output (a web server's access log). The log now outlives Create: 1 MiB
// written after release drains, lands in the file, and the file closes when
// the task's IO ends.
func TestTaskLogKeepsDrainingAfterCreateReturns(t *testing.T) {
	fifoIOSeams(t)
	d := &Driver{}
	logPath := filepath.Join(t.TempDir(), "sb-1.log")
	creator, release, err := d.taskLogIO(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tio, err := creator("sb-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.drainedTasks.Load("sb-1"); !ok {
		t.Fatal("a task whose IO this process built is not marked as drained")
	}
	release() // what Create's deferred cleanup runs on return

	if !writeAll(t, tio.Config().Stdout, 1<<20, 10*time.Second) {
		t.Fatal("1 MiB of output blocked after Create returned: nothing drains the task's FIFO")
	}
	waitLogSize(t, logPath, 1<<20)
	tio.Cancel()
	tio.Wait()
	_ = tio.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := d.drainedTasks.Load("sb-1"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the drained mark outlived the task's IO")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitLogSize waits for the copy goroutines to land want bytes in the log.
func waitLogSize(t *testing.T, path string, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, err := os.Stat(path)
		if err == nil && info.Size() == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("task log = %v, %v; want %d bytes", info, err, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A log containerd never took (NewTask failed before building IO) is closed
// by release; one it took is not.
func TestTaskLogReleaseClosesOnlyAnUnusedLog(t *testing.T) {
	l, err := openTaskLog(filepath.Join(t.TempDir(), "unused.log"), false)
	if err != nil {
		t.Fatal(err)
	}
	l.release()
	if !l.w.closed {
		t.Fatal("release left an unused log open")
	}

	l2, err := openTaskLog(filepath.Join(t.TempDir(), "used.log"), false)
	if err != nil {
		t.Fatal(err)
	}
	l2.handedOff.Store(true)
	l2.release()
	if l2.w.closed {
		t.Fatal("release closed a log whose task IO still drains into it")
	}
	l2.close()
}

// After sandboxd restarts, a running task's FIFOs have no reader (the shim
// keeps them open, so output just backs up). The boot reconcile re-attaches:
// the task's output drains again, appends to the log it already had, and a
// second pass does not attach twice.
func TestListManagedReattachesARunningTaskOnce(t *testing.T) {
	stubToolboxProbe(t)
	dir := t.TempDir()
	stdout, stderr := filepath.Join(dir, "sb-run-stdout"), filepath.Join(dir, "sb-run-stderr")
	for _, p := range []string{stdout, stderr} {
		if err := unix.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	running := &fakeContainer{
		id:          "sb-run",
		task:        &fakeTask{status: cntr.Running},
		attachFIFOs: cio.NewFIFOSet(cio.Config{Stdout: stdout, Stderr: stderr}, nil),
	}
	stopped := &fakeContainer{id: "sb-stopped", task: &fakeTask{status: cntr.Stopped}}
	tr := newFakeTransport()
	tr.containers[running.id] = running
	tr.containers[stopped.id] = stopped
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	logPath, err := d.taskLogPath("sb-run")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("before restart\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for pass := range 2 {
		if _, err := d.ListManaged(context.Background()); err != nil {
			t.Fatalf("ListManaged pass %d: %v", pass, err)
		}
	}
	if running.attaches != 1 {
		t.Fatalf("running task attached %d times over two passes, want 1", running.attaches)
	}
	if stopped.attaches != 0 {
		t.Fatalf("stopped task attached %d times, want 0", stopped.attaches)
	}
	if !writeAll(t, stdout, 1<<20, 10*time.Second) {
		t.Fatal("1 MiB of output blocked after the re-attach: the running task's FIFO is still not drained")
	}
	waitLogSize(t, logPath, int64(len("before restart\n"))+1<<20) // appended, not truncated
	if v, ok := d.drainedTasks.Load("sb-run"); ok {
		v.(*taskLog).close()
	}
}

// A re-attach that containerd never runs (no task to load) leaves no mark
// behind, so a later pass tries again.
func TestEnsureTaskDrainWithoutATaskLeavesNoMark(t *testing.T) {
	d := newTestDriver(t)
	gone := &fakeContainer{id: "sb-gone"}
	d.ensureTaskDrain(context.Background(), gone)
	if _, ok := d.drainedTasks.Load("sb-gone"); ok {
		t.Fatal("a task containerd could not load is marked as drained")
	}
}

// When containerd fails to build the task's IO, the log is closed at once
// (nothing will ever own it) and no drained mark is left.
func TestTaskLogClosesWhenContainerdCannotBuildIO(t *testing.T) {
	origCreator, origAttach := newTaskIOCreator, newTaskIOAttach
	t.Cleanup(func() { newTaskIOCreator, newTaskIOAttach = origCreator, origAttach })
	boom := errors.New("fifo: no space")
	newTaskIOCreator = func(io.Writer) cio.Creator { return func(string) (cio.IO, error) { return nil, boom } }
	newTaskIOAttach = func(io.Writer) cio.Attach { return func(*cio.FIFOSet) (cio.IO, error) { return nil, boom } }

	d := &Driver{}
	creator, release, err := d.taskLogIO(filepath.Join(t.TempDir(), "sb-x.log"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := creator("sb-x"); !errors.Is(err, boom) {
		t.Fatalf("creator error = %v, want %v", err, boom)
	}
	release()
	if _, ok := d.drainedTasks.Load("sb-x"); ok {
		t.Fatal("a failed IO left a drained mark")
	}

	l, err := openTaskLog(filepath.Join(t.TempDir(), "sb-y.log"), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.attach()(nil); !errors.Is(err, boom) || !l.w.closed {
		t.Fatalf("attach error = %v closed = %v; want %v and a closed log", err, l.w.closed, boom)
	}
}

// ensureTaskDrain gives up (with a warning) when the log cannot be reopened,
// and an already-drained task is not loaded again.
func TestEnsureTaskDrainSkipsDrainedAndUnopenableLogs(t *testing.T) {
	d := newTestDriver(t)
	c := &fakeContainer{id: "sb-z", task: &fakeTask{status: cntr.Running}}
	path, err := d.taskLogPath("sb-z")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil { // a directory where the log file goes
		t.Fatal(err)
	}
	d.ensureTaskDrain(context.Background(), c)
	if c.attaches != 0 {
		t.Fatalf("attached %d times with no log to drain into", c.attaches)
	}
	if _, ok := d.drainedTasks.Load("sb-z"); ok {
		t.Fatal("a failed reopen left a drained mark")
	}

	d.drainedTasks.Store("sb-z", &taskLog{})
	d.ensureTaskDrain(context.Background(), c)
	if c.attaches != 0 {
		t.Fatal("re-attached a task this process already drains")
	}
}
