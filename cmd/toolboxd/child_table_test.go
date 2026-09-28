package main

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// reapBeforeWait reproduces the PID-1 race deterministically: the reaper's
// wait4 collects the child before the handler's cmd.Wait gets to it. The test
// reaps the child's own pid, not -1, so it cannot steal children from other
// tests running in parallel.
func reapBeforeWait(t *testing.T, child *trackedChild) syscall.WaitStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		pid, status, tracked, ok := execChildren.reap(child.pid)
		if ok {
			if pid != child.pid || !tracked {
				t.Fatalf("reap = pid %d tracked=%v, want pid %d tracked", pid, tracked, child.pid)
			}
			return status
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("child %d never exited", child.pid)
	return 0
}

// UC-84 regression: a command that fails must not be reported as exit 0
// because the reaper reaped it before cmd.Wait.
func TestTrackedChildKeepsExitStatusWhenReaperWinsTheRace(t *testing.T) {
	tests := []struct {
		name       string
		script     string
		wantCode   int
		wantSignal string
	}{
		{name: "non-zero exit", script: "exit 3", wantCode: 3},
		{name: "read-only write shape", script: "echo nope > /nonexistent-dir/should-fail.txt", wantCode: 2},
		{name: "killed by signal", script: "kill -9 $$", wantCode: -1, wantSignal: "killed"},
		{name: "success stays success", script: "exit 0", wantCode: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", tc.script)
			child, err := startTracked(cmd)
			if err != nil {
				t.Fatalf("startTracked: %v", err)
			}
			reapBeforeWait(t, child)

			waitErr := child.wait()
			code, sig := interpretWaitResult(waitErr)
			wantCode := tc.wantCode
			if tc.name == "read-only write shape" && code != 0 {
				// sh's code for a failed redirect varies (dash 2, busybox 1).
				// The regression is only about it being reported as 0.
				wantCode = code
			}
			if code != wantCode || sig != tc.wantSignal {
				t.Fatalf("interpretWaitResult = (%d, %q), want (%d, %q); waitErr=%v", code, sig, wantCode, tc.wantSignal, waitErr)
			}
			if tc.wantCode == 0 && waitErr != nil {
				t.Fatalf("exit 0 reaped by the reaper must wait() to nil, got %v", waitErr)
			}
			if _, still := execChildren.byPID[child.pid]; still {
				t.Fatalf("pid %d still registered after wait", child.pid)
			}
		})
	}
}

// Without the race, wait is plain cmd.Wait: the real *exec.ExitError comes
// back and the table entry is dropped.
func TestTrackedChildWaitWithoutReaper(t *testing.T) {
	child, err := startTracked(exec.Command("sh", "-c", "exit 5"))
	if err != nil {
		t.Fatalf("startTracked: %v", err)
	}
	waitErr := child.wait()
	var ee *exec.ExitError
	if !errors.As(waitErr, &ee) || ee.ExitCode() != 5 {
		t.Fatalf("wait = %v, want *exec.ExitError code 5", waitErr)
	}
	execChildren.mu.Lock()
	_, still := execChildren.byPID[child.pid]
	execChildren.mu.Unlock()
	if still {
		t.Fatalf("pid %d still registered after wait", child.pid)
	}
}

func TestChildTableStartFailureRegistersNothing(t *testing.T) {
	before := len(execChildren.byPID)
	if _, err := startTracked(exec.Command("/nonexistent/binary")); err == nil {
		t.Fatal("startTracked of a missing binary succeeded")
	}
	if got := len(execChildren.byPID); got != before {
		t.Fatalf("registered %d entries on a failed start", got-before)
	}
}

// When cmd.Wait reaps the child itself and the kernel reuses the pid for a
// new registered child, the old waiter must not delete the new entry.
func TestTrackedChildWaitKeepsAReusedPIDEntry(t *testing.T) {
	child, err := startTracked(exec.Command("sh", "-c", "exit 0"))
	if err != nil {
		t.Fatalf("startTracked: %v", err)
	}
	newer := make(chan syscall.WaitStatus, 1)
	execChildren.mu.Lock()
	execChildren.byPID[child.pid] = newer // simulate start() of a reused pid
	execChildren.mu.Unlock()
	if err := child.wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	execChildren.mu.Lock()
	got := execChildren.byPID[child.pid]
	delete(execChildren.byPID, child.pid)
	execChildren.mu.Unlock()
	if got != newer {
		t.Fatal("old waiter deleted the reused pid's registration")
	}
}

func TestReapWithNothingExitedIsNotOK(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	child, err := startTracked(cmd)
	if err != nil {
		t.Fatalf("startTracked: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = child.wait() }()
	if _, _, _, ok := execChildren.reap(child.pid); ok {
		t.Fatal("reap reported a still-running child as exited")
	}
}

func TestInterpretWaitResultLostStatusIsNotSuccess(t *testing.T) {
	code, msg := interpretWaitResult(syscall.ECHILD)
	if code == 0 {
		t.Fatalf("ECHILD interpreted as exit 0 (%q); a lost status must not look like success", msg)
	}
}

func TestReapedExitError(t *testing.T) {
	if got := (&reapedExit{status: syscall.WaitStatus(3 << 8)}).Error(); got != "exit status 3" {
		t.Fatalf("Error() = %q", got)
	}
	if got := (&reapedExit{status: syscall.WaitStatus(syscall.SIGKILL)}).Error(); !strings.Contains(got, "killed") {
		t.Fatalf("Error() = %q, want signal text", got)
	}
}

func TestTrackedCombinedOutput(t *testing.T) {
	out, err := trackedCombinedOutput(exec.Command("sh", "-c", "echo out; echo err >&2; exit 4"))
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 4 {
		t.Fatalf("err = %v, want exit 4", err)
	}
	if s := string(out); !strings.Contains(s, "out") || !strings.Contains(s, "err") {
		t.Fatalf("output = %q, want both streams", s)
	}
	cmd := exec.Command("true")
	cmd.Stdout = &strings.Builder{}
	if _, err := trackedCombinedOutput(cmd); err == nil {
		t.Fatal("trackedCombinedOutput with Stdout preset succeeded")
	}
}
