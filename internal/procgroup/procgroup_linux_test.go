//go:build linux

package procgroup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// runs reports whether pid runs: there, and not a zombie waiting for its
// parent to reap it (a zombie runs no more of its code).
func runs(pid int) bool {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || (s[i+2] != 'Z' && s[i+2] != 'X')
}

// childPid waits for the pid a test's shell wrote.
func childPid(t *testing.T, path string) int {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if raw, err := os.ReadFile(path); err == nil && strings.HasSuffix(string(raw), "\n") {
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
	}
	t.Fatal("the child never started")
	return 0
}

// TestRunEndsTheGroupOnCancel (PR 4 review): a cancelled call kills the
// child and the child it started (a CNI plugin's IPAM plugin), and Run
// returns only once neither runs.
func TestRunEndsTheGroupOnCancel(t *testing.T) {
	pidf := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sh", "-c", "sleep 30 & echo $! > "+pidf+"; wait")
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cmd) }()
	grandchild := childPid(t, pidf)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a killed run reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the cancel")
	}
	if runs(grandchild) {
		t.Fatalf("the child's own child (pid %d) outlived the cancelled call", grandchild)
	}
}

// TestRunEndsWhatTheChildLeft: a child that exits and leaves a child of
// its own running takes it with it.
func TestRunEndsWhatTheChildLeft(t *testing.T) {
	pidf := filepath.Join(t.TempDir(), "pid")
	if err := Run(context.Background(), exec.Command("sh", "-c", "sleep 30 & echo $! > "+pidf)); err != nil {
		t.Fatal(err)
	}
	if pid := childPid(t, pidf); runs(pid) {
		t.Fatalf("pid %d outlived the run that started it", pid)
	}
}

func TestRunAnswersTheChildsExit(t *testing.T) {
	if err := Run(context.Background(), exec.Command("true")); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), exec.Command("false")); err == nil {
		t.Fatal("a failed child reported success")
	}
	if err := Run(context.Background(), exec.Command("/nonexistent/binary")); err == nil {
		t.Fatal("a missing binary reported success")
	}
}

// TestWaitGoneIsBounded: a group whose member never goes is waited for
// no longer than GoneWait.
func TestWaitGoneIsBounded(t *testing.T) {
	orig := GoneWait
	GoneWait = 50 * time.Millisecond
	t.Cleanup(func() { GoneWait = orig })
	// The test's own process group: it never empties.
	start := time.Now()
	waitGone(syscall.Getpgrp())
	if d := time.Since(start); d < GoneWait || d > 2*time.Second {
		t.Fatalf("waited %v for a group that never empties; the bound is %v", d, GoneWait)
	}
}
