//go:build linux

package supervisor

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestStartHelperByPidfd: the helper is followed by its pidfd, so its end
// is seen whoever reaps it, and once it has ended no signal is sent; a
// cgroup that is not one, and a binary that is not there, fail the start.
func TestStartHelperByPidfd(t *testing.T) {
	script := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, err := StartHelper("", script, os.Environ(), nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Done():
		t.Fatal("ended before it was told to")
	case <-time.After(50 * time.Millisecond):
	}
	if err := c.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("SIGTERM did not end it")
	}
	if err := c.Signal(syscall.SIGKILL); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("a signal after it ended = %v, want os.ErrProcessDone", err)
	}

	if _, err := StartHelper(t.TempDir(), script, nil, nil); err == nil {
		t.Fatal("started in a folder that is not a cgroup")
	}
	if _, err := StartHelper(filepath.Join(t.TempDir(), "missing"), script, nil, nil); err == nil {
		t.Fatal("started in a cgroup that is not there")
	}
	if _, err := StartHelper("", filepath.Join(t.TempDir(), "missing"), nil, nil); err == nil {
		t.Fatal("started a binary that is not there")
	}
}

// TestOpenPidfd: the group's kill by hand holds a process by pidfd and
// kills it through it; a pid with no process cannot be held.
func TestOpenPidfd(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	p, err := openPidfd(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	// Reap (another test's) may collect it first: then Wait fails with
	// ECHILD, and the process is reaped all the same.
	err = cmd.Wait()
	var ee *exec.ExitError
	if err == nil || (errors.As(err, &ee) && ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL) {
		t.Fatalf("the held process ended with %v, want SIGKILL", err)
	}
	if err := p.Kill(); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("a kill after it was reaped = %v, want ESRCH (never another process)", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openPidfd(-1); err == nil {
		t.Fatal("held pid -1")
	}
}
