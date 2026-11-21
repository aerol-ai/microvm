//go:build linux

package supervisor

import (
	"errors"
	"os"
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
