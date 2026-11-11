//go:build linux

package supervisor

import (
	"errors"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The reaper collects a child Go does not wait for and reports the watched
// one; an ordinary folder is no cgroup to start a child in.
func TestProcessCallsOnLinux(t *testing.T) {
	if err := BecomeReaper(); err != nil {
		t.Fatalf("BecomeReaper: %v", err)
	}
	// Lowering the score needs CAP_SYS_RESOURCE, which root in a plain
	// container lacks (the worker's runtime container has it, spike S7);
	// Run only logs a failure, so either result is fine here.
	_ = LowerOwnOOMScore()
	// A path that is not a mount point is no error; a missing one is.
	if err := Unmount(t.TempDir()); err != nil && !errors.Is(err, syscall.EPERM) {
		t.Fatalf("Unmount of a plain folder: %v", err)
	}
	if err := Unmount(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("unmounted a path that does not exist")
	}
	if _, err := StartInGroup(filepath.Join(t.TempDir(), "missing"), []string{"true"}); err == nil {
		t.Fatal("started in a group that does not exist")
	}
	if _, err := StartInGroup(t.TempDir(), []string{"true"}); err == nil {
		t.Fatal("started in a folder that is not a cgroup")
	}

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	var watched atomic.Int64
	watched.Store(int64(pid))
	exited := make(chan int, 1)
	go Reap(&watched, exited, quiet())
	Terminate(pid)
	select {
	case got := <-exited:
		if got != pid {
			t.Fatalf("reaped %d, want %d", got, pid)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the watched child was not reaped")
	}
}
