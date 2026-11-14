//go:build linux

package hostproc

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// inCgroup reports whether a start asks the clone for a cgroup.
func inCgroup(cmd *exec.Cmd) bool {
	return cmd.SysProcAttr != nil && cmd.SysProcAttr.UseCgroupFD
}

// TestOpenHoldsALiveChild holds a real child by its pidfd: Done closes when
// it exits, and a signal after that is refused, never sent to a later
// process with the same pid.
func TestOpenHoldsALiveChild(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start sleep:", err)
	}
	reaped := make(chan struct{})
	go func() { _ = cmd.Wait(); close(reaped) }()
	p, ticks, err := OpenPID(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("OpenPID: %v", err)
	}
	if p.Pid() != cmd.Process.Pid || ticks == 0 {
		t.Fatalf("pid %d ticks %d", p.Pid(), ticks)
	}
	if _, err := Open(cmd.Process.Pid, ticks+1); !errors.Is(err, ErrGone) {
		t.Fatalf("Open with the wrong start time = %v, want ErrGone", err)
	}
	if err := p.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not close after the child died")
	}
	<-reaped
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal("second Close:", err)
	}
	if err := p.Signal(syscall.SIGTERM); !errors.Is(err, ErrGone) {
		t.Fatalf("Signal after Close = %v, want ErrGone", err)
	}
	if _, err := Open(cmd.Process.Pid, ticks); err == nil {
		t.Fatal("Open of a reaped child succeeded")
	}
}

// TestCgroupStartsAChildInside needs root and a writable cgroup v2 root (a
// privileged container or a real node); it skips elsewhere.
func TestCgroupStartsAChildInside(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("no cgroup v2")
	}
	name := "aerolvm-hostproc-test-" + strconv.Itoa(os.Getpid())
	cg := NewCgroup(nil, "", name, "test workers")
	t.Cleanup(func() { _ = os.Remove(cg.Path()) })
	if !cg.Active() {
		t.Skip("cannot make a cgroup here")
	}
	cmd, err := cg.Start(func() (*exec.Cmd, error) { return exec.Command("sleep", "30"), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pids, err := cg.PIDs()
	if err != nil || len(pids) != 1 || pids[0] != cmd.Process.Pid {
		t.Fatalf("cgroup pids = %v, %v, want [%d]", pids, err, cmd.Process.Pid)
	}
	own, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "cgroup"))
	if want := "0::/" + name + "\n"; string(own) != want {
		t.Fatalf("child cgroup = %q, want %q", own, want)
	}
}
