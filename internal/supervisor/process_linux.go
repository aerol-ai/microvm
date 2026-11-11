//go:build linux

package supervisor

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// BecomeReaper makes this process the reaper for its orphans when it is not
// the container's PID 1 (a pod sharing one process namespace): a shim whose
// containerd exited is re-parented here and must be collected here.
func BecomeReaper() error { return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }

// Reap collects every child that exits, forever, and sends the pid of the
// watched one to exited. Orphaned shims are collected and dropped, so they
// never pile up as zombies.
func Reap(watched *atomic.Int64, exited chan<- int, log *slog.Logger) {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		switch {
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.ECHILD):
			time.Sleep(200 * time.Millisecond) // no children yet
			continue
		case err != nil:
			log.Warn("supervisor: wait", "error", err)
			time.Sleep(time.Second)
			continue
		}
		if int64(pid) == watched.Load() {
			log.Warn("supervisor: containerd ended", "pid", pid, "status", ws.ExitStatus(), "signal", ws.Signal().String())
			exited <- pid
		}
	}
}

// StartInGroup starts argv as a child placed in the cgroup at dir from its
// first instruction (clone3 with CLONE_INTO_CGROUP), so nothing it spawns is
// ever charged elsewhere: memory stays charged where it was first used. Its
// output is this container's, and the reaper, not Go, waits for it.
func StartInGroup(dir string, argv []string) (int, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	return pid, nil
}

// Terminate asks pid to stop.
func Terminate(pid int) { _ = syscall.Kill(pid, syscall.SIGTERM) }

// LowerOwnOOMScore makes this process, and what it starts, the kernel's last
// choice when the pod runs out of memory: the machinery must outlive any
// sandbox (finding F10).
func LowerOwnOOMScore() error {
	return os.WriteFile("/proc/self/oom_score_adj", []byte(strconv.Itoa(-999)), 0o644)
}
