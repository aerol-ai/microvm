//go:build linux

package supervisor

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"sync"
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

// Unmount detaches the mount at path; a path that is not a mount point
// (EINVAL) is no error.
func Unmount(path string) error {
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) {
		return err
	}
	return nil
}

// Terminate asks pid to stop.
func Terminate(pid int) { _ = syscall.Kill(pid, syscall.SIGTERM) }

// LowerOwnOOMScore makes this process, and what it starts, the kernel's last
// choice when the pod runs out of memory: the machinery must outlive any
// sandbox (finding F10).
func LowerOwnOOMScore() error {
	return os.WriteFile("/proc/self/oom_score_adj", []byte(strconv.Itoa(-999)), 0o644)
}

// StartHelper starts the root helper at bin, in the cgroup at dir (none
// when dir is empty, for tests), with env and with files as descriptors 3
// and up. Its output is this container's.
//
// The reaper collects it like any child, so it is followed by pidfd, not
// pid: the pidfd says when it ended whoever reaped it, and a signal sent
// through it reaches only it. Once reaped, its pid may go to a sandbox's
// process, which a signal by pid would then kill.
func StartHelper(dir, bin string, env []string, files []*os.File) (Child, error) {
	pidfd := -1
	attr := &syscall.SysProcAttr{PidFD: &pidfd}
	if dir != "" {
		fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		defer unix.Close(fd)
		attr.UseCgroupFD, attr.CgroupFD = true, fd
	}
	cmd := exec.Command(bin)
	cmd.Env, cmd.ExtraFiles, cmd.SysProcAttr = env, files, attr
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if pidfd < 0 {
		// A kernel with no pidfd (before 5.3) cannot be followed safely.
		_ = cmd.Process.Kill()
		_ = cmd.Process.Release()
		return nil, errNoPidfd
	}
	_ = cmd.Process.Release()
	return newPidfdChild(pidfd), nil
}

var errNoPidfd = errors.New("this kernel gives no pidfd; the root helper needs Linux 5.3 or newer")

// pidfdChild is a child followed by its pidfd.
type pidfdChild struct {
	mu   sync.Mutex
	fd   int // -1 once the child has exited and the pidfd is closed
	done chan struct{}
}

func newPidfdChild(fd int) *pidfdChild {
	c := &pidfdChild{fd: fd, done: make(chan struct{})}
	go c.wait()
	return c
}

// wait polls the pidfd, which reads as ready once the process has exited.
func (c *pidfdChild) wait() {
	fds := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, -1)
		if errors.Is(err, unix.EINTR) || (err == nil && n == 0) {
			continue
		}
		break // ready, or the pidfd is unusable: either way it is over
	}
	c.mu.Lock()
	_ = unix.Close(c.fd)
	c.fd = -1
	close(c.done)
	c.mu.Unlock()
}

func (c *pidfdChild) Signal(sig syscall.Signal) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return os.ErrProcessDone
	}
	return unix.PidfdSendSignal(c.fd, sig, nil, 0)
}

func (c *pidfdChild) Done() <-chan struct{} { return c.done }
