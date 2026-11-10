//go:build linux

package hostproc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// openCgroupDir makes the cgroup name under root and opens it for clone.
// cgroup v2 only: v1 has no CLONE_INTO_CGROUP and no single tree to leave
// sandboxd's unit through.
func openCgroupDir(root, name string) (*os.File, error) {
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("no cgroup v2 hierarchy at %s: %w", root, err)
	}
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	// The kernel makes cgroup.procs with the cgroup, so a missing one means
	// dir is not a cgroup.
	if _, err := os.Stat(filepath.Join(dir, "cgroup.procs")); err != nil {
		return nil, fmt.Errorf("%s is not a cgroup: %w", dir, err)
	}
	return os.Open(dir)
}

// setCgroupFD makes the clone start the process in the cgroup open at fd
// (clone3 with CLONE_INTO_CGROUP, Linux 5.7+).
func setCgroupFD(attr *syscall.SysProcAttr, fd int) {
	attr.UseCgroupFD = true
	attr.CgroupFD = fd
}

// pidfdProcess is a process held by a pidfd.
type pidfdProcess struct {
	pid  int
	fd   int
	done chan struct{}

	mu     sync.Mutex
	closed bool
}

// Open holds pid if it is still the process that started at startTicks.
// The check runs after the pidfd is open, so the pid cannot be reused
// between the two.
func Open(pid int, startTicks uint64) (Process, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil, fmt.Errorf("pid %d: %w", pid, ErrGone)
		}
		return nil, fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	ticks, err := StartTicks(pid)
	if err != nil || ticks != startTicks {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("pid %d is no longer the process that started at tick %d: %w", pid, startTicks, ErrGone)
	}
	p := &pidfdProcess{pid: pid, fd: fd, done: make(chan struct{})}
	go p.watch()
	return p, nil
}

// watch closes done when the process exits: a pidfd turns readable then.
// The timeout lets Close end the loop.
func (p *pidfdProcess) watch() {
	defer close(p.done)
	fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
	for {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return
		}
		n, err := unix.Poll(fds, int(time.Second/time.Millisecond))
		if err != nil && !errors.Is(err, unix.EINTR) {
			return
		}
		if n > 0 && fds[0].Revents != 0 {
			return
		}
	}
}

func (p *pidfdProcess) Pid() int { return p.pid }

func (p *pidfdProcess) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrGone
	}
	err := unix.PidfdSendSignal(p.fd, sig, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return ErrGone
	}
	return err
}

func (p *pidfdProcess) Done() <-chan struct{} { return p.done }

func (p *pidfdProcess) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	// The watcher holds the fd in poll; it notices closed within a second.
	<-p.done
	return unix.Close(p.fd)
}
