//go:build linux

package mounts

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// pidfdProcess is a helper this sandboxd did not start, held by a pidfd so a
// signal can never reach another process that reused its pid. It mirrors the
// Firecracker driver's adopted-VM handle (internal/runtime/firecracker).
type pidfdProcess struct {
	pid  int
	fd   int
	done chan struct{}

	mu     sync.Mutex
	closed bool
}

// openHelperPidfd opens pid if it still runs argv. The check runs after the
// pidfd is open, so a pid reused between the listing and the open is never
// taken for the helper.
func openHelperPidfd(pid int, argv []string) (liveProcess, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	got, err := readCmdline(pid)
	if err != nil || !slices.Equal(got, argv) {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("pid %d no longer runs %q: %w", pid, argv, errProcessGone)
	}
	p := &pidfdProcess{pid: pid, fd: fd, done: make(chan struct{})}
	go p.watch()
	return p, nil
}

// watch closes done when the process exits: a pidfd turns readable then. The
// timeout lets Close end the loop.
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
		return errProcessGone
	}
	err := unix.PidfdSendSignal(p.fd, sig, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return errProcessGone
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
