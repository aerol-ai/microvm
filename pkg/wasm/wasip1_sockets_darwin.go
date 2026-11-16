//go:build darwin

package wasm

import (
	"math"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The host calls under wasip1_sockets.go. macOS has no accept4, SOCK_*
// type flags or pipe2, so close-on-exec is set under syscall.ForkLock (as
// Go's net does there) and non-blocking right after. SO_NOSIGPIPE keeps a
// write to a gone peer an EPIPE.

func wasip1SysSocket(family int) (int, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(family, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, err
	}
	return wasip1SetSockOpts(fd)
}

func wasip1SysAccept(fd int) (int, error) {
	syscall.ForkLock.RLock()
	nfd, _, err := unix.Accept(fd)
	if err == nil {
		unix.CloseOnExec(nfd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, err
	}
	return wasip1SetSockOpts(nfd)
}

func wasip1SetSockOpts(fd int) (int, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_NOSIGPIPE, 1)
	return fd, nil
}

func wasip1SysPipe() (int, int, error) {
	var p [2]int
	syscall.ForkLock.RLock()
	err := unix.Pipe(p[:])
	if err == nil {
		unix.CloseOnExec(p[0])
		unix.CloseOnExec(p[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, -1, err
	}
	for _, fd := range p {
		if err := unix.SetNonblock(fd, true); err != nil {
			_ = unix.Close(p[0])
			_ = unix.Close(p[1])
			return -1, -1, err
		}
	}
	return p[0], p[1], nil
}

// wasip1SysPoll waits up to timeout (forever when negative). macOS has no
// ppoll: poll takes milliseconds, rounded up so a short guest timer waits
// a little long rather than spinning.
func wasip1SysPoll(fds []unix.PollFd, timeout time.Duration) (int, error) {
	ms := -1
	if timeout >= 0 {
		ms = int(min((timeout+time.Millisecond-1)/time.Millisecond, math.MaxInt32))
	}
	return unix.Poll(fds, ms)
}
