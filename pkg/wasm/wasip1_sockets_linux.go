//go:build linux

package wasm

import (
	"time"

	"golang.org/x/sys/unix"
)

// The host calls under wasip1_sockets.go: every descriptor non-blocking and
// close-on-exec from birth, so none leaks into a process the worker starts.

func wasip1SysSocket(family int) (int, error) {
	return unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
}

func wasip1SysAccept(fd int) (int, error) {
	nfd, _, err := unix.Accept4(fd, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
	return nfd, err
}

func wasip1SysPipe() (int, int, error) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return -1, -1, err
	}
	return p[0], p[1], nil
}

// wasip1SysPoll waits up to timeout (forever when negative). ppoll takes
// nanoseconds, so a guest timer as short as Go's runtime asks for fires on
// time.
func wasip1SysPoll(fds []unix.PollFd, timeout time.Duration) (int, error) {
	if timeout < 0 {
		return unix.Ppoll(fds, nil, nil)
	}
	ts := unix.NsecToTimespec(int64(timeout))
	return unix.Ppoll(fds, &ts, nil)
}
