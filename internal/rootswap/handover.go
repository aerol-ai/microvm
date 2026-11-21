package rootswap

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The handover between the supervisor and each helper it starts. The
// supervisor owns the helper's listening socket and passes it down, so a
// new helper serves the socket the old one stopped accepting on: an agent
// that connects mid-swap waits in the socket's backlog for the new helper
// instead of finding no socket (eng review D4, outside review O6). The
// helper says when it serves by writing one byte to a pipe, which is how
// the supervisor tells a helper that started from one that died starting,
// and goes back to the old helper.
const (
	// ListenFDEnv names the inherited listening socket's descriptor.
	ListenFDEnv = "SB_ROOTD_LISTEN_FD"
	// ReadyFDEnv names the pipe the helper writes to once it serves.
	ReadyFDEnv = "SB_ROOTD_READY_FD"
	// The descriptors the supervisor puts them at: the first two after
	// stdin, stdout and stderr.
	ListenFD = 3
	ReadyFD  = 4
)

// HandoverEnv is what the supervisor adds to a helper's environment.
func HandoverEnv() []string {
	return []string{ListenFDEnv + "=" + strconv.Itoa(ListenFD), ReadyFDEnv + "=" + strconv.Itoa(ReadyFD)}
}

// fdFromEnv reads a descriptor number; ok is false when key is unset.
func fdFromEnv(getenv func(string) string, key string) (fd int, ok bool, err error) {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 3 {
		// 0, 1 and 2 are stdio: never a socket the helper should serve.
		return 0, false, fmt.Errorf("%s=%q: want a descriptor number above 2", key, v)
	}
	return n, true, nil
}

// InheritedListener is the listening socket the supervisor passed, or nil
// when it passed none (the helper then makes its own, as on a VM). It must
// be a Unix stream socket, bound to a path and listening; anything else is
// closed and refused. Closing it never removes the socket file: the
// supervisor keeps it for the next helper.
func InheritedListener(getenv func(string) string) (*net.UnixListener, error) {
	fd, ok, err := fdFromEnv(getenv, ListenFDEnv)
	if err != nil || !ok {
		return nil, err
	}
	// Checked on the bare descriptor first: net's listener for a socket
	// with no path cannot even be closed.
	if err := checkListening(fd); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%s=%d: %w", ListenFDEnv, fd, err)
	}
	f := os.NewFile(uintptr(fd), "inherited root helper socket")
	// FileListener dups the descriptor (close-on-exec); the original goes,
	// so nothing the helper starts inherits the socket.
	ln, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("%s=%d: %w", ListenFDEnv, fd, err)
	}
	ul, isUnix := ln.(*net.UnixListener)
	if !isUnix {
		_ = ln.Close()
		return nil, fmt.Errorf("%s=%d: not a Unix socket", ListenFDEnv, fd)
	}
	ul.SetUnlinkOnClose(false)
	return ul, nil
}

// checkListening: a Unix stream socket bound to a path, listening.
func checkListening(fd int) error {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return fmt.Errorf("not a socket: %w", err)
	}
	if u, isUnix := sa.(*unix.SockaddrUnix); !isUnix || u.Name == "" || u.Name[0] == '@' {
		return errors.New("not a Unix socket bound to a path")
	}
	if typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || typ != unix.SOCK_STREAM {
		return errors.New("not a stream socket")
	}
	on, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	switch {
	case errors.Is(err, unix.ENOPROTOOPT):
		// macOS will not say for a Unix socket; Linux, where the helper
		// runs, always does.
		return nil
	case err != nil:
		return err
	case on == 0:
		return errors.New("the socket is not listening")
	}
	return nil
}

// NotifyReady tells the supervisor the helper serves, when the supervisor
// asked to be told; with no pipe named it does nothing. The pipe is
// closed after, so nothing the helper starts holds it.
func NotifyReady(getenv func(string) string) error {
	fd, ok, err := fdFromEnv(getenv, ReadyFDEnv)
	if err != nil || !ok {
		return err
	}
	f := os.NewFile(uintptr(fd), "root helper ready pipe")
	if f == nil {
		return fmt.Errorf("%s=%d: no such descriptor", ReadyFDEnv, fd)
	}
	_, err = f.Write([]byte{'1'})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%s=%d: %w", ReadyFDEnv, fd, err)
	}
	return nil
}
