//go:build linux

package firecracker

// vsock_dial_linux.go is the production VsockDialer for Linux hosts —
// the only OS where AF_VSOCK is real. The darwin stub
// (vsock_dial_other.go) returns "not supported" so the rest of the
// driver compiles on a dev box without changing the seam's signatures.
//
// Why a custom dialer rather than github.com/mdlayher/vsock: keeping
// the dependency surface small. The Linux syscalls for vsock are
// stable and the wrapper here is short — mdlayher's lib would buy us
// nothing the driver actually uses.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// linuxVsockDialer is the production VsockDialer. Zero value is usable.
type linuxVsockDialer struct{}

// NewLinuxVsockDialer returns the production VsockDialer for use from
// cmd/sandboxd/main.go.
func NewLinuxVsockDialer() VsockDialer { return &linuxVsockDialer{} }

// Dial opens an AF_VSOCK stream socket and connects to (cid, port).
// Honors ctx for the deadline: if ctx has a deadline before the kernel
// completes the connect, we close the half-built socket and return
// ctx.Err(). On success the returned io.ReadWriteCloser is a *net.Conn
// wrapping the underlying fd — callers can read/write without further
// syscall ceremony.
func (d *linuxVsockDialer) Dial(ctx context.Context, cid, port uint32) (io.ReadWriteCloser, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock dial: socket: %w", err)
	}
	// Hand the fd to a *os.File so a panic between here and the
	// successful Conn construction still closes the fd via the
	// finalizer; without this, the cleanup paths below would have to
	// be defensive about double-close.
	cleanupFd := fd
	defer func() {
		if cleanupFd >= 0 {
			_ = unix.Close(cleanupFd)
		}
	}()

	// Non-blocking connect lets us cooperate with ctx — a synchronous
	// connect() would hold the goroutine until the kernel's own
	// timeout (~minutes). Set O_NONBLOCK after the SOCK_CLOEXEC flag
	// above; setting both at creation is the simplest race-free path.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("vsock dial: set nonblock: %w", err)
	}

	sa := &unix.SockaddrVM{CID: cid, Port: port}
	err = unix.Connect(fd, sa)
	if err != nil && !errors.Is(err, syscall.EINPROGRESS) && !errors.Is(err, syscall.EAGAIN) {
		return nil, fmt.Errorf("vsock dial cid=%d port=%d: %w", cid, port, err)
	}
	// Poll for write-readiness; that's the kernel signal that connect()
	// completed (whether successfully or with a deferred error).
	if err := waitWritable(ctx, fd); err != nil {
		return nil, err
	}
	// Inspect SO_ERROR — the connect's actual outcome lives there for
	// non-blocking sockets. A non-zero value is the connect error.
	soErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return nil, fmt.Errorf("vsock dial: getsockopt SO_ERROR: %w", err)
	}
	if soErr != 0 {
		return nil, fmt.Errorf("vsock dial cid=%d port=%d: %w", cid, port, syscall.Errno(soErr))
	}

	// Hand the fd off to os.File → FileConn. Setting the fd back to
	// blocking before the handoff lets net.FileConn's runtime poller
	// own the I/O loop; the alternative is to roll our own read/write
	// against a non-blocking fd, which is needless.
	if err := unix.SetNonblock(fd, false); err != nil {
		return nil, fmt.Errorf("vsock dial: clear nonblock: %w", err)
	}

	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock:cid=%d:port=%d", cid, port))
	if f == nil {
		return nil, errors.New("vsock dial: os.NewFile returned nil")
	}
	// Detach fd from the cleanup defer — ownership transfers to the
	// returned Conn / underlying *os.File.
	cleanupFd = -1

	conn, err := vsockConnFromFile(f, cid, port)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return conn, nil
}

// waitWritable blocks until fd reports POLLOUT (the kernel's signal
// that an in-flight connect() has completed). ctx.Done cancels the
// wait — without this the goroutine could be stuck in the kernel
// polling-state for minutes on a misconfigured vsock CID. The 50 ms
// poll cadence matches WaitSocket — same ergonomic trade.
func waitWritable(ctx context.Context, fd int) error {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(5 * time.Second)
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		now := time.Now()
		if now.After(deadline) {
			return fmt.Errorf("vsock dial: connect timed out after %s", deadline.Sub(now))
		}
		// Use unix.Poll with a 50 ms slice; that's tight enough to
		// look responsive (real connects complete in microseconds) and
		// loose enough that the goroutine isn't busy-looping.
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(fds, 50)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("vsock dial: poll: %w", err)
		}
		if n > 0 && fds[0].Revents&unix.POLLOUT != 0 {
			return nil
		}
	}
}

// vsockConn wraps an *os.File representing an AF_VSOCK fd, satisfying
// net.Conn so net/http / json.Encoder over the connection work without
// further plumbing. We don't expose net.Conn directly because the seam
// only promises io.ReadWriteCloser — keeping the type unexported avoids
// implying address semantics we don't have.
type vsockConn struct {
	f    *os.File
	cid  uint32
	port uint32
}

func vsockConnFromFile(f *os.File, cid, port uint32) (*vsockConn, error) {
	return &vsockConn{f: f, cid: cid, port: port}, nil
}

func (c *vsockConn) Read(p []byte) (int, error)  { return c.f.Read(p) }
func (c *vsockConn) Write(p []byte) (int, error) { return c.f.Write(p) }
func (c *vsockConn) Close() error                { return c.f.Close() }

// vsockAddr is a minimal net.Addr implementation for vsock connections.
// Used only if a caller upcasts the io.ReadWriteCloser to net.Conn —
// today no caller does, but it costs nothing to keep correct.
type vsockAddr struct {
	cid  uint32
	port uint32
}

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("cid=%d:port=%d", a.cid, a.port) }

// LocalAddr / RemoteAddr / SetDeadline are stubs that satisfy net.Conn
// if a caller upcasts. AF_VSOCK doesn't expose meaningful local/remote
// addresses through *os.File without extra getsockname plumbing — we
// only do that if a caller actually needs it.
func (c *vsockConn) LocalAddr() net.Addr  { return vsockAddr{cid: 2, port: 0} }
func (c *vsockConn) RemoteAddr() net.Addr { return vsockAddr{cid: c.cid, port: c.port} }

func (c *vsockConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }
