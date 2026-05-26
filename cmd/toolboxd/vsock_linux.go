//go:build linux

package main

// vsock_linux.go is the Linux AF_VSOCK socket layer beneath the portable
// protocol in vsock.go. We use raw syscalls via golang.org/x/sys/unix
// rather than github.com/mdlayher/vsock to keep the dependency surface
// of the toolbox binary minimal — the toolbox ships inside every
// sandbox image, and ~50 lines of socket setup is cheaper than a
// transitive module pull.
//
// Wire details (mirroring the upstream virtio-vsock spec):
//
//   AF_VSOCK socket family (40)
//   SOCK_STREAM transport, connection-oriented
//   Bind to (VMADDR_CID_ANY, port) — accept connections from any CID
//   The host dials (CID=3, port=1024) from the host's vsock device,
//   and inside the guest we see those as connections from CID 2 (host)

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// vsockServer owns the listening AF_VSOCK fd plus the goroutine that
// accepts connections and dispatches them to handleVsockConn. One
// instance per toolbox process; the Serve loop returns when Close is
// called or the listener errors fatally.
type vsockServer struct {
	port    uint32
	fd      int
	handler VsockHandler
	logger  *slog.Logger

	closeOnce sync.Once
	closed    chan struct{}
}

// newVsockServer creates the listening socket. Returns an error if vsock
// support is missing from the kernel (which is the case on developer
// laptops without /dev/vsock) — the caller should warn and continue,
// not crash. The HTTP listener is fine on its own; vsock is additive.
func newVsockServer(port uint32, handler VsockHandler, logger *slog.Logger) (*vsockServer, error) {
	if handler == nil {
		return nil, errors.New("vsock: handler is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock: socket: %w", err)
	}
	addr := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock: bind cid=any port=%d: %w", port, err)
	}
	if err := unix.Listen(fd, 8); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock: listen: %w", err)
	}
	return &vsockServer{
		port:    port,
		fd:      fd,
		handler: handler,
		logger:  logger,
		closed:  make(chan struct{}),
	}, nil
}

// Serve runs the accept loop until Close is called. Each accepted
// connection is dispatched to handleVsockConn in its own goroutine —
// the protocol's per-connection message loop is sequential, but
// connections are independent. The host typically opens one connection
// per op and closes it, so concurrency here is mostly about overlap
// between a slow pre_snapshot and a fast ping.
func (s *vsockServer) Serve(ctx context.Context) error {
	for {
		nfd, _, err := unix.Accept(s.fd)
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("vsock: accept: %w", err)
		}
		go s.handle(ctx, nfd)
	}
}

// handle wraps the accepted fd in a vsockConn and runs the protocol
// loop. The conn's Close is called from defer; handleVsockConn does not
// close the connection itself (mirroring net.Conn convention).
func (s *vsockServer) handle(ctx context.Context, fd int) {
	conn := newVsockConn(fd)
	defer conn.Close()
	handleVsockConn(ctx, conn, s.handler, s.logger)
}

// Close stops the accept loop and unblocks any pending Accept. Best-
// effort: a Close while Serve is mid-Accept races with the syscall, but
// the s.closed channel lets the loop return cleanly on the next wakeup.
func (s *vsockServer) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		err = unix.Close(s.fd)
	})
	return err
}

// vsockConn is the bare minimum net.Conn shim for an AF_VSOCK fd. We
// use os.NewFile to take ownership of the fd, then *os.File's Read and
// Write methods handle the syscall layer. *os.File implements every
// method net.Conn needs except LocalAddr/RemoteAddr/SetDeadline; we
// stub LocalAddr/RemoteAddr (the protocol layer doesn't consult them)
// and pass deadlines through to *os.File.SetReadDeadline /
// SetWriteDeadline (which work for any pollable fd).
type vsockConn struct {
	*os.File
}

func newVsockConn(fd int) *vsockConn {
	return &vsockConn{File: os.NewFile(uintptr(fd), "vsock")}
}

func (c *vsockConn) LocalAddr() net.Addr  { return vsockAddr{} }
func (c *vsockConn) RemoteAddr() net.Addr { return vsockAddr{} }

func (c *vsockConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// vsockAddr is the placeholder net.Addr. The protocol doesn't care
// about peer identity (CID 2 is always the host in our topology), so
// the Network/String methods just identify the family.
type vsockAddr struct{}

func (vsockAddr) Network() string { return "vsock" }
func (vsockAddr) String() string  { return "vsock" }
