//go:build linux

package worker

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// workerConn is sandboxd's end of a connection to a worker: every byte it
// reads came with no descriptor, and no descriptor the worker queued is
// released on the goroutine that reads or closes it (reaper.go).
//
// A read peeks first. MSG_PEEK takes counted copies of a segment's
// descriptors and, with no control buffer, drops them again at once, which
// releases nothing (the queued segment still holds them), and flags them
// with MSG_CTRUNC; only bytes that came with none are then consumed, by a
// read(2) that has no descriptor to drop (and that the race detector counts
// as ordering, as codec.go needs). Out-of-band data is read inline
// (SO_OOBINLINE): otherwise a read skips the out-of-band segment and frees
// it, descriptors and all, on its own, and a peek does not see it.
type workerConn struct {
	uc   *net.UnixConn
	rc   syscall.RawConn
	path string

	// readMu keeps one read, or the closing drain, at a time: a consume
	// must take exactly the bytes its peek saw.
	readMu sync.Mutex
	// fill takes a short read's bytes, so a reply's header and small body
	// cost one peek and one read, as one plain read would take them;
	// pending is what of it the caller has not read yet.
	fill, pending []byte
	broken        atomic.Bool
	// deadline: a read deadline was set (the closing drain clears it).
	deadline  atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// fillSize is how much a short read peeks for at once.
const fillSize = 4 << 10

// wrapWorkerConn wraps a Unix connection to the worker at path; anything
// else (a test's pipe) cannot carry descriptors and is returned as it is.
func wrapWorkerConn(c net.Conn, path string) (net.Conn, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return c, nil
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		_ = uc.Close()
		return nil, err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_OOBINLINE, 1) }); err != nil {
		serr = err
	}
	if serr != nil {
		_ = uc.Close()
		return nil, serr
	}
	return &workerConn{uc: uc, rc: rc, path: path}, nil
}

func (c *workerConn) unixConn() *net.UnixConn { return c.uc }

func (c *workerConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.read(b, true)
}

// read is Read under readMu; wait=false returns at once when nothing is
// queued.
func (c *workerConn) read(b []byte, wait bool) (int, error) {
	if c.broken.Load() {
		return 0, errWorkerSentFDs
	}
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	dst := b
	if len(b) < fillSize {
		if c.fill == nil {
			c.fill = make([]byte, fillSize)
		}
		dst = c.fill
	}
	n, _, more, err := c.peek(dst, nil, wait)
	switch {
	case err != nil:
		return 0, err
	case more:
		c.violate("a reply carried descriptors")
		return 0, errWorkerSentFDs
	case n == 0:
		return 0, io.EOF
	}
	n, err = c.uc.Read(dst[:n])
	if len(b) >= fillSize {
		return n, err
	}
	k := copy(b, dst[:n])
	c.pending = dst[k:n]
	return k, err
}

// peek peeks into b, with oob as the control buffer (nil: take none). It
// reports the bytes seen, the descriptor the control buffer took (-1 for
// none), and whether the bytes came with descriptors the buffer did not
// take.
func (c *workerConn) peek(b, oob []byte, wait bool) (n, fd int, more bool, err error) {
	var (
		oobn, flags int
		serr        error
	)
	err = c.rc.Read(func(sysfd uintptr) bool {
		for {
			n, oobn, flags, _, serr = unix.Recvmsg(int(sysfd), b, oob, unix.MSG_PEEK|unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
			if serr != unix.EINTR {
				return !wait || serr != unix.EAGAIN
			}
		}
	})
	if err == nil {
		err = serr
	}
	fd = -1
	if oobn > 0 {
		fds, perr := parseRights(oob[:oobn])
		for i, got := range fds {
			if i == 0 {
				fd = got
				continue
			}
			disposeFD(got)
			more = true
		}
		more = more || perr != nil
	}
	if err != nil {
		if fd >= 0 {
			disposeFD(fd)
		}
		return 0, -1, false, err
	}
	return n, fd, more || flags&unix.MSG_CTRUNC != 0, nil
}

// violate marks the connection broken and quarantines its worker.
func (c *workerConn) violate(why string) {
	if !c.broken.Swap(true) {
		quarantineWorker(c.path, why)
	}
}

func (c *workerConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.close() })
	return c.closeErr
}

func (c *workerConn) close() error {
	// Once reads are shut the worker can queue nothing more, and a read
	// blocked on this connection returns: what is queued now is all a close
	// could release.
	_ = c.uc.CloseRead()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	// The drain never waits, and a deadline a cancelled request left in the
	// past would fail it at once, sending a clean connection to the reaper.
	if c.deadline.Load() {
		_ = c.uc.SetReadDeadline(time.Time{})
	}
	if !c.broken.Load() && c.drain() {
		return c.uc.Close()
	}
	reap(c.uc)
	return nil
}

// drain reads what is left in the queue as Read would, and reports whether
// it emptied it with no descriptor in it. A streaming run's connection
// closed early has output left; any other has nothing.
func (c *workerConn) drain() bool {
	// What is buffered came with no descriptor.
	c.pending = nil
	var one [1]byte
	n, _, more, err := c.peek(one[:], nil, false)
	if err != nil || more {
		if more {
			c.violate("descriptors queued after the reply")
		}
		return false
	}
	if n == 0 {
		return true
	}
	buf := make([]byte, 64<<10)
	for total := 0; total <= maxFrameSize; {
		n, err := c.read(buf, false)
		if errors.Is(err, io.EOF) {
			return true
		}
		if err != nil {
			return false
		}
		total += n
	}
	return false
}

func (c *workerConn) Write(b []byte) (int, error)        { return c.uc.Write(b) }
func (c *workerConn) LocalAddr() net.Addr                { return c.uc.LocalAddr() }
func (c *workerConn) RemoteAddr() net.Addr               { return c.uc.RemoteAddr() }
func (c *workerConn) SetWriteDeadline(t time.Time) error { return c.uc.SetWriteDeadline(t) }

func (c *workerConn) SetDeadline(t time.Time) error {
	if !t.IsZero() {
		c.deadline.Store(true)
	}
	return c.uc.SetDeadline(t)
}

func (c *workerConn) SetReadDeadline(t time.Time) error {
	if !t.IsZero() {
		c.deadline.Store(true)
	}
	return c.uc.SetReadDeadline(t)
}

// readGuestListenerReply reads guest_listener's reply: the one descriptor
// that rides its 4-byte header (writeFrameFiles), which must be a socket,
// and a body that carries none. The socket is returned open (nil when the
// reply carried none); a reply with anything else is refused and its
// worker quarantined.
func readGuestListenerReply(conn net.Conn) (Envelope, *os.File, error) {
	c, ok := conn.(*workerConn)
	if !ok {
		env, err := readFrame(conn)
		return env, nil, err
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	listener := -1
	oob := make([]byte, unix.CmsgSpace(4))
	header := func(b []byte) (int, error) {
		if c.broken.Load() {
			return 0, errWorkerSentFDs
		}
		// A control buffer for one descriptor: it takes a counted copy of
		// the first, and the rest stay queued, flagged with MSG_CTRUNC.
		n, fd, more, err := c.peek(b, oob, true)
		if err != nil {
			return 0, err
		}
		why := ""
		switch {
		case fd >= 0 && (listener >= 0 || more):
			why = "guest_listener carried more than one descriptor"
		case fd >= 0 && !isSocket(fd):
			why = "guest_listener carried a descriptor that is not a socket"
		case fd < 0 && more:
			why = "guest_listener carried descriptors it could not take"
		}
		if why != "" {
			if fd >= 0 {
				disposeFD(fd)
			}
			c.violate(why)
			return 0, errWorkerSentFDs
		}
		if fd >= 0 {
			listener = fd
		}
		if n == 0 {
			return 0, io.EOF
		}
		// The segment's own reference goes with it; sandboxd holds the
		// copy, so nothing is released here.
		return c.uc.Read(b[:n])
	}
	env, _, err := readFrameFrom(header, func(b []byte) (int, error) { return c.read(b, true) }, nil)
	var f *os.File
	if listener >= 0 {
		f = os.NewFile(uintptr(listener), guestListenerFDName)
	}
	if err != nil {
		if f != nil {
			_ = f.Close()
		}
		return env, nil, err
	}
	return env, f, nil
}

// isSocket reports whether fd is a socket: SO_TYPE fails with ENOTSOCK on
// anything else before any file system is asked.
func isSocket(fd int) bool {
	_, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	return err == nil
}

// disposeFD closes a descriptor a worker sent: a socket at once (its close
// does not wait), anything else on the reaper.
func disposeFD(fd int) {
	if isSocket(fd) {
		_ = unix.Close(fd)
		return
	}
	reap(fdCloser(fd))
}
