//go:build linux

package worker

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fdReply is how a hostile worker answers one request.
type fdReply struct {
	env Envelope
	// fds ride the frame's 4-byte header.
	fds []int
	// closeAfter is closed once the frame is sent: the worker drops its
	// own copy, so the copies in flight are the last.
	closeAfter []*os.File
	// after runs once the frame is out, on the same connection.
	after func(uc *net.UnixConn)
}

// fdWorker serves a Unix socket as a hostile worker that answers each
// request with what answer returns. It counts the connections it took.
func fdWorker(t *testing.T, answer func(Envelope) fdReply) (string, *atomic.Int64) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "w.sock")
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ul.Close() })
	var accepted atomic.Int64
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func(c *net.UnixConn) {
				defer c.Close()
				env, files, err := readFrameFiles(c)
				closeFiles(files)
				if err != nil {
					return
				}
				r := answer(env)
				frame, err := encodeFrame(r.env)
				if err != nil {
					return
				}
				var rights []byte
				if len(r.fds) > 0 {
					rights = unix.UnixRights(r.fds...)
				}
				_, _, werr := c.WriteMsgUnix(frame[:4], rights, nil)
				for _, f := range r.closeAfter {
					_ = f.Close()
				}
				if werr != nil {
					return
				}
				if _, err := c.Write(frame[4:]); err != nil {
					return
				}
				if r.after != nil {
					r.after(c)
				}
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}(c.(*net.UnixConn))
		}
	}()
	return sock, &accepted
}

// pipeProbe is a pipe whose read end a hostile worker sends. The test
// keeps the write end, whose writes fail with EPIPE once the last copy of
// the read end is released, wherever it was.
type pipeProbe struct{ r, w *os.File }

func newPipeProbe(t *testing.T) *pipeProbe {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return &pipeProbe{r: r, w: w}
}

func (p *pipeProbe) fd(t *testing.T) int {
	t.Helper()
	fd, err := rawFD(p.r)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

// released reports whether every copy of the read end is gone.
func (p *pipeProbe) released() bool {
	_, err := p.w.Write([]byte{0})
	return errors.Is(err, syscall.EPIPE)
}

// eventuallyReleased waits for the read end's last copy to go.
func (p *pipeProbe) eventuallyReleased() bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if p.released() {
			return true
		}
	}
	return false
}

// Review round 4, F4: a reply that carries a descriptor is refused, not
// read past (read(2) would drop the descriptor, and dropping the last copy
// of a file on a stalled NFS mount blocks the reading thread), and the
// worker that sent it is quarantined: sandboxd does not connect to it
// again. Its descriptor is released, off the request's goroutine.
func TestReplyWithDescriptorsQuarantinesTheWorker(t *testing.T) {
	probe := newPipeProbe(t)
	fd := probe.fd(t)
	var calls atomic.Int64
	sock, accepted := fdWorker(t, func(Envelope) fdReply {
		if calls.Add(1) > 1 {
			return fdReply{env: Envelope{Type: MsgPong}}
		}
		return fdReply{env: Envelope{Type: MsgPong}, fds: []int{fd}, closeAfter: []*os.File{probe.r}}
	})
	c := NewClient(sock)
	if err := c.Ping("sb"); err == nil {
		t.Fatal("a pong that carried a descriptor was taken")
	}
	if err := c.Ping("sb"); err == nil || !strings.Contains(err.Error(), "quarantined") || accepted.Load() != 1 {
		t.Fatalf("after the violation: %v, %d connections", err, accepted.Load())
	}
	if !probe.eventuallyReleased() {
		t.Fatal("the descriptor was never released")
	}
}

// Review round 4, F4: guest_listener's reply carries a descriptor that is
// not a socket (here a pipe; a file on a stalled FUSE mount blocks the
// close that sandboxd's request thread made). It is refused, its worker
// quarantined, and the descriptor released off the request's goroutine.
func TestGuestListenerReplyWithAFileQuarantinesTheWorker(t *testing.T) {
	probe := newPipeProbe(t)
	fd := probe.fd(t)
	var calls atomic.Int64
	sock, accepted := fdWorker(t, func(Envelope) fdReply {
		if calls.Add(1) > 1 {
			return fdReply{env: Envelope{Type: MsgError, Payload: mustPayload(t, errorPayload{Message: "wasm guest is not listening"})}}
		}
		body, _ := encodePayload(guestListenerResult{Host: "127.0.0.1", Port: 1})
		return fdReply{env: Envelope{Type: MsgOK, Payload: body, FDPaths: []string{guestListenerFDName}}, fds: []int{fd}, closeAfter: []*os.File{probe.r}}
	})
	c := NewClient(sock)
	proxy := func() error {
		return c.ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{1}, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if err := proxy(); err == nil {
		t.Fatal("a pipe was taken for a listener")
	}
	if err := proxy(); err == nil || !strings.Contains(err.Error(), "quarantined") || accepted.Load() != 1 {
		t.Fatalf("after the violation: %v, %d connections", err, accepted.Load())
	}
	if !probe.eventuallyReleased() {
		t.Fatal("the descriptor was never released")
	}
}
