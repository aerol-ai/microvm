//go:build linux

package worker

import (
	"context"
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

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"golang.org/x/sys/unix"
)

// guestServer is an HTTP server standing in for a guest's listener: it
// answers with the body it read, and counts the requests it served.
func guestServer(t *testing.T, network, addr string) (net.Listener, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	var served atomic.Int64
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(append([]byte("guest got "), body...))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln, &served
}

// workerOn serves s on a Unix socket, as a worker does.
func workerOn(t *testing.T, s *Server) *Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "w.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = s.Serve(c) }()
		}
	}()
	return NewClient(sock)
}

func portOf(ln net.Listener) int { return ln.Addr().(*net.TCPAddr).Port }

// The whole host-dialed path: the worker hands over its listening socket,
// sandboxd connects to it and relays the request itself, counting the
// bytes as the worker would have. The worker's own counters stay at zero:
// it never touched the request.
func TestProxyHTTPDialedEndToEnd(t *testing.T) {
	ln, served := guestServer(t, "tcp", "127.0.0.1:0")
	eng := &fakeMultiListenEngine{listeners: []wasmengine.WASIListener{{GuestPort: 8080, HostPort: portOf(ln)}}, accepted: map[int]bool{8080: true}}
	s := &Server{eng: eng, lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1"}}
	client := workerOn(t, s)

	var in, out atomic.Int64
	req := httptest.NewRequest(http.MethodPost, "http://gateway/x", strings.NewReader("hello"))
	rec := httptest.NewRecorder()
	if err := client.ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{portOf(ln)}, &in, &out, rec, req); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "guest got hello" || served.Load() != 1 {
		t.Fatalf("status %d body %q served %d", rec.Code, rec.Body.String(), served.Load())
	}
	// The same totals the worker's proxy counts: the request body and what
	// came back from the guest in, what went to the guest and the response
	// body out.
	var win, wout atomic.Int64
	wrec := httptest.NewRecorder()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := proxyOverConn(t.Context(), conn, ln.Addr().String(), &win, &wout, wrec, httptest.NewRequest(http.MethodPost, "http://gateway/x", strings.NewReader("hello"))); err != nil {
		t.Fatal(err)
	}
	// The HTTP transport counts what it wrote in its own goroutine, once
	// the write returned, which can be a moment after the relay itself
	// returned (sandboxd drains usage later, so a late count is not lost):
	// compare the totals once they settle.
	settled := func() bool {
		return in.Load() != 0 && out.Load() != 0 && in.Load() == win.Load() && out.Load() == wout.Load()
	}
	for deadline := time.Now().Add(2 * time.Second); !settled() && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if !settled() {
		t.Fatalf("counted in %d out %d, a worker counts in %d out %d", in.Load(), out.Load(), win.Load(), wout.Load())
	}
	if u := s.netUsageFor("sb"); u.bytesIn.Load() != 0 || u.bytesOut.Load() != 0 {
		t.Fatalf("the worker counted a request it never relayed: in %d out %d", u.bytesIn.Load(), u.bytesOut.Load())
	}
	// sandboxd keeps none of the worker's descriptors.
	before := openFDCount(t)
	for range 3 {
		rec := httptest.NewRecorder()
		if err := client.ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{portOf(ln)}, &in, &out, rec, httptest.NewRequest(http.MethodGet, "/", nil)); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("again: %v %d", err, rec.Code)
		}
	}
	if after := openFDCount(t); after > before+2 {
		t.Fatalf("descriptors %d -> %d after three requests", before, after)
	}
}

func openFDCount(t *testing.T) int {
	t.Helper()
	time.Sleep(50 * time.Millisecond) // let closed connections settle
	names, err := fdNames()
	if err != nil {
		t.Fatal(err)
	}
	return len(names)
}

// sandboxd connects only to a listener it checked: one bound to the guest
// listen host, on a port this sandbox's state names, with SO_REUSEPORT
// off. Anything else is refused before any connection is made.
func TestProxyHTTPDialedRefusesListeners(t *testing.T) {
	ln, served := guestServer(t, "tcp", "127.0.0.1:0")
	eng := &fakeMultiListenEngine{listeners: []wasmengine.WASIListener{{GuestPort: 8080, HostPort: portOf(ln)}}, accepted: map[int]bool{8080: true}}
	client := workerOn(t, &Server{eng: eng, lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1"}})
	for _, tc := range []struct {
		name  string
		host  string
		ports []int
		want  string
	}{
		{"a port the sandbox does not have", "127.0.0.1", []int{portOf(ln) + 1}, "not one of this sandbox's listeners"},
		{"another host", "127.0.97.1", []int{portOf(ln)}, "not the guest listen host"},
		{"a host that is not an address", "localhost", []int{portOf(ln)}, "guest listen host"},
	} {
		err := client.ProxyHTTPDialed("sb", 8080, tc.host, tc.ports, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if served.Load() != 0 {
		t.Fatalf("a refused listener served %d requests", served.Load())
	}
}

func TestCheckGuestListener(t *testing.T) {
	ln, _ := guestServer(t, "tcp", "127.0.0.1:0")
	file := func(c interface{ File() (*os.File, error) }) *os.File {
		f, err := c.File()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	if ap, err := checkGuestListener(file(ln.(*net.TCPListener)), "127.0.0.1", []int{portOf(ln)}); err != nil || int(ap.Port()) != portOf(ln) {
		t.Fatalf("a good listener: %v %v", ap, err)
	}
	// A connected socket, not a listener.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := checkGuestListener(file(c.(*net.TCPConn)), "127.0.0.1", []int{portOf(ln)}); err == nil || !strings.Contains(err.Error(), "not a listening TCP socket") {
		t.Fatalf("connected socket: %v", err)
	}
	// A listener others could share the port with.
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) }); err != nil {
			return err
		}
		return serr
	}}
	shared, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	if _, err := checkGuestListener(file(shared.(*net.TCPListener)), "127.0.0.1", []int{portOf(shared)}); err == nil || !strings.Contains(err.Error(), "SO_REUSEPORT") {
		t.Fatalf("reuseport listener: %v", err)
	}
	// A Unix listener.
	ul, err := net.Listen("unix", filepath.Join(t.TempDir(), "u.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	if _, err := checkGuestListener(file(ul.(*net.UnixListener)), "127.0.0.1", []int{1}); err == nil {
		t.Fatal("a unix listener passed")
	}
	// Not a socket at all.
	reg, err := os.CreateTemp(t.TempDir(), "f")
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	if _, err := checkGuestListener(reg, "127.0.0.1", []int{1}); err == nil {
		t.Fatal("a regular file passed")
	}
	_ = reg.Close()
	if _, err := checkGuestListener(reg, "127.0.0.1", []int{1}); err == nil {
		t.Fatal("a closed file passed")
	}
}

// With no live listener, guest_listener is refused and nothing connects.
func TestGuestListenerNotListening(t *testing.T) {
	client := workerOn(t, &Server{eng: &fakeMultiListenEngine{}})
	err := client.ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{1}, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if err == nil || !strings.Contains(err.Error(), "not listening") {
		t.Fatalf("no listener: %v", err)
	}
	// A port the engine reports but no socket of this process holds.
	ln, _ := guestServer(t, "tcp", "127.0.0.1:0")
	port := portOf(ln)
	_ = ln.Close()
	client = workerOn(t, &Server{eng: &fakeMultiListenEngine{listeners: []wasmengine.WASIListener{{GuestPort: 8080, HostPort: port}}}})
	err = client.ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{port}, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if err == nil || !strings.Contains(err.Error(), "no listening socket") {
		t.Fatalf("closed listener: %v", err)
	}
	if _, err := findListener("not-an-address", port); err == nil {
		t.Fatal("a bad host was looked up")
	}
	prev := fdDir
	fdDir = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { fdDir = prev })
	if _, err := findListener("127.0.0.1", port); err == nil || !strings.Contains(err.Error(), "list descriptors") {
		t.Fatalf("no fd folder: %v", err)
	}
}

// A worker the client cannot reach, or one that hangs up, fails the
// request without a connection to any guest.
func TestProxyHTTPDialedTransportErrors(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "none.sock"))
	if err := c.ProxyHTTPDialed("sb", 8080, "127.0.0.1", nil, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("no worker")
	}
	c.dial = func(string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { _, _ = readFrame(b); _ = b.Close() }()
		return a, nil
	}
	if err := c.ProxyHTTPDialed("sb", 8080, "127.0.0.1", nil, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("a worker that hung up")
	}
}

// hostileWorker answers guest_listener with listener attached, then
// records what else sandboxd sends on that connection.
func hostileWorker(t *testing.T, listener net.Listener, onListener func(*os.File)) (sock string, later chan []*os.File) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "w.sock")
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ul.Close() })
	later = make(chan []*os.File, 64)
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if env, _, err := readFrameFiles(c); err != nil || env.Type != MsgGuestListener {
					return
				}
				lf, err := listener.(*net.TCPListener).File()
				if err != nil {
					return
				}
				if onListener != nil {
					onListener(lf)
				}
				body, _ := encodePayload(guestListenerResult{Host: "127.0.0.1", Port: portOf(listener)})
				_ = writeFrameFiles(c, Envelope{Type: MsgOK, Payload: body, FDPaths: []string{guestListenerFDName}}, []*os.File{lf})
				_ = lf.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, files, _ := readFrameFiles(c)
				later <- files
			}(c)
		}
	}()
	return sock, later
}

// sandboxd never hands a worker a socket it made: nft matches packets by
// the uid of the process that made the socket, so a root socket in a
// worker's hands would be root's to the fence wherever the worker pointed
// it. After guest_listener, sandboxd sends nothing more; it serves the
// request itself.
func TestProxyHTTPDialedHandsTheWorkerNoSocket(t *testing.T) {
	ln, served := guestServer(t, "tcp", "127.0.0.1:0")
	sock, later := hostileWorker(t, ln, nil)
	rec := httptest.NewRecorder()
	if err := NewClient(sock).ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{portOf(ln)}, new(atomic.Int64), new(atomic.Int64), rec, httptest.NewRequest(http.MethodGet, "/", nil)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || served.Load() != 1 {
		t.Fatalf("status %d served %d", rec.Code, served.Load())
	}
	if files := <-later; len(files) != 0 {
		closeFiles(files)
		t.Fatalf("sandboxd sent the worker %d descriptors after guest_listener", len(files))
	}
}

// A worker that sets SO_LINGER on the listener it hands over, and drops
// its own copy so sandboxd's close is the last, holds no sandboxd thread:
// a listening socket's close never waits for data, and sandboxd hands out
// nothing else to linger on.
func TestProxyHTTPDialedHostileLingerReturns(t *testing.T) {
	ln, _ := guestServer(t, "tcp", "127.0.0.1:0")
	sock, _ := hostileWorker(t, ln, func(f *os.File) {
		if fd, err := rawFD(f); err == nil {
			_ = unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1, Linger: 3600})
		}
	})
	const n = 20
	done := make(chan error, n)
	for range n {
		go func() {
			done <- NewClient(sock).ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{portOf(ln)}, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}
	for i := range n {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("call %d: %v", i, err)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("%d of %d calls still blocked after 15s", n-i, n)
		}
	}
}

// One reply can make sandboxd hold no more than one message's worth of a
// worker's descriptors: readFrame (every reply but guest_listener) reads
// with read(2), so the kernel drops any sent; readFrameFiles fails a frame
// that carries more than maxFrameFiles.
func TestFrameDescriptorFlood(t *testing.T) {
	flood := func(t *testing.T, read func(net.Conn)) int {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		sandboxd, _ := net.FileConn(os.NewFile(uintptr(pair[0]), "sandboxd"))
		t.Cleanup(func() { _ = sandboxd.Close() })
		worker := pair[1]
		t.Cleanup(func() { _ = unix.Close(worker) })
		devnull, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = devnull.Close() })
		fds := make([]int, 32)
		for i := range fds {
			fds[i] = int(devnull.Fd())
		}
		base := openFDCount(t)
		var hdr [4]byte
		hdr[1] = 0x10 // a 1 MiB frame that never ends
		_ = unix.Sendmsg(worker, hdr[:1], unix.UnixRights(fds...), nil, 0)
		_ = unix.Sendmsg(worker, hdr[1:2], unix.UnixRights(fds...), nil, 0)
		_ = unix.Sendmsg(worker, hdr[2:], unix.UnixRights(fds...), nil, 0)
		for range 200 {
			if err := unix.Sendmsg(worker, []byte{' '}, unix.UnixRights(fds...), nil, 0); err != nil {
				break
			}
		}
		go read(sandboxd)
		time.Sleep(300 * time.Millisecond)
		return openFDCount(t) - base
	}
	if held := flood(t, func(c net.Conn) { _, _ = readFrame(c) }); held > 0 {
		t.Fatalf("readFrame holds %d descriptors of an unfinished reply", held)
	}
	errs := make(chan error, 1)
	if held := flood(t, func(c net.Conn) { _, _, err := readFrameFiles(c); errs <- err }); held > maxFrameFiles {
		t.Fatalf("readFrameFiles holds %d descriptors (cap %d)", held, maxFrameFiles)
	}
	select {
	case err := <-errs:
		if !errors.Is(err, errTooManyFDs) {
			t.Fatalf("readFrameFiles = %v, want errTooManyFDs", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readFrameFiles kept reading a frame with too many descriptors")
	}
}
