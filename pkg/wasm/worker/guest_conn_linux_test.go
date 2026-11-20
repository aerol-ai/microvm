//go:build linux

package worker

import (
	"context"
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
// sandboxd connects to it and passes the connection back, and the worker
// proxies the request over it and counts its bytes.
func TestProxyHTTPDialedEndToEnd(t *testing.T) {
	ln, served := guestServer(t, "tcp", "127.0.0.1:0")
	eng := &fakeMultiListenEngine{listeners: []wasmengine.WASIListener{{GuestPort: 8080, HostPort: portOf(ln)}}, accepted: map[int]bool{8080: true}}
	s := &Server{eng: eng, lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1"}}
	client := workerOn(t, s)

	req := httptest.NewRequest(http.MethodPost, "http://gateway/x", strings.NewReader("hello"))
	rec := httptest.NewRecorder()
	if err := client.ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{portOf(ln)}, rec, req); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "guest got hello" || served.Load() != 1 {
		t.Fatalf("status %d body %q served %d", rec.Code, rec.Body.String(), served.Load())
	}
	if u := s.netUsageFor("sb"); u.bytesIn.Load() == 0 || u.bytesOut.Load() == 0 {
		t.Fatalf("usage not counted: in %d out %d", u.bytesIn.Load(), u.bytesOut.Load())
	}

	// The worker's listener is still non-blocking (its copy was passed
	// without Fd): the guest keeps accepting.
	for range 3 {
		rec := httptest.NewRecorder()
		if err := client.ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{portOf(ln)}, rec, httptest.NewRequest(http.MethodGet, "/", nil)); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("again: %v %d", err, rec.Code)
		}
	}
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
		err := client.ProxyHTTPDialed("sb", 8080, tc.host, tc.ports, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
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

// The worker uses a connection sandboxd passed only when it leads to the
// listener the request would go to now; one that leads anywhere else is
// closed unused, and the request is refused.
func TestWorkerRefusesConnectionToAnotherListener(t *testing.T) {
	mine, minesServed := guestServer(t, "tcp", "127.0.0.1:0")
	other, othersServed := guestServer(t, "tcp", "127.0.0.1:0")
	eng := &fakeMultiListenEngine{listeners: []wasmengine.WASIListener{{GuestPort: 8080, HostPort: portOf(mine)}}, accepted: map[int]bool{8080: true}}
	client := workerOn(t, &Server{eng: eng, lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1"}})

	send := func(conns ...net.Conn) Envelope {
		t.Helper()
		uc, err := net.Dial("unix", client.socketPath)
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		var files []*os.File
		var names []string
		for _, c := range conns {
			f, err := c.(*net.TCPConn).File()
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			files = append(files, f)
			names = append(names, guestConnFDName)
		}
		body := mustPayload(t, proxyHTTPPayload{GuestPort: 8080, Method: http.MethodGet, RequestURI: "/"})
		if err := writeFrameFiles(uc, Envelope{Type: MsgProxyHTTP, SandboxID: "sb", Payload: body, FDPaths: names}, files); err != nil {
			t.Fatal(err)
		}
		reply, err := readFrame(uc)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	dial := func(ln net.Listener) net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	if reply := send(dial(other)); reply.Type != MsgError || !strings.Contains(string(reply.Payload), "leads to") {
		t.Fatalf("a connection to another listener: %s %s", reply.Type, reply.Payload)
	}
	if reply := send(dial(mine), dial(mine)); reply.Type != MsgError || !strings.Contains(string(reply.Payload), "want one") {
		t.Fatalf("two connections: %s %s", reply.Type, reply.Payload)
	}
	if reply := send(dial(mine)); reply.Type != MsgProxyHTTPResult {
		t.Fatalf("its own listener: %s %s", reply.Type, reply.Payload)
	}
	time.Sleep(50 * time.Millisecond)
	if othersServed.Load() != 0 || minesServed.Load() != 1 {
		t.Fatalf("served: other %d, mine %d", othersServed.Load(), minesServed.Load())
	}
}

// With no live listener, guest_listener is refused and nothing connects.
func TestGuestListenerNotListening(t *testing.T) {
	client := workerOn(t, &Server{eng: &fakeMultiListenEngine{}})
	err := client.ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{1}, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if err == nil || !strings.Contains(err.Error(), "not listening") {
		t.Fatalf("no listener: %v", err)
	}
	// A port the engine reports but no socket of this process holds.
	ln, _ := guestServer(t, "tcp", "127.0.0.1:0")
	port := portOf(ln)
	_ = ln.Close()
	client = workerOn(t, &Server{eng: &fakeMultiListenEngine{listeners: []wasmengine.WASIListener{{GuestPort: 8080, HostPort: port}}}})
	err = client.ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{port}, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
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
	if err := c.ProxyHTTPDialed("sb", 8080, "127.0.0.1", nil, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("no worker")
	}
	c.dial = func(string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { _, _ = readFrame(b); _ = b.Close() }()
		return a, nil
	}
	if err := c.ProxyHTTPDialed("sb", 8080, "127.0.0.1", nil, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("a worker that hung up")
	}
}
