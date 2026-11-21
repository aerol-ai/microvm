//go:build linux

package worker

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// rawListener makes a listening socket of the given kind on ip:port as
// the test process; skip names why the kernel refused it.
func rawListener(t *testing.T, family, typ, proto int, ip string, port int, before func(fd int) error) (*os.File, int) {
	t.Helper()
	fd, err := unix.Socket(family, typ|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		t.Skipf("socket(%d, %d, %d): %v", family, typ, proto, err)
	}
	f := os.NewFile(uintptr(fd), "listener")
	t.Cleanup(func() { _ = f.Close() })
	if before != nil {
		if err := before(fd); err != nil {
			t.Skipf("socket option: %v", err)
		}
	}
	var sa unix.Sockaddr
	if family == unix.AF_INET6 {
		s6 := &unix.SockaddrInet6{Port: port}
		copy(s6.Addr[:], net.ParseIP(ip).To16())
		sa = s6
	} else {
		s4 := &unix.SockaddrInet4{Port: port}
		copy(s4.Addr[:], net.ParseIP(ip).To4())
		sa = s4
	}
	if err := unix.Bind(fd, sa); err != nil {
		t.Fatalf("bind %s:%d: %v", ip, port, err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		t.Fatalf("listen: %v", err)
	}
	got, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	switch got := got.(type) {
	case *unix.SockaddrInet4:
		return f, got.Port
	case *unix.SockaddrInet6:
		return f, got.Port
	}
	t.Fatalf("getsockname = %T", got)
	return nil, 0
}

// Review round 4, F1 and F2: a listener whose connections do not all come
// through TCP's port space on every device is refused. SCTP (one-to-one,
// SOCK_STREAM) listens and is bound like TCP but has its own port space;
// a listener bound to a device never sees a connection on loopback.
// MPTCP and a v4-mapped IPv6 TCP listener are TCP's port space and pass.
func TestCheckGuestListenerRefusesOtherKinds(t *testing.T) {
	t.Run("sctp", func(t *testing.T) {
		f, port := rawListener(t, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP, "127.0.0.1", 0, nil)
		if _, err := checkGuestListener(f, "127.0.0.1", []int{port}); err == nil || !strings.Contains(err.Error(), "not TCP") {
			t.Fatalf("an SCTP listener: %v", err)
		}
	})
	t.Run("sctp seqpacket", func(t *testing.T) {
		f, port := rawListener(t, unix.AF_INET, unix.SOCK_SEQPACKET, unix.IPPROTO_SCTP, "127.0.0.1", 0, nil)
		if _, err := checkGuestListener(f, "127.0.0.1", []int{port}); err == nil {
			t.Fatal("an SCTP one-to-many socket passed")
		}
	})
	t.Run("bound to a device", func(t *testing.T) {
		f, port := rawListener(t, unix.AF_INET, unix.SOCK_STREAM, 0, "127.0.0.1", 0, func(fd int) error {
			return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo")
		})
		if _, err := checkGuestListener(f, "127.0.0.1", []int{port}); err == nil || !strings.Contains(err.Error(), "bound to a device") {
			t.Fatalf("a device-bound listener: %v", err)
		}
	})
	t.Run("mptcp", func(t *testing.T) {
		f, port := rawListener(t, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP, "127.0.0.1", 0, nil)
		if ap, err := checkGuestListener(f, "127.0.0.1", []int{port}); err != nil || int(ap.Port()) != port {
			t.Fatalf("an MPTCP listener: %v %v", ap, err)
		}
	})
	t.Run("v4-mapped tcp6", func(t *testing.T) {
		f, port := rawListener(t, unix.AF_INET6, unix.SOCK_STREAM, 0, "::ffff:127.0.0.1", 0, nil)
		if ap, err := checkGuestListener(f, "127.0.0.1", []int{port}); err != nil || int(ap.Port()) != port {
			t.Fatalf("a v4-mapped TCP listener: %v %v", ap, err)
		}
	})
}

// listenerWorker is a hostile worker that answers every guest_listener
// with listener attached.
func listenerWorker(t *testing.T, listener *os.File) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "w.sock")
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ul.Close() })
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				env, files, err := readFrameFiles(c)
				closeFiles(files)
				if err != nil || env.Type != MsgGuestListener {
					return
				}
				body, _ := encodePayload(guestListenerResult{Host: "127.0.0.1"})
				_ = writeFrameFiles(c, Envelope{Type: MsgOK, Payload: body, FDPaths: []string{guestListenerFDName}}, []*os.File{listener})
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _ = readFrame(c)
			}(c)
		}
	}()
	return sock
}

// countingService is a node service on addr that records what reaches it.
func countingService(t *testing.T, ln net.Listener) *atomic.Int64 {
	t.Helper()
	var hits atomic.Int64
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprintf(w, "NODE-SERVICE %s", r.URL.Path)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &hits
}

// Review round 4, F1: a worker answers guest_listener with an SCTP
// listener bound to the port of a TCP service on every address of the
// node. SCTP ports are not TCP ports, so the bind succeeds beside it, and
// sandboxd's TCP connection would land on the service and relay the
// tenant's request to it. sandboxd must refuse the socket and reach
// nothing.
func TestProxyHTTPDialedRefusesAnSCTPListener(t *testing.T) {
	svc, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	hits := countingService(t, svc)
	port := svc.Addr().(*net.TCPAddr).Port
	sctp, _ := rawListener(t, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP, "127.0.0.1", port, nil)
	rec := httptest.NewRecorder()
	err = NewClient(listenerWorker(t, sctp)).ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{port}, new(atomic.Int64), new(atomic.Int64), rec, httptest.NewRequest(http.MethodGet, "http://gateway/internal/secret", nil))
	if err == nil || hits.Load() != 0 {
		t.Fatalf("SCTP listener on a node service's port: err %v, the service served %d requests (%d %q)", err, hits.Load(), rec.Code, rec.Body.String())
	}
}

// Review round 4, F2: a worker answers with a TCP listener bound to
// another device on the port of a service bound to loopback on every
// address. The binds do not clash, sandboxd's connection arrives on
// loopback, and the service would take it.
func TestProxyHTTPDialedRefusesADeviceBoundListener(t *testing.T) {
	dev := ""
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback == 0 {
			dev = i.Name
			break
		}
	}
	if dev == "" {
		t.Skip("no interface but loopback")
	}
	bindTo := func(name string) func(int) error {
		return func(fd int) error { return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name) }
	}
	svcFile, port := rawListener(t, unix.AF_INET, unix.SOCK_STREAM, 0, "0.0.0.0", 0, bindTo("lo"))
	svc, err := net.FileListener(svcFile)
	if err != nil {
		t.Fatal(err)
	}
	hits := countingService(t, svc)
	worker, _ := rawListener(t, unix.AF_INET, unix.SOCK_STREAM, 0, "127.0.0.1", port, bindTo(dev))
	rec := httptest.NewRecorder()
	err = NewClient(listenerWorker(t, worker)).ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{port}, new(atomic.Int64), new(atomic.Int64), rec, httptest.NewRequest(http.MethodGet, "http://gateway/internal/secret", nil))
	if err == nil || hits.Load() != 0 {
		t.Fatalf("listener bound to %s: err %v, the service served %d requests (%d %q)", dev, err, hits.Load(), rec.Code, rec.Body.String())
	}
}
