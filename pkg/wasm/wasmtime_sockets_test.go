//go:build wasmtime

package wasm

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/wasmtestguest"
	"github.com/bytecodealliance/wasmtime-go/v37"
)

// These run the real wasmtime engine against real guests: the Go wasip1
// HTTP guest (pkg/wasm/testdata/aerolhttp), the stdio guest, and small WAT
// guests for the calls Go's runtime never makes on its own.

// newTestWasmtime loads modPath on a fresh wasmtime engine closed with the
// test.
func newTestWasmtime(t *testing.T, modPath string) *wasmtimeEngine {
	t.Helper()
	eng, err := newWasmtimeEngine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e := eng.(*wasmtimeEngine)
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	if err := e.LoadModule(context.Background(), modPath, LoadOptions{}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	return e
}

// watModule compiles a WAT guest to a .wasm file.
func watModule(t *testing.T, src string) string {
	t.Helper()
	bin, err := wasmtime.Wat2Wasm(src)
	if err != nil {
		t.Fatalf("wat2wasm: %v", err)
	}
	path := filepath.Join(t.TempDir(), "guest.wasm")
	if err := os.WriteFile(path, bin, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// serve instantiates caps and runs _start in the background; the returned
// channel gets its result.
func serve(t *testing.T, e *wasmtimeEngine, caps Capabilities) <-chan error {
	t.Helper()
	return serveCtx(t, e, context.Background(), caps)
}

func serveCtx(t *testing.T, e *wasmtimeEngine, ctx context.Context, caps Capabilities) <-chan error {
	t.Helper()
	if err := e.Instantiate(context.Background(), caps); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- e.InvokeExport(ctx, "_start") }()
	return done
}

// waitDone fails unless the guest call returns within d.
func waitDone(t *testing.T, done <-chan error, d time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("guest call still running after %v", d)
		return nil
	}
}

// post sends body to the guest on port, retrying while it starts.
func post(t *testing.T, port int, path, body string) string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	url := "http://127.0.0.1:" + strconv.Itoa(port) + path
	var lastErr error
	for attempt := 0; attempt < 100; attempt++ {
		var resp *http.Response
		var err error
		if body == "" {
			resp, err = client.Get(url)
		} else {
			resp, err = client.Post(url, "text/plain", strings.NewReader(body))
		}
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: status %d: %s", url, resp.StatusCode, b)
			}
			return string(b)
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: %v", url, lastErr)
	return ""
}

func TestWasmtimeServesHTTPOnOneListener(t *testing.T) {
	e := newTestWasmtime(t, wasmtestguest.Path(t, wasmtestguest.HTTP))
	if !e.SupportsListen() {
		t.Fatal("the wasmtime engine serves listeners itself now")
	}
	done := serve(t, e, Capabilities{WASIListenPort: 0, Args: []string{"aerolhttp"}})
	port, ok := e.ResolvedListenPort()
	if !ok || port <= 0 {
		t.Fatalf("ResolvedListenPort = %d, %v", port, ok)
	}
	if got := e.ResolvedListeners(); len(got) != 1 || got[0].HostPort != port || got[0].GuestPort != 0 {
		t.Fatalf("ResolvedListeners = %+v", got)
	}
	if got := post(t, port, "/", "hello wasmtime"); got != "hello wasmtime\n" {
		t.Fatalf("body = %q", got)
	}
	// Keep-alive: several requests on one connection.
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodPost, "http://guest/", strings.NewReader(fmt.Sprintf("req-%d", i)))
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(b) != fmt.Sprintf("req-%d\n", i) {
			t.Fatalf("keep-alive request %d: %q", i, b)
		}
	}

	if err := e.StopInstance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := waitDone(t, done, 5*time.Second); err == nil {
		t.Fatal("a stopped guest's call ends with an error")
	}
	if _, ok := e.ResolvedListenPort(); ok {
		t.Fatal("no listener after a stop")
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second); err == nil {
		t.Fatal("the host port must be closed after a stop")
	}
}

func TestWasmtimeServesTwoPorts(t *testing.T) {
	e := newTestWasmtime(t, wasmtestguest.Path(t, wasmtestguest.HTTP))
	caps := Capabilities{
		WASIListenPort: WASIListenPortDisabled,
		WASIListeners:  []WASIListener{{GuestPort: 9090}, {GuestPort: 8080}},
		Args:           []string{"aerolhttp", "multiport"},
	}
	serve(t, e, caps)
	got := e.ResolvedListeners()
	if len(got) != 2 || got[0].GuestPort != 8080 || got[1].GuestPort != 9090 || got[0].HostPort == got[1].HostPort {
		t.Fatalf("ResolvedListeners = %+v", got)
	}
	for _, l := range got {
		if body := post(t, l.HostPort, "/port", ""); body != strconv.Itoa(l.GuestPort) {
			t.Fatalf("host port %d answered %q, want %d", l.HostPort, body, l.GuestPort)
		}
		if !e.ListenerAccepted(l.GuestPort) {
			t.Fatalf("guest accepts on %d", l.GuestPort)
		}
	}
	if e.ListenerAccepted(7070) {
		t.Fatal("no listener for 7070")
	}
}

func TestWasmtimeSingleListenerGuestWithTwoPorts(t *testing.T) {
	// A guest written for one listener accepts on AEROL_WASM_LISTEN_FD only:
	// the second listener is bound but never accepted on, which is what
	// the worker routes by (listenerFor).
	e := newTestWasmtime(t, wasmtestguest.Path(t, wasmtestguest.HTTP))
	serve(t, e, Capabilities{
		WASIListenPort: WASIListenPortDisabled,
		WASIListeners:  []WASIListener{{GuestPort: 8080}, {GuestPort: 9090}},
		Args:           []string{"aerolhttp"},
	})
	got := e.ResolvedListeners()
	if len(got) != 2 {
		t.Fatalf("ResolvedListeners = %+v", got)
	}
	if body := post(t, got[0].HostPort, "/port", ""); body != "single" {
		t.Fatalf("primary answered %q", body)
	}
	if !e.ListenerAccepted(8080) || e.ListenerAccepted(9090) {
		t.Fatalf("accepted 8080=%v 9090=%v, want true/false", e.ListenerAccepted(8080), e.ListenerAccepted(9090))
	}
}

func TestWasmtimeConcurrentConnections(t *testing.T) {
	e := newTestWasmtime(t, wasmtestguest.Path(t, wasmtestguest.HTTP))
	serve(t, e, Capabilities{WASIListenPort: 0, Args: []string{"aerolhttp"}})
	port, _ := e.ResolvedListenPort()
	post(t, port, "/", "warm") // the guest is up

	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := strings.Repeat(fmt.Sprintf("conn-%02d;", i), 2000) // ~16 KiB: several reads each way
			client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
			resp, err := client.Post("http://127.0.0.1:"+strconv.Itoa(port)+"/", "text/plain", strings.NewReader(body))
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)
			if string(got) != body+"\n" {
				errs <- fmt.Errorf("conn %d: got %d bytes, want %d", i, len(got), len(body)+1)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestWasmtimeClientGoesAwayMidRequest(t *testing.T) {
	e := newTestWasmtime(t, wasmtestguest.Path(t, wasmtestguest.HTTP))
	done := serve(t, e, Capabilities{WASIListenPort: 0, Args: []string{"aerolhttp"}})
	port, _ := e.ResolvedListenPort()
	post(t, port, "/", "warm")
	addr := "127.0.0.1:" + strconv.Itoa(port)

	for _, abort := range []string{"close", "reset"} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		// Headers promise a body that never comes.
		if _, err := conn.Write([]byte("POST / HTTP/1.1\r\nHost: g\r\nContent-Length: 100\r\n\r\npartial")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Millisecond)
		if abort == "reset" {
			_ = conn.(*net.TCPConn).SetLinger(0) // RST instead of FIN
		}
		_ = conn.Close()
	}
	// The guest is still serving.
	if got := post(t, port, "/", "after"); got != "after\n" {
		t.Fatalf("body = %q", got)
	}
	select {
	case err := <-done:
		t.Fatalf("the guest stopped: %v", err)
	default:
	}
}

// acceptForeverWAT blocks in sock_accept on the first listener with the
// listener left in blocking mode: no Go guest does this, a C one may.
const acceptForeverWAT = `(module
  (import "wasi_snapshot_preview1" "sock_accept" (func $accept (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (loop $l
      (drop (call $accept (i32.const 16777216) (i32.const 0) (i32.const 0)))
      (br $l))))`

// sleepForeverWAT never accepts: it sleeps in one-second clock polls.
const sleepForeverWAT = `(module
  (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (i32.store (i32.const 16) (i32.const 1))
    (i64.store (i32.const 24) (i64.const 1000000000))
    (loop $l
      (drop (call $poll (i32.const 0) (i32.const 64) (i32.const 1) (i32.const 128)))
      (br $l))))`

func TestWasmtimeGuestThatNeverAccepts(t *testing.T) {
	e := newTestWasmtime(t, watModule(t, sleepForeverWAT))
	done := serve(t, e, Capabilities{WASIListeners: []WASIListener{{GuestPort: 8080}}, WASIListenPort: WASIListenPortDisabled})
	port, ok := e.ResolvedListenPort()
	if !ok {
		t.Fatal("the listener is bound before the guest accepts")
	}
	if e.ListenerAccepted(8080) {
		t.Fatal("the guest never accepted")
	}
	// The kernel queues the connection; nobody answers it.
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("nothing should answer")
	}
	start := time.Now()
	if err := e.StopInstance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := waitDone(t, done, 2*time.Second); err == nil || time.Since(start) > time.Second {
		t.Fatalf("stop during a one-second sleep: err %v after %v", err, time.Since(start))
	}
	// The queued client sees its connection end.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the queued connection must close with the listener")
	}
}

func TestWasmtimeStopsBlockedGuests(t *testing.T) {
	httpGuest := wasmtestguest.Path(t, wasmtestguest.HTTP)
	listen := Capabilities{WASIListenPort: 0, Args: []string{"aerolhttp"}}
	for _, tc := range []struct {
		name string
		mod  string
		caps Capabilities
		stop func(*wasmtimeEngine) error
	}{
		{"StopInstance in poll_oneoff", httpGuest, listen, func(e *wasmtimeEngine) error { return e.StopInstance(context.Background()) }},
		{"Close in poll_oneoff", httpGuest, listen, func(e *wasmtimeEngine) error { return e.Close(context.Background()) }},
		{"re-Instantiate in poll_oneoff", httpGuest, listen, func(e *wasmtimeEngine) error { return e.Instantiate(context.Background(), listen) }},
		{"StopInstance in sock_accept", watModule(t, acceptForeverWAT), listen, func(e *wasmtimeEngine) error { return e.StopInstance(context.Background()) }},
		{"Close in sock_accept", watModule(t, acceptForeverWAT), listen, func(e *wasmtimeEngine) error { return e.Close(context.Background()) }},
		{"Close in a sleep, no listener", watModule(t, sleepForeverWAT), Capabilities{WASIListenPort: WASIListenPortDisabled}, func(e *wasmtimeEngine) error { return e.Close(context.Background()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestWasmtime(t, tc.mod)
			done := serve(t, e, tc.caps)
			if port, ok := e.ResolvedListenPort(); ok && tc.mod == httpGuest {
				post(t, port, "/", "up") // parked in poll_oneoff from here
			} else {
				time.Sleep(50 * time.Millisecond)
			}
			start := time.Now()
			if err := tc.stop(e); err != nil {
				t.Fatal(err)
			}
			// The guest traps in the layer's wait, or, if its runtime was
			// between waits, at the epoch tick.
			err := waitDone(t, done, 5*time.Second)
			if err == nil || (!strings.Contains(err.Error(), errWasip1Stopped.Error()) && !strings.Contains(err.Error(), "interrupt")) {
				t.Fatalf("err = %v", err)
			}
			if d := time.Since(start); d > time.Second {
				t.Fatalf("stop took %v", d)
			}
		})
	}
}

func TestWasmtimeWallTimeoutEndsABlockedGuest(t *testing.T) {
	e := newTestWasmtime(t, watModule(t, acceptForeverWAT))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	done := serveCtx(t, e, ctx, Capabilities{WASIListenPort: 0})
	if err := waitDone(t, done, 5*time.Second); err == nil || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
	// The instance is spent, as a wazero module whose context ended; a new
	// one serves again.
	if _, ok := e.ResolvedListenPort(); ok {
		t.Fatal("an interrupted guest serves no listener")
	}
	if err := e.Instantiate(context.Background(), Capabilities{WASIListenPort: 0}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.ResolvedListenPort(); !ok {
		t.Fatal("a fresh instance has its listener")
	}
}

// refusingDialer satisfies the aerol/vm/net import of the stdio guest.
type refusingDialer struct{}

func (refusingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, ErrNetworkEgressBlocked
}

func stdioEngine(t *testing.T, dial NetDialer) *wasmtimeEngine {
	t.Helper()
	e := newTestWasmtime(t, wasmtestguest.Path(t, wasmtestguest.Stdio))
	e.SetNetworkHook(&NetworkHook{Dial: dial})
	return e
}

func TestWasmtimeStopsSpinningAndEgressBlockedGuests(t *testing.T) {
	t.Run("spinning in guest code", func(t *testing.T) {
		e := stdioEngine(t, refusingDialer{})
		done := serve(t, e, Capabilities{WASIListenPort: 0, Args: []string{"aerolstdio", "spin"}})
		time.Sleep(50 * time.Millisecond)
		if err := e.StopInstance(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := waitDone(t, done, 5*time.Second); err == nil {
			t.Fatal("an interrupted spin ends with a trap")
		}
	})
	t.Run("blocked reading a mediated connection", func(t *testing.T) {
		upstream, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer upstream.Close()
		go func() {
			c, err := upstream.Accept()
			if err == nil {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c) // never writes
			}
		}()
		e := stdioEngine(t, &net.Dialer{})
		done := serve(t, e, Capabilities{WASIListenPort: WASIListenPortDisabled, Args: []string{"aerolstdio", "dial-read", upstream.Addr().String()}})
		time.Sleep(100 * time.Millisecond)
		if err := e.StopInstance(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitDone(t, done, 5*time.Second)
	})
}

func TestWasmtimeFilesAndStdioPassThrough(t *testing.T) {
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "hello.txt"), []byte("from a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	preopen := []Preopen{{GuestPath: "/work", HostPath: work}}

	t.Run("a serving guest reads /work", func(t *testing.T) {
		e := newTestWasmtime(t, wasmtestguest.Path(t, wasmtestguest.HTTP))
		serve(t, e, Capabilities{WASIListenPort: 0, Preopens: preopen, Args: []string{"aerolhttp"}})
		port, _ := e.ResolvedListenPort()
		if got := post(t, port, "/?workfile=hello.txt", ""); got != "from a file" {
			t.Fatalf("body = %q", got)
		}
	})

	for _, tc := range []struct {
		name   string
		listen bool
	}{{"with the socket layer", true}, {"poll layer only", false}} {
		t.Run(tc.name, func(t *testing.T) {
			e := stdioEngine(t, refusingDialer{})
			caps := func(args ...string) Capabilities {
				c := Capabilities{WASIListenPort: WASIListenPortDisabled, Preopens: preopen, Args: append([]string{"aerolstdio"}, args...)}
				if tc.listen {
					c.WASIListenPort = 0
				}
				return c
			}
			ctx := context.Background()
			res, err := e.Run(ctx, caps("read-file", "/work/hello.txt"), "")
			if err != nil || res.ExitCode != 0 || res.Stdout != "from a file" {
				t.Fatalf("read-file: %+v, %v", res, err)
			}
			if res.Usage.Instructions <= 0 {
				t.Fatalf("instructions = %d", res.Usage.Instructions)
			}
			res, err = e.Run(ctx, caps("write-work", "out.txt", "written"), "")
			if err != nil || res.ExitCode != 0 {
				t.Fatalf("write-work: %+v, %v", res, err)
			}
			if b, _ := os.ReadFile(filepath.Join(work, "out.txt")); string(b) != "written" {
				t.Fatalf("out.txt = %q", b)
			}
			res, err = e.Run(ctx, caps("stderr", "to", "stderr"), "")
			if err != nil || res.Stderr != "to stderr" {
				t.Fatalf("stderr: %+v, %v", res, err)
			}
			res, err = e.Run(ctx, caps("exit", "7"), "")
			if err != nil || res.ExitCode != 7 {
				t.Fatalf("exit 7: %+v, %v", res, err)
			}
			res, err = e.Run(ctx, caps("echo"), "") // stdin is empty
			if err != nil || res.ExitCode != 0 || res.Stdout != "" {
				t.Fatalf("echo: %+v, %v", res, err)
			}
			res, err = e.Run(ctx, caps("env", ListenFDEnv), "")
			want := ""
			if tc.listen {
				want = strconv.Itoa(int(wasip1SocketFDBase))
			}
			if err != nil || res.Stdout != want {
				t.Fatalf("%s = %q, want %q (%v)", ListenFDEnv, res.Stdout, want, err)
			}
		})
	}
}

// clockGuestWAT sleeps once in poll_oneoff and prints "slept" when the
// call reports one clock event. abstime: the deadline is the guest's
// monotonic clock plus 50ms, read with clock_time_get, which makes the
// layer read the guest's clock through the trampoline too.
func clockGuestWAT(abstime bool) string {
	timeout := `(i64.const 50000000)`
	flags := `(i32.const 0)`
	if abstime {
		timeout = `(i64.add (i64.load (i32.const 200)) (i64.const 50000000))`
		flags = `(i32.const 1)`
	}
	return `(module
  (import "wasi_snapshot_preview1" "clock_time_get" (func $now (param i32 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 300) "slept\n")
  (func (export "_start")
    (drop (call $now (i32.const 1) (i64.const 1) (i32.const 200)))
    (i32.store (i32.const 16) (i32.const 1))
    (i64.store (i32.const 24) ` + timeout + `)
    (i32.store16 (i32.const 40) ` + flags + `)
    (if (i32.and
          (i32.eqz (call $poll (i32.const 0) (i32.const 64) (i32.const 1) (i32.const 128)))
          (i32.eq (i32.load (i32.const 128)) (i32.const 1)))
      (then
        (i32.store (i32.const 400) (i32.const 300))
        (i32.store (i32.const 404) (i32.const 6))
        (drop (call $write (i32.const 1) (i32.const 400) (i32.const 1) (i32.const 408)))))))`
}

// stdinPollWAT polls stdin alone: the layer hands that to wasmtime.
const stdinPollWAT = `(module
  (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 300) "stdin\n")
  (func (export "_start")
    (i32.store8 (i32.const 8) (i32.const 1))
    (i32.store (i32.const 16) (i32.const 0))
    (if (i32.and
          (i32.eqz (call $poll (i32.const 0) (i32.const 64) (i32.const 1) (i32.const 128)))
          (i32.eq (i32.load8_u (i32.const 74)) (i32.const 1)))
      (then
        (i32.store (i32.const 400) (i32.const 300))
        (i32.store (i32.const 404) (i32.const 6))
        (drop (call $write (i32.const 1) (i32.const 400) (i32.const 1) (i32.const 408)))))))`

func TestWasmtimePollClocksAndStdin(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want string
		min  time.Duration
	}{
		{"relative clock", clockGuestWAT(false), "slept\n", 50 * time.Millisecond},
		{"absolute clock", clockGuestWAT(true), "slept\n", 40 * time.Millisecond},
		{"stdin alone", stdinPollWAT, "stdin\n", 0},
	} {
		for _, listen := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s listen=%v", tc.name, listen), func(t *testing.T) {
				e := newTestWasmtime(t, watModule(t, tc.src))
				caps := Capabilities{WASIListenPort: WASIListenPortDisabled}
				if listen {
					caps.WASIListenPort = 0
				}
				start := time.Now()
				res, err := e.Run(context.Background(), caps, "")
				if err != nil || res.Stdout != tc.want || time.Since(start) < tc.min {
					t.Fatalf("res %+v err %v after %v", res, err, time.Since(start))
				}
			})
		}
	}
}

// noMemoryWAT exports no memory: the layer cannot serve it (nor can
// wasmtime's own WASI, so it makes no WASI call).
const noMemoryWAT = `(module (func (export "_start")))`

func TestWasmtimeModuleWithoutMemory(t *testing.T) {
	e := newTestWasmtime(t, watModule(t, noMemoryWAT))
	if e.SupportsListen() {
		t.Fatal("a module with no memory export cannot have listeners here; the worker moves it to wazero")
	}
	if err := e.Instantiate(context.Background(), Capabilities{WASIListenPort: 0}); err == nil {
		t.Fatal("a listener needs the layer")
	}
	res, err := e.Run(context.Background(), Capabilities{WASIListenPort: WASIListenPortDisabled}, "")
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("plain run: %+v, %v", res, err)
	}
	// A trap is exit code 1 with the trap in stderr, as on wazero.
	trapping := newTestWasmtime(t, watModule(t, `(module (memory (export "memory") 1) (func (export "_start") unreachable))`))
	res, err = trapping.Run(context.Background(), Capabilities{WASIListenPort: WASIListenPortDisabled}, "")
	if err == nil || res.ExitCode != 1 || !strings.Contains(res.Stderr, "unreachable") {
		t.Fatalf("trap: %+v, %v", res, err)
	}
}

func TestWasmtimeGuestExitEndsItsListeners(t *testing.T) {
	e := stdioEngine(t, refusingDialer{})
	done := serve(t, e, Capabilities{WASIListenPort: 0, Args: []string{"aerolstdio", "exit", "0"}})
	if err := waitDone(t, done, 5*time.Second); err == nil {
		t.Fatal("proc_exit surfaces as an error from InvokeExport")
	}
	if _, ok := e.ResolvedListenPort(); ok {
		t.Fatal("an exited guest serves no listener")
	}
	if got := e.ResolvedListeners(); got != nil {
		t.Fatalf("ResolvedListeners = %+v", got)
	}
}

func TestWasmtimeSnapshotWithTheLayer(t *testing.T) {
	e := newTestWasmtime(t, watModule(t, sleepForeverWAT))
	ctx := context.Background()
	caps := Capabilities{WASIListenPort: 0}
	if err := e.Instantiate(ctx, caps); err != nil {
		t.Fatal(err)
	}
	snap, err := e.CaptureSnapshot(ctx)
	if err != nil || len(snap.Memory) != 65536 {
		t.Fatalf("capture: %d bytes, %v", len(snap.Memory), err)
	}
	snap.Memory[1000] = 42
	if err := e.RestoreSnapshot(ctx, SnapshotRestoreInput{Memory: snap.Memory}, caps); err != nil {
		t.Fatal(err)
	}
	again, err := e.CaptureSnapshot(ctx)
	if err != nil || !bytes.Equal(again.Memory, snap.Memory) {
		t.Fatalf("restore did not take: %v", err)
	}
	if _, ok := e.ResolvedListenPort(); !ok {
		t.Fatal("the restored instance has its listener")
	}
	if err := e.StopInstance(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CaptureSnapshot(ctx); err == nil {
		t.Fatal("no instance, no snapshot")
	}
	if err := e.InvokeExport(ctx, "_start"); err == nil {
		t.Fatal("no instance, no call")
	}
}

func TestWasmtimeTrampolineSource(t *testing.T) {
	// Every override has a pass-through, and the source compiles.
	src := wasip1TrampolineWAT()
	for _, p := range wasip1Passthroughs {
		if !strings.Contains(src, fmt.Sprintf("(export %q)", p.name)) {
			t.Fatalf("no pass-through for %s", p.name)
		}
	}
	eng := wasmtime.NewEngine()
	defer eng.Close()
	mod, err := compileWasip1Trampoline(eng)
	if err != nil {
		t.Fatal(err)
	}
	mod.Close()
}
