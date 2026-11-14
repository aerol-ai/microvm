package toolboxhttp

import (
	"context"
	"errors"
	"expvar"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func dialErr(errno syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

func dialRetryCount(result string) int64 {
	if n, ok := dialRetriesTotal.Get(result).(*expvar.Int); ok {
		return n.Value()
	}
	return 0
}

// recordWaits replaces waitRetry for one test: it records each wait, does
// not sleep, and reports what keepWaiting says.
func recordWaits(t *testing.T, keepWaiting func(n int) bool) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	old := waitRetry
	waitRetry = func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		return keepWaiting(len(waits))
	}
	t.Cleanup(func() { waitRetry = old })
	return &waits
}

func TestDialRetryingRefused(t *testing.T) {
	refused := dialErr(syscall.ECONNREFUSED)
	ms := func(v ...int) []time.Duration {
		var out []time.Duration
		for _, n := range v {
			out = append(out, time.Duration(n)*time.Millisecond)
		}
		return out
	}
	cases := []struct {
		name string
		// errs is what each dial returns in turn (nil: connected).
		errs        []error
		callerLeft  bool // the caller gives up on the first wait
		wantDials   int
		wantWaits   []time.Duration
		wantErr     error
		wantResults map[string]int64
	}{
		{name: "connects at once", errs: []error{nil}, wantDials: 1},
		{name: "refused then connects", errs: []error{refused, refused, nil}, wantDials: 3, wantWaits: ms(200, 400),
			wantResults: map[string]int64{"refused": 1, "connected": 1}},
		{name: "refused on every try", errs: []error{refused, refused, refused, refused}, wantDials: 4, wantWaits: ms(200, 400, 800),
			wantErr: syscall.ECONNREFUSED, wantResults: map[string]int64{"refused": 3}},
		{name: "timed out: not retried", errs: []error{dialErr(syscall.ETIMEDOUT)}, wantDials: 1, wantErr: syscall.ETIMEDOUT},
		{name: "unreachable: not retried", errs: []error{dialErr(syscall.EHOSTUNREACH)}, wantDials: 1, wantErr: syscall.EHOSTUNREACH},
		{name: "reset: not retried", errs: []error{dialErr(syscall.ECONNRESET)}, wantDials: 1, wantErr: syscall.ECONNRESET},
		{name: "deadline: not retried", errs: []error{context.DeadlineExceeded}, wantDials: 1, wantErr: context.DeadlineExceeded},
		{name: "refused then unreachable: stops", errs: []error{refused, dialErr(syscall.EHOSTUNREACH)}, wantDials: 2, wantWaits: ms(200),
			wantErr: syscall.EHOSTUNREACH, wantResults: map[string]int64{"error": 1}},
		{name: "caller left during the wait", errs: []error{refused}, callerLeft: true, wantDials: 1, wantWaits: ms(200),
			wantErr: syscall.ECONNREFUSED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			waits := recordWaits(t, func(int) bool { return !tc.callerLeft })
			before := map[string]int64{}
			for _, k := range []string{"connected", "refused", "error"} {
				before[k] = dialRetryCount(k)
			}
			dials := 0
			dial := func(context.Context, string, string) (net.Conn, error) {
				if dials >= len(tc.errs) {
					t.Fatalf("dial %d: more dials than the case allows", dials+1)
				}
				err := tc.errs[dials]
				dials++
				if err != nil {
					return nil, err
				}
				a, b := net.Pipe()
				_ = b.Close()
				return a, nil
			}
			conn, err := dialRetryingRefused(context.Background(), "tcp", "10.0.0.1:2280", dial, dialRetryDelays)
			if conn != nil {
				_ = conn.Close()
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("err = %v, want a connection", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if (err == nil) == (conn == nil) {
				t.Fatalf("conn %v with err %v", conn, err)
			}
			if dials != tc.wantDials {
				t.Fatalf("dials = %d, want %d", dials, tc.wantDials)
			}
			if !slices.Equal(*waits, tc.wantWaits) {
				t.Fatalf("waits = %v, want %v", *waits, tc.wantWaits)
			}
			for _, k := range []string{"connected", "refused", "error"} {
				if got := dialRetryCount(k) - before[k]; got != tc.wantResults[k] {
					t.Fatalf("retries counted %q = %d, want %d", k, got, tc.wantResults[k])
				}
			}
		})
	}
}

func TestWaitRetry(t *testing.T) {
	if !waitRetry(context.Background(), time.Millisecond) {
		t.Fatal("a wait that ran out reported the caller gone")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if waitRetry(ctx, time.Hour) {
		t.Fatal("a wait whose caller left reported true")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a cancelled wait took %v", took)
	}
}

// closedPort is a loopback address nothing listens on, so a dial is refused.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// serveAt starts an HTTP server on addr, which must be free.
func serveAt(t *testing.T, addr string, h http.Handler) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

// connects counts the TCP connects a request's dial makes, and runs
// onRefused once, synchronously, after the first refused connect.
func connects(ctx context.Context, onRefused func()) (context.Context, *atomic.Int64) {
	var n atomic.Int64
	var once sync.Once
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		ConnectStart: func(string, string) { n.Add(1) },
		ConnectDone: func(_, _ string, err error) {
			if isRefused(err) && onRefused != nil {
				once.Do(onRefused)
			}
		},
	}), &n
}

// oneShotBody is a request body that can be read once: a second pass over
// it reads nothing, so a request sent twice would arrive short.
type oneShotBody struct {
	r     io.Reader
	bytes atomic.Int64
}

func (b *oneShotBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.bytes.Add(int64(n))
	return n, err
}

// I1: a toolbox that refuses the first connect and listens by the next is
// reached, and a body that cannot be re-read arrives once and whole.
func TestProxyTransportRedialsARefusedToolbox(t *testing.T) {
	addr := closedPort(t)
	const payload = "upload bytes that can be read only once"
	var requests atomic.Int64
	var got string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		_, _ = io.WriteString(w, "ok")
	})
	before := dialRetryCount("connected")
	// toolboxd starts listening while the retry waits.
	ctx, dials := connects(context.Background(), func() { serveAt(t, addr, handler) })
	body := &oneShotBody{r: strings.NewReader(payload)}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/files/upload", body)
	start := time.Now()
	resp, err := ProxyClient(5 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("a toolbox that listened by the retry was not reached: %v", err)
	}
	reply, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(reply) != "ok" {
		t.Fatalf("reply = %d %q", resp.StatusCode, reply)
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("connects = %d, want 2 (refused, then connected)", n)
	}
	if took := time.Since(start); took < dialRetryDelays[0] {
		t.Fatalf("answered after %v, before the first retry delay", took)
	}
	if requests.Load() != 1 || got != payload || body.bytes.Load() != int64(len(payload)) {
		t.Fatalf("toolbox saw %d requests with body %q; %d body bytes read, want 1, %q, %d",
			requests.Load(), got, body.bytes.Load(), payload, len(payload))
	}
	if dialRetryCount("connected") != before+1 {
		t.Fatal("the saved call was not counted")
	}
}

// I1: a toolbox that never listens is dialed four times on the schedule,
// and the caller gets the refusal.
func TestProxyTransportGivesUpOnAToolboxThatNeverListens(t *testing.T) {
	waits := recordWaits(t, func(int) bool { return true })
	addr := closedPort(t)
	ctx, dials := connects(context.Background(), nil)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/process/execute", strings.NewReader(`{"command":"true"}`))
	_, err := ProxyTransport.RoundTrip(req)
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("err = %v, want the refusal", err)
	}
	if n := dials.Load(); n != 4 {
		t.Fatalf("connects = %d, want 4", n)
	}
	if !slices.Equal(*waits, dialRetryDelays) {
		t.Fatalf("waits = %v, want %v", *waits, dialRetryDelays)
	}
}

// I1: once a request went out, nothing is sent again: not when the toolbox
// drops the connection after reading the request, and not when the
// response is cut short.
func TestProxyTransportNeverResendsASentRequest(t *testing.T) {
	cases := []struct {
		name string
		// serve answers the request after reading its body.
		serve   func(w http.ResponseWriter)
		wantErr bool // from RoundTrip; otherwise from reading the body
	}{
		{name: "dropped before any response", wantErr: true, serve: func(w http.ResponseWriter) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}},
		{name: "response cut short", serve: func(w http.ResponseWriter) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "partial")
			w.(http.Flusher).Flush()
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				tc.serve(w)
			}))
			defer srv.Close()
			before := dialRetryCount("connected") + dialRetryCount("refused") + dialRetryCount("error")
			ctx, dials := connects(context.Background(), nil)
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/process/execute", strings.NewReader(`{"command":"rm -rf /tmp/x"}`))
			resp, err := ProxyTransport.RoundTrip(req)
			if err == nil {
				_, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if tc.wantErr {
					t.Fatal("RoundTrip succeeded on a dropped connection")
				}
			}
			if err == nil {
				t.Fatal("a broken exchange reported no error")
			}
			if n := requests.Load(); n != 1 {
				t.Fatalf("the toolbox saw the request %d times, want once", n)
			}
			if n := dials.Load(); n != 1 {
				t.Fatalf("connects = %d, want 1", n)
			}
			if after := dialRetryCount("connected") + dialRetryCount("refused") + dialRetryCount("error"); after != before {
				t.Fatalf("a failure after the dial was retried (%d retries)", after-before)
			}
		})
	}
}

// Probes keep the plain Transport: a toolbox that refuses is reported at
// once, and the next probe tries again.
func TestTransportDoesNotRetryARefusedDial(t *testing.T) {
	waits := recordWaits(t, func(int) bool { return true })
	addr := closedPort(t)
	ctx, dials := connects(context.Background(), nil)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/health", nil)
	if _, err := Client(time.Second).Do(req); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("err = %v, want the refusal", err)
	}
	if n := dials.Load(); n != 1 || len(*waits) != 0 {
		t.Fatalf("connects = %d, waits = %v; want one connect and no wait", n, *waits)
	}
}

// ProxyTransport is Transport apart from its dial: no connection outlives
// its call (TestEveryCallGetsItsOwnConnection).
func TestProxyTransportKeepsTransportSettings(t *testing.T) {
	if !ProxyTransport.DisableKeepAlives {
		t.Fatal("ProxyTransport pools connections")
	}
	if ProxyTransport == Transport {
		t.Fatal("ProxyTransport is Transport: probes would retry too")
	}
}
