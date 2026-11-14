package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/testport"
)

// dialRetryToolbox is a toolbox port nothing listens on yet. start makes
// it listen with handler; a request's trace from trace() calls start after
// the first refused connect, so the proxy's retry is what reaches it.
type dialRetryToolbox struct {
	t        *testing.T
	port     int
	handler  http.Handler
	connects atomic.Int64
	once     sync.Once
}

func newDialRetryToolbox(t *testing.T, handler http.Handler) *dialRetryToolbox {
	t.Helper()
	// The toolbox binds this port later; testport keeps it free till then.
	return &dialRetryToolbox{t: t, port: testport.Reserve(t, false), handler: handler}
}

func (tb *dialRetryToolbox) start() {
	ln, err := net.Listen("tcp", (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tb.port}).String())
	if err != nil {
		tb.t.Errorf("toolbox listen: %v", err)
		return
	}
	srv := httptest.NewUnstartedServer(tb.handler)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	tb.t.Cleanup(srv.Close)
}

// trace counts the connects of a call on ctx; listen starts the toolbox
// after the first refused one.
func (tb *dialRetryToolbox) trace(ctx context.Context, listen bool) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		ConnectStart: func(string, string) { tb.connects.Add(1) },
		ConnectDone: func(_, _ string, err error) {
			if listen && errors.Is(err, syscall.ECONNREFUSED) {
				tb.once.Do(tb.start)
			}
		},
	})
}

// onceReader counts the bytes read from a request body that cannot be
// re-read: sent twice, the second copy would arrive empty.
type onceReader struct {
	r io.Reader
	n atomic.Int64
}

func (o *onceReader) Read(p []byte) (int, error) {
	n, err := o.r.Read(p)
	o.n.Add(int64(n))
	return n, err
}

// bodyRecorder is a toolbox handler that keeps every body it was sent.
type bodyRecorder struct {
	mu     sync.Mutex
	bodies []string
}

func (b *bodyRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	b.mu.Lock()
	b.bodies = append(b.bodies, string(body))
	b.mu.Unlock()
	_, _ = io.WriteString(w, "ok")
}

func (b *bodyRecorder) got() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.bodies...)
}

// I1 at both service chokepoints: a toolboxd that refuses the first connect
// and listens by the retry is reached, the body that cannot be re-read
// arrives once and whole, and O4 counts the call once.
func TestToolboxProxiesRetryARefusedDial(t *testing.T) {
	ctx := context.Background()
	const payload = `{"command":"echo once"}`
	cases := []struct {
		name    string
		surface string
		call    func(t *testing.T, svc *Service, ctx context.Context, body io.Reader) int
	}{
		{name: "reverse proxy", surface: ToolboxSurfaceV1, call: func(t *testing.T, svc *Service, ctx context.Context, body io.Reader) int {
			req := httptest.NewRequest(http.MethodPost, "http://x/files/upload", body)
			rec := httptest.NewRecorder()
			if err := svc.ServeToolboxReverseProxy(ctx, "sb-i1", rec, req, "/files/upload"); err != nil {
				t.Fatal(err)
			}
			return rec.Code
		}},
		{name: "round trip", surface: ToolboxSurfaceRunloop, call: func(t *testing.T, svc *Service, ctx context.Context, body io.Reader) int {
			resp, err := svc.RoundTripToolbox(ctx, "sb-i1", http.MethodPost, "/files/upload", nil, body, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return resp.StatusCode
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &bodyRecorder{}
			tb := newDialRetryToolbox(t, rec)
			svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
			svc.cfg.ToolboxPort = tb.port
			seedCallSandbox(t, st, "sb-i1")

			before := toolboxCallCount(tc.surface, "files", "2xx")
			body := &onceReader{r: strings.NewReader(payload)}
			callCtx := tb.trace(WithToolboxSurface(ctx, tc.surface), true)
			if code := tc.call(t, svc, callCtx, body); code != http.StatusOK {
				t.Fatalf("status = %d, want 200 from the toolbox that listened by the retry", code)
			}
			if n := tb.connects.Load(); n != 2 {
				t.Fatalf("connects = %d, want 2 (refused, then connected)", n)
			}
			if got := rec.got(); len(got) != 1 || got[0] != payload || body.n.Load() != int64(len(payload)) {
				t.Fatalf("toolbox got bodies %q, %d bytes read; want one %q", got, body.n.Load(), payload)
			}
			if got := toolboxCallCount(tc.surface, "files", "2xx"); got != before+1 {
				t.Fatalf("O4 counted the retried call %d times, want once", got-before)
			}
			if n := svc.toolboxCalls.inFlight("sb-i1"); n != 0 {
				t.Fatalf("in flight after the call = %d", n)
			}
		})
	}
}

// I1: a request that reached toolboxd is never sent again, even when the
// connection breaks before any answer; the caller gets the 502 and O4
// counts one failed call.
func TestToolboxProxyNeverResendsASentRequest(t *testing.T) {
	ctx := context.Background()
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ToolboxPort = port
	seedCallSandbox(t, st, "sb-i1-sent")
	tb := &dialRetryToolbox{t: t, port: port}
	before := toolboxCallCount("v1", "exec", "5xx")
	req := httptest.NewRequest(http.MethodPost, "http://x/process/execute", strings.NewReader(`{"command":"touch /tmp/once"}`))
	rec := httptest.NewRecorder()
	if err := svc.ServeToolboxReverseProxy(tb.trace(WithToolboxSurface(ctx, ToolboxSurfaceV1), false), "sb-i1-sent", rec, req, "/process/execute"); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("toolboxd saw the request %d times, want once", n)
	}
	if n := tb.connects.Load(); n != 1 {
		t.Fatalf("connects = %d, want 1", n)
	}
	if got := toolboxCallCount("v1", "exec", "5xx"); got != before+1 {
		t.Fatalf("O4 counted %d failed calls, want 1", got-before)
	}
}

// I1: a toolboxd that never listens is dialed four times, 1.4 s of waits,
// then the caller gets the error and O4 counts one call.
func TestToolboxRoundTripGivesUpOnARefusingToolbox(t *testing.T) {
	ctx := context.Background()
	tb := newDialRetryToolbox(t, nil)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ToolboxPort = tb.port
	seedCallSandbox(t, st, "sb-i1-down")
	before := toolboxCallCount("daytona", "exec", "5xx")
	start := time.Now()
	_, err := svc.RoundTripToolbox(tb.trace(WithToolboxSurface(ctx, ToolboxSurfaceDaytona), false), "sb-i1-down", http.MethodPost, "/process/execute", nil, strings.NewReader(`{}`), nil)
	took := time.Since(start)
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("err = %v, want the refusal", err)
	}
	if n := tb.connects.Load(); n != 4 {
		t.Fatalf("connects = %d, want 4", n)
	}
	// 200 + 400 + 800 ms of waits; the bound is what the I1 call-out quotes.
	if took < 1400*time.Millisecond || took > 5*time.Second {
		t.Fatalf("gave up after %v, want just over 1.4s", took)
	}
	if got := toolboxCallCount("daytona", "exec", "5xx"); got != before+1 {
		t.Fatalf("O4 counted %d failed calls, want 1", got-before)
	}
	if n := svc.toolboxCalls.inFlight("sb-i1-down"); n != 0 {
		t.Fatalf("in flight after the error = %d", n)
	}
}
