package ingressproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
)

type fakeResolver struct {
	target    string
	err       error
	callCnt   int
	lastID    string
	lastPrt   int
	touchCnt  atomic.Int32
	touchedID atomic.Value // string
	// started flips IsSandboxStarted's return. Default false keeps
	// the body-buffering branch live for tests that exercise it
	// (oversize cap, replay, upgrade-skip); warm-bypass tests flip
	// it to true to assert buffering is skipped.
	started    bool
	startedErr error
}

func (f *fakeResolver) WakeAwarePortTarget(_ context.Context, id string, port int) (service.PortEndpoint, error) {
	f.callCnt++
	f.lastID = id
	f.lastPrt = port
	if f.err != nil {
		return service.PortEndpoint{}, f.err
	}
	return service.PortEndpoint{URL: f.target}, nil
}

func (f *fakeResolver) TouchSandbox(_ context.Context, id string) error {
	f.touchCnt.Add(1)
	f.touchedID.Store(id)
	return nil
}

func (f *fakeResolver) IsSandboxStarted(_ context.Context, _ string) (bool, error) {
	return f.started, f.startedErr
}

func newHandler(resolver PortResolver, max int64) http.Handler {
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Resolver:       resolver,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBufferBytes: max,
	})
	return mux
}

func TestHTTPWakeProxiesToUpstream(t *testing.T) {
	// Upstream simulates the now-awake container on its exposed port.
	var gotPath, gotBody, gotMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("X-Upstream", "hit")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	resolver := &fakeResolver{target: upstream.URL}
	h := newHandler(resolver, 1024)

	req := httptest.NewRequest(http.MethodPost,
		"/__ingress/http/abc123/3000/api/echo?q=1",
		strings.NewReader("payload"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Upstream") != "hit" {
		t.Fatalf("missing upstream header — proxy didn't reach it: %+v", rec.Header())
	}
	if resolver.lastID != "abc123" || resolver.lastPrt != 3000 {
		t.Fatalf("resolver got id=%q port=%d", resolver.lastID, resolver.lastPrt)
	}
	if gotPath != "/api/echo" {
		t.Fatalf("upstream path = %q, want /api/echo", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("upstream method = %q", gotMethod)
	}
	if gotBody != "payload" {
		t.Fatalf("upstream body = %q", gotBody)
	}
}

func TestHTTPWakeNoTrailingPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("upstream path = %q, want /", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := newHandler(&fakeResolver{target: upstream.URL}, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/abc/8080", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestHTTPWakeRejectsInvalidPort(t *testing.T) {
	h := newHandler(&fakeResolver{target: "http://unused"}, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/abc/not-a-number/path", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHTTPWakeRejectsOversizedBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("upstream should not be reached for oversize body")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Sandbox cold (started=false default) so the buffering branch
	// engages — that's the path the 413 cap belongs to.
	h := newHandler(&fakeResolver{target: upstream.URL}, 8)
	req := httptest.NewRequest(http.MethodPost,
		"/__ingress/http/abc/3000/api",
		strings.NewReader(strings.Repeat("x", 100)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%q", rec.Code, rec.Body.String())
	}
}

func TestHTTPWakeManualStopReturns409(t *testing.T) {
	h := newHandler(&fakeResolver{err: service.ErrSandboxManuallyStopped}, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/abc/3000/api", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%q", rec.Code, rec.Body.String())
	}
}

func TestHTTPWakeCircuitOpenReturns503WithRetryAfter(t *testing.T) {
	h := newHandler(&fakeResolver{err: service.ErrWakeCircuitOpen}, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/abc/3000/api", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q, want 60", rec.Header().Get("Retry-After"))
	}
}

// TestHTTPWakeTouchesSandboxAtRequestStart: every wake-proxied request
// must bump last_active_at exactly once at request start so the
// lifecycle idle sweep does not stop the sandbox we just woke.
func TestHTTPWakeTouchesSandboxAtRequestStart(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	resolver := &fakeResolver{target: upstream.URL}
	h := newHandler(resolver, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-touch/3000/path", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := resolver.touchCnt.Load(); got != 1 {
		t.Fatalf("touch count = %d, want 1", got)
	}
	if got, _ := resolver.touchedID.Load().(string); got != "sb-touch" {
		t.Fatalf("touched id = %q, want sb-touch", got)
	}
}

// TestHTTPWakeActivityTickerFiresOnLongLivedConnection: while a stream
// response is in flight, the 30s activity ticker must re-touch the
// sandbox so the lifecycle idle sweep does not stop it mid-stream.
// We shrink activityTickInterval for the test so it runs in <1s.
func TestHTTPWakeActivityTickerFiresOnLongLivedConnection(t *testing.T) {
	prev := activityTickInterval
	activityTickInterval = 50 * time.Millisecond
	t.Cleanup(func() { activityTickInterval = prev })

	// Upstream holds the response open for ~300ms — long enough for
	// several ticks at the shrunken interval.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			_, _ = fmt.Fprintf(w, "data: tick-%d\n\n", i)
			if flusher != nil {
				flusher.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}))
	defer upstream.Close()

	resolver := &fakeResolver{target: upstream.URL}
	h := newHandler(resolver, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-stream/3000/events", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	// 1 touch at request-start + at least 2 ticker fires within
	// the upstream's ~300ms wall time. Anything < 2 means the
	// ticker either did not start or did not survive the proxy hop.
	if got := resolver.touchCnt.Load(); got < 2 {
		t.Fatalf("touch count = %d, want >= 2 (request-start + ticker fires)", got)
	}
}

// TestHTTPWakeBufferedBodyIsReplayedToUpstream: D2 — a POST body
// within MaxBufferBytes is buffered before wake, then re-played to
// the upstream byte-for-byte so the cold-start request sees the
// original payload (Content-Length included).
func TestHTTPWakeBufferedBodyIsReplayedToUpstream(t *testing.T) {
	var (
		gotBody []byte
		gotLen  int64
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLen = r.ContentLength
		b, _ := io.ReadAll(r.Body)
		gotBody = b
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	payload := strings.Repeat("payload-byte-", 100) // ~1.3 KiB, under the 8 KiB cap
	h := newHandler(&fakeResolver{target: upstream.URL}, 8*1024)
	req := httptest.NewRequest(http.MethodPost,
		"/__ingress/http/sb-replay/3000/api/echo",
		strings.NewReader(payload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if string(gotBody) != payload {
		t.Fatalf("upstream body mismatch:\n got %q\nwant %q", string(gotBody), payload)
	}
	if gotLen != int64(len(payload)) {
		t.Fatalf("upstream Content-Length = %d, want %d", gotLen, len(payload))
	}
}

// TestHTTPWakeUpgradeBodyNotBuffered: D4 — when the request carries
// Upgrade headers, the body-buffer path is skipped entirely so the
// hijacked stream reaches the upstream. MaxBufferBytes=0 would
// normally trip the 413 path on any non-empty body — asserting the
// request reaches the upstream (with its Upgrade headers intact)
// proves the buffer branch was skipped because of the Upgrade.
//
// A real 101 hand-off needs a hijack-capable client connection (not
// httptest.ResponseRecorder), which is out of scope here — we assert
// the buffer-skip + header propagation, not the protocol-switch.
func TestHTTPWakeUpgradeBodyNotBuffered(t *testing.T) {
	var (
		gotUpgrade    string
		gotConnection string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUpgrade = r.Header.Get("Upgrade")
		gotConnection = r.Header.Get("Connection")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := newHandler(&fakeResolver{target: upstream.URL}, 0)
	req := httptest.NewRequest(http.MethodPost, "/__ingress/http/sb-ws/3000/socket",
		strings.NewReader("nonempty-body-that-would-413"))
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("got 413 — buffer-skip on Upgrade did not engage")
	}
	if gotUpgrade != "websocket" {
		t.Fatalf("upstream Upgrade = %q, want websocket", gotUpgrade)
	}
	if !strings.EqualFold(gotConnection, "Upgrade") {
		t.Fatalf("upstream Connection = %q, want Upgrade", gotConnection)
	}
}

// TestHTTPWakeWarmRequestBypassesBodyBuffer: P1 — when the sandbox is
// already running, the buffering branch must be skipped so a normal
// upload doesn't get capped at MaxBufferBytes. We set MaxBufferBytes=8
// (anything stopped would 413) and send a 1 KiB POST. With warm-bypass
// engaged the body streams straight through to the upstream and the
// request returns 200.
func TestHTTPWakeWarmRequestBypassesBodyBuffer(t *testing.T) {
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = b
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	resolver := &fakeResolver{target: upstream.URL, started: true}
	h := newHandler(resolver, 8) // 8 byte cap → would 413 a cold request

	payload := strings.Repeat("x", 1024)
	req := httptest.NewRequest(http.MethodPost,
		"/__ingress/http/sb-warm/3000/upload",
		strings.NewReader(payload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (warm bypass should skip buffer cap); body=%q", rec.Code, rec.Body.String())
	}
	if string(gotBody) != payload {
		t.Fatalf("upstream body mismatch len got=%d want=%d", len(gotBody), len(payload))
	}
}

// TestHTTPWakeWarmRequestSurfaces404OnMissingSandbox: the warm-bypass
// preflight check runs first, so a missing sandbox must short-circuit
// to 404 before the buffer / wake-target paths are reached.
func TestHTTPWakeWarmRequestSurfaces404OnMissingSandbox(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("upstream should not be reached when sandbox is missing")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	resolver := &fakeResolver{target: upstream.URL, startedErr: store.ErrNotFound}
	h := newHandler(resolver, 1024)

	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-missing/3000/api", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestHTTPWakeColdStartTimeoutReturns503: P1 — a wake that fails with
// a generic error (e.g. context.DeadlineExceeded from wakeStartTimeout,
// or any unclassified Docker start error) must surface as 503 +
// Retry-After:2, not 400. Pre-fix the handler delegated to
// WriteStoreAwareError whose fallback is 400 Bad Request, so
// load-balancers and clients saw a 4xx for a transient cold-start
// failure and would not retry.
func TestHTTPWakeColdStartTimeoutReturns503(t *testing.T) {
	resolver := &fakeResolver{err: context.DeadlineExceeded}
	h := newHandler(resolver, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-slow/3000/api", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2", got)
	}
}

// TestHTTPWakeUnknownStartErrorReturns503: same shape as the timeout
// case but with an arbitrary error (think Docker daemon transient).
// Anything not on the recognized-sentinel list must be 503 so clients
// retry instead of treating the failure as permanent.
func TestHTTPWakeUnknownStartErrorReturns503(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("docker daemon: connection refused")}
	h := newHandler(resolver, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-err/3000/api", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2", got)
	}
}

// TestHTTPWakeSSEResponseStreamsWithoutBuffering: D4 — FlushInterval=-1
// must reach the client as upstream emits, even for slow streams. We
// drive an upstream that flushes events spaced by 100ms and assert
// the client sees each event before the upstream closes the response.
func TestHTTPWakeSSEResponseStreamsWithoutBuffering(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			_, _ = fmt.Fprintf(w, "data: %d\n\n", i)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	// Spin up the handler on a real listener so we can read the
	// response over a real TCP socket (httptest.ResponseRecorder
	// buffers, which would defeat the streaming check).
	h := newHandler(&fakeResolver{target: upstream.URL}, 1024)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "GET /__ingress/http/sb-sse/3000/stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

	br := bufio.NewReader(conn)
	// Skip status + headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// Read up to ~600ms — long enough for all 3 events at 50ms spacing.
	_ = conn.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	var seen int
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "data:") {
			seen++
			if seen >= 3 {
				break
			}
		}
	}
	if seen < 3 {
		t.Fatalf("saw %d SSE events, want 3 — streaming may be buffered", seen)
	}
}
