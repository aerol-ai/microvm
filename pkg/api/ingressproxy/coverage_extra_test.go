package ingressproxy

import (
	"context"
	"errors"
	"expvar"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

func TestNewTLSAskHandler_DefaultLogger(t *testing.T) {
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver: newFakeDomainResolver(nil),
	})
	if h == nil || h.deps.Logger == nil {
		t.Fatal("expected default logger when Logger is nil")
	}
}

func TestEvictNegativeCache_NilReceiver(t *testing.T) {
	var h *TLSAskHandler
	h.EvictNegativeCache("example.com") // must not panic
}

func TestNegativeCache_AddRefreshesExistingEntry(t *testing.T) {
	c := newNegativeCache(10, time.Hour)
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	c.add("refresh.example.com")
	now = now.Add(time.Minute)
	c.add("refresh.example.com") // refresh path: updates addedAt, moves to front
	if !c.has("refresh.example.com") {
		t.Fatal("expected refreshed entry to remain cached")
	}
}

func TestAcquireBufferZeroAndDoubleRelease(t *testing.T) {
	s := newProxyState(0, 0, 100)
	release, err := s.acquireBuffer(0)
	if err != nil {
		t.Fatalf("acquire 0: %v", err)
	}
	release()
	release() // idempotent

	rel, err := s.acquireBuffer(50)
	if err != nil {
		t.Fatal(err)
	}
	rel()
	rel() // double release must not drive counter negative
}

func TestWaitForUpstreamReadySuccessAndCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			_ = conn.Close()
		}
	}()

	prev := dialUpstream
	t.Cleanup(func() { dialUpstream = prev })
	dialUpstream = func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}

	if err := waitForUpstreamReady(context.Background(), ln.Addr().String(), time.Second); err != nil {
		t.Fatalf("expected ready: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForUpstreamReady(ctx, ln.Addr().String(), time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	prev = dialUpstream
	dialUpstream = func(_ context.Context, _ string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = waitForUpstreamReady(ctx, "127.0.0.1:1", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestWriteWakeErrorBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantRetry  string
	}{
		{"not_found", store.ErrNotFound, http.StatusNotFound, ""},
		{"manual_stop", service.ErrSandboxManuallyStopped, http.StatusConflict, ""},
		{"circuit_open", service.ErrWakeCircuitOpen, http.StatusServiceUnavailable, "60"},
		{"capacity", capacity.ErrCapacityExceeded, http.StatusServiceUnavailable, ""},
		{"cluster_capacity", cluster.ErrCapacityExceeded, http.StatusServiceUnavailable, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeWakeError(logger, rec, "sb", 3000, tc.err)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantRetry != "" && rec.Header().Get("Retry-After") != tc.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", rec.Header().Get("Retry-After"), tc.wantRetry)
			}
		})
	}
}

func TestScheduleActivityTouchCancelledContext(t *testing.T) {
	h := &handlers{
		deps: Deps{
			Resolver: &fakeResolver{target: "http://unused"},
			Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.scheduleActivityTouch(ctx, "sb-cancelled") // must not panic
}

func TestHTTPWakeDirectValidationPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &handlers{
		deps: Deps{
			Resolver:       &fakeResolver{target: "http://127.0.0.1:1"},
			Logger:         logger,
			MaxBufferBytes: 1024,
		},
		state: newProxyState(0, 0, 0),
	}

	t.Run("missing_id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		h.httpWake(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("invalid_target_url", func(t *testing.T) {
		h.deps.Resolver = &fakeResolver{target: "://not-a-url", started: true}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetPathValue("id", "sb")
		req.SetPathValue("port", "3000")
		h.httpWake(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("body_read_error", func(t *testing.T) {
		h.deps.Resolver = &fakeResolver{target: "http://127.0.0.1:1"}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", errorReader{})
		req.SetPathValue("id", "sb")
		req.SetPathValue("port", "3000")
		req.ContentLength = 10
		h.httpWake(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestHTTPWakeProxyErrorHandler(t *testing.T) {
	// Point at a port with nothing listening so the reverse proxy fails.
	h := newHandler(&fakeResolver{target: "http://127.0.0.1:1", started: true}, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-proxy/3000/api", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After = %q, want 2", rec.Header().Get("Retry-After"))
	}
}

func TestHTTPWakeColdPOSTWithUnknownContentLength(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if len(b) == 0 {
			t.Fatal("expected body to be buffered")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	prev := dialUpstream
	t.Cleanup(func() { dialUpstream = prev })
	dialUpstream = func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}

	h := newHandler(&fakeResolver{target: upstream.URL}, 1024)
	req := httptest.NewRequest(http.MethodPost, "/__ingress/http/sb-chunk/3000/api", strings.NewReader("payload"))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
}

func TestHTTPWakePerSandboxAdmissionRejection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Resolver:             &fakeResolver{target: upstream.URL},
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBufferBytes:       1024,
		MaxPendingPerSandbox: 1,
		MaxPendingGlobal:     10,
		UpstreamReadyTimeout: time.Second,
	})

	prev := dialUpstream
	t.Cleanup(func() { dialUpstream = prev })
	var holds atomic.Int32
	dialUpstream = func(ctx context.Context, _ string) (net.Conn, error) {
		holds.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	go func() {
		req := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-same/3000/api", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
	}()

	time.Sleep(30 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-same/3000/other", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (per-sandbox cap)", rec.Code)
	}
	if holds.Load() < 1 {
		t.Fatal("expected first request to hold probe")
	}
}

func TestIssuanceTrackerStartedEmptyHost(t *testing.T) {
	tr := newIssuanceTrackerWithGauge(new(expvar.Map).Init())
	tr.Started("") // no-op
	if tr.inProgress() != 0 {
		t.Fatalf("inProgress = %d, want 0", tr.inProgress())
	}
}
