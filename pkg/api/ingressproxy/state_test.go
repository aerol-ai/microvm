package ingressproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAcquirePendingPerSandboxCap: once a sandbox holds the per-sandbox
// cap of pending slots, further acquires for that sandbox must return
// errAdmissionPerSandbox until a release happens, while OTHER sandboxes
// are unaffected (the cap is per-id, not global).
func TestAcquirePendingPerSandboxCap(t *testing.T) {
	s := newProxyState(2 /*perSandbox*/, 10 /*global*/, 0 /*buffer disabled*/)

	rel1, err := s.acquirePending("sb-a")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	rel2, err := s.acquirePending("sb-a")
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if _, err := s.acquirePending("sb-a"); !errors.Is(err, errAdmissionPerSandbox) {
		t.Fatalf("third acquire = %v, want errAdmissionPerSandbox", err)
	}
	// Different sandbox unaffected.
	if _, err := s.acquirePending("sb-b"); err != nil {
		t.Fatalf("other-sandbox acquire: %v", err)
	}
	rel1()
	if _, err := s.acquirePending("sb-a"); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	rel2() // idempotency check: double-release is a no-op
	rel2()
}

// TestAcquirePendingGlobalCap: regardless of per-sandbox spread, once
// the global cap is reached every further acquire must reject with
// errAdmissionGlobal.
func TestAcquirePendingGlobalCap(t *testing.T) {
	s := newProxyState(0 /*perSandbox disabled*/, 3 /*global*/, 0)

	for i := 0; i < 3; i++ {
		if _, err := s.acquirePending("sb-" + string(rune('a'+i))); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	if _, err := s.acquirePending("sb-x"); !errors.Is(err, errAdmissionGlobal) {
		t.Fatalf("post-cap acquire = %v, want errAdmissionGlobal", err)
	}
}

// TestAcquireBufferBudget: the buffer-byte semaphore must reject
// reservations that would overflow the cap and accept any reservation
// that fits, including back-to-back after release.
func TestAcquireBufferBudget(t *testing.T) {
	s := newProxyState(0, 0, 100 /*100B cap*/)

	rel1, err := s.acquireBuffer(60)
	if err != nil {
		t.Fatalf("acquire 60: %v", err)
	}
	if _, err := s.acquireBuffer(50); !errors.Is(err, errBufferBudget) {
		t.Fatalf("acquire 50 (would total 110) = %v, want errBufferBudget", err)
	}
	// 40 fits exactly under the remaining 40.
	rel2, err := s.acquireBuffer(40)
	if err != nil {
		t.Fatalf("acquire 40: %v", err)
	}
	rel1()
	// Now 60 fits again.
	if _, err := s.acquireBuffer(60); err != nil {
		t.Fatalf("acquire 60 after release: %v", err)
	}
	rel2()
}

// TestProbeOnceCollapsesConcurrentCallers: 100 callers converging on
// the same (id, port) must trigger exactly ONE probeFn invocation;
// all 100 see the same result. This is the per-sandbox single-flight
// that prevents 10k SYNs to one cold container.
func TestProbeOnceCollapsesConcurrentCallers(t *testing.T) {
	s := newProxyState(0, 0, 0)

	var probeCalls atomic.Int32
	probeFn := func(_ context.Context, _ time.Duration) error {
		probeCalls.Add(1)
		time.Sleep(50 * time.Millisecond) // hold the flight long enough for followers to enroll
		return nil
	}

	const N = 100
	var wg sync.WaitGroup
	var errs atomic.Int32
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.probeOnce(context.Background(), "sb-x", 3000, time.Second, probeFn); err != nil {
				errs.Add(1)
			}
		}()
	}
	wg.Wait()

	if probeCalls.Load() != 1 {
		t.Fatalf("probeFn invocations = %d, want 1 (single-flight broken)", probeCalls.Load())
	}
	if errs.Load() != 0 {
		t.Fatalf("got %d errors, want 0", errs.Load())
	}
}

// TestProbeOnceLeaderCancelDoesNotStrandFollowers: when the leader's
// caller context is cancelled mid-probe, followers must still receive
// the probe's eventual result. The leader runs with a detached context
// derived only from the budget, so the leader's cancellation does not
// kill the shared probe.
func TestProbeOnceLeaderCancelDoesNotStrandFollowers(t *testing.T) {
	s := newProxyState(0, 0, 0)

	probeStarted := make(chan struct{})
	probeFn := func(_ context.Context, _ time.Duration) error {
		close(probeStarted)
		time.Sleep(100 * time.Millisecond)
		return nil
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		leaderDone <- s.probeOnce(leaderCtx, "sb-x", 3000, 500*time.Millisecond, probeFn)
	}()
	<-probeStarted

	// Enrol a follower with its own context.
	followerDone := make(chan error, 1)
	go func() {
		followerDone <- s.probeOnce(context.Background(), "sb-x", 3000, 500*time.Millisecond, probeFn)
	}()

	// Cancel the leader — its own probeOnce call should surface the
	// cancellation, but the underlying probe keeps running and the
	// follower still gets the success result.
	time.Sleep(20 * time.Millisecond)
	cancelLeader()

	leaderErr := <-leaderDone
	if !errors.Is(leaderErr, context.Canceled) {
		t.Fatalf("leader err = %v, want context.Canceled", leaderErr)
	}
	if followerErr := <-followerDone; followerErr != nil {
		t.Fatalf("follower err = %v, want nil — leader cancel must not strand", followerErr)
	}
}

// TestHTTPWakeAdmissionRejection: when the global pending cap is full,
// the handler must reject new cold-start requests with 503 + Retry-After
// rather than queuing them indefinitely.
func TestHTTPWakeAdmissionRejection(t *testing.T) {
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
		MaxPendingGlobal:     1,
		UpstreamReadyTimeout: 1 * time.Second,
	})
	// Substitute a dialer that blocks until released so the first
	// request stays pending while the second tries to admit.
	prev := dialUpstream
	t.Cleanup(func() { dialUpstream = prev })
	hold := make(chan struct{})
	dialUpstream = func(ctx context.Context, _ string) (net.Conn, error) {
		select {
		case <-hold:
			return nil, errors.New("released")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Kick off the first request asynchronously — it will hold the
	// pending slot for the lifetime of the (blocked) probe.
	first := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-cap/3000/api", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		first <- rec.Code
	}()

	// Give the first request a moment to acquire the slot.
	time.Sleep(50 * time.Millisecond)

	// Second request must be admission-rejected. Use a DIFFERENT
	// sandbox so the rejection comes from the global cap (1), not
	// from the per-sandbox cap that the first request occupies for
	// "sb-cap". We expose this distinction via separate per/global
	// caps in the Deps wiring above.
	req2 := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-other/3000/api", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("second request status = %d, want 503 (admission)", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After = %q, want 2", rec2.Header().Get("Retry-After"))
	}
	if !strings.Contains(rec2.Body.String(), "pending wake limit") {
		t.Fatalf("body = %q, want admission rejection text", rec2.Body.String())
	}

	close(hold)
	<-first
}

// TestHTTPWakeBufferBudgetRejection: when the cross-request buffer
// budget is exhausted, a cold POST must be rejected with 503 rather
// than allowed to push the node further over its memory ceiling.
func TestHTTPWakeBufferBudgetRejection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("upstream should not be reached when buffer budget rejects")
	}))
	defer upstream.Close()

	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Resolver:             &fakeResolver{target: upstream.URL},
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBufferBytes:       100,
		MaxPendingPerSandbox: 10,
		MaxPendingGlobal:     10,
		MaxBufferBytesGlobal: 50, // budget too small for the request
		UpstreamReadyTimeout: 1 * time.Second,
	})

	req := httptest.NewRequest(http.MethodPost,
		"/__ingress/http/sb-budget/3000/api",
		strings.NewReader(strings.Repeat("x", 80)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "buffer budget") {
		t.Fatalf("body = %q, want buffer-budget rejection", rec.Body.String())
	}
}

// TestHTTPWakeRetriesOnNonRefusedErrors: the widened retry policy
// must hold the request when the dial returns ECONNRESET / generic
// network errors during the container's brief boot window, then
// succeed once the upstream is bound. Before the widening this would
// have surfaced immediately as 503 / closed connection.
func TestHTTPWakeRetriesOnNonRefusedErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	prev := dialUpstream
	t.Cleanup(func() { dialUpstream = prev })
	start := time.Now()
	dialUpstream = func(ctx context.Context, addr string) (net.Conn, error) {
		if time.Since(start) < 100*time.Millisecond {
			// Pretend the kernel briefly returns a "host unreachable"
			// or "reset by peer" during container start.
			return nil, errors.New("connect: host unreachable")
		}
		d := net.Dialer{Timeout: 500 * time.Millisecond}
		return d.DialContext(ctx, "tcp", addr)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Resolver:             &fakeResolver{target: upstream.URL},
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBufferBytes:       1024,
		MaxPendingPerSandbox: 10,
		MaxPendingGlobal:     10,
		MaxBufferBytesGlobal: 1024,
		UpstreamReadyTimeout: 1 * time.Second,
	})

	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/sb-rst/3000/api", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (probe should retry through non-ECONNREFUSED errors); body=%q", rec.Code, rec.Body.String())
	}
}
