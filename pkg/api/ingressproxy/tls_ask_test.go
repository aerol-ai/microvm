package ingressproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

type fakeDomainResolver struct {
	mu        sync.Mutex
	known     map[string]string
	calls     atomic.Int64
	failNext  bool
	failErr   error
	failCount atomic.Int64
}

func newFakeDomainResolver(known map[string]string) *fakeDomainResolver {
	return &fakeDomainResolver{known: known}
}

func (f *fakeDomainResolver) ResolveCustomDomain(_ context.Context, host string) (string, error) {
	f.calls.Add(1)
	f.mu.Lock()
	fail := f.failNext
	failErr := f.failErr
	if fail {
		f.failCount.Add(1)
	}
	f.mu.Unlock()
	if fail {
		if failErr == nil {
			failErr = errors.New("resolver outage")
		}
		return "", failErr
	}
	if id, ok := f.known[host]; ok {
		return id, nil
	}
	return "", store.ErrNotFound
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newAskRequest(host string) *http.Request {
	q := url.Values{}
	q.Set("domain", host)
	return httptest.NewRequest(http.MethodGet, "/internal/tls-ask?"+q.Encode(), nil)
}

func TestTLSAsk_MissingDomain(t *testing.T) {
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:    newFakeDomainResolver(nil),
		BaseDomain:  "aerol.cloud",
		NegCacheTTL: time.Minute,
		NegCacheCap: 100,
		Logger:      discardLogger(),
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/internal/tls-ask", nil)
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", w.Code)
	}
}

func TestTLSAsk_KnownHostAllowed(t *testing.T) {
	resolver := newFakeDomainResolver(map[string]string{"api.acme.com": "sb-abc"})
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:    resolver,
		BaseDomain:  "aerol.cloud",
		NegCacheTTL: time.Minute,
		NegCacheCap: 100,
		Logger:      discardLogger(),
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("api.acme.com"))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("expected 1 resolver call, got %d", resolver.calls.Load())
	}
}

func TestTLSAsk_UnknownHostForbiddenAndCached(t *testing.T) {
	resolver := newFakeDomainResolver(nil)
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:    resolver,
		BaseDomain:  "aerol.cloud",
		NegCacheTTL: time.Minute,
		NegCacheCap: 100,
		Logger:      discardLogger(),
	})

	// First miss → resolver hit, 403, host cached.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("evil.example.com"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("first miss: got %d, want 403", w.Code)
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("expected 1 resolver call after first miss, got %d", resolver.calls.Load())
	}

	// Second miss → served from negative cache, no resolver call.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("evil.example.com"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("second miss: got %d, want 403", w.Code)
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("negative cache should suppress resolver call, got %d total", resolver.calls.Load())
	}
}

func TestTLSAsk_BaseDomainPassthrough(t *testing.T) {
	// Even with a resolver that returns ErrNotFound, hostnames under the
	// deployment base domain must short-circuit to 200 — they are served
	// by the wildcard policy, not on-demand.
	resolver := newFakeDomainResolver(nil)
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:    resolver,
		BaseDomain:  "aerol.cloud",
		NegCacheTTL: time.Minute,
		NegCacheCap: 100,
		Logger:      discardLogger(),
	})

	for _, host := range []string{"aerol.cloud", "sb-xyz.aerol.cloud", "sb-xyz-8080.aerol.cloud"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newAskRequest(host))
		if w.Code != http.StatusOK {
			t.Fatalf("host %q: got %d, want 200", host, w.Code)
		}
	}
	if resolver.calls.Load() != 0 {
		t.Fatalf("base-domain passthrough must not touch resolver, got %d calls", resolver.calls.Load())
	}
}

func TestTLSAsk_TrailingDotAndCaseFolded(t *testing.T) {
	resolver := newFakeDomainResolver(map[string]string{"api.acme.com": "sb-abc"})
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:    resolver,
		BaseDomain:  "aerol.cloud",
		NegCacheTTL: time.Minute,
		NegCacheCap: 100,
		Logger:      discardLogger(),
	})
	for _, host := range []string{"API.Acme.COM", "api.acme.com.", "  api.acme.com  "} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newAskRequest(host))
		if w.Code != http.StatusOK {
			t.Fatalf("host %q normalized incorrectly: got %d, want 200", host, w.Code)
		}
	}
}

func TestTLSAsk_ResolverErrorIsTransient(t *testing.T) {
	// Backend failures must return 5xx (not 4xx) and must NOT poison the
	// negative cache — otherwise a transient SQLite hiccup turns into a
	// 60s lockout for legitimate hosts.
	resolver := newFakeDomainResolver(nil)
	resolver.failNext = true
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:    resolver,
		BaseDomain:  "aerol.cloud",
		NegCacheTTL: time.Minute,
		NegCacheCap: 100,
		Logger:      discardLogger(),
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("api.acme.com"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500", w.Code)
	}

	// Flip resolver healthy + add the host. A second call must hit the
	// resolver (proving the host was NOT cached on the 5xx path).
	resolver.mu.Lock()
	resolver.failNext = false
	resolver.known = map[string]string{"api.acme.com": "sb-abc"}
	resolver.mu.Unlock()

	w = httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("api.acme.com"))
	if w.Code != http.StatusOK {
		t.Fatalf("after recovery: got %d, want 200", w.Code)
	}
}

func TestTLSAsk_EvictNegativeCacheAfterAdd(t *testing.T) {
	// Simulate the AddCustomDomain → evict flow: a scanner pokes the host
	// before the operator registers it (403 + cache); the operator then
	// adds it; eviction lets the next ask succeed without waiting out the
	// TTL.
	resolver := newFakeDomainResolver(nil)
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:    resolver,
		BaseDomain:  "aerol.cloud",
		NegCacheTTL: time.Hour,
		NegCacheCap: 100,
		Logger:      discardLogger(),
	})

	// 1) Scanner poke caches the negative.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("api.acme.com"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("scanner poke: got %d, want 403", w.Code)
	}

	// 2) Operator adds the domain → resolver knows it now, but cache
	//    still holds the negative. Without eviction the ask would 403.
	resolver.mu.Lock()
	resolver.known = map[string]string{"api.acme.com": "sb-abc"}
	resolver.mu.Unlock()
	h.EvictNegativeCache("API.Acme.COM.") // exercise the normalize-on-evict path

	// 3) Next ask succeeds because the cache entry was evicted.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("api.acme.com"))
	if w.Code != http.StatusOK {
		t.Fatalf("after evict: got %d, want 200", w.Code)
	}
}

func TestNegativeCache_TTLExpiry(t *testing.T) {
	c := newNegativeCache(10, 5*time.Second)
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	c.add("a.com")
	if !c.has("a.com") {
		t.Fatalf("expected hit immediately after add")
	}
	now = now.Add(6 * time.Second) // past TTL
	if c.has("a.com") {
		t.Fatalf("expected miss after TTL expiry")
	}
}

func TestNegativeCache_CapEvictsOldest(t *testing.T) {
	c := newNegativeCache(3, time.Hour)
	c.add("a")
	c.add("b")
	c.add("c")
	c.add("d") // evicts "a"
	if c.has("a") {
		t.Fatalf("oldest entry should have been evicted")
	}
	for _, h := range []string{"b", "c", "d"} {
		if !c.has(h) {
			t.Fatalf("expected %q to still be cached", h)
		}
	}
}

func TestNegativeCache_DisabledWhenZero(t *testing.T) {
	if newNegativeCache(0, time.Minute) != nil {
		t.Fatalf("zero cap should disable cache")
	}
	if newNegativeCache(10, 0) != nil {
		t.Fatalf("zero TTL should disable cache")
	}
}

func TestNegativeCache_RemoveIsIdempotent(t *testing.T) {
	c := newNegativeCache(5, time.Hour)
	c.remove("missing") // must not panic
	c.add("x")
	c.remove("x")
	if c.has("x") {
		t.Fatalf("remove failed")
	}
	c.remove("x") // second remove is a no-op
}

func TestTLSAsk_HandlerWithoutCache(t *testing.T) {
	// Cache disabled (cap=0). Every miss should still 403 but each one
	// hits the resolver — proving the handler degrades cleanly without
	// the LRU.
	resolver := newFakeDomainResolver(nil)
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:   resolver,
		BaseDomain: "aerol.cloud",
		Logger:     discardLogger(),
	})
	for i := range 3 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newAskRequest("evil.example.com"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("iter %d: got %d, want 403", i, w.Code)
		}
	}
	if resolver.calls.Load() != 3 {
		t.Fatalf("expected 3 resolver calls with cache disabled, got %d", resolver.calls.Load())
	}
}

// TestTLSAsk_BudgetThrottleReturns429: when the ACME budget refuses,
// the handler must return 429 with Retry-After set in seconds. Caddy
// reads Retry-After to back off — silently dropping it would leave
// Caddy hammering the brake.
func TestTLSAsk_BudgetThrottleReturns429(t *testing.T) {
	resolver := newFakeDomainResolver(map[string]string{"api.acme.com": "sb-abc"})
	budget := &stubBudget{allow: false, retry: 90 * time.Second}
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver: resolver,
		Logger:   discardLogger(),
		Budget:   budget,
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("api.acme.com"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "90" {
		t.Fatalf("Retry-After = %q, want 90", got)
	}
	if budget.callsFor("sb-abc", "api.acme.com") != 1 {
		t.Fatal("budget Reserve not called with sandbox_id + host")
	}
}

// TestTLSAsk_BudgetSkippedForUnknownHost: budget must not be consumed
// when the resolver doesn't know the host — unknown-host floods from
// internet scanners would otherwise drain the bucket and starve real
// custom domains.
func TestTLSAsk_BudgetSkippedForUnknownHost(t *testing.T) {
	resolver := newFakeDomainResolver(nil)
	budget := &stubBudget{allow: false, retry: time.Second}
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver: resolver,
		Logger:   discardLogger(),
		Budget:   budget,
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("evil.example.com"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", w.Code)
	}
	if budget.total() != 0 {
		t.Fatalf("budget consumed %d times for unknown host; want 0", budget.total())
	}
}

// TestTLSAsk_BudgetSkippedForBaseDomain: wildcard-policy hosts under
// SB_DOMAIN must not consume budget either — they aren't going through
// the on-demand path even if the ask handler short-circuits.
func TestTLSAsk_BudgetSkippedForBaseDomain(t *testing.T) {
	budget := &stubBudget{allow: false, retry: time.Second}
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:   newFakeDomainResolver(nil),
		BaseDomain: "aerol.cloud",
		Logger:     discardLogger(),
		Budget:     budget,
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("sb-xyz.aerol.cloud"))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	if budget.total() != 0 {
		t.Fatalf("budget consumed %d times for base domain; want 0", budget.total())
	}
}

// TestTLSAsk_TrackerStartedOnFirstOK: the issuance tracker is signalled
// only on a successful issuance ask, not on base-domain passthrough or
// unknown-host rejection. Wrong gating would inflate the
// aerolvm_acme_lock_held_seconds gauge with hostnames Caddy never
// touched.
func TestTLSAsk_TrackerStartedOnFirstOK(t *testing.T) {
	resolver := newFakeDomainResolver(map[string]string{"api.acme.com": "sb-abc"})
	tracker := &stubTracker{}
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:   resolver,
		BaseDomain: "aerol.cloud",
		Logger:     discardLogger(),
		Tracker:    tracker,
	})
	// 1. base-domain — no tracker hit
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("sb-xyz.aerol.cloud"))
	// 2. unknown — no tracker hit
	w = httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("evil.example.com"))
	// 3. known — tracker hit
	w = httptest.NewRecorder()
	h.ServeHTTP(w, newAskRequest("api.acme.com"))
	if got := tracker.calls("api.acme.com"); got != 1 {
		t.Fatalf("tracker.Started(api.acme.com) = %d, want 1", got)
	}
	if got := tracker.total(); got != 1 {
		t.Fatalf("tracker total = %d, want 1", got)
	}
}

func TestRegisterTLSAsk_RoutesOnMux(t *testing.T) {
	resolver := newFakeDomainResolver(map[string]string{"api.acme.com": "sb-abc"})
	h := NewTLSAskHandler(TLSAskDeps{
		Resolver:    resolver,
		BaseDomain:  "aerol.cloud",
		NegCacheTTL: time.Minute,
		NegCacheCap: 100,
		Logger:      discardLogger(),
	})
	mux := http.NewServeMux()
	RegisterTLSAsk(mux, h)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/internal/tls-ask?domain=api.acme.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
}

type stubBudget struct {
	mu    sync.Mutex
	allow bool
	retry time.Duration
	hits  map[string]int // "sandbox|host" → count
}

func (b *stubBudget) Reserve(sandboxID, host string) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.hits == nil {
		b.hits = map[string]int{}
	}
	b.hits[sandboxID+"|"+host]++
	return b.allow, b.retry
}

func (b *stubBudget) callsFor(sandboxID, host string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hits[sandboxID+"|"+host]
}

func (b *stubBudget) total() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, v := range b.hits {
		n += v
	}
	return n
}

type stubTracker struct {
	mu   sync.Mutex
	seen map[string]int
}

func (t *stubTracker) Started(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen == nil {
		t.seen = map[string]int{}
	}
	t.seen[host]++
}

func (t *stubTracker) calls(host string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.seen[host]
}

func (t *stubTracker) total() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, v := range t.seen {
		n += v
	}
	return n
}
