package ingressproxy

import (
	"container/list"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

// ACMEBudgetReserver is the daemon-wide brake on new ACME orders. A nil
// implementation is fine: the handler treats nil as "no brake" so the
// hot path stays one-branch when the feature is off. The handler calls
// Reserve only when the ask would actually allow issuance — base-domain
// fast-fail and negative-cache hits don't consume budget.
//
// Returns (true, 0) to permit, (false, retryAfter) to refuse. The
// retryAfter is surfaced as the HTTP Retry-After header on the 429
// response so Caddy backs off coherently with the budget window.
type ACMEBudgetReserver interface {
	Reserve(sandboxID, hostname string) (bool, time.Duration)
}

// TLSAskPath is Caddy's on-demand TLS `ask` callback path. Caddy passes the
// requested hostname as the `domain` query parameter and decides whether to
// attempt issuance based on the HTTP status: 2xx → issue, anything else →
// refuse. The path is fixed so both the Caddy install-time config push and
// this handler share a single grep target.
const TLSAskPath = "/internal/tls-ask"

// CustomDomainResolver is the narrow lookup the ask handler needs. In PR #2
// it is backed by store.ResolveCustomDomain (single PK lookup); PR #3 swaps
// in the local Raft FSM's hostname → sandbox map so the hot path stays
// fully in-process across the cluster. The interface intentionally returns
// store.ErrNotFound on miss so the handler treats both backends the same.
type CustomDomainResolver interface {
	ResolveCustomDomain(ctx context.Context, hostname string) (string, error)
}

// TLSAskDeps wires the ask handler. BaseDomain is the wildcard zone served
// out of cfg.Domain — when set, requests for the apex or any subdomain pass
// through with 200 as defense in depth (Caddy's wildcard policy should
// already match first, but a stray on-demand fallthrough must never trigger
// per-host issuance for a hostname covered by the wildcard).
//
// NegCacheTTL and NegCacheCap bound the negative-cache footprint. Zero on
// either disables the cache (intended for tests).
type TLSAskDeps struct {
	Resolver    CustomDomainResolver
	BaseDomain  string
	NegCacheTTL time.Duration
	NegCacheCap int
	Logger      *slog.Logger
	// Budget is the daemon-wide ACME issuance brake (OV5A). Nil disables
	// the brake — single-node deployments and tests that don't care
	// about LE rate limits pass nil and Reserve is skipped entirely.
	Budget ACMEBudgetReserver
	// Tracker observes the issuance lifecycle for the
	// aerolvm_acme_lock_held_seconds gauge. Nil disables tracking. Wired
	// to the package-global tracker in production via the helpers in
	// metrics.go; tests can substitute a stub.
	Tracker IssuanceObserver
}

// IssuanceObserver lets the handler signal the issuance lifecycle
// without depending on the concrete tracker — kept minimal so tests can
// stub it without dragging in expvar state.
type IssuanceObserver interface {
	Started(hostname string)
}

// TLSAskHandler answers Caddy's on-demand TLS `ask` callback for custom
// hostnames. Hot path: PK-style lookup with an LRU negative cache so an SNI
// flood from an internet-facing scanner does not turn into per-request
// store traffic.
type TLSAskHandler struct {
	deps     TLSAskDeps
	negCache *negativeCache
}

// NewTLSAskHandler builds a handler. Resolver and Logger are required;
// BaseDomain is recommended whenever cfg.Domain is set.
func NewTLSAskHandler(d TLSAskDeps) *TLSAskHandler {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &TLSAskHandler{
		deps:     d,
		negCache: newNegativeCache(d.NegCacheCap, d.NegCacheTTL),
	}
}

// EvictNegativeCache drops a hostname from the negative cache. The service
// layer calls this after AddCustomDomain succeeds so a legitimate add does
// not have to wait out the TTL before Caddy will issue a cert.
func (h *TLSAskHandler) EvictNegativeCache(host string) {
	if h == nil || h.negCache == nil {
		return
	}
	h.negCache.remove(normalizeAskHost(host))
}

// ServeHTTP implements http.Handler. GET /internal/tls-ask?domain=<host>.
func (h *TLSAskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := normalizeAskHost(r.URL.Query().Get("domain"))
	if host == "" {
		RecordAskResult(AskResultBadRequest)
		http.Error(w, "missing domain", http.StatusBadRequest)
		return
	}

	// Defense in depth — the wildcard policy should match first, but if
	// the on-demand policy fires for a hostname under the deployment base
	// domain (misconfigured order, sb-* names racing wildcard install,
	// etc.) we must not let Caddy attempt a per-host LE issuance for it.
	if h.deps.BaseDomain != "" {
		base := strings.ToLower(h.deps.BaseDomain)
		if host == base || strings.HasSuffix(host, "."+base) {
			RecordAskResult(AskResultBaseDomain)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	if h.negCache != nil && h.negCache.has(host) {
		RecordAskResult(AskResultUnknown)
		http.Error(w, "unknown host", http.StatusForbidden)
		return
	}

	sandboxID, err := h.deps.Resolver.ResolveCustomDomain(r.Context(), host)
	if err == nil {
		// Daemon-wide ACME budget brake (OV5A). Reserve only after the
		// hostname is known to be ours so unknown-host floods can't
		// drain the bucket. A nil budget allows unconditionally.
		if h.deps.Budget != nil {
			if ok, retry := h.deps.Budget.Reserve(sandboxID, host); !ok {
				RecordAskResult(AskResultThrottled)
				if retry > 0 {
					// Retry-After in seconds, RFC 7231 §7.1.3. Round
					// up so a sub-second retry doesn't become "0"
					// (which Caddy reads as "no backoff").
					secs := max(int((retry+time.Second-1)/time.Second), 1)
					w.Header().Set("Retry-After", strconv.Itoa(secs))
				}
				http.Error(w, "acme budget exhausted", http.StatusTooManyRequests)
				return
			}
		}
		if h.deps.Tracker != nil {
			h.deps.Tracker.Started(host)
		}
		RecordAskResult(AskResultOK)
		w.WriteHeader(http.StatusOK)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		if h.negCache != nil {
			h.negCache.add(host)
		}
		RecordAskResult(AskResultUnknown)
		http.Error(w, "unknown host", http.StatusForbidden)
		return
	}
	// Resolver outage (store I/O error, ctx cancelled, etc.). Refuse
	// cautiously — a 5xx here tells Caddy "don't issue right now", which
	// is the right answer when we can't confirm the hostname is ours.
	// Do NOT add to the negative cache: this is a transient backend
	// failure, not a "host doesn't exist" signal.
	h.deps.Logger.WarnContext(r.Context(), "tls-ask resolve failed", "host", host, "err", err)
	RecordAskResult(AskResultResolveError)
	http.Error(w, "resolve failed", http.StatusInternalServerError)
}

// normalizeAskHost lower-cases the host and strips a trailing dot. Caddy
// has been observed to send absolute (FQDN with trailing dot) names from
// SNI in some setups.
func normalizeAskHost(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
}

// negativeCache is an LRU with per-entry TTL. Cap and TTL come from
// TLSAskDeps; zero on either disables caching (newNegativeCache returns
// nil, and callers null-check).
//
// We use a plain map + container/list rather than pulling in a third-party
// LRU package — the working set is tiny (cap is bounded, evictions are
// rare under normal traffic) and the package already has no external
// dependencies for similar shaped state.
type negativeCache struct {
	mu      sync.Mutex
	cap     int
	ttl     time.Duration
	entries map[string]*list.Element
	order   *list.List // front = most recent
	now     func() time.Time
}

type negCacheEntry struct {
	host    string
	addedAt time.Time
}

func newNegativeCache(cap int, ttl time.Duration) *negativeCache {
	if cap <= 0 || ttl <= 0 {
		return nil
	}
	return &negativeCache{
		cap:     cap,
		ttl:     ttl,
		entries: make(map[string]*list.Element, cap),
		order:   list.New(),
		now:     time.Now,
	}
}

func (c *negativeCache) has(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[host]
	if !ok {
		return false
	}
	entry := el.Value.(*negCacheEntry)
	if c.now().Sub(entry.addedAt) > c.ttl {
		c.order.Remove(el)
		delete(c.entries, host)
		return false
	}
	c.order.MoveToFront(el)
	return true
}

func (c *negativeCache) add(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[host]; ok {
		entry := el.Value.(*negCacheEntry)
		entry.addedAt = c.now()
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&negCacheEntry{host: host, addedAt: c.now()})
	c.entries[host] = el
	for c.order.Len() > c.cap {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*negCacheEntry).host)
	}
}

func (c *negativeCache) remove(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[host]; ok {
		c.order.Remove(el)
		delete(c.entries, host)
	}
}
