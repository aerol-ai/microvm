package ingressproxy

import (
	"container/list"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

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
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	if h.negCache != nil && h.negCache.has(host) {
		http.Error(w, "unknown host", http.StatusForbidden)
		return
	}

	_, err := h.deps.Resolver.ResolveCustomDomain(r.Context(), host)
	if err == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		if h.negCache != nil {
			h.negCache.add(host)
		}
		http.Error(w, "unknown host", http.StatusForbidden)
		return
	}
	// Resolver outage (store I/O error, ctx cancelled, etc.). Refuse
	// cautiously — a 5xx here tells Caddy "don't issue right now", which
	// is the right answer when we can't confirm the hostname is ours.
	// Do NOT add to the negative cache: this is a transient backend
	// failure, not a "host doesn't exist" signal.
	h.deps.Logger.WarnContext(r.Context(), "tls-ask resolve failed", "host", host, "err", err)
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
