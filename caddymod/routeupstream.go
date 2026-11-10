// Package caddymod holds AerolVM's Caddy plugins.
//
// http.reverse_proxy.upstreams.aerolvm_route finds a sandbox host's upstream
// by asking the sandboxd route responder (internal/routedns) for its A
// record. It replaces Caddy's stock "a" source on the owner's static sandbox
// route (pkg/caddy/static_routes.go), where every sandbox request looks up
// its upstream. The stock source does not hold up there:
//
//   - its cache is process-wide and holds 100 names. Past that it thrashes,
//     and every request becomes a lookup;
//   - every lookup runs under one process-wide write lock, so every request,
//     cache hits included, waits behind it;
//   - a failed lookup is never cached, and is logged at ERROR. NXDOMAIN is
//     the responder's normal answer for WASM/isolate, masked, waking and
//     in-flux hosts (the router serves them), so each of their requests was
//     a lookup under that lock and an error line;
//   - it asks for A and AAAA, and the responder only answers A.
//
// With Caddy 2.11.9 and 64 callers that was 2.4M lookups/s at 100 hosts,
// 27k at 150 and 4.9k at 1,000, for the whole node.
//
// This source keeps a cache per route, sized for a node and split into
// shards, so a lookup for one host never waits on another host. One lookup
// per host is in flight at a time. A host the responder does not answer is
// cached like any answer and served the fallback upstream (the router)
// directly, with no error.
package caddymod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/miekg/dns"
)

func init() {
	caddy.RegisterModule(RouteUpstreams{})
	caddy.RegisterModule(adminRoute{})
}

// The contract with sandboxd (pkg/caddy/static_routes.go).
const (
	SourceName     = "aerolvm_route"
	SourceModuleID = "http.reverse_proxy.upstreams." + SourceName
	AdminModuleID  = "admin.api." + SourceName
	// AdminPath answers 200 on a Caddy built with this package. sandboxd
	// asks it before it writes a route that names the source: the route
	// goes in with one batched /load, and an unknown module would fail the
	// whole load.
	AdminPath = "/aerolvm/route-upstream"
)

// lookupTimeout bounds one query. The responder answers from memory on
// loopback, so a slow answer is a fault, and the request then takes Caddy's
// static upstream (also the router), as any lookup error does. A var so
// tests can shorten it.
var lookupTimeout = time.Second

const (
	defaultRefresh    = time.Second
	defaultMaxEntries = 16384
	// maxLookups bounds queries in flight. Every unknown host a scanner
	// sends is a new name, so a lookup of its own; unbounded, a flood would
	// open a UDP socket per request.
	maxLookups  = 256
	cacheShards = 64
	// evictSample is how many entries a full shard looks at to pick one to
	// drop. An entry lives one refresh interval, so almost any sample holds
	// an expired one.
	evictSample = 8
)

// RouteUpstreams is the upstream source. All four strings are required.
type RouteUpstreams struct {
	// Name is the name to look up, with placeholders: "{http.request.host}.".
	Name string `json:"name,omitempty"`
	// Port is the upstream port, with placeholders: "{sbport}".
	Port string `json:"port,omitempty"`
	// Resolver is the route responder's UDP host:port.
	Resolver string `json:"resolver,omitempty"`
	// Fallback is the dial address for a host the responder does not
	// answer (NXDOMAIN, or no A record): the sandboxd router.
	Fallback string `json:"fallback,omitempty"`
	// Refresh is how long an answer, found or not, is reused. Default 1s:
	// a moved sandbox is routed to its new address within about a second.
	Refresh caddy.Duration `json:"refresh,omitempty"`
	// MaxEntries caps the cache. Default 16384, about 4 MiB when full.
	MaxEntries int `json:"max_entries,omitempty"`

	cache  *routeCache
	client *dns.Client
	sem    chan struct{}
}

// CaddyModule returns the Caddy module information.
func (RouteUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: SourceModuleID, New: func() caddy.Module { return new(RouteUpstreams) }}
}

// Provision checks the config and sets up the cache.
func (ru *RouteUpstreams) Provision(caddy.Context) error {
	if ru.Name == "" || ru.Port == "" || ru.Resolver == "" || ru.Fallback == "" {
		return errors.New(SourceName + ": name, port, resolver and fallback are required")
	}
	for field, addr := range map[string]string{"resolver": ru.Resolver, "fallback": ru.Fallback} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s: %s %q: %w", SourceName, field, addr, err)
		}
	}
	if ru.Refresh <= 0 {
		ru.Refresh = caddy.Duration(defaultRefresh)
	}
	if ru.MaxEntries <= 0 {
		ru.MaxEntries = defaultMaxEntries
	}
	ru.client = &dns.Client{Net: "udp", Timeout: lookupTimeout}
	ru.sem = make(chan struct{}, maxLookups)
	ru.cache = newRouteCache(ru.MaxEntries, time.Duration(ru.Refresh), time.Now)
	liveCaches.add(ru.cache)
	return nil
}

// Cleanup drops the cache from the admin counters.
func (ru *RouteUpstreams) Cleanup() error {
	liveCaches.remove(ru.cache)
	return nil
}

// GetUpstreams returns the one upstream for the request's host.
func (ru *RouteUpstreams) GetUpstreams(r *http.Request) ([]*reverseproxy.Upstream, error) {
	name, port := ru.Name, ru.Port
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		name, port = repl.ReplaceAll(name, ""), repl.ReplaceAll(port, "")
	}
	name = dns.Fqdn(strings.ToLower(name))
	if _, ok := dns.IsDomainName(name); !ok {
		// A name DNS cannot carry (a label over 63 bytes, a name over 255):
		// the query would fail to encode, and every such request would be an
		// error line. No host the responder knows looks like that. Not
		// cached: junk Host headers would only push real hosts out.
		counters.notFound.Add(1)
		return upstream(ru.Fallback), nil
	}
	dial, err := ru.cache.get(r.Context(), name+" "+port, func() (string, error) { return ru.lookup(name, port) })
	if err != nil {
		return nil, err
	}
	return upstream(dial), nil
}

func upstream(dial string) []*reverseproxy.Upstream {
	return []*reverseproxy.Upstream{{Dial: dial}}
}

// lookup asks the responder for name's A record. A host it does not answer
// (NXDOMAIN, or NOERROR with no A record) is not an error: the responder
// means "take the router", so lookup returns the fallback.
func (ru *RouteUpstreams) lookup(name, port string) (string, error) {
	// Not the request's context: callers waiting on this lookup share it,
	// and the first caller's client going away must not fail theirs.
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	select {
	case ru.sem <- struct{}{}:
		defer func() { <-ru.sem }()
	case <-ctx.Done():
		counters.errors.Add(1)
		return "", fmt.Errorf("%s: look up %s: %d lookups already in flight", SourceName, name, maxLookups)
	}
	counters.lookups.Add(1)
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	q.RecursionDesired = false
	resp, _, err := ru.client.ExchangeContext(ctx, q, ru.Resolver)
	if err != nil {
		counters.errors.Add(1)
		return "", fmt.Errorf("%s: look up %s: %w", SourceName, name, err)
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				return net.JoinHostPort(a.A.String(), port), nil
			}
		}
	case dns.RcodeNameError:
	default:
		counters.errors.Add(1)
		return "", fmt.Errorf("%s: look up %s: %s", SourceName, name, dns.RcodeToString[resp.Rcode])
	}
	counters.notFound.Add(1)
	return ru.Fallback, nil
}

// routeCache maps "name port" to a dial address.
type routeCache struct {
	shards   [cacheShards]cacheShard
	perShard int
	ttl      time.Duration
	now      func() time.Time
	seed     maphash.Seed
}

type cacheShard struct {
	mu sync.Mutex
	m  map[string]*cacheEntry
}

type cacheEntry struct {
	done    chan struct{} // closed once the lookup has set dial, err and expires
	dial    string
	err     error
	expires time.Time
}

func (e *cacheEntry) finished() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

func newRouteCache(maxEntries int, ttl time.Duration, now func() time.Time) *routeCache {
	c := &routeCache{perShard: max(1, maxEntries/cacheShards), ttl: ttl, now: now, seed: maphash.MakeSeed()}
	for i := range c.shards {
		c.shards[i].m = make(map[string]*cacheEntry)
	}
	return c
}

// get returns key's dial address. Callers that miss on the same key at the
// same time share one lookup. A failed lookup goes to those callers and is
// not cached, so the next request asks again.
func (c *routeCache) get(ctx context.Context, key string, lookup func() (string, error)) (string, error) {
	sh := &c.shards[maphash.String(c.seed, key)%cacheShards]
	sh.mu.Lock()
	if e, ok := sh.m[key]; ok {
		if !e.finished() {
			sh.mu.Unlock()
			select {
			case <-e.done:
				return e.dial, e.err
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		if c.now().Before(e.expires) {
			sh.mu.Unlock()
			counters.hits.Add(1)
			return e.dial, nil
		}
	} else {
		sh.makeRoomLocked(c.perShard, c.now())
	}
	e := &cacheEntry{done: make(chan struct{})}
	sh.m[key] = e
	sh.mu.Unlock()

	dial, err := lookup()

	sh.mu.Lock()
	e.dial, e.err, e.expires = dial, err, c.now().Add(c.ttl)
	if err != nil && sh.m[key] == e {
		delete(sh.m, key)
	}
	close(e.done)
	sh.mu.Unlock()
	return dial, err
}

// makeRoomLocked drops one entry from a full shard: of the first few
// finished entries the map's random order yields, the first expired one, or
// else the one that expires soonest. In-flight entries stay: their callers
// are waiting on them.
func (sh *cacheShard) makeRoomLocked(limit int, now time.Time) {
	if len(sh.m) < limit {
		return
	}
	var victim *cacheEntry
	var victimKey string
	seen := 0
	for k, e := range sh.m {
		if !e.finished() {
			continue
		}
		if victim == nil || e.expires.Before(victim.expires) {
			victim, victimKey = e, k
		}
		if seen++; seen == evictSample || !victim.expires.After(now) {
			break
		}
	}
	if victim != nil {
		delete(sh.m, victimKey)
	}
}

func (c *routeCache) len() int {
	n := 0
	for i := range c.shards {
		sh := &c.shards[i]
		sh.mu.Lock()
		n += len(sh.m)
		sh.mu.Unlock()
	}
	return n
}

// counters are process-wide, like Caddy's own: they survive config reloads.
var counters struct {
	hits, lookups, notFound, errors atomic.Int64
}

// liveCaches is every provisioned source's cache, for the entry count. A
// config reload provisions the new route before it cleans up the old one,
// so for a moment there are two.
var liveCaches cacheSet

type cacheSet struct {
	mu  sync.Mutex
	set map[*routeCache]struct{}
}

func (s *cacheSet) add(c *routeCache) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set == nil {
		s.set = make(map[*routeCache]struct{})
	}
	s.set[c] = struct{}{}
}

func (s *cacheSet) remove(c *routeCache) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.set, c)
}

func (s *cacheSet) entries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for c := range s.set {
		n += c.len()
	}
	return n
}

// adminRoute is admin.api.aerolvm_route. Caddy loads every admin.api module
// on its own, so a 200 on AdminPath means this Caddy has the source, and a
// stock Caddy answers 404. The body is the cache counters.
type adminRoute struct{}

// CaddyModule returns the Caddy module information.
func (adminRoute) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: AdminModuleID, New: func() caddy.Module { return new(adminRoute) }}
}

// Routes returns the admin endpoint.
func (adminRoute) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{{Pattern: AdminPath, Handler: caddy.AdminHandlerFunc(serveStatus)}}
}

type status struct {
	Entries  int   `json:"entries"`
	Hits     int64 `json:"hits"`
	Lookups  int64 `json:"lookups"`
	NotFound int64 `json:"not_found"`
	Errors   int64 `json:"errors"`
}

func serveStatus(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: errors.New("method not allowed")}
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(status{
		Entries:  liveCaches.entries(),
		Hits:     counters.hits.Load(),
		Lookups:  counters.lookups.Load(),
		NotFound: counters.notFound.Load(),
		Errors:   counters.errors.Load(),
	})
}

var (
	_ caddy.Provisioner           = (*RouteUpstreams)(nil)
	_ caddy.CleanerUpper          = (*RouteUpstreams)(nil)
	_ reverseproxy.UpstreamSource = (*RouteUpstreams)(nil)
	_ caddy.AdminRouter           = adminRoute{}
)
