package caddymod

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/logging"
	"github.com/miekg/dns"
)

// answer is how the stub responder answers one name.
type answer struct {
	ip    string        // the A record; empty (and no rcode) is NODATA
	rcode int           // an error rcode instead of an answer
	delay time.Duration // before answering
	drop  bool          // never answer
}

// stubResponder stands in for internal/routedns on loopback. A name it has
// no answer for is NXDOMAIN, as the real responder answers; the "*" entry,
// when set, answers every name instead.
type stubResponder struct {
	mu      sync.Mutex
	zone    map[string]answer
	queries map[string]int
}

func startResponder(t testing.TB, zone map[string]answer) (*stubResponder, string) {
	t.Helper()
	if zone == nil {
		zone = map[string]answer{}
	}
	s := &stubResponder{zone: zone, queries: map[string]int{}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.serve)}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return s, pc.LocalAddr().String()
}

func (s *stubResponder) serve(w dns.ResponseWriter, req *dns.Msg) {
	q := req.Question[0]
	s.mu.Lock()
	s.queries[q.Name]++
	a, ok := s.zone[q.Name]
	if !ok {
		a, ok = s.zone["*"]
	}
	s.mu.Unlock()
	if a.drop {
		return
	}
	time.Sleep(a.delay)
	m := new(dns.Msg)
	m.SetReply(req)
	// Authoritative, as internal/routedns answers. Go's resolver (Caddy's
	// stock source) takes an empty non-authoritative answer, such as the
	// AAAA "no record" reply, for a lame referral and asks again, up to
	// four times: a stub without this made the stock source look slower
	// than it is against the real responder.
	m.Authoritative = true
	switch {
	case !ok:
		m.Rcode = dns.RcodeNameError
	case a.rcode != 0:
		m.Rcode = a.rcode
	case a.ip != "" && q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
			A:   net.ParseIP(a.ip),
		})
	}
	_ = w.WriteMsg(m)
}

func (s *stubResponder) set(name string, a answer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zone[name] = a
}

func (s *stubResponder) count(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries[name]
}

func (s *stubResponder) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.queries {
		n += c
	}
	return n
}

const testFallback = "127.0.0.1:21213"

func newSource(t testing.TB, resolver string, maxEntries int) *RouteUpstreams {
	t.Helper()
	ru := &RouteUpstreams{Name: "{http.request.host}.", Port: "{sbport}", Resolver: resolver, Fallback: testFallback, MaxEntries: maxEntries}
	if err := ru.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ru.Cleanup() })
	return ru
}

// request carries the host and port the way the static route does: in
// placeholders, set by Caddy and by the route's map handler.
func request(ctx context.Context, host string) *http.Request {
	repl := caddy.NewReplacer()
	repl.Set("http.request.host", host)
	repl.Set("sbport", "3000")
	r, _ := http.NewRequestWithContext(context.WithValue(ctx, caddy.ReplacerCtxKey, repl), http.MethodGet, "http://upstream.invalid/", nil)
	return r
}

func dialOf(ru *RouteUpstreams, host string) (string, error) {
	ups, err := ru.GetUpstreams(request(context.Background(), host))
	if err != nil {
		return "", err
	}
	if len(ups) != 1 {
		return "", fmt.Errorf("%d upstreams, want 1", len(ups))
	}
	return ups[0].Dial, nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Each case asks twice: the second ask shows whether the first was cached.
func TestGetUpstreams(t *testing.T) {
	cases := []struct {
		name, host string
		want       string // dial address; empty means an error
		queries    int    // queries for the host's lower-case name, after both asks
	}{
		{"an answered host dials its address", "sb1.example.test", "10.0.0.7:3000", 1},
		{"a mixed-case host is the same host", "SB1.Example.TEST", "10.0.0.7:3000", 1},
		{"NXDOMAIN takes the router, cached", "wasm.example.test", testFallback, 1},
		{"no A record takes the router, cached", "nodata.example.test", testFallback, 1},
		{"SERVFAIL is an error, not cached", "broken.example.test", "", 2},
		{"a name DNS cannot carry takes the router with no lookup", strings.Repeat("x", 64) + ".example.test", testFallback, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub, addr := startResponder(t, map[string]answer{
				"sb1.example.test.":    {ip: "10.0.0.7"},
				"nodata.example.test.": {},
				"broken.example.test.": {rcode: dns.RcodeServerFailure},
			})
			ru := newSource(t, addr, 0)
			for i := range 2 {
				got, err := dialOf(ru, tc.host)
				if tc.want == "" {
					if err == nil {
						t.Fatalf("ask %d: got %q, want an error", i, got)
					}
					continue
				}
				if err != nil || got != tc.want {
					t.Fatalf("ask %d: got %q, %v; want %q", i, got, err, tc.want)
				}
			}
			name := dns.Fqdn(strings.ToLower(tc.host))
			if tc.queries == 0 {
				if n := stub.total(); n != 0 {
					t.Fatalf("%d queries, want none", n)
				}
			} else if n := stub.count(name); n != tc.queries {
				t.Fatalf("%d queries for %s, want %d", n, name, tc.queries)
			}
		})
	}
}

// A moved sandbox, and one that becomes ready, are routed by the next lookup
// after one refresh, never sooner and never later.
func TestAnswersLastOneRefresh(t *testing.T) {
	stub, addr := startResponder(t, map[string]answer{"sb1.example.test.": {ip: "10.0.0.7"}})
	ru := newSource(t, addr, 0)
	now := time.Unix(1_000_000, 0)
	ru.cache.now = func() time.Time { return now }
	step := func(want string) {
		t.Helper()
		if got, err := dialOf(ru, "sb1.example.test"); err != nil || got != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	}
	step("10.0.0.7:3000")
	stub.set("sb1.example.test.", answer{ip: "10.0.0.8"})
	now = now.Add(999 * time.Millisecond)
	step("10.0.0.7:3000")
	now = now.Add(time.Millisecond)
	step("10.0.0.8:3000")

	// Not found is cached the same way: a waking sandbox gets the router
	// until the refresh, then its own address.
	stub.set("sb1.example.test.", answer{rcode: dns.RcodeNameError})
	now = now.Add(time.Second)
	step(testFallback)
	stub.set("sb1.example.test.", answer{ip: "10.0.0.9"})
	step(testFallback)
	now = now.Add(time.Second)
	step("10.0.0.9:3000")
	if n := stub.count("sb1.example.test."); n != 4 {
		t.Fatalf("%d queries, want 4 (one per refresh)", n)
	}
}

func TestOneLookupPerHostAtATime(t *testing.T) {
	stub, addr := startResponder(t, map[string]answer{"slow.example.test.": {ip: "10.0.0.7", delay: 200 * time.Millisecond}})
	ru := newSource(t, addr, 0)
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := dialOf(ru, "slow.example.test"); err != nil || got != "10.0.0.7:3000" {
				errs <- fmt.Errorf("got %q, %v", got, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := stub.count("slow.example.test."); n != 1 {
		t.Fatalf("%d lookups for one host, want 1", n)
	}
}

// Regression for the stock source: it held one process-wide lock across
// every lookup, so a slow lookup for one host held up all the others.
func TestSlowHostDoesNotHoldUpOthers(t *testing.T) {
	stub, addr := startResponder(t, map[string]answer{
		"slow.example.test.": {ip: "10.0.0.7", delay: 600 * time.Millisecond},
		"fast.example.test.": {ip: "10.0.0.8"},
	})
	ru := newSource(t, addr, 0)
	slow := make(chan struct{})
	go func() {
		defer close(slow)
		_, _ = dialOf(ru, "slow.example.test")
	}()
	waitFor(t, "the slow lookup", func() bool { return stub.count("slow.example.test.") == 1 })
	start := time.Now()
	if got, err := dialOf(ru, "fast.example.test"); err != nil || got != "10.0.0.8:3000" {
		t.Fatalf("got %q, %v", got, err)
	}
	if waited := time.Since(start); waited > 300*time.Millisecond {
		t.Fatalf("the fast host waited %v behind the slow one", waited)
	}
	<-slow
}

func TestUnansweredLookupFailsWithinTheTimeout(t *testing.T) {
	old := lookupTimeout
	lookupTimeout = 100 * time.Millisecond
	t.Cleanup(func() { lookupTimeout = old })
	_, addr := startResponder(t, map[string]answer{"gone.example.test.": {drop: true}})
	ru := newSource(t, addr, 0)
	start := time.Now()
	if got, err := dialOf(ru, "gone.example.test"); err == nil {
		t.Fatalf("got %q, want an error", got)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("took %v, want about the 100ms timeout", took)
	}
}

// A request that waits on another request's lookup stops with its own
// context, and the lookup still finishes for the caller that started it.
func TestWaiterStopsWithItsRequest(t *testing.T) {
	stub, addr := startResponder(t, map[string]answer{"slow.example.test.": {ip: "10.0.0.7", delay: 300 * time.Millisecond}})
	ru := newSource(t, addr, 0)
	first := make(chan error, 1)
	go func() {
		got, err := dialOf(ru, "slow.example.test")
		if err == nil && got != "10.0.0.7:3000" {
			err = fmt.Errorf("got %q", got)
		}
		first <- err
	}()
	waitFor(t, "the first lookup", func() bool { return stub.count("slow.example.test.") == 1 })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ru.GetUpstreams(request(ctx, "slow.example.test")); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter got %v, want context.Canceled", err)
	}
	if err := <-first; err != nil {
		t.Fatalf("first caller: %v", err)
	}
}

func TestCacheStaysWithinMaxEntries(t *testing.T) {
	_, addr := startResponder(t, nil) // every name is NXDOMAIN, as for a scanner
	ru := newSource(t, addr, 640)
	for i := range 3000 {
		if _, err := dialOf(ru, fmt.Sprintf("h%d.example.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := ru.cache.len(); n == 0 || n > 640 {
		t.Fatalf("cache holds %d entries, want 1..640", n)
	}
}

func TestMakeRoom(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	done := func(exp time.Duration) *cacheEntry {
		e := &cacheEntry{done: make(chan struct{}), expires: now.Add(exp)}
		close(e.done)
		return e
	}
	inFlight := func() *cacheEntry { return &cacheEntry{done: make(chan struct{})} }
	cases := []struct {
		name    string
		limit   int
		entries map[string]*cacheEntry
		gone    string // the key dropped; empty means none
	}{
		{"an expired entry goes first", 3, map[string]*cacheEntry{"a": done(time.Second), "b": done(-time.Second), "c": done(2 * time.Second)}, "b"},
		{"else the soonest to expire", 3, map[string]*cacheEntry{"a": done(3 * time.Second), "b": done(time.Second), "c": done(2 * time.Second)}, "b"},
		{"in-flight entries stay", 2, map[string]*cacheEntry{"a": inFlight(), "b": inFlight()}, ""},
		{"below the limit nothing goes", 4, map[string]*cacheEntry{"a": done(-time.Second), "b": done(time.Second)}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sh := &cacheShard{m: tc.entries}
			before := len(sh.m)
			sh.makeRoomLocked(tc.limit, now)
			if tc.gone == "" {
				if len(sh.m) != before {
					t.Fatalf("dropped an entry: %d left of %d", len(sh.m), before)
				}
				return
			}
			if _, ok := sh.m[tc.gone]; ok || len(sh.m) != before-1 {
				t.Fatalf("want only %q dropped, left %v", tc.gone, keys(sh.m))
			}
		})
	}
}

func keys(m map[string]*cacheEntry) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestProvision(t *testing.T) {
	full := func() RouteUpstreams {
		return RouteUpstreams{Name: "{http.request.host}.", Port: "{sbport}", Resolver: "127.0.0.1:53053", Fallback: testFallback}
	}
	cases := []struct {
		name   string
		change func(*RouteUpstreams)
	}{
		{"no name", func(r *RouteUpstreams) { r.Name = "" }},
		{"no port", func(r *RouteUpstreams) { r.Port = "" }},
		{"no resolver", func(r *RouteUpstreams) { r.Resolver = "" }},
		{"no fallback", func(r *RouteUpstreams) { r.Fallback = "" }},
		{"a resolver with no port", func(r *RouteUpstreams) { r.Resolver = "127.0.0.1" }},
		{"a fallback with no port", func(r *RouteUpstreams) { r.Fallback = "127.0.0.1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ru := full()
			tc.change(&ru)
			if err := ru.Provision(caddy.Context{}); err == nil {
				_ = ru.Cleanup()
				t.Fatal("provisioned, want an error")
			}
		})
	}
	ru := full()
	if err := ru.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	defer ru.Cleanup()
	if time.Duration(ru.Refresh) != time.Second || ru.MaxEntries != defaultMaxEntries {
		t.Fatalf("defaults: refresh %v, max entries %d", time.Duration(ru.Refresh), ru.MaxEntries)
	}
}

func readStatus(t *testing.T) status {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := serveStatus(rec, httptest.NewRequest(http.MethodGet, AdminPath, nil)); err != nil {
		t.Fatal(err)
	}
	var s status
	if err := json.NewDecoder(rec.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAdminStatus(t *testing.T) {
	_, addr := startResponder(t, map[string]answer{"sb1.example.test.": {ip: "10.0.0.7"}})
	ru := newSource(t, addr, 0)
	before := readStatus(t)
	for _, host := range []string{"sb1.example.test", "sb1.example.test", "wasm.example.test"} {
		if _, err := dialOf(ru, host); err != nil {
			t.Fatal(err)
		}
	}
	after := readStatus(t)
	got := status{
		Entries:  after.Entries,
		Hits:     after.Hits - before.Hits,
		Lookups:  after.Lookups - before.Lookups,
		NotFound: after.NotFound - before.NotFound,
		Errors:   after.Errors - before.Errors,
	}
	if want := (status{Entries: 2, Hits: 1, Lookups: 2, NotFound: 1}); got != want {
		t.Fatalf("status %+v, want %+v", got, want)
	}
	_ = ru.Cleanup()
	if n := readStatus(t).Entries; n != 0 {
		t.Fatalf("%d entries after cleanup, want 0", n)
	}
	var apiErr caddy.APIError
	if err := serveStatus(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, AdminPath, nil)); !errors.As(err, &apiErr) || apiErr.HTTPStatus != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %v, want 405", err)
	}
}

func TestModulesRegistered(t *testing.T) {
	for _, id := range []string{SourceModuleID, AdminModuleID} {
		if _, err := caddy.GetModule(id); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
	if routes := (adminRoute{}).Routes(); len(routes) != 1 || routes[0].Pattern != AdminPath {
		t.Fatalf("admin routes = %+v", routes)
	}
}

// testdata/static_route_source.json is the dynamic_upstreams block sandboxd
// writes (pkg/caddy TestStaticSandboxRouteUsesThePlugin checks its side
// against the same file). Every field must be one this source knows.
func TestSandboxdRouteConfigLoads(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "static_route_source.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["source"]) != `"`+SourceName+`"` {
		t.Fatalf("source = %s, want %q", fields["source"], SourceName)
	}
	delete(fields, "source") // Caddy's module key, not a field
	rest, _ := json.Marshal(fields)
	dec := json.NewDecoder(bytes.NewReader(rest))
	dec.DisallowUnknownFields()
	var ru RouteUpstreams
	if err := dec.Decode(&ru); err != nil {
		t.Fatalf("sandboxd's config does not decode: %v", err)
	}
	if err := ru.Provision(caddy.Context{}); err != nil {
		t.Fatalf("sandboxd's config does not provision: %v", err)
	}
	_ = ru.Cleanup()
}

func listenLoopback(t testing.TB) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func freeAddr(t testing.TB) string {
	t.Helper()
	ln := listenLoopback(t)
	defer ln.Close()
	return ln.Addr().String()
}

func textServer(t *testing.T, body string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
	t.Cleanup(srv.Close)
	return srv
}

// End to end through a real Caddy: the static route's reverse_proxy loads
// this source, a host the responder answers goes to its sandbox, and one it
// does not goes to the router with no error line. A second route on the
// stock "a" source shows what that error line looks like, so the check
// below cannot pass by not looking.
func TestThroughCaddy(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	sandbox := textServer(t, "sandbox")
	router := textServer(t, "router")
	sandboxURL, _ := url.Parse(sandbox.URL)
	routerAddr := strings.TrimPrefix(router.URL, "http://")
	_, dnsAddr := startResponder(t, map[string]answer{"sb1.example.test.": {ip: "127.0.0.1"}})
	adminAddr, httpAddr := freeAddr(t), freeAddr(t)
	logFile := filepath.Join(t.TempDir(), "caddy.log")

	cfg := map[string]any{
		"admin":   map[string]any{"listen": adminAddr, "config": map[string]any{"persist": false}},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"writer": map[string]any{"output": "file", "filename": logFile}}}},
		"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"srv0": map[string]any{
			"listen":          []string{httpAddr},
			"automatic_https": map[string]any{"disable": true},
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{"host": []string{"stock.example.test"}}},
					"handle": []any{map[string]any{
						"handler": "reverse_proxy",
						"dynamic_upstreams": map[string]any{
							"source": "a", "name": "{http.request.host}.", "port": sandboxURL.Port(),
							"refresh": "1s", "resolver": map[string]any{"addresses": []string{dnsAddr}},
						},
						"upstreams": []any{map[string]any{"dial": routerAddr}},
					}},
				},
				map[string]any{
					"handle": []any{map[string]any{
						"handler": "reverse_proxy",
						"dynamic_upstreams": map[string]any{
							"source": SourceName, "name": "{http.request.host}.", "port": sandboxURL.Port(),
							"refresh": "1s", "resolver": dnsAddr, "fallback": routerAddr,
						},
						"upstreams": []any{map[string]any{"dial": routerAddr}},
					}},
				},
			},
		}}}},
	}
	raw, _ := json.Marshal(cfg)
	if err := caddy.Load(raw, true); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			_ = caddy.Stop()
		}
	}
	t.Cleanup(stop)

	get := func(host string) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "http://"+httpAddr+"/", nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	for host, want := range map[string]string{
		"sb1.example.test":   "sandbox",
		"wasm.example.test":  "router",
		"stock.example.test": "router",
	} {
		for range 3 {
			if got := get(host); got != want {
				t.Fatalf("%s answered %q, want %q", host, got, want)
			}
		}
	}

	resp, err := http.Get("http://" + adminAddr + AdminPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s on a Caddy with the plugin: %d, want 200", AdminPath, resp.StatusCode)
	}

	stop() // flushes the log
	logged, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	const failed = "failed getting dynamic upstreams"
	var stockLines, ourLines int
	for _, line := range strings.Split(string(logged), "\n") {
		if !strings.Contains(line, failed) {
			continue
		}
		switch {
		case strings.Contains(line, "stock.example.test"):
			stockLines++
		case strings.Contains(line, ".example.test"):
			ourLines++
		}
	}
	if stockLines == 0 {
		t.Fatalf("the stock source logged no %q line; the check below proves nothing\n%s", failed, logged)
	}
	if ourLines != 0 {
		t.Fatalf("this source logged %d %q lines, want none\n%s", ourLines, failed, logged)
	}
}

// BenchmarkLookup1000Hosts is 1,000 hosts at once: the stock source's cache
// holds 100, so there it is a lookup per request under one lock.
func BenchmarkLookup1000Hosts(b *testing.B) {
	_, addr := startResponder(b, map[string]answer{"*": {ip: "10.0.0.7"}})
	ru := newSource(b, addr, 0)
	hosts := make([]string, 1000)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%04d.example.test", i)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := ru.GetUpstreams(request(context.Background(), hosts[i%len(hosts)])); err != nil {
				b.Error(err)
				return
			}
			i += 7
		}
	})
}
