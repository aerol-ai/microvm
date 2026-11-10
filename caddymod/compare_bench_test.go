package caddymod

// Benchmarks that compare this source with Caddy's stock "a" source, set up
// the way pkg/caddy's static route sets up each. The numbers in
// docs/src/content/docs/engineering-route-lookup.mdx come from:
//
//	go test -run '^$' -bench 'Lookup$|ThroughCaddy' -benchtime 2s
//
// Both sources run in one binary, against one stub responder, with Caddy's
// logging at INFO into a discard writer, as in production minus the output.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/miekg/dns"
)

const benchCallers = 64

// loadQuietCaddy runs a Caddy config with logging at INFO into a discard
// writer, so a module provisioned from caddy.ActiveContext() logs the way it
// does in production. Outside a loaded config Caddy hands modules a debug
// logger, and the stock source's debug lines would dominate its numbers.
func loadQuietCaddy(b *testing.B, apps map[string]any) {
	b.Helper()
	b.Setenv("XDG_CONFIG_HOME", b.TempDir())
	b.Setenv("XDG_DATA_HOME", b.TempDir())
	cfg := map[string]any{
		"admin":   map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "INFO", "writer": map[string]any{"output": "discard"}}}},
	}
	if apps != nil {
		cfg["apps"] = apps
	}
	raw, _ := json.Marshal(cfg)
	if err := caddy.Load(raw, true); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = caddy.Stop() })
}

// stockSource is Caddy's "a" source as pkg/caddy wrote it before the plugin
// (A and AAAA), or as it writes it now for a Caddy without the plugin
// (ipv4Only).
func stockSource(b *testing.B, resolver string, ipv4Only bool) reverseproxy.UpstreamSource {
	b.Helper()
	au := &reverseproxy.AUpstreams{
		Name: "{http.request.host}.", Port: "{sbport}", Refresh: caddy.Duration(time.Second),
		Resolver: &reverseproxy.UpstreamResolver{Addresses: []string{resolver}},
	}
	if ipv4Only {
		on := true
		au.Versions = &reverseproxy.IPVersions{IPv4: &on}
	}
	if err := au.Provision(caddy.ActiveContext()); err != nil {
		b.Fatal(err)
	}
	return au
}

func hostList(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%05d-3000.example.test", prefix, i)
	}
	return out
}

// latencies collects per-call times from every caller.
type latencies struct {
	mu  sync.Mutex
	all []time.Duration
}

func (l *latencies) add(d []time.Duration) {
	l.mu.Lock()
	l.all = append(l.all, d...)
	l.mu.Unlock()
}

func (l *latencies) report(b *testing.B, elapsed time.Duration, unit string) {
	slices.Sort(l.all)
	pct := func(p float64) float64 {
		return float64(l.all[int(float64(len(l.all)-1)*p)]) / float64(time.Microsecond)
	}
	b.ReportMetric(float64(len(l.all))/elapsed.Seconds(), unit+"/s")
	b.ReportMetric(pct(0.50), "p50-µs")
	b.ReportMetric(pct(0.99), "p99-µs")
}

// runCallers splits b.N calls over benchCallers goroutines, each picking a
// random host, and reports calls per second and the p50 and p99 call time.
func runCallers(b *testing.B, hosts []string, unit string, call func(host string) error) {
	b.Helper()
	var lat latencies
	var wg sync.WaitGroup
	b.ResetTimer()
	start := time.Now()
	for w := range benchCallers {
		n := b.N / benchCallers
		if w < b.N%benchCallers {
			n++
		}
		wg.Add(1)
		go func(seed uint64, n int) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed, 42))
			own := make([]time.Duration, 0, n)
			for range n {
				h := hosts[rng.IntN(len(hosts))]
				t0 := time.Now()
				if err := call(h); err != nil {
					b.Error(err)
					return
				}
				own = append(own, time.Since(t0))
			}
			lat.add(own)
		}(uint64(w), n)
	}
	wg.Wait()
	elapsed := time.Since(start)
	b.StopTimer()
	if len(lat.all) > 0 {
		lat.report(b, elapsed, unit)
	}
}

// BenchmarkLookup is the lookup alone: GetUpstreams for a random host, 64
// callers at once, hosts spread evenly (the worst case for a cache).
func BenchmarkLookup(b *testing.B) {
	stub, addr := startResponder(b, nil)
	for i := range 50 {
		stub.set(fmt.Sprintf("nx%05d-3000.example.test.", i), answer{rcode: dns.RcodeNameError})
	}
	stub.set("*", answer{ip: "10.0.0.7"})
	loadQuietCaddy(b, nil)
	ours := newSource(b, addr, 0)
	sources := []struct {
		name string
		src  reverseproxy.UpstreamSource
	}{
		{"stock_a", stockSource(b, addr, false)},
		{"stock_a_ipv4", stockSource(b, addr, true)},
		{"aerolvm_route", ours},
	}
	cases := []struct {
		name  string
		hosts func(prefix string) []string
	}{
		{"hosts=100", func(p string) []string { return hostList(p, 100) }},
		{"hosts=150", func(p string) []string { return hostList(p, 150) }},
		{"hosts=300", func(p string) []string { return hostList(p, 300) }},
		{"hosts=1000", func(p string) []string { return hostList(p, 1000) }},
		{"hosts=5000", func(p string) []string { return hostList(p, 5000) }},
		// The responder's NXDOMAIN hosts: WASM/isolate, waking, in flux.
		{"50ok+50notfound", func(p string) []string { return append(hostList(p, 50), hostList("nx", 50)...) }},
	}
	for si, s := range sources {
		for ci, tc := range cases {
			b.Run(s.name+"/"+tc.name, func(b *testing.B) {
				// A prefix per case: the stock cache is process-wide. Only
				// letters, digits and dashes: Go's resolver refuses others.
				hosts := tc.hosts(fmt.Sprintf("s%d-c%d-", si, ci))
				before := stub.total()
				start := time.Now()
				runCallers(b, hosts, "lookups", func(h string) error {
					_, err := s.src.GetUpstreams(request(context.Background(), h))
					if err != nil && !strings.HasPrefix(h, "nx") {
						return err
					}
					return nil
				})
				b.ReportMetric(float64(stub.total()-before)/time.Since(start).Seconds(), "dns-q/s")
			})
		}
	}
}

// BenchmarkThroughCaddy is whole HTTP requests through a running Caddy: the
// static route's reverse_proxy, with each source, to one backend. Client,
// Caddy, backend and responder share one machine, so compare the two
// sources, not the absolute numbers.
func BenchmarkThroughCaddy(b *testing.B) {
	_, dnsAddr := startResponder(b, map[string]answer{"*": {ip: "127.0.0.1"}})
	backend := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })}
	ln := listenLoopback(b)
	go func() { _ = backend.Serve(ln) }()
	b.Cleanup(func() { _ = backend.Close() })
	backendURL, _ := url.Parse("http://" + ln.Addr().String())
	routerAddr := ln.Addr().String()

	for si, source := range []string{"stock_a", "aerolvm_route"} {
		for _, n := range []int{100, 1000} {
			b.Run(fmt.Sprintf("%s/hosts=%d", source, n), func(b *testing.B) {
				lookup := map[string]any{
					"source": "a", "name": "{http.request.host}.", "port": backendURL.Port(), "refresh": "1s",
					"resolver": map[string]any{"addresses": []string{dnsAddr}},
				}
				if source == "aerolvm_route" {
					lookup = map[string]any{
						"source": SourceName, "name": "{http.request.host}.", "port": backendURL.Port(), "refresh": "1s",
						"resolver": dnsAddr, "fallback": routerAddr,
					}
				}
				httpAddr := freeAddr(b)
				loadQuietCaddy(b, map[string]any{"http": map[string]any{"servers": map[string]any{"srv0": map[string]any{
					"listen":          []string{httpAddr},
					"automatic_https": map[string]any{"disable": true},
					"routes": []any{map[string]any{"handle": []any{map[string]any{
						"handler": "reverse_proxy", "dynamic_upstreams": lookup,
						"upstreams": []any{map[string]any{"dial": routerAddr}},
						// Caddy keeps 32 idle backend connections by default.
						// 64 callers past that open and close one per request,
						// and on a laptop's loopback the ports run out.
						"transport": map[string]any{"protocol": "http", "keep_alive": map[string]any{"max_idle_conns_per_host": 2 * benchCallers}},
					}}}},
				}}}})
				client := &http.Client{Transport: &http.Transport{MaxIdleConns: benchCallers, MaxIdleConnsPerHost: benchCallers}}
				b.Cleanup(client.CloseIdleConnections)
				hosts := hostList(fmt.Sprintf("e%d-n%d-", si, n), n)
				runCallers(b, hosts, "requests", func(h string) error {
					req, _ := http.NewRequest(http.MethodGet, "http://"+httpAddr+"/", nil)
					req.Host = h
					resp, err := client.Do(req)
					if err != nil {
						return err
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("%s: status %d", h, resp.StatusCode)
					}
					return nil
				})
			})
		}
	}
}
