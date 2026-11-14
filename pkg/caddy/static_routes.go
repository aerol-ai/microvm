package caddy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Static routes for routing without per-sandbox Caddy writes
// (plans/ingress-proxy-routing.md §3.1, task T4). They are installed once at
// boot, idempotently. Per-sandbox route changes then never touch Caddy config
// again, so nothing reloads it and drops connections.
//
// Owner http app (srv): ONE route, at the head of the route list.
//
//	match: any host but the apex
//	map {http.request.host} → {sbport}   (SandboxPortHostRegexp; default = toolbox port)
//	reverse_proxy dynamic A name={http.request.host}. port={sbport} resolver=route responder
//	              static upstream = sandboxd router  (used when the responder says NXDOMAIN)
//	              lookup = AerolVM's Caddy plugin when Caddy has it (staticRouteSource)
//
// Ingress tls-mux: three routes ahead of the fallback.
//
//	0 local_ip LocalIP/32 → fallback   breaks the self-dial loop (see below)
//	1 sni apex            → fallback   the API never goes through the responder
//	2 tls (any SNI)       → dial {l4.tls.server_name}.rt.internal:443
//
// The loop: tls-mux listens on ":443", every address. When the responder
// answers LocalIP (owner == self, or an unroutable platform host), the
// dial lands on tls-mux AGAIN. Route 0 matches that second pass by its
// local address and hands it to the http app, which terminates with the
// wildcard cert. External clients never arrive on a loopback local address.
// Spike-verified with the production build.

const (
	StaticSandboxRouteID  = "sandbox-ingress-proxy"
	StaticLoopbackRouteID = "sandbox-local-loopback"
	StaticApexSNIRouteID  = "sandbox-apex-sni"
	StaticSNIRouteID      = "sandbox-sni-route"

	// RouteDNSZone is appended to the SNI for the ingress dial. The node's
	// resolver routes this domain, and only this domain, to the responder.
	RouteDNSZone = "rt.internal"
)

// SandboxPortHostRegexp is the ONE rule for "which port does this Host
// dial": {id}-{port}.{domain} → port, else the toolbox port. The static map
// uses it here; the route responder uses it to refuse an answer Caddy would
// dial on the wrong port.
const SandboxPortHostRegexp = `^[^.]+-([0-9]+)\.`

// StaticRouteSpec configures the static routes.
type StaticRouteSpec struct {
	RouteDNSAddr string // route responder (loopback), e.g. 127.0.0.1:53053
	RouterAddr   string // sandboxd router (loopback), e.g. 127.0.0.1:21213
	ToolboxPort  int
	LocalIP      string // ingress self-dial marker, e.g. 127.0.0.1
	// RouteUpstream: this Caddy has AerolVM's upstream plugin
	// (HasRouteUpstream). The owner route then looks up with it, not with
	// Caddy's stock "a" source.
	RouteUpstream bool
}

// AerolVM's Caddy plugin (caddymod/, built into every release Caddy).
// TestRouteUpstreamMatchesThePlugin checks these against the plugin's
// source, and TestStaticSandboxRouteUsesThePlugin checks the route against
// the config the plugin's own tests load
// (caddymod/testdata/static_route_source.json).
const (
	routeUpstreamSource     = "aerolvm_route"
	routeUpstreamStatusPath = "/aerolvm/route-upstream"
)

// StaticSandboxRoute is the owner http route (see the file comment).
func (c *Client) StaticSandboxRoute(spec StaticRouteSpec) map[string]any {
	return map[string]any{
		"@id":   StaticSandboxRouteID,
		"match": []map[string]any{{"not": []map[string]any{{"host": []string{c.domain}}}}},
		"handle": []map[string]any{
			{
				"handler":      "map",
				"source":       "{http.request.host}",
				"destinations": []string{"{sbport}"},
				"mappings":     []map[string]any{{"input_regexp": SandboxPortHostRegexp, "outputs": []string{"${1}"}}},
				"defaults":     []string{strconv.Itoa(spec.ToolboxPort)},
			},
			{
				"handler":           "reverse_proxy",
				"dynamic_upstreams": staticRouteSource(spec),
				// The router, for every host the responder answers NXDOMAIN:
				// wake, 503, WASM/isolate mediators, masked hosts, unknown
				// hosts. The stock source fails over to it; the plugin returns
				// the router itself, so Caddy takes this only when the
				// plugin's lookup fails.
				"upstreams":          []map[string]any{{"dial": spec.RouterAddr}},
				"flush_interval":     -1,
				"stream_close_delay": streamCloseDelay,
			},
		},
	}
}

// staticRouteSource is the owner route's lookup: the Host, fully qualified
// (trailing dot: no search-domain expansion), as an A record from the route
// responder, re-asked every second, on the map's {sbport}.
//
// Every sandbox request goes through it. Caddy's stock "a" source caches 100
// hosts for the whole process and looks up under one lock, so past 100
// hosts every request is a lookup and they all queue (2.4M lookups/s at 100
// hosts, 4.9k at 1,000). It caches no NXDOMAIN, the responder's answer for
// every host the router serves (WASM/isolate, masked, waking, in flux), and
// logs each one at ERROR. The plugin caches per host with no shared lock,
// caches "not found" too and sends it to the router itself.
//
// The stock source stays for a Caddy without the plugin: install.sh falls
// back to Caddy's build service when the release Caddy cannot be fetched,
// and that service cannot add a private plugin. IPv4 only there: the
// responder answers only A, so the AAAA query doubled the lookups for
// nothing.
func staticRouteSource(spec StaticRouteSpec) map[string]any {
	if spec.RouteUpstream {
		return map[string]any{
			"source":   routeUpstreamSource,
			"name":     "{http.request.host}.",
			"port":     "{sbport}",
			"refresh":  "1s",
			"resolver": spec.RouteDNSAddr,
			"fallback": spec.RouterAddr,
		}
	}
	return map[string]any{
		"source":   "a",
		"name":     "{http.request.host}.",
		"port":     "{sbport}",
		"refresh":  "1s",
		"resolver": map[string]any{"addresses": []string{spec.RouteDNSAddr}},
		"versions": map[string]any{"ipv4": true},
	}
}

// HasRouteUpstream reports whether this Caddy has AerolVM's upstream plugin.
// The plugin's admin module answers routeUpstreamStatusPath and a stock
// Caddy answers 404. It asks with a read, not by trying the route: the route
// goes in with one batched /load, which an unknown module fails whole. The
// read goes straight to Caddy, so it works inside a Batch too. Any failure
// reads as "no": the stock source is slower, never wrong.
func (c *Client) HasRouteUpstream(ctx context.Context) bool {
	if !c.enabled {
		return false
	}
	status, _, err := c.sendDirect(ctx, http.MethodGet, c.baseURL+routeUpstreamStatusPath, nil)
	return err == nil && status == http.StatusOK
}

// StaticIngressRoutes are the tls-mux routes, in order (see the file comment).
// Routes 0 and 1 hand the connection to the same HTTPS site the tls-mux
// fallback does, so they send the same PROXY header when the flag is on:
// route 1 carries every API request on an ingress-proxy-routing node.
func (c *Client) StaticIngressRoutes(spec StaticRouteSpec) []map[string]any {
	fallback := func() []map[string]any {
		return []map[string]any{tlsFallbackProxy(c.l4TLSFallback, c.l4FallbackProxyProtocol)}
	}
	return []map[string]any{
		{
			"@id":    StaticLoopbackRouteID,
			"match":  []map[string]any{{"local_ip": map[string]any{"ranges": []string{spec.LocalIP + "/32"}}}},
			"handle": fallback(),
		},
		{
			"@id":    StaticApexSNIRouteID,
			"match":  []map[string]any{{"tls": map[string]any{"sni": []string{c.domain}}}},
			"handle": fallback(),
		},
		{
			"@id":   StaticSNIRouteID,
			"match": []map[string]any{{"tls": map[string]any{}}},
			"handle": []map[string]any{{
				"handler":   "proxy",
				"upstreams": []map[string]any{{"dial": []string{"{l4.tls.server_name}." + RouteDNSZone + ":443"}}},
			}},
		},
	}
}

// EnsureStaticSandboxRoute installs or refreshes the owner route. It is a
// PATCH when the route exists, and otherwise an insert at index 0, where
// per-sandbox routes always went. Its matcher excludes the apex, so the API
// keeps working regardless of order.
//
// WHY index 0 and not "before the catch-all": the Caddyfile's sandbox
// catch-all is a *.<domain> site route ("Sandbox not found") with a host
// matcher, not a matcher-less route. Inserted after it, the static route
// never matched, and every sandbox URL on a live cluster answered 404.
//
// One admin write, at boot.
func (c *Client) EnsureStaticSandboxRoute(ctx context.Context, spec StaticRouteSpec) error {
	if !c.enabled {
		return nil
	}
	if c.domain == "" {
		return fmt.Errorf("static sandbox route needs domain mode")
	}
	route := c.StaticSandboxRoute(spec)
	routesPath := fmt.Sprintf("/config/apps/http/servers/%s/routes", c.serverID)
	return c.ensureRouteAt(ctx, StaticSandboxRouteID, routesPath, route, func([]map[string]any) int { return 0 })
}

// EnsureStaticIngressRoutes installs the three tls-mux routes at the head of
// tls-mux, in order. EnsureLayer4 must have created tls-mux.
func (c *Client) EnsureStaticIngressRoutes(ctx context.Context, spec StaticRouteSpec) error {
	if !c.enabled {
		return nil
	}
	if c.domain == "" || c.l4TLSListen == "" {
		return fmt.Errorf("static ingress routes need domain mode and the tls-mux listener")
	}
	routesPath := fmt.Sprintf("/config/apps/layer4/servers/%s/routes", tlsMuxServerID)
	for i, route := range c.StaticIngressRoutes(spec) {
		pos := i
		if err := c.ensureRouteAt(ctx, route["@id"].(string), routesPath, route, func([]map[string]any) int { return pos }); err != nil {
			return err
		}
	}
	return nil
}

// RemoveStaticRoutes deletes every static route, for flag-off rollback. A
// route that is already gone is fine.
func (c *Client) RemoveStaticRoutes(ctx context.Context) error {
	if !c.enabled {
		return nil
	}
	for _, id := range []string{StaticSandboxRouteID, StaticSNIRouteID, StaticApexSNIRouteID, StaticLoopbackRouteID} {
		status, err := c.sendJSON(ctx, http.MethodDelete, c.baseURL+"/id/"+id, nil)
		if err != nil {
			return err
		}
		if status >= 400 && status != http.StatusNotFound {
			return fmt.Errorf("delete static route %s failed: %d", id, status)
		}
	}
	return nil
}

// ensureRouteAt PATCHes /id/{id} if present, and otherwise inserts at
// position(pos) in the route list. The index is computed from a GET of the
// list, so the whole sequence holds the admin lock: an insert by another
// writer in between would shift the list under the computed index.
func (c *Client) ensureRouteAt(ctx context.Context, id, routesPath string, route map[string]any, position func([]map[string]any) int) error {
	body, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("marshal static route %s: %w", id, err)
	}
	return c.withAdminLock(ctx, func(ctx context.Context) error {
		return c.ensureRouteAtLocked(ctx, id, routesPath, body, position)
	})
}

func (c *Client) ensureRouteAtLocked(ctx context.Context, id, routesPath string, body []byte, position func([]map[string]any) int) error {
	status, err := c.sendJSON(ctx, http.MethodPatch, c.baseURL+"/id/"+id, body)
	if err != nil {
		return err
	}
	if status < 400 {
		return nil
	}
	if status != http.StatusNotFound {
		return fmt.Errorf("patch static route %s failed: %d", id, status)
	}
	routes, err := c.getRouteList(ctx, routesPath)
	if err != nil {
		return err
	}
	idx := min(position(routes), len(routes))
	status, err = c.sendJSON(ctx, http.MethodPut, fmt.Sprintf("%s%s/%d", c.baseURL, routesPath, idx), body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("insert static route %s at %d failed: %d", id, idx, status)
	}
	return nil
}

func (c *Client) getRouteList(ctx context.Context, path string) ([]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("get %s failed: %d", path, resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return nil, nil
	}
	var routes []map[string]any
	if err := json.Unmarshal(raw, &routes); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return routes, nil
}

// IsStaticRouteID reports the static routes' ids. They share the "sandbox-"
// prefix with per-sandbox routes, so anything that sweeps that prefix
// (Snapshot, reconcile GC, PruneDynamicRoutes) must skip them.
func IsStaticRouteID(id string) bool {
	switch id {
	case StaticSandboxRouteID, StaticLoopbackRouteID, StaticApexSNIRouteID, StaticSNIRouteID:
		return true
	}
	return false
}

// PruneDynamicRoutes deletes what the static routes replace (plan §4):
//   - every per-sandbox http route;
//   - every ingress "-ingress-sni" passthrough route in tls-mux;
//   - every tcp-port-* layer4 server (raw TCP moves to kernel forwarding).
//
// The owner's protocol=tls SNI routes stay: they are still Caddy-written
// (a rare write per expose, plan §3). Call it inside Batch so the whole
// prune is one load. It reports how many entries it removed.
func (c *Client) PruneDynamicRoutes(ctx context.Context) (int, error) {
	if !c.enabled {
		return 0, nil
	}
	snap, err := c.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, id := range snap.HTTPRouteIDs {
		if err := c.deleteRoute(ctx, id); err != nil {
			return removed, err
		}
		removed++
	}
	for _, id := range snap.L4TLSRouteIDs {
		if !strings.HasSuffix(id, "-ingress-sni") {
			continue
		}
		if err := c.deleteRoute(ctx, id); err != nil {
			return removed, err
		}
		removed++
	}
	for _, id := range snap.L4TCPServerIDs {
		if err := c.DeleteTCPServer(ctx, id); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
