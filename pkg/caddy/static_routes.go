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
}

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
				"handler": "reverse_proxy",
				// Fully qualified (trailing dot): no search-domain expansion.
				"dynamic_upstreams": map[string]any{
					"source":   "a",
					"name":     "{http.request.host}.",
					"port":     "{sbport}",
					"refresh":  "1s",
					"resolver": map[string]any{"addresses": []string{spec.RouteDNSAddr}},
				},
				// Taken whenever the responder answers NXDOMAIN: wake, 503,
				// WASM/isolate mediators, masked hosts, unknown hosts.
				"upstreams":      []map[string]any{{"dial": spec.RouterAddr}},
				"flush_interval": -1,
			},
		},
	}
}

// StaticIngressRoutes are the tls-mux routes, in order (see the file comment).
func (c *Client) StaticIngressRoutes(spec StaticRouteSpec) []map[string]any {
	fallback := func() []map[string]any {
		return []map[string]any{{"handler": "proxy", "upstreams": []map[string]any{{"dial": []string{c.l4TLSFallback}}}}}
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
