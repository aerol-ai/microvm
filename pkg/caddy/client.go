package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
)

type Client struct {
	baseURL       string
	serverID      string
	domain        string
	publicHost    string
	enabled       bool
	l4TLSListen   string
	l4TLSFallback string
	httpClient    *http.Client
}

func New(cfg config.Config) *Client {
	return &Client{
		baseURL:  strings.TrimRight(cfg.CaddyAdminURL, "/"),
		serverID: cfg.CaddyServerID,
		domain:   cfg.Domain,
		// In cluster mode an operator points SB_INGRESS_ADVERTISE_HOST at
		// whatever fronts the ingress tier (cloud NLB, MetalLB VIP, wildcard
		// DNS RR, etc.) so SDK-returned URLs resolve there rather than at
		// this specific node. EffectivePublicHost falls back to PublicHost so
		// single-node and pre-cluster deployments stay byte-identical.
		publicHost:    cfg.EffectivePublicHost(),
		enabled:       cfg.EnableCaddy,
		l4TLSListen:   cfg.L4TLSListen,
		l4TLSFallback: cfg.L4TLSFallback,
		// Every admin call rides this client, so the instrumenting transport
		// (pkg/caddy/metrics.go) catches latency + error counters for all of
		// them without per-call-site instrumentation drift.
		httpClient: &http.Client{
			Timeout:   cfg.HTTPClientTimeout,
			Transport: wrapTransport(http.DefaultTransport),
		},
	}
}

// L4TLSListen returns the listen address configured for the shared TLS-SNI
// multiplexer. Empty means TLS-SNI exposure is disabled — the service layer
// should reject protocol="tls" requests and skip EnsureLayer4 of the mux.
func (c *Client) L4TLSListen() string { return c.l4TLSListen }

// L4TLSFallback returns the address caddy-l4 forwards non-sandbox SNI to
// (the regular HTTPS Caddy site that handles the API, on-demand TLS, and the
// 404 catch-all). Meaningful only when L4TLSListen is non-empty.
func (c *Client) L4TLSFallback() string { return c.l4TLSFallback }

// SNIHost is the per-sandbox subdomain caddy-l4 routes by for a TLS exposure.
// Returns empty in IP mode (no domain configured), which the service layer
// uses to detect "TLS not supported in this deployment" without sniffing.
func (c *Client) SNIHost(id string, port int) string {
	if c.domain == "" {
		return ""
	}
	return fmt.Sprintf("%s-%d.%s", id, port, c.domain)
}

func (c *Client) Enabled() bool {
	return c.enabled
}

// PublicHost returns the dial target for raw-TCP exposures. In domain mode the
// base domain is returned so TCP URLs are consistent with HTTP sandbox URLs;
// otherwise falls back to the configured publicHost IP.
func (c *Client) PublicHost() string {
	if c.domain != "" {
		return c.domain
	}
	return c.publicHost
}

func (c *Client) Ping(ctx context.Context) error {
	if !c.enabled {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/config/", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("caddy admin returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) SandboxPublicURL(id string) string {
	if c.domain != "" {
		return fmt.Sprintf("https://%s.%s", id, c.domain)
	}
	return fmt.Sprintf("http://%s/%s/", c.publicHost, id)
}

func (c *Client) PortPublicURL(id string, port int) string {
	if c.domain != "" {
		return fmt.Sprintf("https://%s-%d.%s", id, port, c.domain)
	}
	return fmt.Sprintf("http://%s/%s/proxy/%d/", c.publicHost, id, port)
}

// TCPPublicEndpoint returns the URL clients dial for a raw TCP exposure
// allocated at hostPort. In domain mode the base domain is used as the dial
// target (e.g. tcp://sandbox.aerol.cloud:22534); otherwise falls back to
// publicHost.
func (c *Client) TCPPublicEndpoint(hostPort int) string {
	host := c.publicHost
	if c.domain != "" {
		host = c.domain
	}
	return fmt.Sprintf("tcp://%s:%d", host, hostPort)
}

// TLSPublicEndpoint returns the dial target for a TLS-SNI multiplexed
// exposure. The host portion is the per-sandbox subdomain caddy-l4 uses for
// SNI matching (so the certificate the upstream presents must cover that
// name); the port is the layer4 listener address operators configured. Empty
// l4Listen means TLS-SNI mode is disabled.
func (c *Client) TLSPublicEndpoint(id string, port int, l4Listen string) string {
	if c.domain == "" || l4Listen == "" {
		return ""
	}
	listenPort := strings.TrimPrefix(l4Listen, ":")
	return fmt.Sprintf("tls://%s-%d.%s:%s", id, port, c.domain, listenPort)
}

func (c *Client) UpsertSandboxRoute(ctx context.Context, id, containerIP string, toolboxPort int) error {
	if !c.enabled {
		return nil
	}

	routeID := sandboxRouteID(id)
	route := map[string]any{
		"@id": routeID,
		"handle": []map[string]any{{
			"handler": "reverse_proxy",
			"upstreams": []map[string]string{{
				"dial": fmt.Sprintf("%s:%d", containerIP, toolboxPort),
			}},
		}},
		"terminal": true,
	}

	if c.domain != "" {
		route["match"] = []map[string]any{{"host": []string{fmt.Sprintf("%s.%s", id, c.domain)}}}
	} else {
		route["match"] = []map[string]any{{"path": []string{fmt.Sprintf("/%s", id), fmt.Sprintf("/%s/*", id)}}}
	}

	return c.upsertRoute(ctx, routeID, route)
}

// UpsertSandboxRouteToPeer installs the IP/path-mode ingress route for a
// sandbox owned by another node. Domain-mode clusters use caddy-l4 SNI
// pass-through instead, because the local HTTPS app sits behind the :443
// layer4 mux and remote proxying would require dynamic upstream TLS SNI.
func (c *Client) UpsertSandboxRouteToPeer(ctx context.Context, id, peerHost string) error {
	if !c.enabled || c.domain != "" {
		return nil
	}
	routeID := sandboxRouteID(id)
	route := map[string]any{
		"@id": routeID,
		"match": []map[string]any{{"path": []string{
			fmt.Sprintf("/%s", id),
			fmt.Sprintf("/%s/*", id),
		}}},
		"handle": []map[string]any{{
			"handler": "reverse_proxy",
			"upstreams": []map[string]string{{
				"dial": net.JoinHostPort(peerHost, "80"),
			}},
		}},
		"terminal": true,
	}
	return c.upsertRoute(ctx, routeID, route)
}

func (c *Client) DeleteSandboxRoute(ctx context.Context, id string) error {
	if !c.enabled {
		return nil
	}
	return c.deleteRoute(ctx, sandboxRouteID(id))
}

func (c *Client) UpsertPortRoute(ctx context.Context, id, containerIP string, port int) error {
	if !c.enabled || c.domain == "" {
		return nil
	}

	routeID := portRouteID(id, port)
	route := map[string]any{
		"@id":   routeID,
		"match": []map[string]any{{"host": []string{fmt.Sprintf("%s-%d.%s", id, port, c.domain)}}},
		"handle": []map[string]any{{
			"handler": "reverse_proxy",
			"upstreams": []map[string]string{{
				"dial": fmt.Sprintf("%s:%d", containerIP, port),
			}},
		}},
		"terminal": true,
	}

	return c.upsertRoute(ctx, routeID, route)
}

// UpsertPortRouteToPeer installs the IP/path-mode per-port route for a
// sandbox owned by another node. In domain mode this is handled by SNI
// pass-through routes in the layer4 mux.
func (c *Client) UpsertPortRouteToPeer(ctx context.Context, id string, port int, peerHost string) error {
	if !c.enabled || c.domain != "" {
		return nil
	}
	routeID := portRouteID(id, port)
	route := map[string]any{
		"@id": routeID,
		"match": []map[string]any{{"path": []string{
			fmt.Sprintf("/%s/proxy/%d", id, port),
			fmt.Sprintf("/%s/proxy/%d/*", id, port),
		}}},
		"handle": []map[string]any{{
			"handler": "reverse_proxy",
			"upstreams": []map[string]string{{
				"dial": net.JoinHostPort(peerHost, "80"),
			}},
		}},
		"terminal": true,
	}
	return c.upsertRoute(ctx, routeID, route)
}

func (c *Client) DeletePortRoute(ctx context.Context, id string, port int) error {
	if !c.enabled || c.domain == "" {
		return nil
	}
	return c.deleteRoute(ctx, portRouteID(id, port))
}

// UpsertInFluxSandboxRoute installs an HTTP route for the sandbox's public
// hostname/path that responds with 503 Service Unavailable + Retry-After: 2.
// Used by the cluster-ingress reconciler when a placement is orphaned or
// when the owner's data-plane host hasn't gossiped yet — the alternative is
// the Caddy fallback 404, which clients can't tell apart from "sandbox does
// not exist". The route has its own @id namespace (suffix "-in-flux") so it
// can coexist with a live route during transitions; the reconciler is
// responsible for deleting the live route before installing the in-flux
// route, and vice versa.
//
// In domain mode the L4 SNI mux falls through to the local HTTPS listener
// for any SNI it doesn't recognize, so an HTTP route registered for the
// sandbox hostname captures in-flux traffic without needing a separate L4
// route.
func (c *Client) UpsertInFluxSandboxRoute(ctx context.Context, id string) error {
	if !c.enabled {
		return nil
	}
	routeID := inFluxSandboxRouteID(id)
	route := inFluxRoute(routeID, c.inFluxMatchSandbox(id))
	return c.upsertRoute(ctx, routeID, route)
}

// UpsertInFluxPortRoute mirrors UpsertInFluxSandboxRoute for per-port URLs.
func (c *Client) UpsertInFluxPortRoute(ctx context.Context, id string, port int) error {
	if !c.enabled {
		return nil
	}
	routeID := inFluxPortRouteID(id, port)
	route := inFluxRoute(routeID, c.inFluxMatchPort(id, port))
	return c.upsertRoute(ctx, routeID, route)
}

// DeleteInFluxSandboxRoute drops the in-flux 503 route once the live route
// is back. 404 is treated as success.
func (c *Client) DeleteInFluxSandboxRoute(ctx context.Context, id string) error {
	if !c.enabled {
		return nil
	}
	return c.deleteRoute(ctx, inFluxSandboxRouteID(id))
}

// DeleteInFluxPortRoute mirrors DeleteInFluxSandboxRoute for per-port URLs.
func (c *Client) DeleteInFluxPortRoute(ctx context.Context, id string, port int) error {
	if !c.enabled {
		return nil
	}
	return c.deleteRoute(ctx, inFluxPortRouteID(id, port))
}

// inFluxRoute builds the static-503 handler used by both
// UpsertInFlux*Route helpers.
func inFluxRoute(routeID string, match []map[string]any) map[string]any {
	return map[string]any{
		"@id":   routeID,
		"match": match,
		"handle": []map[string]any{{
			"handler":     "static_response",
			"status_code": 503,
			"headers": map[string][]string{
				"Retry-After":  {"2"},
				"Content-Type": {"text/plain; charset=utf-8"},
			},
			"body": "Sandbox placement in flux. Retry in a moment.\n",
		}},
		"terminal": true,
	}
}

func (c *Client) inFluxMatchSandbox(id string) []map[string]any {
	if c.domain != "" {
		return []map[string]any{{"host": []string{fmt.Sprintf("%s.%s", id, c.domain)}}}
	}
	return []map[string]any{{"path": []string{fmt.Sprintf("/%s", id), fmt.Sprintf("/%s/*", id)}}}
}

func (c *Client) inFluxMatchPort(id string, port int) []map[string]any {
	if c.domain != "" {
		return []map[string]any{{"host": []string{fmt.Sprintf("%s-%d.%s", id, port, c.domain)}}}
	}
	return []map[string]any{{"path": []string{
		fmt.Sprintf("/%s/proxy/%d", id, port),
		fmt.Sprintf("/%s/proxy/%d/*", id, port),
	}}}
}

// upsertRoute writes one route by its @id without touching the rest of the
// routes array. PATCH /id/<routeID> replaces the existing node in place; if
// it doesn't exist yet (404), we insert it at index 0 of the server's routes
// list with PUT so it sits ahead of the fallback "Sandbox not found" route.
// Per-route admin calls keep this O(1) regardless of how many sandboxes exist.
func (c *Client) upsertRoute(ctx context.Context, routeID string, route map[string]any) error {
	body, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("marshal caddy route: %w", err)
	}

	patchURL := fmt.Sprintf("%s/id/%s", c.baseURL, routeID)
	status, err := c.sendJSON(ctx, http.MethodPatch, patchURL, body)
	if err != nil {
		return err
	}
	if status < 400 {
		return nil
	}
	if status != http.StatusNotFound {
		return fmt.Errorf("patch caddy route failed: %d", status)
	}

	// Fresh route: insert at the front of the routes array. PUT to an array
	// index is Caddy's "insert before" — existing entries shift right, so
	// the catch-all fallback (if any) stays at the tail.
	insertURL := fmt.Sprintf("%s/config/apps/http/servers/%s/routes/0", c.baseURL, c.serverID)
	status, err = c.sendJSON(ctx, http.MethodPut, insertURL, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("insert caddy route failed: %d", status)
	}
	return nil
}

// DeleteRouteByID is the zombie-GC entry point: the reconcile sweep finds an
// @id under apps/http or the tls-mux server that doesn't correspond to any
// sandbox row, and calls this to drop it. Wraps the same DELETE /id/<routeID>
// the typed helpers use, so 404 is still treated as success.
func (c *Client) DeleteRouteByID(ctx context.Context, routeID string) error {
	if !c.enabled || routeID == "" {
		return nil
	}
	return c.deleteRoute(ctx, routeID)
}

// DeleteTCPServer drops a layer4 server by its name (e.g. tcp-port-37412).
// Used by reconcile's zombie GC; not tied to a specific sandbox/port pair so
// the caller doesn't have to know which exposure originally owned the port.
func (c *Client) DeleteTCPServer(ctx context.Context, serverID string) error {
	if !c.enabled || serverID == "" {
		return nil
	}
	target := fmt.Sprintf("%s/config/apps/layer4/servers/%s", c.baseURL, serverID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, target, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete l4 server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete l4 server failed: %d", resp.StatusCode)
	}
	return nil
}

// deleteRoute removes one route by @id. 404 is treated as success — the route
// already isn't there, which is the desired post-condition.
func (c *Client) deleteRoute(ctx context.Context, routeID string) error {
	target := fmt.Sprintf("%s/id/%s", c.baseURL, routeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, target, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete caddy route: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete caddy route failed: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) sendJSON(ctx context.Context, method, target string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, target, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func sandboxRouteID(id string) string {
	return "sandbox-" + id
}

func portRouteID(id string, port int) string {
	return fmt.Sprintf("sandbox-%s-port-%d", id, port)
}

func inFluxSandboxRouteID(id string) string {
	return "sandbox-" + id + "-in-flux"
}

func inFluxPortRouteID(id string, port int) string {
	return fmt.Sprintf("sandbox-%s-port-%d-in-flux", id, port)
}

// IDs exposed for the zombie GC to add to its keep-set.
func SandboxRouteID(id string) string              { return sandboxRouteID(id) }
func PortRouteID(id string, port int) string       { return portRouteID(id, port) }
func InFluxSandboxRouteID(id string) string        { return inFluxSandboxRouteID(id) }
func InFluxPortRouteID(id string, port int) string { return inFluxPortRouteID(id, port) }

// Layer4 admin API conventions.
//
// Each raw-TCP exposure gets its own server keyed by tcp-port-<hostPort>,
// listening on :<hostPort> and forwarding the connection to the container's
// IP:port. The route inside also carries a stable @id so reconcile can find
// it without parsing server config.
//
// TLS-SNI multiplexing reuses one shared server (tlsMuxServerID) listening
// on the operator-configured address (typically :443) and routes connections
// by SNI to the matching upstream. Each route here gets an @id so PATCH /id/
// works the same way the HTTP path already does.
const tlsMuxServerID = "tls-mux"

// tlsFallbackRouteID is the @id of the unmatched-SNI route inside tls-mux.
// Tail of the routes array; per-sandbox SNI routes are PUT at routes/0 so
// they always shadow this one. Any SNI we don't recognize — the API host
// itself, on-demand-TLS validation, plain SSL probes — ends up here and
// gets proxied to the local HTTPS listener.
const tlsFallbackRouteID = "tls-mux-fallback"

func tcpServerID(hostPort int) string {
	return fmt.Sprintf("tcp-port-%d", hostPort)
}

func tcpRouteID(id string, port int) string {
	return fmt.Sprintf("sandbox-%s-port-%d-tcp", id, port)
}

func tlsRouteID(id string, port int) string {
	return fmt.Sprintf("sandbox-%s-port-%d-tls", id, port)
}

func ingressSandboxSNIRouteID(id string) string {
	return fmt.Sprintf("sandbox-%s-ingress-sni", id)
}

func ingressPortSNIRouteID(id string, port int) string {
	return fmt.Sprintf("sandbox-%s-port-%d-ingress-sni", id, port)
}

func IngressSandboxSNIRouteID(id string) string {
	return ingressSandboxSNIRouteID(id)
}

func IngressPortSNIRouteID(id string, port int) string {
	return ingressPortSNIRouteID(id, port)
}

// EnsureLayer4 idempotently bootstraps the layer4 app and (when tlsListen is
// non-empty) the shared SNI-mux server. Safe to call on every sandboxd start
// — the admin API treats a no-op POST as 200 and a PATCH on a missing key as
// 404, so we issue a PUT only when the path actually doesn't exist.
//
// Without this bootstrap, the very first UpsertTCPRoute would fail because
// /config/apps/layer4 doesn't exist yet on a fresh Caddy.
//
// When tlsListen is non-empty, tlsFallback must point at the local HTTPS
// listener that owned the same port before caddy-l4 took it over (the API
// site, the on-demand-TLS catch-all, etc.). caddy-l4 routes by SNI for
// sandbox subdomains and forwards the rest of the traffic — including ACME
// HTTP-01 cert validation that piggy-backs on :443 ALPN and any non-sandbox
// hostname — to the fallback. Empty tlsFallback with non-empty tlsListen is
// rejected; the service layer surfaces it as a config error at boot.
func (c *Client) EnsureLayer4(ctx context.Context, tlsListen, tlsFallback string) error {
	if !c.enabled {
		return nil
	}
	if tlsListen != "" && tlsFallback == "" {
		return errors.New("tls fallback required when tls listen is set")
	}

	// Ensure /config/apps/layer4 exists. We only PUT it if it isn't there;
	// otherwise we'd clobber any servers added since last boot.
	exists, err := c.pathExists(ctx, "/config/apps/layer4")
	if err != nil {
		return err
	}
	if !exists {
		body, err := json.Marshal(map[string]any{"servers": map[string]any{}})
		if err != nil {
			return fmt.Errorf("marshal layer4 app: %w", err)
		}
		status, err := c.sendJSON(ctx, http.MethodPut, c.baseURL+"/config/apps/layer4", body)
		if err != nil {
			return err
		}
		if status >= 400 {
			return fmt.Errorf("create layer4 app failed: %d", status)
		}
	}

	// SNI mux server only matters when an operator has configured a listen
	// address. Empty tlsListen leaves caddy alone and the TLS code paths
	// short-circuit at the service layer.
	if tlsListen == "" {
		return nil
	}
	muxPath := fmt.Sprintf("/config/apps/layer4/servers/%s", tlsMuxServerID)
	exists, err = c.pathExists(ctx, muxPath)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	// The fallback route has no match clause and sits at the END of the
	// routes array; per-sandbox SNI routes inserted via UpsertTLSSNIRoute go
	// to routes/0, so they always win over the fallback. Only connections
	// whose SNI doesn't match any sandbox subdomain hit the proxy below.
	server := map[string]any{
		"listen": []string{tlsListen},
		"routes": []any{
			map[string]any{
				"@id": tlsFallbackRouteID,
				"handle": []map[string]any{{
					"handler":   "proxy",
					"upstreams": []map[string]any{{"dial": []string{tlsFallback}}},
				}},
			},
		},
	}
	body, err := json.Marshal(server)
	if err != nil {
		return fmt.Errorf("marshal tls mux server: %w", err)
	}
	status, err := c.sendJSON(ctx, http.MethodPut, c.baseURL+muxPath, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("create tls mux server failed: %d", status)
	}
	return nil
}

// UpsertTCPRoute creates (or replaces) the layer4 server bound to hostPort.
// One server per host-port allocation; PUT replaces the entire server config
// in place, so re-running with a different upstream IP after a sandbox
// restart is the right way to refresh routing without poking at routes/0.
func (c *Client) UpsertTCPRoute(ctx context.Context, id, containerIP string, port, hostPort int) error {
	if !c.enabled {
		return nil
	}
	if hostPort <= 0 {
		return errors.New("host port must be positive")
	}
	server := map[string]any{
		"listen": []string{fmt.Sprintf(":%d", hostPort)},
		"routes": []any{
			map[string]any{
				"@id": tcpRouteID(id, port),
				"handle": []map[string]any{{
					"handler":   "proxy",
					"upstreams": []map[string]any{{"dial": []string{fmt.Sprintf("%s:%d", containerIP, port)}}},
				}},
			},
		},
	}
	body, err := json.Marshal(server)
	if err != nil {
		return fmt.Errorf("marshal tcp server: %w", err)
	}
	target := fmt.Sprintf("%s/config/apps/layer4/servers/%s", c.baseURL, tcpServerID(hostPort))
	status, err := c.sendJSON(ctx, http.MethodPut, target, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("upsert tcp server failed: %d", status)
	}
	return nil
}

// UpsertTCPProxyRoute creates a raw-TCP ingress server bound to hostPort that
// forwards to another node's hostPort. This is the non-owner half of stable
// cluster TCP exposure: every node can accept tcp://cluster-host:hostPort, but
// only the owner forwards from hostPort to the container.
func (c *Client) UpsertTCPProxyRoute(ctx context.Context, id string, port, hostPort int, peerHost string, peerPort int) error {
	if !c.enabled {
		return nil
	}
	if hostPort <= 0 || peerPort <= 0 {
		return errors.New("host port must be positive")
	}
	server := map[string]any{
		"listen": []string{fmt.Sprintf(":%d", hostPort)},
		"routes": []any{
			map[string]any{
				"@id": tcpRouteID(id, port),
				"handle": []map[string]any{{
					"handler":   "proxy",
					"upstreams": []map[string]any{{"dial": []string{net.JoinHostPort(peerHost, strconv.Itoa(peerPort))}}},
				}},
			},
		},
	}
	body, err := json.Marshal(server)
	if err != nil {
		return fmt.Errorf("marshal tcp proxy server: %w", err)
	}
	target := fmt.Sprintf("%s/config/apps/layer4/servers/%s", c.baseURL, tcpServerID(hostPort))
	status, err := c.sendJSON(ctx, http.MethodPut, target, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("upsert tcp proxy server failed: %d", status)
	}
	return nil
}

// DeleteTCPRoute removes the layer4 server holding hostPort. 404 is treated
// as success — the desired post-condition is "not present", and it isn't.
func (c *Client) DeleteTCPRoute(ctx context.Context, hostPort int) error {
	if !c.enabled {
		return nil
	}
	if hostPort <= 0 {
		return nil
	}
	target := fmt.Sprintf("%s/config/apps/layer4/servers/%s", c.baseURL, tcpServerID(hostPort))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, target, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete tcp server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete tcp server failed: %d", resp.StatusCode)
	}
	return nil
}

// UpsertTLSSNIRoute publishes (or refreshes) one SNI route inside the shared
// tls-mux layer4 server. PATCH /id/<routeID> replaces the existing route in
// place without disturbing siblings; if the @id isn't there yet (404) we PUT
// at routes/0 so SNI matching tries it ahead of any future fallback.
//
// The handler chain is [tls, proxy]: caddy-l4 terminates TLS using Caddy's
// own cert manager (which already holds the wildcard for *.$DOMAIN, issued
// once at startup via DNS-01), then proxies the now-plaintext bytes to the
// container on its native port. The container speaks raw TCP — no cert, no
// private key, nothing TLS-related lives inside the user's sandbox. The
// connection_policies entry is intentionally empty: Caddy picks the cert by
// SNI from the shared cert manager, so there is no per-route cert config.
//
// Caller must have already called EnsureLayer4 with a non-empty tlsListen at
// least once; otherwise the routes/0 PUT will land on a missing server.
func (c *Client) UpsertTLSSNIRoute(ctx context.Context, id, sniHost, containerIP string, port int) error {
	if !c.enabled {
		return nil
	}
	routeID := tlsRouteID(id, port)
	route := map[string]any{
		"@id": routeID,
		"match": []map[string]any{{
			"tls": map[string]any{"sni": []string{sniHost}},
		}},
		"handle": []map[string]any{
			{
				"handler":             "tls",
				"connection_policies": []map[string]any{{}},
			},
			{
				"handler":   "proxy",
				"upstreams": []map[string]any{{"dial": []string{fmt.Sprintf("%s:%d", containerIP, port)}}},
			},
		},
	}
	body, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("marshal tls sni route: %w", err)
	}

	patchURL := fmt.Sprintf("%s/id/%s", c.baseURL, routeID)
	status, err := c.sendJSON(ctx, http.MethodPatch, patchURL, body)
	if err != nil {
		return err
	}
	if status < 400 {
		return nil
	}
	if status != http.StatusNotFound {
		return fmt.Errorf("patch tls sni route failed: %d", status)
	}

	insertURL := fmt.Sprintf("%s/config/apps/layer4/servers/%s/routes/0", c.baseURL, tlsMuxServerID)
	status, err = c.sendJSON(ctx, http.MethodPut, insertURL, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("insert tls sni route failed: %d", status)
	}
	return nil
}

// UpsertSNIPassthroughRoute publishes a layer4 SNI route that does not
// terminate TLS. Non-owner ingress nodes use this to forward domain-mode
// sandbox hosts to the owner node's :443 mux, preserving the original ClientHello
// and letting the owner perform the normal local routing.
func (c *Client) UpsertSNIPassthroughRoute(ctx context.Context, routeID, sniHost, peerHost string, peerPort int) error {
	if !c.enabled {
		return nil
	}
	if routeID == "" || sniHost == "" || peerHost == "" || peerPort <= 0 {
		return errors.New("route id, sni host, peer host, and peer port are required")
	}
	route := map[string]any{
		"@id": routeID,
		"match": []map[string]any{{
			"tls": map[string]any{"sni": []string{sniHost}},
		}},
		"handle": []map[string]any{{
			"handler":   "proxy",
			"upstreams": []map[string]any{{"dial": []string{net.JoinHostPort(peerHost, strconv.Itoa(peerPort))}}},
		}},
	}
	body, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("marshal sni passthrough route: %w", err)
	}
	patchURL := fmt.Sprintf("%s/id/%s", c.baseURL, routeID)
	status, err := c.sendJSON(ctx, http.MethodPatch, patchURL, body)
	if err != nil {
		return err
	}
	if status < 400 {
		return nil
	}
	if status != http.StatusNotFound {
		return fmt.Errorf("patch sni passthrough route failed: %d", status)
	}
	insertURL := fmt.Sprintf("%s/config/apps/layer4/servers/%s/routes/0", c.baseURL, tlsMuxServerID)
	status, err = c.sendJSON(ctx, http.MethodPut, insertURL, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("insert sni passthrough route failed: %d", status)
	}
	return nil
}

// DeleteTLSSNIRoute removes one SNI route by @id. 404 is treated as success
// for the same reason DeleteSandboxRoute does.
func (c *Client) DeleteTLSSNIRoute(ctx context.Context, id string, port int) error {
	if !c.enabled {
		return nil
	}
	return c.deleteRoute(ctx, tlsRouteID(id, port))
}

// Snapshot is the read side of reconcile's zombie-route detection. It walks
// the live Caddy config once and returns every entity whose name follows our
// conventions, so the service layer can compare against the DB and delete
// anything that has no matching row.
type Snapshot struct {
	// HTTPRouteIDs are the @ids of routes under apps/http that match our
	// "sandbox-..." prefix. Both the per-sandbox toolbox routes and the
	// per-port HTTP routes show up here.
	HTTPRouteIDs []string
	// L4TCPServerIDs are server names under apps/layer4 of the form
	// tcp-port-<hostPort>. Each maps 1:1 to a host-port allocation in the DB.
	L4TCPServerIDs []string
	// L4TLSRouteIDs are @ids of SNI routes inside the tls-mux server.
	L4TLSRouteIDs []string
}

func (c *Client) Snapshot(ctx context.Context) (Snapshot, error) {
	var snap Snapshot
	if !c.enabled {
		return snap, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/config/", nil)
	if err != nil {
		return snap, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return snap, fmt.Errorf("get caddy config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return snap, fmt.Errorf("get caddy config failed: %d", resp.StatusCode)
	}

	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []map[string]any `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
			Layer4 struct {
				Servers map[string]struct {
					Routes []map[string]any `json:"routes"`
				} `json:"servers"`
			} `json:"layer4"`
		} `json:"apps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return snap, fmt.Errorf("decode caddy config: %w", err)
	}

	for _, server := range cfg.Apps.HTTP.Servers {
		for _, route := range server.Routes {
			if id, _ := route["@id"].(string); strings.HasPrefix(id, "sandbox-") {
				snap.HTTPRouteIDs = append(snap.HTTPRouteIDs, id)
			}
		}
	}
	for serverID, server := range cfg.Apps.Layer4.Servers {
		if strings.HasPrefix(serverID, "tcp-port-") {
			snap.L4TCPServerIDs = append(snap.L4TCPServerIDs, serverID)
		}
		if serverID == tlsMuxServerID {
			for _, route := range server.Routes {
				if id, _ := route["@id"].(string); strings.HasPrefix(id, "sandbox-") {
					snap.L4TLSRouteIDs = append(snap.L4TLSRouteIDs, id)
				}
			}
		}
	}
	return snap, nil
}

// pathExists is a thin GET wrapper used by EnsureLayer4 to distinguish
// "needs creating" from "already there". Caddy returns 404 for missing
// config nodes; anything else either succeeds or surfaces as an error.
func (c *Client) pathExists(ctx context.Context, path string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("get %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode >= 400 {
		return false, fmt.Errorf("get %s failed: %d", path, resp.StatusCode)
	}
	// Caddy returns "null" for a path that exists in the config tree but has
	// no value yet. Treat that as "needs creating" so the PUT actually runs.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("read %s body: %w", path, err)
	}
	return strings.TrimSpace(string(body)) != "null", nil
}
