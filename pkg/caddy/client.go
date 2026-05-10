package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
)

type Client struct {
	baseURL     string
	serverID    string
	domain      string
	publicHost  string
	enabled     bool
	l4TLSListen string
	httpClient  *http.Client
}

func New(cfg config.Config) *Client {
	return &Client{
		baseURL:     strings.TrimRight(cfg.CaddyAdminURL, "/"),
		serverID:    cfg.CaddyServerID,
		domain:      cfg.Domain,
		publicHost:  cfg.PublicHost,
		enabled:     cfg.EnableCaddy,
		l4TLSListen: cfg.L4TLSListen,
		httpClient:  &http.Client{Timeout: cfg.HTTPClientTimeout},
	}
}

// L4TLSListen returns the listen address configured for the shared TLS-SNI
// multiplexer. Empty means TLS-SNI exposure is disabled — the service layer
// should reject protocol="tls" requests and skip EnsureLayer4 of the mux.
func (c *Client) L4TLSListen() string { return c.l4TLSListen }

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
// allocated at hostPort. Always uses the publicHost as the dial target — TCP
// has no DNS-shaped wildcard equivalent, so even in domain mode the parent
// host's address is the right value here. Operators that want a friendly DNS
// name should add their own A record pointing at PublicHost.
func (c *Client) TCPPublicEndpoint(hostPort int) string {
	return fmt.Sprintf("tcp://%s:%d", c.publicHost, hostPort)
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

func (c *Client) DeletePortRoute(ctx context.Context, id string, port int) error {
	if !c.enabled || c.domain == "" {
		return nil
	}
	return c.deleteRoute(ctx, portRouteID(id, port))
}

func (c *Client) AllowTLSDomain(host string) bool {
	host = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://"), "/"))
	if host == "" || c.domain == "" {
		return false
	}
	return host == c.domain || strings.HasSuffix(host, "."+c.domain)
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

func tcpServerID(hostPort int) string {
	return fmt.Sprintf("tcp-port-%d", hostPort)
}

func tcpRouteID(id string, port int) string {
	return fmt.Sprintf("sandbox-%s-port-%d-tcp", id, port)
}

func tlsRouteID(id string, port int) string {
	return fmt.Sprintf("sandbox-%s-port-%d-tls", id, port)
}

// EnsureLayer4 idempotently bootstraps the layer4 app and (when tlsListen is
// non-empty) the shared SNI-mux server. Safe to call on every sandboxd start
// — the admin API treats a no-op POST as 200 and a PATCH on a missing key as
// 404, so we issue a PUT only when the path actually doesn't exist.
//
// Without this bootstrap, the very first UpsertTCPRoute would fail because
// /config/apps/layer4 doesn't exist yet on a fresh Caddy.
func (c *Client) EnsureLayer4(ctx context.Context, tlsListen string) error {
	if !c.enabled {
		return nil
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
	server := map[string]any{
		"listen": []string{tlsListen},
		"routes": []any{},
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
		"handle": []map[string]any{{
			"handler":   "proxy",
			"upstreams": []map[string]any{{"dial": []string{fmt.Sprintf("%s:%d", containerIP, port)}}},
		}},
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
