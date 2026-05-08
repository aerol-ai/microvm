package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
)

type Client struct {
	baseURL    string
	serverID   string
	domain     string
	publicHost string
	enabled    bool
	httpClient *http.Client
}

func New(cfg config.Config) *Client {
	return &Client{
		baseURL:    strings.TrimRight(cfg.CaddyAdminURL, "/"),
		serverID:   cfg.CaddyServerID,
		domain:     cfg.Domain,
		publicHost: cfg.PublicHost,
		enabled:    cfg.EnableCaddy,
		httpClient: &http.Client{Timeout: cfg.HTTPClientTimeout},
	}
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
