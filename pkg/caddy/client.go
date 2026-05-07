package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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

func (c *Client) upsertRoute(ctx context.Context, routeID string, route map[string]any) error {
	routes, err := c.loadRoutes(ctx)
	if err != nil {
		return err
	}

	filtered := filterRoutesByID(routes, routeID)
	updated := make([]map[string]any, 0, len(filtered)+1)
	updated = append(updated, route)
	updated = append(updated, filtered...)
	return c.saveRoutes(ctx, updated)
}

func (c *Client) deleteRoute(ctx context.Context, routeID string) error {
	routes, err := c.loadRoutes(ctx)
	if err != nil {
		return err
	}

	updated := filterRoutesByID(routes, routeID)
	if len(updated) == len(routes) {
		return nil
	}
	return c.saveRoutes(ctx, updated)
}

func (c *Client) loadRoutes(ctx context.Context) ([]map[string]any, error) {
	target := fmt.Sprintf("%s/config/apps/http/servers/%s/routes", c.baseURL, url.PathEscape(c.serverID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("load caddy routes: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("load caddy routes failed: %d", resp.StatusCode)
	}

	var routes []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		return nil, fmt.Errorf("decode caddy routes: %w", err)
	}
	return routes, nil
}

func (c *Client) saveRoutes(ctx context.Context, routes []map[string]any) error {
	body, err := json.Marshal(routes)
	if err != nil {
		return fmt.Errorf("marshal caddy routes: %w", err)
	}

	target := fmt.Sprintf("%s/config/apps/http/servers/%s/routes", c.baseURL, url.PathEscape(c.serverID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("save caddy routes: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("save caddy routes failed: %d", resp.StatusCode)
	}
	return nil
}

func filterRoutesByID(routes []map[string]any, routeID string) []map[string]any {
	filtered := make([]map[string]any, 0, len(routes))
	for _, route := range routes {
		if currentID, _ := route["@id"].(string); currentID == routeID {
			continue
		}
		filtered = append(filtered, route)
	}
	return filtered
}

func sandboxRouteID(id string) string {
	return "sandbox-" + id
}

func portRouteID(id string, port int) string {
	return fmt.Sprintf("sandbox-%s-port-%d", id, port)
}

var _ = time.Second
