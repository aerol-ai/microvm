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

	"github.com/aerolai/sandbox-library/internal/config"
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
	if err := c.deleteByID(ctx, routeID); err != nil {
		return err
	}

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

	return c.appendRoute(ctx, route)
}

func (c *Client) DeleteSandboxRoute(ctx context.Context, id string) error {
	if !c.enabled {
		return nil
	}
	return c.deleteByID(ctx, sandboxRouteID(id))
}

func (c *Client) UpsertPortRoute(ctx context.Context, id, containerIP string, port int) error {
	if !c.enabled || c.domain == "" {
		return nil
	}

	routeID := portRouteID(id, port)
	if err := c.deleteByID(ctx, routeID); err != nil {
		return err
	}

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

	return c.appendRoute(ctx, route)
}

func (c *Client) DeletePortRoute(ctx context.Context, id string, port int) error {
	if !c.enabled || c.domain == "" {
		return nil
	}
	return c.deleteByID(ctx, portRouteID(id, port))
}

func (c *Client) AllowTLSDomain(host string) bool {
	host = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://"), "/"))
	if host == "" || c.domain == "" {
		return false
	}
	return host == c.domain || strings.HasSuffix(host, "."+c.domain)
}

func (c *Client) appendRoute(ctx context.Context, route map[string]any) error {
	body, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("marshal route: %w", err)
	}

	target := fmt.Sprintf("%s/config/apps/http/servers/%s/routes", c.baseURL, url.PathEscape(c.serverID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("append caddy route: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("append caddy route failed: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) deleteByID(ctx context.Context, routeID string) error {
	target := fmt.Sprintf("%s/id/%s", c.baseURL, url.PathEscape(routeID))
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

func sandboxRouteID(id string) string {
	return "sandbox-" + id
}

func portRouteID(id string, port int) string {
	return fmt.Sprintf("sandbox-%s-port-%d", id, port)
}

var _ = time.Second
