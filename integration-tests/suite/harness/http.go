package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// rawGet issues an authenticated GET against the scenario's control-plane API
// for the handful of endpoints the Go SDK does not wrap yet (capacity,
// metrics, cluster/* observability, ops). The suite is primarily a Go-SDK
// integration test; this escape hatch keeps the ops/cluster use cases honest
// without bloating the SDK. PAT is always attached — the deployments under
// test enforce auth (UC-10).
func (c *Client) rawGet(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.sc.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.sc.PAT)
	return http.DefaultClient.Do(req)
}

// rawPost issues an authenticated POST with an optional JSON body. Used by the
// cluster operator controls (drain/uncordon/reclaim) that have no SDK method.
func (c *Client) rawPost(ctx context.Context, path string, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.sc.BaseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.sc.PAT)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

// GetJSON GETs path and decodes a 2xx JSON body into out. Any non-2xx is an
// error carrying the status and a snippet of the body, so a failing use case
// reports what the server actually said.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	resp, err := c.rawGet(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, snippet(b))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

// GetText GETs path and returns the raw 2xx body (for /v1/metrics, which is
// Prometheus text, not JSON).
func (c *Client) GetText(ctx context.Context, path string) (string, error) {
	resp, err := c.rawGet(ctx, path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, snippet(b))
	}
	return string(b), nil
}

// PostJSON POSTs an optional JSON body and decodes a 2xx JSON response into out
// (out may be nil to ignore the body). Non-2xx is an error with the status.
func (c *Client) PostJSON(ctx context.Context, path string, body, out any) error {
	resp, err := c.rawPost(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, snippet(b))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

// BaseURL exposes the scenario's API base URL for tests that build their own
// requests (e.g. the no-auth 401 check already does this directly via sc).
func (c *Client) BaseURL() string { return c.sc.BaseURL }

func snippet(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}
