package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"syscall"
	"time"
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

// Delete issues an authenticated DELETE and returns an error on any non-2xx.
// Used by the isolate js-bundle catalogue UC, whose delete verb the Go SDK does
// not wrap. 204 No Content (the catalogue's success status) and any 2xx count as
// success; the body snippet on failure surfaces what the server said.
func (c *Client) Delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.sc.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.sc.PAT)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("DELETE %s: status %d: %s", path, resp.StatusCode, snippet(b))
	}
	return nil
}

// transientGatewayStatuses are the edge failing to reach the daemon, not the
// daemon answering. Caddy fronts the API, and a sandboxd restart — which
// several security use cases perform deliberately — leaves a window where it
// answers 502. Recording that as a use case's verdict attributes a gateway
// hiccup to the product: the live gate lost UC-136 twice to exactly this.
var transientGatewayStatuses = map[int]bool{502: true, 503: true, 504: true}

// gatewayRetries and gatewayRetryDelay bound the wait. Short and few: this
// is for a restart window, not for a node that is down — a genuinely dead
// daemon must still fail the case promptly rather than after minutes.
// Deliberately small. Retries MULTIPLY across pagination: AllAuditPages
// walks up to maxPages requests, so 4 attempts at 3s turned one history read
// into eight minutes and hung UC-149 past the suite's own 60m timeout. This
// covers a restart window of a few seconds, not an outage to ride out;
// anything longer belongs to the caller's own deadline.
const gatewayRetries = 2

// gatewayRetryDelay is a var so the offline tests can collapse it; nothing
// else reassigns it.
var gatewayRetryDelay = 2 * time.Second

// gatewayRetryDelayForTest shortens the delay and returns a restore func.
func gatewayRetryDelayForTest(d time.Duration) func() {
	prev := gatewayRetryDelay
	gatewayRetryDelay = d
	return func() { gatewayRetryDelay = prev }
}

// GetJSON GETs path and decodes a 2xx JSON body into out. Any non-2xx is an
// error carrying the status and a snippet of the body, so a failing use case
// reports what the server actually said.
//
// A transient gateway status is retried rather than returned; see
// transientGatewayStatuses.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	resp, err := c.getWithGatewayRetry(ctx, path)
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

// getWithGatewayRetry issues the GET, retrying only while the EDGE is
// failing. Any response the daemon itself produced — including a 4xx or a
// 500 — is returned immediately, because those are answers and a use case
// must assert on them.
func (c *Client) getWithGatewayRetry(ctx context.Context, path string) (*http.Response, error) {
	var resp *http.Response
	var err error
	for attempt := 0; ; attempt++ {
		resp, err = c.rawGet(ctx, path)
		// A dropped connection is the same class as a 502: the edge went
		// away mid-request. UC-147 failed on a bare
		// "read tcp ...: connection reset" while a node was restarting, and
		// only HTTP statuses were being retried.
		if err != nil {
			if attempt >= gatewayRetries || ctx.Err() != nil || !isRetriableTransportErr(err) {
				return nil, err
			}
		} else if !transientGatewayStatuses[resp.StatusCode] || attempt >= gatewayRetries {
			return resp, err
		} else {
			// Drain and close so the connection can be reused for the retry.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(gatewayRetryDelay):
		}
	}
}

// isRetriableTransportErr reports whether an error is the connection failing
// rather than the server answering. Only the shapes a restarting edge
// produces — a refused dial, a reset or a half-closed read — so a genuine
// client bug (a bad URL, a TLS trust failure) still fails immediately.
func isRetriableTransportErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}
	msg := err.Error()
	for _, s := range []string{"connection reset", "connection refused", "unexpected EOF", "server closed idle connection", "broken pipe"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
