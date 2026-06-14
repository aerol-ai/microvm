//go:build integration

package suite

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-29 — exposing a port returns a preview URL.
func TestExposePortReturnsURL(t *testing.T) {
	harness.Require(t, sc, "UC-29")
	c := client(t)
	// A tiny http server so the exposed port has something to answer with.
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Image:            "python:3.12-alpine",
		Name:             harness.UniqueName(sc, t),
		ContainerCommand: []string{"python3", "-m", "http.server", "8080"},
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExposePort(ctx, 8080)
	if err != nil {
		t.Fatalf("expose port: %v", err)
	}
	if res.PublicURL == "" {
		t.Fatal("expose returned empty public_url")
	}
	t.Logf("preview URL: %s", res.PublicURL)
}

// UC-30 — the preview URL is actually reachable over HTTPS (domain scenarios).
func TestPreviewURLReachable(t *testing.T) {
	harness.Require(t, sc, "UC-30")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Image:            "python:3.12-alpine",
		Name:             harness.UniqueName(sc, t),
		ContainerCommand: []string{"python3", "-m", "http.server", "8080"},
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExposePort(ctx, 8080)
	if err != nil {
		t.Fatalf("expose port: %v", err)
	}

	// Routing + DNS + TLS can lag a few seconds behind the API response. Poll
	// with a bounded window rather than asserting on the first try.
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	var lastCode int
	for time.Now().Before(deadline) {
		rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, _ := http.NewRequestWithContext(rctx, http.MethodGet, res.PublicURL, nil)
		resp, err := http.DefaultClient.Do(req)
		rcancel()
		if err != nil {
			lastErr = err
			time.Sleep(3 * time.Second)
			continue
		}
		resp.Body.Close()
		lastCode = resp.StatusCode
		// Any non-5xx means the route is live and the app answered. The app is
		// a directory listing, so 200 is expected, but we accept <500 to avoid
		// coupling to the served content.
		if resp.StatusCode < 500 {
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("preview URL %s never became reachable (last code %d, last err %v)", res.PublicURL, lastCode, lastErr)
}
