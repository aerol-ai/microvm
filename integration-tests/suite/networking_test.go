//go:build integration

package suite

import (
	"context"
	"net/http"
	"strings"
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

// UC-97 — A create that omits allow_public_traffic is private: no ingress route,
// empty public_url, exposePort refused, while toolbox exec still works.
func TestCreatePrivateByDefault(t *testing.T) {
	harness.Require(t, sc, "UC-97")
	c := client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// Bypass NewSandbox — the harness opts in to public traffic for the other UCs.
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage,
		Name:  harness.UniqueName(sc, t),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().Destroy(cctx, sb.ID)
	})
	waitRunning(t, sb)

	if sb.PublicURL != "" {
		t.Fatalf("public_url = %q, want empty for a default (private) create", sb.PublicURL)
	}

	ectx, ecancel := context.WithTimeout(context.Background(), time.Minute)
	defer ecancel()
	_, err = sb.ExposePort(ectx, 8080)
	if err == nil {
		t.Fatal("expose port on private sandbox succeeded; want refusal")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "public traffic") {
		t.Fatalf("expose error = %v, want public-traffic refusal", err)
	}

	res, err := sb.ExecCommand(ectx, "echo private-ok")
	if err != nil {
		t.Fatalf("exec on private sandbox: %v", err)
	}
	if !strings.Contains(res.Stdout, "private-ok") {
		t.Fatalf("exec stdout = %q, want private-ok", res.Stdout)
	}
}
