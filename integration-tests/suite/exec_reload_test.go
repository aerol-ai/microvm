//go:build integration

package suite

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Streams across a Caddy reload (#712). Every interactive stream (an exec
// stream, aerolvm shell, a session attach) is a WebSocket that Caddy's API
// site proxies to sandboxd. Every sandbox route change reloads Caddy, and a
// reload used to close every such WebSocket at once with close code 1001, so
// one user exposing a port cut every other user's open streams. UC-68 failed
// that way on cluster-hetero-lite-secrets on 2026-10-16. The fix is
// stream_close_delay on every reverse_proxy (scripts/install.sh, pkg/caddy).

// changeSandboxRoute makes Caddy reload while the caller holds a stream open.
// It creates a public sandbox that serves HTTP, exposes a port on it, and
// waits for the port's public URL to answer 200. That answer proves the
// ingress applied the new route, which means its Caddy loaded a new config.
func changeSandboxRoute(t *testing.T) {
	t.Helper()
	c := client(t)
	// NewSandbox opts in to public traffic, so the create writes a route too.
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Image:            "python:3.12-alpine",
		Name:             harness.UniqueName(sc, t) + "-route",
		ContainerCommand: []string{"python3", "-m", "http.server", "8080"},
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExposePort(ctx, 8080)
	if err != nil {
		t.Fatalf("expose port on the route-change sandbox: %v", err)
	}
	fetchEventually(t, res.PublicURL)
	// More than one ingress node can serve the API, and each applies the route
	// on its own reconcile tick (5 s). The 200 came from one of them, so give
	// the others a tick and a margin before the caller uses its stream.
	time.Sleep(10 * time.Second)
}

// UC-266 — an exec stream opened before another sandbox's route changes still
// carries stdin and stdout afterwards, and Wait reports the real exit code.
// Before the fix, Wait failed with "stream closed before exit: close
// code=1001".
func TestExecStreamSurvivesCaddyReload(t *testing.T) {
	harness.Require(t, sc, "UC-266")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	// The context bounds the stream's whole life, which includes creating and
	// exposing the second sandbox.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// OnStdout runs on the SDK's read loop, so guard the buffer.
	var mu sync.Mutex
	var out strings.Builder
	stdout := func() string {
		mu.Lock()
		defer mu.Unlock()
		return out.String()
	}
	// ready-266 proves the stream is up end to end before the route changes;
	// `read` then holds the process until the line is written after it.
	handle, err := sb.ExecStream(ctx, sdktypes.ExecStreamOptions{
		Command: `echo ready-266; read line; echo "echoed:$line"`,
		OnStdout: func(b []byte) {
			mu.Lock()
			out.Write(b)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("exec stream: %v", err)
	}
	deadline := time.Now().Add(time.Minute)
	for !strings.Contains(stdout(), "ready-266") {
		if time.Now().After(deadline) {
			t.Fatalf("the stream never printed ready-266; stdout = %q", stdout())
		}
		time.Sleep(100 * time.Millisecond)
	}

	changeSandboxRoute(t)

	if err := handle.WriteString("marker-266\n"); err != nil {
		t.Fatalf("write stdin after the route change: %v", err)
	}
	info, err := handle.Wait()
	if err != nil {
		t.Fatalf("wait after the route change: %v (close code=1001 is Caddy's reload closing the stream)", err)
	}
	if info.Code != 0 {
		t.Fatalf("stream exit code = %d, want 0", info.Code)
	}
	if got := stdout(); !strings.Contains(got, "echoed:marker-266") {
		t.Fatalf("stream stdout = %q, want it to contain echoed:marker-266", got)
	}
}
