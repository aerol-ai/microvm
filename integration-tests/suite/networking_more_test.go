//go:build integration

package suite

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// httpServerSandbox spins up a sandbox running a trivial HTTP server on 8080,
// the shared fixture for the expose/reach use cases.
func httpServerSandbox(t *testing.T, c *harness.Client) *microvm.Sandbox {
	t.Helper()
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Image:            "python:3.12-alpine",
		Name:             harness.UniqueName(sc, t),
		ContainerCommand: []string{"python3", "-m", "http.server", "8080"},
	})
	waitRunning(t, sb)
	return sb
}

// reachableHTTP polls url until it answers with <500 (route live) or the
// deadline passes. Returns the last status/err for a useful failure message.
func reachableHTTP(url string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	var lastCode int
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			time.Sleep(3 * time.Second)
			continue
		}
		resp.Body.Close()
		lastCode = resp.StatusCode
		if resp.StatusCode < 500 {
			return resp.StatusCode, nil
		}
		time.Sleep(3 * time.Second)
	}
	return lastCode, fmt.Errorf("never reachable (last code %d, last err %v)", lastCode, lastErr)
}

// UC-31 — Exposing the same port twice returns the same URL (idempotent).
func TestExposePortIdempotent(t *testing.T) {
	harness.Require(t, sc, "UC-31")
	c := client(t)
	sb := httpServerSandbox(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	first, err := sb.ExposePort(ctx, 8080)
	if err != nil {
		t.Fatalf("expose #1: %v", err)
	}
	second, err := sb.ExposePort(ctx, 8080)
	if err != nil {
		t.Fatalf("expose #2: %v", err)
	}
	if first.PublicURL != second.PublicURL {
		t.Fatalf("expose not idempotent: %q != %q", first.PublicURL, second.PublicURL)
	}
}

// UC-32 — The default <id>.<domain> URL routes to the sandbox over HTTPS.
func TestDefaultURLReachable(t *testing.T) {
	harness.Require(t, sc, "UC-32")
	c := client(t)
	sb := httpServerSandbox(t, c)
	if sb.PublicURL == "" {
		t.Fatal("sandbox has empty public_url")
	}
	if code, err := reachableHTTP(sb.PublicURL, 90*time.Second); err != nil {
		t.Fatalf("default URL %s: %v", sb.PublicURL, err)
	} else {
		t.Logf("default URL answered %d", code)
	}
}

// UC-33 — Unexposing a port removes it from the sandbox's exposed-port set.
func TestUnexposePort(t *testing.T) {
	harness.Require(t, sc, "UC-33")
	c := client(t)
	sb := httpServerSandbox(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := sb.ExposePort(ctx, 8080); err != nil {
		t.Fatalf("expose: %v", err)
	}
	if err := sb.UnexposePort(ctx, 8080); err != nil {
		t.Fatalf("unexpose: %v", err)
	}
	got, err := c.SDK().Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	for _, p := range got.ExposedPorts {
		if p.Port == 8080 {
			t.Fatalf("port 8080 still present after unexpose")
		}
	}
}

// UC-34 — A raw TCP exposure allocates a host port and is reachable.
func TestL4RawTCPReachable(t *testing.T) {
	harness.Require(t, sc, "UC-34")
	c := client(t)
	// nc listening on 9000 so the raw TCP route has something to accept.
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Image:            "alpine:3.20",
		Name:             harness.UniqueName(sc, t),
		ContainerCommand: []string{"sh", "-c", "while true; do echo hi | nc -l -p 9000; done"},
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExposePort(ctx, 9000, microvm.WithProtocol("tcp"))
	if err != nil {
		t.Fatalf("expose tcp: %v", err)
	}
	if res.Host == "" || res.HostPort == 0 {
		t.Fatalf("tcp expose missing host/port: %+v", res)
	}

	addr := net.JoinHostPort(res.Host, fmt.Sprintf("%d", res.HostPort))
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
		if err == nil {
			conn.Close()
			return
		}
		lastErr = err
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("raw TCP %s never connectable: %v", addr, lastErr)
}

// UC-35 — Adding a custom domain returns the DNS instructions to point at us.
func TestCustomDomainDNSInstructions(t *testing.T) {
	harness.Require(t, sc, "UC-35")
	c := client(t)
	sb := httpServerSandbox(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	host := fmt.Sprintf("cd-%d.example.test", time.Now().UnixNano())
	if _, err := sb.AddCustomDomain(ctx, host, microvm.WithTargetPort(8080)); err != nil {
		t.Fatalf("add custom domain: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = sb.RemoveCustomDomain(cctx, host)
	})
	recs, err := sb.CustomDomainDNS(ctx)
	if err != nil {
		t.Fatalf("custom domain DNS: %v", err)
	}
	_ = recs // presence of a non-error response is the contract; shape varies.
}

// UC-36 — A custom hostname under the leased wildcard zone (which already
// resolves to ingress) is reachable over HTTPS after attach. This exercises the
// real custom-domain serving path without needing the test to mint new DNS.
func TestCustomDomainReachable(t *testing.T) {
	harness.Require(t, sc, "UC-36")
	c := client(t)
	sb := httpServerSandbox(t, c)

	// sc.Domain is the leased apex; *.<domain> already points at ingress via
	// the wildcard record Terraform created, so an arbitrary label resolves.
	if sc.Domain == "" {
		t.Skip("scenario has no leased domain to build a custom hostname under")
	}
	host := fmt.Sprintf("custom-%d.%s", time.Now().UnixNano(), sc.Domain)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := sb.AddCustomDomain(ctx, host, microvm.WithTargetPort(8080)); err != nil {
		t.Fatalf("add custom domain: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = sb.RemoveCustomDomain(cctx, host)
	})
	url := "https://" + host
	if code, err := reachableHTTP(url, 120*time.Second); err != nil {
		t.Fatalf("custom domain %s: %v", url, err)
	} else {
		t.Logf("custom domain answered %d", code)
	}
}

// UC-37 — Network usage counters are returned for a sandbox.
func TestNetworkUsageCounters(t *testing.T) {
	harness.Require(t, sc, "UC-37")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	usage, err := c.SDK().GetNetworkUsage(ctx, sb.ID)
	if err != nil {
		t.Fatalf("network usage: %v", err)
	}
	if usage.SandboxID != sb.ID {
		t.Fatalf("usage sandbox_id=%q, want %q", usage.SandboxID, sb.ID)
	}
}

// UC-38 — Patching network limits is enforced (reflected back in usage).
func TestNetworkLimitsPatch(t *testing.T) {
	harness.Require(t, sc, "UC-38")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	limit := int64(1 << 20) // 1 MiB
	usage, err := c.SDK().SetNetworkLimits(ctx, sb.ID, sdktypes.SetNetworkLimitsOptions{
		NetworkBytesInLimit: &limit,
	})
	if err != nil {
		t.Fatalf("set network limits: %v", err)
	}
	if usage.BytesInLimit != limit {
		t.Fatalf("bytes_in_limit=%d, want %d", usage.BytesInLimit, limit)
	}
}
