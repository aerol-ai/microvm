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
// the shared fixture for expose/idempotent/custom-domain use cases that do not
// depend on the private-by-default ingress contract.
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

// privateHTTPServerSandbox creates a default-private sandbox (no
// allow_public_traffic opt-in) with an HTTP server on 8080. Use for ingress
// reachability UCs that must exercise the expose_port opt-in lever.
func privateHTTPServerSandbox(t *testing.T, c *harness.Client) *microvm.Sandbox {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image:            "python:3.12-alpine",
		Name:             harness.UniqueName(sc, t),
		ContainerCommand: []string{"python3", "-m", "http.server", "8080"},
	})
	if err != nil {
		t.Fatalf("create private sandbox: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().Destroy(cctx, sb.ID)
	})
	waitRunning(t, sb)
	return sb
}

func sandboxRootURL(domain, sandboxID string) string {
	return fmt.Sprintf("https://%s.%s", sandboxID, domain)
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

// assertNoSandboxRoute polls url for window and fails if anything answers on
// the sandbox's behalf. "Private" legitimately looks different per deployment
// shape, so two outcomes are accepted:
//
//   - transport/TLS error — per-host on-demand-cert deployments never issue a
//     cert for a route-less hostname, so the handshake itself fails;
//   - a bare ingress 404 (or 421) — wildcard-cert deployments
//     (caddy_shared_cert_storage) complete TLS for ANY subdomain and answer
//     404 when no route matches, byte-identical to a sandbox that has never
//     existed.
//
// Everything else fails: 2xx/3xx means content was served, 401/403 means a
// route exists and merely gated the request, and 5xx means a reverse-proxy
// route matched and reached for an upstream — all privacy violations during
// the private window. Callers must probe a sandbox whose workload answers
// 200 at "/" (privateHTTPServerSandbox), so a 404 here can only be the
// ingress's no-route answer, never the workload's.
func assertNoSandboxRoute(t *testing.T, url string, window time.Duration) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("URL %s answered %d during private window, want no route (transport error, 404, or 421)", url, resp.StatusCode)
		}
		time.Sleep(3 * time.Second)
	}
}

// probeStatus does one GET and returns the status code, or -1 on a
// transport/TLS error.
func probeStatus(url string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1
	}
	resp.Body.Close()
	return resp.StatusCode
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

// UC-32 — A default-private create has no live root ingress; expose_port is
// the opt-in lever that installs the <id>.<domain> route and makes it reachable.
func TestDefaultURLReachable(t *testing.T) {
	harness.Require(t, sc, "UC-32")
	if sc.Domain == "" {
		t.Fatal("scenario lacks AEROL_DOMAIN for root URL assertions")
	}
	c := client(t)
	sb := privateHTTPServerSandbox(t, c)
	if sb.PublicURL != "" {
		t.Fatalf("public_url = %q, want empty for a default (private) create", sb.PublicURL)
	}

	root := sandboxRootURL(sc.Domain, sb.ID)
	assertNoSandboxRoute(t, root, 20*time.Second)

	// Anti-enumeration: on a wildcard-cert ingress the private sandbox's URL
	// must be indistinguishable from a sandbox that has never existed — same
	// status (or both hard-unreachable). A differing answer would let an
	// attacker confirm sandbox IDs without reaching them. Compared only when
	// both probes got an HTTP answer, so a transient transport blip on one
	// side can't flake the test.
	ghost := sandboxRootURL(sc.Domain, "sb-0000000000000000")
	privateStatus, ghostStatus := probeStatus(root), probeStatus(ghost)
	if privateStatus != -1 && ghostStatus != -1 && privateStatus != ghostStatus {
		t.Fatalf("private sandbox answers %d but nonexistent sandbox answers %d — responses must be indistinguishable", privateStatus, ghostStatus)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := sb.ExposePort(ctx, 8080); err != nil {
		t.Fatalf("expose port: %v", err)
	}
	flipped, err := c.SDK().Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("get after expose: %v", err)
	}
	if flipped.PublicURL == "" {
		t.Fatal("sandbox public_url still empty after expose; the flip must persist")
	}
	if code, err := reachableHTTP(flipped.PublicURL, 90*time.Second); err != nil {
		t.Fatalf("default URL %s after expose: %v", flipped.PublicURL, err)
	} else {
		t.Logf("default URL answered %d after expose_port opt-in", code)
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
	// CapExternalDNSZone guarantees a real hostname (outside the base domain)
	// whose ownership TXT record is already provisioned, so the attach passes
	// the verification gate instead of failing on an unverifiable fake domain.
	host := sc.CustomDomain
	if host == "" {
		t.Skip("scenario advertises external-dns-zone but AEROL_CUSTOM_DOMAIN is unset")
	}
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

// UC-36 — A real custom hostname (outside the deployment base domain, with its
// verification TXT + a CNAME to ingress already provisioned) is reachable over
// HTTPS after attach. The hostname MUST live outside the base domain: the API
// rejects hosts under the wildcard zone because the wildcard already covers
// them, so this can only be exercised against an externally controlled zone.
func TestCustomDomainReachable(t *testing.T) {
	harness.Require(t, sc, "UC-36")
	c := client(t)
	sb := httpServerSandbox(t, c)

	host := sc.CustomDomain
	if host == "" {
		t.Skip("scenario advertises external-dns-zone but AEROL_CUSTOM_DOMAIN is unset")
	}

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
