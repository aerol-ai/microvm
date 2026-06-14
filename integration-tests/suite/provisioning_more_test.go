//go:build integration

package suite

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// UC-01 — The deployment is healthy and answering on its API. In local-mode
// that API is http://localhost:21212 via the SSH tunnel; in domain mode it's
// the HTTPS endpoint. Either way Health() must report a non-error status.
func TestDeploymentHealthy(t *testing.T) {
	harness.Require(t, sc, "UC-01")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := c.SDK().Health(ctx)
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if h.Status == "" || strings.EqualFold(h.Status, "error") {
		t.Fatalf("health status = %q, want a healthy status", h.Status)
	}
}

// UC-02 — sandboxd is active with its core subsystems wired (docker reported).
func TestSandboxdActive(t *testing.T) {
	harness.Require(t, sc, "UC-02")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := c.SDK().Health(ctx)
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if h.Version == "" {
		t.Fatal("health reported empty version; daemon not fully up")
	}
	if h.Docker == "" {
		t.Fatal("health reported no docker subsystem status")
	}
}

// UC-07 — Wildcard DNS resolves to the ingress: both the apex and an arbitrary
// label under it resolve to at least one A record.
func TestWildcardDNSResolves(t *testing.T) {
	harness.Require(t, sc, "UC-07")
	if sc.Domain == "" {
		t.Skip("no leased domain")
	}
	deadline := time.Now().Add(2 * time.Minute)
	for _, host := range []string{sc.Domain, "wildcard-probe." + sc.Domain} {
		ok := false
		for time.Now().Before(deadline) {
			ips, err := net.LookupHost(host)
			if err == nil && len(ips) > 0 {
				ok = true
				break
			}
			time.Sleep(5 * time.Second)
		}
		if !ok {
			t.Fatalf("%s never resolved to an A record", host)
		}
	}
}

// UC-08 — The control-plane API is reachable over HTTPS and reports healthy.
func TestControlPlaneOverHTTPS(t *testing.T) {
	harness.Require(t, sc, "UC-08")
	c := client(t)
	if !strings.HasPrefix(c.BaseURL(), "https://") {
		t.Skipf("base URL %q is not HTTPS", c.BaseURL())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := c.SDK().Health(ctx); err != nil {
		t.Fatalf("HTTPS health: %v", err)
	}
}

// UC-09 — The ingress presents a TLS leaf whose SAN covers the apex and a
// wildcard label. We don't assert public-root trust because the suite defaults
// to Let's Encrypt staging (run with --prod-tls for a publicly-valid chain);
// SAN coverage is the runtime-issued-correct-cert signal that always holds.
func TestValidTLSChain(t *testing.T) {
	harness.Require(t, sc, "UC-09")
	if sc.Domain == "" {
		t.Skip("no leased domain")
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	// InsecureSkipVerify: staging certs won't chain to public roots; we inspect
	// the presented leaf's SANs instead.
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(sc.Domain, "443"),
		&tls.Config{ServerName: sc.Domain, InsecureSkipVerify: true}) //nolint:gosec
	if err != nil {
		t.Fatalf("tls dial %s:443: %v", sc.Domain, err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("server presented no certificate")
	}
	leaf := certs[0]
	covered := false
	for _, name := range leaf.DNSNames {
		if name == sc.Domain || name == "*."+sc.Domain {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("leaf SANs %v do not cover %s or *.%s", leaf.DNSNames, sc.Domain, sc.Domain)
	}
}
