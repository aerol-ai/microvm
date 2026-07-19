//go:build integration

package sims

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// exposeDialTarget resolves the host:port to TCP-probe for an exposure. Raw-TCP
// exposures carry Host/HostPort directly. TLS and HTTP exposures multiplex on
// the shared ingress listener and leave HostPort=0 by design (see
// models.ExposePortResponse: "Host/HostPort are populated only on the raw-TCP
// path"), so their dial target must be parsed from PublicURL — e.g.
// tls://sb-<id>-<port>.<domain>:443. Probing Host/HostPort for a TLS exposure
// dials ":0" (the SVC-01 postgres regression this fixes).
func exposeDialTarget(e sdktypes.ExposeResult) (string, int, error) {
	if e.HostPort != 0 {
		return e.Host, e.HostPort, nil
	}
	u, err := url.Parse(e.PublicURL)
	if err != nil {
		return "", 0, fmt.Errorf("parse public_url %q: %w", e.PublicURL, err)
	}
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("public_url %q has no host", e.PublicURL)
	}
	port := 443 // shared TLS/HTTPS ingress listener when PublicURL omits a port
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil {
			return "", 0, fmt.Errorf("public_url %q port: %w", e.PublicURL, err)
		}
	}
	return host, port, nil
}

func securedExpose(t *testing.T, c *harness.Client, sc *harness.Scenario, opts sdktypes.CreateSandboxOptions, port int, protocol string) (*microvm.Sandbox, sdktypes.ExposeResult) {
	t.Helper()
	if opts.Name == "" {
		opts.Name = harness.UniqueName(sc, t)
	}
	trueVal := true
	opts.AllowPublicTraffic = &trueVal
	sb, err := c.SDK().Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("create service sandbox: %v", err)
	}
	waitRunningTB(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var res sdktypes.ExposeResult
	var exposeErr error
	switch protocol {
	case "tcp":
		res, exposeErr = sb.ExposePort(ctx, port, microvm.WithProtocol(sdktypes.ExposeProtocolTCP))
	case "tls":
		res, exposeErr = sb.ExposePort(ctx, port, microvm.WithProtocol(sdktypes.ExposeProtocolTLS))
	default:
		res, exposeErr = sb.ExposePort(ctx, port)
	}
	if exposeErr != nil {
		t.Fatalf("expose port %d: %v", port, exposeErr)
	}
	t.Cleanup(func() {
		tctx, tcancel := context.WithTimeout(context.Background(), time.Minute)
		defer tcancel()
		_ = sb.UnexposePort(tctx, port)
		_ = c.SDK().Destroy(tctx, sb.ID)
		assertTornDown(t, c, sb.ID, protocol, res.Host, res.HostPort)
	})
	return sb, res
}

// assertTornDown is the CM-5 verified-teardown check: after Destroy the sandbox
// must be gone from the API, and a raw-TCP exposure's host port must stop
// accepting connections. Without this a silently-failed Unexpose/Destroy would
// leave a public DB/Redis route up for the rest of the soak while the run stays
// green. Uses t.Errorf (not Fatalf) so a stuck teardown is reported without
// aborting other cleanups.
func assertTornDown(t *testing.T, c *harness.Client, sbID, protocol, host string, hostPort int) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	// 1) The sandbox (and its caddy route) must disappear from the API.
	for {
		gctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := c.SDK().Get(gctx, sbID)
		cancel()
		if err != nil { // not-found => destroyed
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("CM-5 teardown: sandbox %s still present after destroy", sbID)
			return
		}
		time.Sleep(2 * time.Second)
	}
	// 2) A dedicated raw-TCP host port must refuse new connections. (TLS-SNI/HTTP
	// exposures share the ingress :443, so the sandbox-gone check above is the
	// route signal for those; a port probe there would false-positive on :443.)
	if protocol == "tcp" && host != "" && hostPort != 0 {
		for {
			if err := tcpPing(host, hostPort); err != nil {
				return // refused/timeout => route torn down
			}
			if time.Now().After(deadline) {
				t.Errorf("CM-5 teardown: %s:%d still accepts TCP after destroy", host, hostPort)
				return
			}
			time.Sleep(2 * time.Second)
		}
	}
}

func waitRunningTB(t *testing.T, sb *microvm.Sandbox) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		if string(sb.Status) == "started" {
			return
		}
		if string(sb.Status) == "error" {
			t.Fatalf("sandbox %s error: %s", sb.ID, sb.LastError)
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %s not started", sb.ID)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = sb.Refresh(ctx)
		cancel()
		time.Sleep(2 * time.Second)
	}
}

func tcpPing(host string, port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 10*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

// redisRESPPing sends AUTH (when password != "") then PING. With no password on
// a --requirepass server, Redis answers PING with a NOAUTH error, so this
// returns an error — which is exactly what the CM-5 "unauth must be refused"
// probe relies on.
func redisRESPPing(host string, port int, password string) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	if password != "" {
		if _, err := fmt.Fprintf(conn, "AUTH %s\r\n", password); err != nil {
			return err
		}
		authLine, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(authLine, "+OK") {
			return fmt.Errorf("redis AUTH rejected: %q", strings.TrimSpace(authLine))
		}
	}
	if _, err := fmt.Fprintf(conn, "PING\r\n"); err != nil {
		return err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "PONG") {
		return fmt.Errorf("unexpected RESP: %q", line)
	}
	return nil
}

func waitHTTP200(url string, within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(3 * time.Second)
	}
	return last
}
