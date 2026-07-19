//go:build integration

package sims

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

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
	})
	return sb, res
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

func redisRESPPing(host string, port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "PING\r\n"); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
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
