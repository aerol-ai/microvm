//go:build integration

package suite

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Ingress proxy routing gate (plans/ingress-proxy-routing.md T10). Only
// scenarios whose nodes run SB_INGRESS_PROXY_ROUTING advertise the
// capability.

// routingEchoScript runs an HTTP server on 8080 and a line echo server on
// 9000. The echo server keeps each connection open, so a long-lived session
// can be probed again after a restart (UC-172).
const routingEchoScript = `python3 -m http.server 8080 &
exec python3 -c '
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9000)); s.listen(256)
def h(c):
    while True:
        d = c.recv(4096)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
'`

type routingTarget struct {
	sb      *microvm.Sandbox
	httpURL string
	tcpAddr string
}

// newRoutingTarget starts the echo sandbox, exposes 8080 (http) and 9000
// (tcp), and waits until both answer through the ingress.
func newRoutingTarget(t *testing.T, c *harness.Client) routingTarget {
	t.Helper()
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Image:            "python:3.12-alpine",
		Name:             harness.UniqueName(sc, t),
		ContainerCommand: []string{"sh", "-c", routingEchoScript},
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	hp, err := sb.ExposePort(ctx, 8080)
	if err != nil {
		t.Fatalf("expose http: %v", err)
	}
	tp, err := sb.ExposePort(ctx, 9000, microvm.WithProtocol("tcp"))
	if err != nil {
		t.Fatalf("expose tcp: %v", err)
	}
	if hp.PublicURL == "" || tp.Host == "" || tp.HostPort == 0 {
		t.Fatalf("exposures missing endpoints: http=%+v tcp=%+v", hp, tp)
	}
	target := routingTarget{sb: sb, httpURL: hp.PublicURL, tcpAddr: net.JoinHostPort(tp.Host, fmt.Sprint(tp.HostPort))}
	if code, err := reachableHTTP(target.httpURL, 2*time.Minute); err != nil || code != http.StatusOK {
		t.Fatalf("http %s never served 200 (code %d): %v", target.httpURL, code, err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		err := tcpEchoOnce(target.tcpAddr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tcp %s never echoed: %v", target.tcpAddr, err)
		}
		time.Sleep(3 * time.Second)
	}
	return target
}

// tcpEchoOnce opens a FRESH connection, round-trips one line, and closes.
// A fresh connection per probe is what a routing change can break.
func tcpEchoOnce(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	return echoLine(conn, bufio.NewReader(conn), "ping")
}

func echoLine(conn net.Conn, r *bufio.Reader, msg string) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "%s\n", msg); err != nil {
		return err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != msg {
		return fmt.Errorf("echo = %q, want %q", line, msg)
	}
	return nil
}

type failureTally struct {
	mu    sync.Mutex
	ok    atomic.Int64
	bad   atomic.Int64
	kinds map[string]int
}

func (f *failureTally) record(err error) {
	if err == nil {
		f.ok.Add(1)
		return
	}
	f.bad.Add(1)
	msg := err.Error()
	if len(msg) > 80 {
		msg = msg[:80]
	}
	f.mu.Lock()
	if f.kinds == nil {
		f.kinds = map[string]int{}
	}
	f.kinds[msg]++
	f.mu.Unlock()
}

func (f *failureTally) summary() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.kinds))
	for k := range f.kinds {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return f.kinds[keys[i]] > f.kinds[keys[j]] })
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "\n    %d× %s", f.kinds[k], k)
	}
	return b.String()
}

// UC-171 is the live form of scripts/dev/caddy-reload-repro.py. Fresh HTTP and
// raw-TCP connections to a stable sandbox run while other sandboxes are
// created, exposed (http + tcp) and destroyed. With per-sandbox Caddy routes,
// every churn step reloaded Caddy and ~2.6% of new connections dropped. With
// routing through the responder and kernel DNAT, the target is 0.
func TestIngressRoutingChurnGate(t *testing.T) {
	harness.Require(t, sc, "UC-171")
	c := client(t)
	target := newRoutingTarget(t, c)

	const window = 90 * time.Second
	stop := time.Now().Add(window)
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true}, // a new connection per request
	}
	var httpT, tcpT failureTally
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				resp, err := httpClient.Get(target.httpURL)
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						err = fmt.Errorf("status %d", resp.StatusCode)
					}
				}
				httpT.record(err)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				tcpT.record(tcpEchoOnce(target.tcpAddr))
			}
		}()
	}

	// The churner: each step is what used to be several Caddy admin writes
	// (root route, http port route, tcp-port server, then their deletes).
	var churnOps, churnErrs int
	for time.Now().Before(stop) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		public := true
		sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Image: "alpine:3.20", Name: harness.UniqueName(sc, t), AllowPublicTraffic: &public,
			ContainerCommand: []string{"sleep", "600"},
		})
		if err == nil {
			_, e1 := sb.ExposePort(ctx, 8080)
			_, e2 := sb.ExposePort(ctx, 9000, microvm.WithProtocol("tcp"))
			if e1 != nil || e2 != nil {
				churnErrs++
				t.Logf("churn expose: http=%v tcp=%v", e1, e2)
			}
			if derr := c.SDK().Destroy(ctx, sb.ID); derr != nil {
				churnErrs++
				t.Logf("churn destroy %s: %v", sb.ID, derr)
			}
			churnOps++
		} else {
			churnErrs++
			t.Logf("churn create: %v", err)
		}
		cancel()
	}
	wg.Wait()

	t.Logf("churn gate: %d churn cycles (%d errors); http %d ok / %d failed; tcp %d ok / %d failed",
		churnOps, churnErrs, httpT.ok.Load(), httpT.bad.Load(), tcpT.ok.Load(), tcpT.bad.Load())
	if churnOps < 3 {
		t.Fatalf("only %d churn cycles in %s: the gate measured no churn", churnOps, window)
	}
	if httpT.ok.Load() == 0 || tcpT.ok.Load() == 0 {
		t.Fatal("no successful probes: the gate measured nothing")
	}
	if n := httpT.bad.Load(); n != 0 {
		t.Errorf("%d fresh HTTP connections failed during churn (target 0):%s", n, httpT.summary())
	}
	if n := tcpT.bad.Load(); n != 0 {
		t.Errorf("%d fresh TCP connections failed during churn (target 0):%s", n, tcpT.summary())
	}
}

// UC-173: a live public sandbox with an http and a tcp exposure leaves no
// trace in Caddy on any node. It has no "sandbox-<id>..." route and no
// tcp-port server; the static routes carry it. Proven by reading each node's
// Caddy admin config over SSH.
func TestIngressRoutingNoPerSandboxCaddyRoutes(t *testing.T) {
	harness.Require(t, sc, "UC-173")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	target := newRoutingTarget(t, c)

	checked := 0
	for _, n := range targets.Nodes {
		if n.Role == "server" {
			continue // pure servers serve no sandbox traffic
		}
		host, ok := harness.SSHTarget(n)
		if !ok {
			continue
		}
		out, err := harness.SSHRun(t, host, "curl -fsS http://127.0.0.1:2019/config/")
		if err != nil {
			t.Fatalf("%s: read caddy config: %v\n%s", n.Name, err, out)
		}
		if strings.Contains(out, "sandbox-"+target.sb.ID) {
			t.Errorf("%s: Caddy holds a per-sandbox route for %s under ingress proxy routing", n.Name, target.sb.ID)
		}
		if strings.Contains(out, `"tcp-port-`) {
			t.Errorf("%s: Caddy still has tcp-port servers (raw TCP should be kernel-forwarded)", n.Name)
		}
		if !strings.Contains(out, `"sandbox-ingress-proxy"`) {
			t.Errorf("%s: the static sandbox route is missing (did the flag engage? check sandboxd logs for 'ingress proxy routing refused')", n.Name)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("no sandbox-serving node reachable over SSH")
	}
}
