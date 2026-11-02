//go:build integration

package suite

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
	"github.com/gorilla/websocket"
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

// ingressNodes are the nodes behind the API domain's A records: every node
// whose role includes ingress, and mixed nodes (Terraform/locals.tf
// ingress_node_names). nil without integration targets.
func ingressNodes(targets *harness.IntegrationTargets) []harness.IntegrationNode {
	if targets == nil {
		return nil
	}
	var out []harness.IntegrationNode
	for _, n := range targets.Nodes {
		if n.PublicIP == "" {
			continue
		}
		roles := strings.Split(strings.ReplaceAll(n.Role, " ", ""), ",")
		if n.Role == "mixed" || slices.Contains(roles, "ingress") {
			out = append(out, n)
		}
	}
	return out
}

// pinnedDial sends every dial to ip, keeping the port, so a probe reaches
// one chosen ingress node with the real hostname for SNI and certificate
// checks. An empty ip dials the name as given (DNS picks the node).
func pinnedDial(ip string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if ip == "" {
			return d.DialContext(ctx, network, addr)
		}
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
}

// freshGet opens a NEW TLS connection (no keep-alive) for one request and
// wants a 200.
func freshGet(c *http.Client, rawURL, token string) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// pinnedExecStream is one SDK exec stream, dialled through the ingress at
// ip: the WebSocket upgrade, the start message, then stdout until the exit
// frame. It speaks the SDK's wire protocol (sdk/go/internal/apiclient
// exec_stream.go) because the SDK's dialer cannot be pinned to a node.
func pinnedExecStream(ctx context.Context, ip, baseURL, token, sandboxID, marker string) error {
	u, err := url.Parse(baseURL)
	if err != nil {
		return err
	}
	wsURL := "wss://" + u.Host + "/v1/sandboxes/" + url.PathEscape(sandboxID) + "/toolbox/process/exec/stream"
	d := websocket.Dialer{NetDialContext: pinnedDial(ip), HandshakeTimeout: 15 * time.Second}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	conn, resp, err := d.DialContext(ctx, wsURL, h)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err != nil {
		if resp != nil {
			return fmt.Errorf("websocket dial: %w (status %d)", err, resp.StatusCode)
		}
		return fmt.Errorf("websocket dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	if err := conn.WriteJSON(map[string]string{"command": "echo " + marker}); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	var stdout strings.Builder
	for {
		kind, payload, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("stream closed before exit: %w", err)
		}
		switch kind {
		case websocket.BinaryMessage:
			if len(payload) > 0 && payload[0] == 0x01 {
				stdout.Write(payload[1:])
			}
		case websocket.TextMessage:
			var m struct {
				Type    string `json:"type"`
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			if json.Unmarshal(payload, &m) != nil {
				continue
			}
			switch m.Type {
			case "exit":
				if m.Code != 0 {
					return fmt.Errorf("exit code %d", m.Code)
				}
				if !strings.Contains(stdout.String(), marker) {
					return fmt.Errorf("stdout %q lacks %q", stdout.String(), marker)
				}
				return nil
			case "error":
				return fmt.Errorf("stream error: %s", m.Message)
			}
		}
	}
}

// UC-357 is the exec-stream form of UC-171, and the regression case for the
// cluster-bank-flagship failures of 2026-11-01: UC-230 and UC-266 failed with
// "exec stream websocket dial wss://<domain>/v1/sandboxes/<id>/toolbox/
// process/exec/stream: unexpected EOF", 1 run in 20, while other cases
// churned sandboxes. With per-sandbox routes, every create and destroy
// anywhere in the cluster made every ingress write a "-ingress-sni" route,
// and each write reloaded that ingress's whole Caddy config (330 reloads in
// an hour on one ingress). A reload drops brand-new connections two ways:
// the old HTTPS server closes a connection whose request it reads after
// shutdown began, with zero bytes (the "unexpected EOF"), and the old
// listening socket is closed with connections still queued on it ("connection
// reset by peer"). pkg/caddy TestE2EIngressReloadChurn reproduces both
// locally against the release Caddy build.
//
// Through EVERY ingress node, pinned by address: fresh TLS connections to the
// API host, new exec streams, and fresh TLS connections to a sandbox's public
// URL; plus real SDK exec streams through whatever node DNS picks. All of it
// runs while churners create, expose and destroy public sandboxes, which
// land across the workers. Any failure fails the case: a reset or an EOF on
// a connection that never got a response is exactly the regression.
func TestIngressChurnNewConnectionsAndExecStreams(t *testing.T) {
	harness.Require(t, sc, "UC-357")
	c := client(t)
	execSB := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-exec"})
	waitRunning(t, execSB)
	target := newRoutingTarget(t, c)

	type ingress struct{ name, ip string }
	var nodes []ingress
	for _, n := range ingressNodes(harness.LoadIntegrationTargets()) {
		nodes = append(nodes, ingress{n.Name, n.PublicIP})
	}
	if len(nodes) == 0 {
		// Run outside run.sh: one unpinned "node", whatever DNS answers.
		nodes = []ingress{{"dns", ""}}
	}

	const window = 2 * time.Minute
	stop := time.Now().Add(window)
	ctx, cancel := context.WithTimeout(context.Background(), window+5*time.Minute)
	defer cancel()

	type probeKind struct {
		name  string
		tally map[string]*failureTally // per ingress node
	}
	apiK := probeKind{"api tls", map[string]*failureTally{}}
	wsK := probeKind{"exec stream", map[string]*failureTally{}}
	sbK := probeKind{"sandbox tls", map[string]*failureTally{}}
	var sdkT failureTally
	var probeSeq atomic.Int64

	var wg sync.WaitGroup
	loop := func(fn func() error, tally *failureTally) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) && ctx.Err() == nil {
				tally.record(fn())
			}
		}()
	}
	apiURL := strings.TrimRight(sc.BaseURL, "/") + "/v1/sandboxes/" + url.PathEscape(execSB.ID)
	for _, n := range nodes {
		fresh := &http.Client{
			Timeout: 20 * time.Second,
			// A new TCP and TLS connection per request: a reload breaks
			// those, never a kept-alive one.
			Transport: &http.Transport{DialContext: pinnedDial(n.ip), DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second},
		}
		for _, k := range []probeKind{apiK, wsK, sbK} {
			k.tally[n.name] = &failureTally{}
		}
		for range 2 {
			loop(func() error { return freshGet(fresh, apiURL, sc.PAT) }, apiK.tally[n.name])
			loop(func() error {
				return pinnedExecStream(ctx, n.ip, sc.BaseURL, sc.PAT, execSB.ID, fmt.Sprintf("ok-357-%d", probeSeq.Add(1)))
			}, wsK.tally[n.name])
			loop(func() error { return freshGet(fresh, target.httpURL, "") }, sbK.tally[n.name])
		}
	}
	for range 2 {
		loop(func() error {
			marker := fmt.Sprintf("sdk-357-%d", probeSeq.Add(1))
			var mu sync.Mutex
			var out strings.Builder
			h, err := execSB.ExecStream(ctx, sdktypes.ExecStreamOptions{
				Command: "echo " + marker,
				OnStdout: func(b []byte) {
					mu.Lock()
					out.Write(b)
					mu.Unlock()
				},
			})
			if err != nil {
				return err
			}
			info, err := h.Wait()
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			if info.Code != 0 || !strings.Contains(out.String(), marker) {
				return fmt.Errorf("exit %d, stdout %q", info.Code, out.String())
			}
			return nil
		}, &sdkT)
	}

	// Three churners, so creates and destroys overlap across workers. Each
	// cycle is a public create, an http expose and a destroy: with
	// per-sandbox routes that is several Caddy writes on the owner and on
	// every ingress node.
	var cycles, churnErrs atomic.Int64
	var churn sync.WaitGroup
	for range 3 {
		churn.Add(1)
		go func() {
			defer churn.Done()
			for time.Now().Before(stop) && ctx.Err() == nil {
				opCtx, opCancel := context.WithTimeout(ctx, 2*time.Minute)
				public := true
				sb, err := c.SDK().Create(opCtx, sdktypes.CreateSandboxOptions{
					Image: "alpine:3.20", Name: harness.UniqueName(sc, t), AllowPublicTraffic: &public,
					ContainerCommand: []string{"sleep", "600"},
				})
				if err != nil {
					churnErrs.Add(1)
					t.Logf("churn create: %v", err)
					opCancel()
					continue
				}
				if _, err := sb.ExposePort(opCtx, 8080); err != nil {
					churnErrs.Add(1)
					t.Logf("churn expose %s: %v", sb.ID, err)
				}
				if err := c.SDK().Destroy(opCtx, sb.ID); err != nil {
					churnErrs.Add(1)
					t.Logf("churn destroy %s: %v", sb.ID, err)
				}
				cycles.Add(1)
				opCancel()
			}
		}()
	}
	churn.Wait()
	wg.Wait()

	t.Logf("UC-357: %d churn cycles (%d errors) in %s across %d ingress node(s)", cycles.Load(), churnErrs.Load(), window, len(nodes))
	if cycles.Load() < 5 {
		t.Fatalf("only %d churn cycles in %s: the case measured no churn", cycles.Load(), window)
	}
	for _, k := range []probeKind{apiK, wsK, sbK} {
		for _, n := range nodes {
			tally := k.tally[n.name]
			t.Logf("  %-12s via %-10s %d ok / %d failed", k.name, n.name, tally.ok.Load(), tally.bad.Load())
			if tally.ok.Load() == 0 {
				t.Errorf("%s via %s: no successful probe, so this node was not measured", k.name, n.name)
			}
			if bad := tally.bad.Load(); bad != 0 {
				t.Errorf("%s via %s: %d new connections failed during churn (want 0; a reset or an EOF here is a Caddy reload dropping it):%s", k.name, n.name, bad, tally.summary())
			}
		}
	}
	t.Logf("  %-12s via %-10s %d ok / %d failed", "sdk exec", "dns", sdkT.ok.Load(), sdkT.bad.Load())
	if sdkT.ok.Load() == 0 {
		t.Error("sdk exec stream: no successful probe")
	}
	if bad := sdkT.bad.Load(); bad != 0 {
		t.Errorf("sdk exec stream: %d streams failed during churn (want 0):%s", bad, sdkT.summary())
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
