//go:build e2e && linux

package caddy

// Reload-churn reproduction: why new connections to an ingress fail while
// sandboxes are created and destroyed, and proof that the static routes of
// SB_INGRESS_PROXY_ROUTING do not. Operator-runnable, not CI: it needs a
// Caddy binary built with caddy-l4 (the release build: Caddy v2.11.7 +
// caddy-l4 v0.1.2, .github/workflows/release.yml), named by
// AEROL_E2E_CADDY_BIN. Run it with `make test-ingress-reload-e2e`. Linux
// only, like the ingress: the socket handoff below is Linux behaviour, and
// macOS runs out of ephemeral ports on three fresh hops per dial.
//
// Both arms boot the same Caddy shaped like a dedicated ingress: a layer4
// tls-mux (created by the production EnsureLayer4) whose fallback hands the
// API host to an HTTPS site, which proxies to a WebSocket backend standing in
// for sandboxd's exec-stream endpoint. Clients dial exactly what the SDKs'
// exec streams dial: a fresh TCP connection, TLS to the API host, a
// WebSocket upgrade, one message.
//
//   - legacy: every sandbox create/destroy is what an ingress does with the
//     flag off, UpsertSNIPassthroughRoute then DeleteRouteByID. Each is a
//     Caddy admin write, and each write reloads Caddy's whole config.
//   - static: the static ingress routes are installed once at boot
//     (EnsureStaticIngressRoutes). With the flag on a create/destroy only
//     changes sandboxd's route index, never Caddy; internal/service
//     TestIngressProxyRoutingClusterChurnMakesNoCaddyWrites proves that for
//     the real index writer. Here the same events are a no-op on Caddy.
//
// A reload drops new connections two ways, and the dial phase tells them
// apart:
//
//   - "upgrade: unexpected EOF": TLS completed, then the server closed with
//     zero bytes. Go's http.Server, once Shutdown has begun, reads the next
//     request on a connection it already accepted and returns without
//     answering (net/http conn.serve: `if c.server.shuttingDown() {
//     return }`). Every reload shuts the old HTTPS site down this way. This
//     is the live failure in UC-230 and UC-266 on cluster-bank-flagship.
//   - "tls: connection reset by peer" / "tls: EOF": the connection reached
//     the old config's listening socket and was never accepted. Caddy binds
//     a fresh SO_REUSEPORT socket per config and closes the old one, and
//     Linux resets what was still queued on it. (net.ipv4.tcp_migrate_req,
//     Linux 5.14+, would hand those over; it cannot help the first
//     mechanism, and it is not measured here.)
//
// Neither has a Caddy setting that turns it off (grace_period and
// shutdown_delay measured unchanged, plans/ingress-proxy-routing.md §1), so
// the fix is to stop reloading: the static arm must see zero failures.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/gorilla/websocket"
)

// e2eAPIHost is the apex: production serves the API on SB_DOMAIN itself, which
// is what the static apex route (StaticApexSNIRouteID) matches.
const e2eAPIHost = "e2e.test"

// e2eEnvDuration reads a duration override, so an operator can run a longer
// window without editing the test.
func e2eEnvDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func e2eEnvInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// freeTCPPorts returns n distinct free ports. It holds every probe socket
// open until all n are chosen, so no two ports repeat. Open the test's own
// listeners first: a port freed here can be handed to the next bind(:0).
func freeTCPPorts(t *testing.T, n int) []int {
	t.Helper()
	ports := make([]int, 0, n)
	for range n {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("free port: %v", err)
		}
		defer ln.Close()
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

// e2ePKI writes a CA and a leaf for the API host and *.e2e.test.
func e2ePKI(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aerolvm e2e CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: e2eAPIHost},
		DNSNames:     []string{e2eAPIHost, "*.e2e.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "leaf.pem")
	keyFile = filepath.Join(dir, "leaf-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(caCert)
	return certFile, keyFile, pool
}

// startExecStreamBackend stands in for sandboxd's exec-stream endpoint: it
// upgrades, sends one message and closes.
func startExecStreamBackend(t *testing.T) string {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte("ok"))
		_ = conn.Close()
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// countingTransport counts the client's config writes (every admin request
// but a GET), so the static arm can prove a lifecycle event never reached
// Caddy.
type countingTransport struct {
	next   http.RoundTripper
	writes atomic.Int64
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		c.writes.Add(1)
	}
	return c.next.RoundTrip(r)
}

// retryTransient repeats an admin helper the way sandboxd's callers do:
// Caddy restarts its admin endpoint on every load, so a write can see EOF
// or a reset, and every helper is safe to repeat (IsTransientAdminError).
func retryTransient(fn func() error) error {
	var err error
	for range 10 {
		if err = fn(); !IsTransientAdminError(err) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return err
}

type e2eIngress struct {
	client  *Client
	admin   *countingTransport
	l4Addr  string
	https   string
	rootCAs *x509.CertPool
}

// bootE2EIngress starts Caddy with the HTTPS API site, then builds tls-mux
// through the production EnsureLayer4, as sandboxd does at boot.
func bootE2EIngress(t *testing.T, bin string) *e2eIngress {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, pool := e2ePKI(t, dir)
	backend := startExecStreamBackend(t)
	ports := freeTCPPorts(t, 4)
	adminPort, httpsPort, l4Port, httpPort := ports[0], ports[1], ports[2], ports[3]
	adminAddr := fmt.Sprintf("127.0.0.1:%d", adminPort)
	httpsAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	l4Addr := fmt.Sprintf("127.0.0.1:%d", l4Port)

	cfg := map[string]any{
		"admin":   map[string]any{"listen": adminAddr},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps": map[string]any{
			"tls": map[string]any{"certificates": map[string]any{
				"load_files": []map[string]any{{"certificate": certFile, "key": keyFile}},
			}},
			"http": map[string]any{
				"http_port": httpPort,
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen": []string{httpsAddr},
						"routes": []map[string]any{{
							"match": []map[string]any{{"host": []string{e2eAPIHost}}},
							"handle": []map[string]any{{
								"handler":            "reverse_proxy",
								"upstreams":          []map[string]any{{"dial": backend}},
								"flush_interval":     -1,
								"stream_close_delay": streamCloseDelay,
							}},
						}},
						"tls_connection_policies": []map[string]any{{}},
						"automatic_https":         map[string]any{"disable": true},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "caddy.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "--config", cfgPath)
	cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
	logFile, err := os.Create(filepath.Join(dir, "caddy.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
		_ = logFile.Close()
		if t.Failed() {
			if b, err := os.ReadFile(logFile.Name()); err == nil {
				t.Logf("caddy log:\n%s", b)
			}
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get("http://" + adminAddr + "/config/")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("caddy admin never came up on %s: %v", adminAddr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	c := New(config.Config{
		CaddyAdminURL:     "http://" + adminAddr,
		CaddyServerID:     "srv0",
		Domain:            "e2e.test",
		EnableCaddy:       true,
		L4TLSListen:       l4Addr,
		L4TLSFallback:     httpsAddr,
		HTTPClientTimeout: 30 * time.Second,
	})
	admin := &countingTransport{next: c.httpClient.Transport}
	c.httpClient.Transport = admin
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.EnsureLayer4(ctx, l4Addr, httpsAddr); err != nil {
		t.Fatalf("EnsureLayer4: %v", err)
	}
	return &e2eIngress{client: c, admin: admin, l4Addr: l4Addr, https: httpsAddr, rootCAs: pool}
}

// execStreamDial is one SDK exec-stream dial through the ingress, split into
// phases so a failure says where the connection died.
func (in *e2eIngress) execStreamDial() (phase string, err error) {
	conn, err := net.DialTimeout("tcp", in.l4Addr, 5*time.Second)
	if err != nil {
		return "dial", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(conn, &tls.Config{ServerName: e2eAPIHost, RootCAs: in.rootCAs, NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		return "tls", err
	}
	// ws://, not wss://: tc is already TLS, and NewClient would wrap a wss
	// URL in a second TLS layer.
	u, _ := url.Parse("ws://" + e2eAPIHost + "/v1/sandboxes/sb-e2e/toolbox/process/exec/stream")
	//nolint:staticcheck // NewClient takes an established conn, which is what splits the phases.
	ws, resp, err := websocket.NewClient(tc, u, http.Header{}, 4096, 4096)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err != nil {
		return "upgrade", err
	}
	_, msg, err := ws.ReadMessage()
	if err != nil {
		return "read", err
	}
	if string(msg) != "ok" {
		return "read", fmt.Errorf("message %q", msg)
	}
	return "", nil
}

// dialTally counts dial outcomes by phase and error class.
type dialTally struct {
	ok    atomic.Int64
	bad   atomic.Int64
	mu    sync.Mutex
	kinds map[string]int
}

func classifyDialErr(err error) string {
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected EOF"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset by peer"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, io.EOF):
		return "EOF"
	case errors.Is(err, syscall.EPIPE):
		return "broken pipe"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	msg := err.Error()
	if len(msg) > 60 {
		msg = msg[:60]
	}
	return msg
}

func (d *dialTally) record(phase string, err error) {
	if err == nil {
		d.ok.Add(1)
		return
	}
	d.bad.Add(1)
	k := phase + ": " + classifyDialErr(err)
	d.mu.Lock()
	if d.kinds == nil {
		d.kinds = map[string]int{}
	}
	d.kinds[k]++
	d.mu.Unlock()
}

func (d *dialTally) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	keys := make([]string, 0, len(d.kinds))
	for k := range d.kinds {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return d.kinds[keys[i]] > d.kinds[keys[j]] })
	var b strings.Builder
	fmt.Fprintf(&b, "%d ok / %d failed", d.ok.Load(), d.bad.Load())
	for _, k := range keys {
		fmt.Fprintf(&b, "\n      %5d  %s", d.kinds[k], k)
	}
	return b.String()
}

// churnRun dials for window while lifecycle() runs every pace, and returns
// the tally and the number of lifecycle events.
func churnRun(t *testing.T, in *e2eIngress, window, pace time.Duration, clients int, lifecycle func(ctx context.Context, i int) error) (*dialTally, int) {
	t.Helper()
	var tally dialTally
	stop := time.Now().Add(window)
	var wg sync.WaitGroup
	for range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				tally.record(in.execStreamDial())
			}
		}()
	}
	events := 0
	ctx := context.Background()
	for time.Now().Before(stop) {
		if err := lifecycle(ctx, events); err != nil {
			t.Errorf("lifecycle event %d: %v", events, err)
			break
		}
		events++
		time.Sleep(pace)
	}
	wg.Wait()
	return &tally, events
}

// TestE2EIngressReloadChurn is the local reproduction. The legacy arm must
// see drops (the detector's proof); the static arm is the gate and must drop
// nothing.
func TestE2EIngressReloadChurn(t *testing.T) {
	bin := os.Getenv("AEROL_E2E_CADDY_BIN")
	if bin == "" {
		t.Skip("AEROL_E2E_CADDY_BIN not set: point it at a Caddy built with caddy-l4 (make test-ingress-reload-e2e)")
	}
	window := e2eEnvDuration("AEROL_E2E_CHURN_WINDOW", 15*time.Second)
	// One create/destroy pair per pace is two reloads with the flag off:
	// ~18 reloads/s at 100ms, the rate scripts/dev/caddy-reload-repro.py
	// measured. A live ingress saw ~0.1-0.5/s (bank flagship); the per-reload
	// drop is the same, only rarer.
	pace := e2eEnvDuration("AEROL_E2E_CHURN_PACE", 100*time.Millisecond)
	clients := e2eEnvInt("AEROL_E2E_CLIENTS", 16)

	t.Run("legacy per-sandbox SNI routes", func(t *testing.T) {
		in := bootE2EIngress(t, bin)
		if phase, err := in.execStreamDial(); err != nil {
			t.Fatalf("baseline dial (%s): %v", phase, err)
		}
		_, peerPort, _ := net.SplitHostPort(in.https)
		port, _ := strconv.Atoi(peerPort)
		// One create and one destroy, each the ingress's real write.
		tally, events := churnRun(t, in, window, pace, clients, func(ctx context.Context, i int) error {
			id := fmt.Sprintf("sb-churn-%d", i)
			routeID := IngressSandboxSNIRouteID(id)
			if err := retryTransient(func() error {
				return in.client.UpsertSNIPassthroughRoute(ctx, routeID, id+".e2e.test", "127.0.0.1", port)
			}); err != nil {
				return err
			}
			return retryTransient(func() error { return in.client.DeleteRouteByID(ctx, routeID) })
		})
		// A create is a PATCH that 404s and a PUT, a destroy a DELETE: two
		// config loads per pair.
		t.Logf("legacy: %d create/destroy pairs (%d Caddy config reloads); exec-stream dials: %s",
			events, 2*events, tally)
		// The detector's proof: if the reload path drops nothing here, the
		// static arm's zero below proves nothing either.
		if tally.bad.Load() == 0 {
			t.Errorf("legacy route churn dropped no exec-stream dial in %s (%d reload pairs); the reproduction lost its signal", window, events)
		}
	})

	t.Run("static routes, lifecycle in the index", func(t *testing.T) {
		in := bootE2EIngress(t, bin)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// LocalIP is not the dial address here, so the API dials take route
		// 1 (the apex SNI route), the path the live failures took.
		if err := in.client.EnsureStaticIngressRoutes(ctx, StaticRouteSpec{LocalIP: "127.0.0.2"}); err != nil {
			t.Fatalf("EnsureStaticIngressRoutes: %v", err)
		}
		if phase, err := in.execStreamDial(); err != nil {
			t.Fatalf("baseline dial (%s): %v", phase, err)
		}
		bootWrites := in.admin.writes.Load()
		// With the flag on a create/destroy is a route-index update in
		// sandboxd; nothing reaches Caddy.
		tally, events := churnRun(t, in, window, pace, clients, func(context.Context, int) error { return nil })
		churnWrites := in.admin.writes.Load() - bootWrites
		t.Logf("static: %d create/destroy events, %d Caddy admin writes during churn; exec-stream dials: %s",
			events, churnWrites, tally)
		if churnWrites != 0 {
			t.Errorf("%d Caddy admin writes during churn; a lifecycle event must not touch Caddy", churnWrites)
		}
		if tally.ok.Load() == 0 {
			t.Fatal("no successful dials: the gate measured nothing")
		}
		if n := tally.bad.Load(); n != 0 {
			t.Errorf("%d exec-stream dials failed under churn with the static routes (want 0): %s", n, tally)
		}
	})
}
