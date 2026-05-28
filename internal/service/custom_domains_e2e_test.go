//go:build e2e

// Custom-domains end-to-end ACME test. Operator-runnable only (not CI) —
// invoked via `make test-acme-e2e`. Closes the gap that all our unit and
// integration tests leave: nothing exercises the full TLS handshake →
// Caddy on-demand → ask handler → ACME-against-Pebble → store-in-S3 flow.
//
// The test asserts three things, in order:
//
//  1. First HTTPS hit to a custom hostname triggers exactly one ACME issuance.
//  2. Second hit reuses the cert (zero new orders).
//  3. Killing Caddy and starting a fresh instance pointed at the same S3
//     bucket reuses the cert (zero new orders) — proves the shared-storage
//     guarantee that multi-node clusters depend on.
//
// Lives in package service_test (not service) to break the import cycle
// with pkg/api/ingressproxy. Construction helpers that need the unexported
// Service fields are exposed via export_e2e_test.go.
//
// Pebble runs with PEBBLE_VA_ALWAYS_VALID=1 so HTTP-01 validation is short-
// circuited at the VA; the test still exercises the order/finalize/download
// cycle that produces a "Signing certificate" log line per issuance, which
// is what we count to assert (1).
package service_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/service/testfixtures/caddyfx"
	"github.com/aerol-ai/microvm/internal/service/testfixtures/dockerfx"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/ingressproxy"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	e2eNetwork    = "aerolvm-e2e"
	e2eS3Bucket   = "caddy-certs"
	e2eAKID       = "test"
	e2eSecret     = "test"
	e2eHostname   = "api.test.local"
	e2eSandboxID  = "sb-e2e-1"
	pebbleImage   = "letsencrypt/pebble:v2.5.1"
	localstackImg = "localstack/localstack:3.4"
	caddyBaseImg  = "alpine:3.19"
)

func TestACME_FirstIssueAndS3Reuse(t *testing.T) {
	if testing.Short() {
		t.Skip("acme e2e: skipping in -short mode")
	}
	cli := dockerfx.Require(t)
	cli.EnsureNetwork(t, e2eNetwork)

	ls := cli.Start(t, localstackSpec())
	pebble := cli.Start(t, pebbleSpec())
	createS3Bucket(t, ls)

	pebbleRoots := fetchPebbleRoots(t, pebble)
	caddyBin := caddyfx.Build(t)

	// In-test HTTP backend so Caddy's reverse_proxy has something to reach
	// once it's terminated TLS. Started ONCE, reused across both Caddy
	// instances so the failover phase doesn't introduce a second backend
	// variable to keep in sync.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	backendPort := portFromURL(t, backend.URL)
	configBytes := caddyfx.Render(t, caddyfx.Config{
		S3Endpoint:   "localstack:4566",
		S3Bucket:     e2eS3Bucket,
		AKID:         e2eAKID,
		Secret:       e2eSecret,
		UpstreamAddr: "host.docker.internal:" + backendPort,
	})

	// Phase 1 — first issuance + cache hit.
	caddy1 := cli.Start(t, caddyContainerSpec(caddyBin))
	loadCaddyConfig(t, caddy1, configBytes)

	h := startInProcessSandboxd(t, caddy1)
	mustCreateE2ESandboxRow(t, h.store, e2eSandboxID)
	if err := h.svc.AddCustomDomain(context.Background(), e2eSandboxID, e2eHostname, 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	patchPebbleACME(t, caddy1, pebbleRoots)

	client := httpsClientForCaddy(t, caddy1, pebbleRoots)

	if got := mustGet(t, client, "https://"+e2eHostname+"/").StatusCode; got != http.StatusOK {
		t.Fatalf("first hit: status = %d, want 200\nlogs:\n%s", got, caddy1.LogTail(200))
	}
	if n := pebbleIssuanceCount(pebble); n != 1 {
		t.Fatalf("after first hit: issuance count = %d, want 1\npebble logs:\n%s", n, pebble.LogTail(400))
	}

	if got := mustGet(t, client, "https://"+e2eHostname+"/").StatusCode; got != http.StatusOK {
		t.Fatalf("second hit: status = %d, want 200", got)
	}
	if n := pebbleIssuanceCount(pebble); n != 1 {
		t.Fatalf("after second hit (cache): issuance count = %d, want 1 — cert should have been reused", n)
	}

	// Phase 2 — failover. New Caddy, same S3 bucket. Must reuse cert.
	caddy1.Stop()
	caddy2 := cli.Start(t, caddyContainerSpec(caddyBin))
	loadCaddyConfig(t, caddy2, configBytes)
	rewireSandboxdAt(t, h, caddy2)
	patchPebbleACME(t, caddy2, pebbleRoots)

	client2 := httpsClientForCaddy(t, caddy2, pebbleRoots)
	if got := mustGet(t, client2, "https://"+e2eHostname+"/").StatusCode; got != http.StatusOK {
		t.Fatalf("failover hit: status = %d, want 200\nlogs:\n%s", got, caddy2.LogTail(200))
	}
	if n := pebbleIssuanceCount(pebble); n != 1 {
		t.Fatalf("after failover: issuance count = %d, want 1 — S3 cert should have been reused", n)
	}
}

// --- container specs -------------------------------------------------------

func localstackSpec() dockerfx.Spec {
	return dockerfx.Spec{
		Image:       localstackImg,
		Name:        "aerolvm-e2e-localstack",
		Env:         []string{"SERVICES=s3", "DEBUG=0"},
		ExposePorts: []string{"4566/tcp"},
		Network:     e2eNetwork,
		ReadyProbe: func(c *dockerfx.Container) error {
			port := c.HostPort("4566/tcp")
			if port == "" {
				return dockerfx.ErrNotReady
			}
			resp, err := http.Get("http://127.0.0.1:" + port + "/_localstack/health")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			if !strings.Contains(string(body), `"s3"`) {
				return fmt.Errorf("s3 not ready: %s", body)
			}
			return nil
		},
	}
}

func pebbleSpec() dockerfx.Spec {
	return dockerfx.Spec{
		Image: pebbleImage,
		Name:  "aerolvm-e2e-pebble",
		Env: []string{
			"PEBBLE_VA_ALWAYS_VALID=1",
			"PEBBLE_AUTHZREUSE=0",
			"PEBBLE_WFE_NONCEREJECT=0",
		},
		ExposePorts: []string{"14000/tcp", "15000/tcp"},
		Network:     e2eNetwork,
		ReadyProbe: func(c *dockerfx.Container) error {
			port := c.HostPort("14000/tcp")
			if port == "" {
				return dockerfx.ErrNotReady
			}
			tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			cli := &http.Client{Transport: tr, Timeout: 2 * time.Second}
			resp, err := cli.Get("https://127.0.0.1:" + port + "/dir")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("dir status %d", resp.StatusCode)
			}
			return nil
		},
	}
}

func caddyContainerSpec(binPath string) dockerfx.Spec {
	return dockerfx.Spec{
		Image:       caddyBaseImg,
		Cmd:         []string{"/usr/bin/caddy", "run", "--config", "/dev/null"},
		HostBinds:   []string{caddyfx.HostMount(binPath)},
		ExposePorts: []string{"443/tcp", "2019/tcp"},
		ExtraHosts:  []string{"host.docker.internal:host-gateway"},
		Network:     e2eNetwork,
		ReadyProbe: func(c *dockerfx.Container) error {
			port := c.HostPort("2019/tcp")
			if port == "" {
				return dockerfx.ErrNotReady
			}
			resp, err := http.Get("http://127.0.0.1:" + port + "/config/")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("admin status %d", resp.StatusCode)
			}
			return nil
		},
	}
}

// --- helpers ---------------------------------------------------------------

// loadCaddyConfig POSTs the JSON config to Caddy's /load endpoint. After this
// returns Caddy has the storage backend, the catch-all reverse proxy, and the
// placeholder on_demand block — EnsureOnDemandTLS rewrites the ask URL and
// appends the on-demand policy.
func loadCaddyConfig(t testing.TB, c *dockerfx.Container, body []byte) {
	t.Helper()
	port := c.HostPort("2019/tcp")
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+port+"/load", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("caddy /load: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		t.Fatalf("caddy /load failed: %d %s", resp.StatusCode, raw)
	}
}

// patchPebbleACME points the on-demand policy's ACME issuer at Pebble and
// pins Pebble's root as a trusted root. Must be called AFTER AddCustomDomain
// has driven EnsureOnDemandTLS — the policy at index 0 only exists after that.
func patchPebbleACME(t testing.TB, c *dockerfx.Container, rootsPEM []byte) {
	t.Helper()
	adminPort := c.HostPort("2019/tcp")
	dockerCpToContainer(t, c, rootsPEM, "/etc/pebble-root.pem")

	issuer := map[string]any{
		"module":                  "acme",
		"ca":                      "https://pebble:14000/dir",
		"trusted_roots_pem_files": []string{"/etc/pebble-root.pem"},
	}
	body, _ := json.Marshal([]any{issuer})
	req, _ := http.NewRequest(http.MethodPatch,
		"http://127.0.0.1:"+adminPort+"/config/apps/tls/automation/policies/0/issuers",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch issuers: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		t.Fatalf("patch issuers failed: %d %s", resp.StatusCode, raw)
	}
}

// dockerCpToContainer uploads a small file into a running container via the
// Docker daemon's /containers/{id}/archive endpoint. We tar the single file
// and PUT it at the destination directory.
func dockerCpToContainer(t testing.TB, c *dockerfx.Container, content []byte, dstPath string) {
	t.Helper()
	dir, name := filepath.Split(dstPath)
	if dir == "" {
		dir = "/"
	}
	tarBuf := makeSingleFileTar(name, content)
	q := url.Values{}
	q.Set("path", dir)
	u := "http://docker/containers/" + c.ID + "/archive?" + q.Encode()
	req, _ := http.NewRequest(http.MethodPut, u, bytes.NewReader(tarBuf))
	req.Header.Set("Content-Type", "application/x-tar")
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
		},
	}
	cli := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("docker cp: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		t.Fatalf("docker cp %s failed: %d %s", dstPath, resp.StatusCode, raw)
	}
}

func makeSingleFileTar(name string, content []byte) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o644,
		Size: int64(len(content)),
	}); err != nil {
		panic(err)
	}
	if _, err := tw.Write(content); err != nil {
		panic(err)
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func createS3Bucket(t testing.TB, ls *dockerfx.Container) {
	t.Helper()
	port := ls.HostPort("4566/tcp")
	req, _ := http.NewRequest(http.MethodPut, "http://127.0.0.1:"+port+"/"+e2eS3Bucket, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusConflict {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		t.Fatalf("create bucket failed: %d %s", resp.StatusCode, raw)
	}
}

func fetchPebbleRoots(t testing.TB, pebble *dockerfx.Container) []byte {
	t.Helper()
	port := pebble.HostPort("15000/tcp")
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	cli := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := cli.Get("https://127.0.0.1:" + port + "/roots/0")
	if err != nil {
		t.Fatalf("fetch pebble roots: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch pebble roots: status %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return raw
}

// pebbleIssuanceCount counts "Signing certificate" lines in Pebble's logs.
// Combined with PEBBLE_AUTHZREUSE=0 every cache miss produces a fresh order
// and a fresh log line — a reliable proxy for "new certs issued".
func pebbleIssuanceCount(pebble *dockerfx.Container) int {
	return pebble.LogContains("Signing certificate")
}

func mustGet(t testing.TB, c *http.Client, urlStr string) *http.Response {
	t.Helper()
	resp, err := c.Get(urlStr)
	if err != nil {
		t.Fatalf("GET %s: %v", urlStr, err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	return resp
}

// httpsClientForCaddy returns an http.Client whose TLS config trusts Pebble's
// root and whose dialer rewrites the custom hostname to the Caddy container's
// host-mapped 443 port.
func httpsClientForCaddy(t testing.TB, c *dockerfx.Container, rootsPEM []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootsPEM) {
		t.Fatalf("pebble root PEM did not parse")
	}
	hostPort := c.HostPort("443/tcp")
	if hostPort == "" {
		t.Fatalf("caddy 443 host port missing")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: e2eHostname},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == e2eHostname+":443" {
				addr = "127.0.0.1:" + hostPort
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// --- in-process sandboxd ---------------------------------------------------

type e2eHarness struct {
	svc        *service.Service
	store      *store.Store
	ingressSrv *http.Server
	ingressLn  net.Listener
	caddy      *caddy.Client
	cfg        config.Config
}

// startInProcessSandboxd builds a Service + TLS-ask handler bound to an
// ephemeral 0.0.0.0 port (so the Caddy container reaches it via
// host.docker.internal) and installs the on-demand TLS policy on Caddy.
func startInProcessSandboxd(t testing.TB, caddyCont *dockerfx.Container) *e2eHarness {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Config{
		EnableCustomDomains:        true,
		Domain:                     "aerol.cloud",
		CustomDomainsMaxPerSandbox: models.MaxCustomDomainsPerSandbox,
		TLSOnDemandBurst:           5,
		TLSOnDemandInterval:        5 * time.Second,
		HTTPClientTimeout:          5 * time.Second,
		EnableCaddy:                true,
		CaddyAdminURL:              "http://127.0.0.1:" + caddyCont.HostPort("2019/tcp"),
	}
	caddyClient := caddy.New(cfg)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.NewForE2ETest(cfg, logger, st, caddyClient)

	resolver := storeResolver{st: st}
	askHandler := ingressproxy.NewTLSAskHandler(ingressproxy.TLSAskDeps{
		Resolver:    resolver,
		BaseDomain:  cfg.Domain,
		NegCacheTTL: 60 * time.Second,
		NegCacheCap: 10000,
		Logger:      logger,
	})
	svc.AttachCustomDomainCacheEvicter(askHandler)

	mux := http.NewServeMux()
	ingressproxy.RegisterTLSAsk(mux, askHandler)

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen ingress: %v", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("ingress server stopped: %v", err)
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	askURL := fmt.Sprintf("http://host.docker.internal:%d%s",
		ln.Addr().(*net.TCPAddr).Port, ingressproxy.TLSAskPath)
	if err := caddyClient.EnsureOnDemandTLS(context.Background(), askURL,
		cfg.TLSOnDemandBurst, cfg.TLSOnDemandInterval); err != nil {
		t.Fatalf("EnsureOnDemandTLS: %v", err)
	}

	return &e2eHarness{
		svc:        svc,
		store:      st,
		ingressSrv: srv,
		ingressLn:  ln,
		caddy:      caddyClient,
		cfg:        cfg,
	}
}

// rewireSandboxdAt repoints the Service at a fresh Caddy container (the
// failover instance) and re-installs the on-demand TLS policy on it. The
// in-process ask handler keeps serving on the same loopback port.
func rewireSandboxdAt(t testing.TB, h *e2eHarness, caddyCont *dockerfx.Container) {
	t.Helper()
	newCfg := h.cfg
	newCfg.CaddyAdminURL = "http://127.0.0.1:" + caddyCont.HostPort("2019/tcp")
	newClient := caddy.New(newCfg)
	h.svc.SetCaddyClientForE2ETest(newClient)
	h.caddy = newClient
	h.cfg = newCfg

	askURL := fmt.Sprintf("http://host.docker.internal:%d%s",
		h.ingressLn.Addr().(*net.TCPAddr).Port, ingressproxy.TLSAskPath)
	if err := newClient.EnsureOnDemandTLS(context.Background(), askURL,
		newCfg.TLSOnDemandBurst, newCfg.TLSOnDemandInterval); err != nil {
		t.Fatalf("rewire EnsureOnDemandTLS: %v", err)
	}
}

// storeResolver is the single-node CustomDomainResolver — a thin shim over
// store.ResolveCustomDomain. The cluster-aware variant lives in
// cmd/sandboxd/main.go and isn't needed here.
type storeResolver struct{ st *store.Store }

func (r storeResolver) ResolveCustomDomain(ctx context.Context, hostname string) (string, error) {
	return r.st.ResolveCustomDomain(ctx, hostname)
}

func mustCreateE2ESandboxRow(t testing.TB, st *store.Store, id string) {
	t.Helper()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:           id,
		Image:        "test-image",
		Status:       models.SandboxStatusStarted,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
}

func portFromURL(t testing.TB, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split %q: %v", u.Host, err)
	}
	return port
}
