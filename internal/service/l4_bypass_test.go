package service

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// shortSockDir returns a tempdir under /tmp (or /var/tmp as a fallback)
// to keep AF_UNIX socket paths under the platform limit (~104 chars on
// Darwin, 108 on Linux). t.TempDir() resolves to
// $TMPDIR/TestLongTestName.../001 which on macOS uses /var/folders/.../T,
// pushing combined paths past the bind limit when the test name is
// long. AF_UNIX sockets created by ensureTLSWakeListener live as
// {dir}/{id}-{port}.sock, so the dir slack we have is roughly 80 chars.
func shortSockDir(t *testing.T) string {
	t.Helper()
	for _, base := range []string{"/tmp", "/var/tmp"} {
		if _, err := os.Stat(base); err == nil {
			dir, err := os.MkdirTemp(base, "l4w")
			if err == nil {
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
				return dir
			}
		}
	}
	return t.TempDir()
}

// l4Fake records the Caddy admin operations install{TCP,TLS}PortRoute
// performs against the layer4 admin surface. Distinct from routeFake
// (HTTP servers) because L4 admin paths live under
// /config/apps/layer4/servers/{tcp-port-N}, the boot probe needs a
// minimal 200 on /config/apps/layer4, and TLS routes use the same
// /id/{routeID} surface but the install path also performs an SNI mux
// PUT that the HTTP fake does not need to handle.
type l4Fake struct {
	mu               sync.Mutex
	tcpServers       map[string]map[string]any
	tcpServerDeletes map[string]int
	tlsRoutes        map[string]map[string]any
	tlsRouteDeletes  map[string]int
}

func newL4Fake() *l4Fake {
	return &l4Fake{
		tcpServers:       map[string]map[string]any{},
		tcpServerDeletes: map[string]int{},
		tlsRoutes:        map[string]map[string]any{},
		tlsRouteDeletes:  map[string]int{},
	}
}

func (f *l4Fake) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// Layer4 bootstrap probe — EnsureLayer4Ready GETs and possibly PUTs.
		case r.URL.Path == "/config/apps/layer4":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
		// TLS mux server existence probe / install — caddy.Client may
		// GET the SNI mux server before patching individual routes.
		case strings.HasPrefix(r.URL.Path, "/config/apps/layer4/servers/tls-sni"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
		case strings.HasPrefix(r.URL.Path, "/config/apps/layer4/servers/"):
			id := strings.TrimPrefix(r.URL.Path, "/config/apps/layer4/servers/")
			f.mu.Lock()
			defer f.mu.Unlock()
			switch r.Method {
			case http.MethodPost, http.MethodPut:
				body, _ := io.ReadAll(r.Body)
				var parsed map[string]any
				_ = json.Unmarshal(body, &parsed)
				f.tcpServers[id] = parsed
				w.WriteHeader(http.StatusOK)
			case http.MethodDelete:
				f.tcpServerDeletes[id]++
				if _, ok := f.tcpServers[id]; !ok {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				delete(f.tcpServers, id)
				w.WriteHeader(http.StatusOK)
			default:
				t.Fatalf("unexpected method %s on %s", r.Method, r.URL.Path)
			}
		case strings.HasPrefix(r.URL.Path, "/id/"):
			id := strings.TrimPrefix(r.URL.Path, "/id/")
			f.mu.Lock()
			defer f.mu.Unlock()
			switch r.Method {
			case http.MethodPatch:
				body, _ := io.ReadAll(r.Body)
				var parsed map[string]any
				_ = json.Unmarshal(body, &parsed)
				if _, ok := f.tlsRoutes[id]; !ok {
					// caddy.Client falls back to insert-via-server-PUT
					// when PATCH returns 404. The HTTP install path uses
					// this idiom too; surfacing 404 here exercises that
					// fallback faithfully.
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				f.tlsRoutes[id] = parsed
				w.WriteHeader(http.StatusOK)
			case http.MethodDelete:
				f.tlsRouteDeletes[id]++
				if _, ok := f.tlsRoutes[id]; !ok {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				delete(f.tlsRoutes, id)
				w.WriteHeader(http.StatusOK)
			default:
				t.Fatalf("unexpected method %s on %s", r.Method, r.URL.Path)
			}
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	})
}

func (f *l4Fake) tcpServerIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.tcpServers))
	for id := range f.tcpServers {
		out = append(out, id)
	}
	return out
}

func (f *l4Fake) tcpServer(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tcpServers[id]
}

func newL4TestService(t *testing.T, fake *l4Fake, cfg config.Config) *Service {
	t.Helper()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	cfg.CaddyAdminURL = server.URL
	cfg.CaddyServerID = "srv0"
	cfg.Domain = "sandbox.example.com"
	cfg.EnableCaddy = true
	if cfg.HTTPClientTimeout == 0 {
		cfg.HTTPClientTimeout = 2 * time.Second
	}
	if cfg.InternalL4WakeAddr == "" {
		cfg.InternalL4WakeAddr = "127.0.0.1:21214"
	}
	if cfg.InternalL4WakeDir == "" {
		cfg.InternalL4WakeDir = shortSockDir(t)
	}
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddy.New(cfg),
		cfg:    cfg,
	}
	// Skip the layer4 bootstrap dance — the fake answers 200 unconditionally.
	svc.l4Ready.Store(true)
	return svc
}

// dialsAddress walks the recorded layer4 server config and returns the
// first upstream dial target. The install path nests dials at
// routes[].handle[].upstreams[].dial[]; pulling the first string at that
// depth is enough to distinguish a direct upstream
// (containerIP:port) from a wake target (cfg.InternalL4WakeAddr).
func dialsAddress(server map[string]any) string {
	routes, _ := server["routes"].([]any)
	if len(routes) == 0 {
		return ""
	}
	route, _ := routes[0].(map[string]any)
	handles, _ := route["handle"].([]any)
	if len(handles) == 0 {
		return ""
	}
	handle, _ := handles[0].(map[string]any)
	ups, _ := handle["upstreams"].([]any)
	if len(ups) == 0 {
		return ""
	}
	upstream, _ := ups[0].(map[string]any)
	dials, _ := upstream["dial"].([]any)
	if len(dials) == 0 {
		return ""
	}
	dial, _ := dials[0].(string)
	return dial
}

func tlsDialAddress(server map[string]any) string {
	handles, _ := server["handle"].([]any)
	if len(handles) < 2 {
		return ""
	}
	handle, _ := handles[1].(map[string]any)
	ups, _ := handle["upstreams"].([]any)
	if len(ups) == 0 {
		return ""
	}
	upstream, _ := ups[0].(map[string]any)
	dials, _ := upstream["dial"].([]any)
	if len(dials) == 0 {
		return ""
	}
	dial, _ := dials[0].(string)
	return dial
}

// proxyProtocolFor returns the proxy_protocol setting on the first
// handle of the first route — wake-aware TCP sets "v1" so sandboxd can
// recover the hostPort from the PROXY v1 header; direct upstreams omit
// it entirely. The string return distinguishes "" (direct) from "v1"
// (wake) cleanly in test assertions.
func proxyProtocolFor(server map[string]any) string {
	routes, _ := server["routes"].([]any)
	if len(routes) == 0 {
		return ""
	}
	route, _ := routes[0].(map[string]any)
	handles, _ := route["handle"].([]any)
	if len(handles) == 0 {
		return ""
	}
	handle, _ := handles[0].(map[string]any)
	pp, _ := handle["proxy_protocol"].(string)
	return pp
}

// TestInstallTCPPortRouteWakeWhenL4BypassDisabled — the Phase 2 gate
// off: every serverless TCP exposure still publishes the wake-aware
// shape regardless of Started/Stopped. This is the pre-rollout
// guarantee — flipping HTTP bypass on must NOT incidentally flip L4
// onto the bypass too.
func TestInstallTCPPortRouteWakeWhenL4BypassDisabled(t *testing.T) {
	fake := newL4Fake()
	svc := newL4TestService(t, fake, config.Config{
		EnableServerless:            true,
		HTTPWakeDirectBypassEnabled: true, // HTTP on, L4 off — kinds are independent
		L4WakeDirectBypassEnabled:   false,
	})
	sb := &models.Sandbox{
		ID:          "tcp-warm",
		Status:      models.SandboxStatusStarted,
		ContainerIP: "10.0.0.50",
		Lifecycle:   models.Lifecycle{Serverless: true},
	}
	if err := svc.installTCPPortRoute(context.Background(), sb, 5432, 37001); err != nil {
		t.Fatalf("installTCPPortRoute: %v", err)
	}
	srv := fake.tcpServer("tcp-port-37001")
	if srv == nil {
		t.Fatalf("expected tcp-port-37001 server to be published; servers=%v", fake.tcpServerIDs())
	}
	if got := proxyProtocolFor(srv); got != "v1" {
		t.Fatalf("L4 bypass off: warm serverless TCP must still get wake shape (proxy_protocol v1); got %q", got)
	}
}

// TestInstallTCPPortRouteDirectWhenL4BypassEnabled — the Phase 2
// payoff: with the L4 flag on, a warm (Started + ContainerIP) serverless
// sandbox publishes the direct-upstream server config (no proxy_protocol).
// Cold serverless traffic still routes through sandboxd; this only
// drops the sandboxd hop while the sandbox is warm.
func TestInstallTCPPortRouteDirectWhenL4BypassEnabled(t *testing.T) {
	fake := newL4Fake()
	svc := newL4TestService(t, fake, config.Config{
		EnableServerless:          true,
		L4WakeDirectBypassEnabled: true,
	})
	sb := &models.Sandbox{
		ID:          "tcp-warm",
		Status:      models.SandboxStatusStarted,
		ContainerIP: "10.0.0.50",
		Lifecycle:   models.Lifecycle{Serverless: true},
	}
	if err := svc.installTCPPortRoute(context.Background(), sb, 5432, 37002); err != nil {
		t.Fatalf("installTCPPortRoute: %v", err)
	}
	srv := fake.tcpServer("tcp-port-37002")
	if srv == nil {
		t.Fatalf("expected tcp-port-37002 server to be published")
	}
	if got := proxyProtocolFor(srv); got != "" {
		t.Fatalf("L4 bypass on warm: direct shape must omit proxy_protocol; got %q", got)
	}
	if got := dialsAddress(srv); got != "10.0.0.50:5432" {
		t.Fatalf("warm direct dial = %q, want containerIP:port", got)
	}
}

// TestInstallTCPPortRouteWakeWhenStoppedArmedBypassOn — cold serverless
// traffic must continue to go through sandboxd. The bypass flag does
// not change the cold-path: it strips the per-request hop only while
// the sandbox is warm.
func TestInstallTCPPortRouteWakeWhenStoppedArmedBypassOn(t *testing.T) {
	fake := newL4Fake()
	svc := newL4TestService(t, fake, config.Config{
		EnableServerless:          true,
		L4WakeDirectBypassEnabled: true,
	})
	sb := &models.Sandbox{
		ID:        "tcp-cold",
		Status:    models.SandboxStatusStopped,
		WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true},
	}
	if err := svc.installTCPPortRoute(context.Background(), sb, 5432, 37003); err != nil {
		t.Fatalf("installTCPPortRoute: %v", err)
	}
	srv := fake.tcpServer("tcp-port-37003")
	if srv == nil {
		t.Fatalf("expected tcp-port-37003 server published")
	}
	if got := proxyProtocolFor(srv); got != "v1" {
		t.Fatalf("Stopped+armed must publish wake shape (proxy_protocol v1); got %q", got)
	}
	if got := dialsAddress(srv); got != svc.cfg.InternalL4WakeAddr {
		t.Fatalf("cold wake dial = %q, want InternalL4WakeAddr %q", got, svc.cfg.InternalL4WakeAddr)
	}
}

// TestInstallTCPPortRouteNoneWhenStoppedUnarmedBypassOn — a serverless
// sandbox that was manually stopped (WakeArmed=false) must NOT auto-
// resume on inbound TCP. Under Phase 2 the server is removed entirely;
// kernel-RST on connect is the correct affordance. Today (bypass off)
// this case would have left a wake route published, which is the
// behavior the flag rolls back to on disable.
func TestInstallTCPPortRouteNoneWhenStoppedUnarmedBypassOn(t *testing.T) {
	fake := newL4Fake()
	// Pre-seed a leftover server so the test proves Delete is called,
	// not just "not POSTed."
	fake.tcpServers["tcp-port-37004"] = map[string]any{"@id": "sandbox-tcp-unarmed-port-5432-tcp"}
	svc := newL4TestService(t, fake, config.Config{
		EnableServerless:          true,
		L4WakeDirectBypassEnabled: true,
	})
	sb := &models.Sandbox{
		ID:        "tcp-unarmed",
		Status:    models.SandboxStatusStopped,
		WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true},
	}
	if err := svc.installTCPPortRoute(context.Background(), sb, 5432, 37004); err != nil {
		t.Fatalf("installTCPPortRoute: %v", err)
	}
	if fake.tcpServerDeletes["tcp-port-37004"] == 0 {
		t.Fatalf("stopped-unarmed serverless TCP must DELETE the L4 server; deletes=%+v", fake.tcpServerDeletes)
	}
	if _, ok := fake.tcpServers["tcp-port-37004"]; ok {
		t.Fatalf("server still present after delete; servers=%v", fake.tcpServerIDs())
	}
}

// TestInstallTCPPortRouteNonServerlessAlwaysDirect — the L4 flag is a
// serverless-only knob; non-serverless TCP exposures continue to publish
// the direct upstream regardless of flag state. Without this guarantee,
// flipping the L4 flag would silently route every non-serverless TCP
// exposure through sandboxd for the duration of the rollout.
func TestInstallTCPPortRouteNonServerlessAlwaysDirect(t *testing.T) {
	fake := newL4Fake()
	svc := newL4TestService(t, fake, config.Config{
		EnableServerless:          true,
		L4WakeDirectBypassEnabled: true,
	})
	sb := &models.Sandbox{
		ID:          "tcp-non-sls",
		Status:      models.SandboxStatusStarted,
		ContainerIP: "10.0.0.51",
		Lifecycle:   models.Lifecycle{Serverless: false},
	}
	if err := svc.installTCPPortRoute(context.Background(), sb, 5432, 37005); err != nil {
		t.Fatalf("installTCPPortRoute: %v", err)
	}
	srv := fake.tcpServer("tcp-port-37005")
	if srv == nil {
		t.Fatalf("expected non-serverless tcp-port-37005 server published")
	}
	if got := proxyProtocolFor(srv); got != "" {
		t.Fatalf("non-serverless must always be direct; got proxy_protocol %q", got)
	}
}

func TestInstallTLSPortRouteDirectWakeAndNone(t *testing.T) {
	fake := newL4Fake()
	svc := newL4TestService(t, fake, config.Config{
		EnableServerless:            true,
		L4WakeDirectBypassEnabled:   true,
		TLSWakeListenerCloseDelay:   0,
		HTTPWakeDirectBypassEnabled: true,
	})
	ctx := context.Background()

	directID := testTLSRouteID("tls-direct", 8443)
	fake.tlsRoutes[directID] = map[string]any{"@id": directID}
	if err := svc.installTLSPortRoute(ctx, &models.Sandbox{
		ID:          "tls-direct",
		Status:      models.SandboxStatusStarted,
		ContainerIP: "10.0.0.60",
		Lifecycle:   models.Lifecycle{Serverless: true},
	}, 8443); err != nil {
		t.Fatalf("installTLSPortRoute direct: %v", err)
	}
	if got := tlsDialAddress(fake.tlsRoutes[directID]); got != "10.0.0.60:8443" {
		t.Fatalf("direct TLS dial = %q, want containerIP:port", got)
	}

	wakeID := testTLSRouteID("tls-wake", 8443)
	fake.tlsRoutes[wakeID] = map[string]any{"@id": wakeID}
	wakePath, err := svc.ensureTLSWakeListener("tls-wake", 8443)
	if err != nil {
		t.Fatalf("ensureTLSWakeListener(wake): %v", err)
	}
	if err := svc.installTLSPortRoute(ctx, &models.Sandbox{
		ID:        "tls-wake",
		Status:    models.SandboxStatusStopped,
		WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true},
	}, 8443); err != nil {
		t.Fatalf("installTLSPortRoute wake: %v", err)
	}
	if got := tlsDialAddress(fake.tlsRoutes[wakeID]); got != "unix//"+strings.TrimPrefix(wakePath, "/") {
		t.Fatalf("wake TLS dial = %q, want unix wake socket", got)
	}

	noneID := testTLSRouteID("tls-none", 8443)
	fake.tlsRoutes[noneID] = map[string]any{"@id": noneID}
	if _, err := svc.ensureTLSWakeListener("tls-none", 8443); err != nil {
		t.Fatalf("ensureTLSWakeListener(none): %v", err)
	}
	if err := svc.installTLSPortRoute(ctx, &models.Sandbox{
		ID:        "tls-none",
		Status:    models.SandboxStatusStopped,
		WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true},
	}, 8443); err != nil {
		t.Fatalf("installTLSPortRoute none: %v", err)
	}
	if fake.tlsRouteDeletes[noneID] == 0 {
		t.Fatalf("none TLS route should be deleted, deletes=%+v", fake.tlsRouteDeletes)
	}
	if _, ok := svc.l4WakeTLS[tlsWakeKey("tls-none", 8443)]; ok {
		t.Fatal("none shape should close the wake listener")
	}
	svc.closeAllTLSWakeListeners()
	if len(svc.l4WakeTLS) != 0 {
		t.Fatalf("closeAllTLSWakeListeners should clear all listeners, got %d", len(svc.l4WakeTLS))
	}
}

// TestScheduleTLSWakeListenerCloseInlineWhenZero — the helper is the
// only place that decides whether to honor a grace window; passing
// delay=0 must close immediately so production code that wants the
// classic "close now" behavior (idempotent cleanup paths, tests) can
// share one helper without sleeping.
func TestScheduleTLSWakeListenerCloseInlineWhenZero(t *testing.T) {
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:    config.Config{InternalL4WakeDir: shortSockDir(t)},
	}
	if _, err := svc.ensureTLSWakeListener("tls-zero", 443); err != nil {
		t.Fatalf("ensureTLSWakeListener: %v", err)
	}
	svc.scheduleTLSWakeListenerClose("tls-zero", 443, 0)
	if _, ok := svc.l4WakeTLS[tlsWakeKey("tls-zero", 443)]; ok {
		t.Fatalf("zero-delay schedule must close listener inline")
	}
	if _, ok := svc.pendingTLSClose[tlsWakeKey("tls-zero", 443)]; ok {
		t.Fatalf("zero-delay schedule must not register a pending timer")
	}
}

// TestScheduleTLSWakeListenerCloseDelaysListenerRemoval — D2 explicitly:
// the listener stays alive across the schedule call, and only the
// timer firing closes it. The PATCH-then-close ordering depends on
// this: if scheduling closed synchronously, an in-flight handshake
// against the wake socket would drop the moment the new direct route
// landed.
func TestScheduleTLSWakeListenerCloseDelaysListenerRemoval(t *testing.T) {
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:    config.Config{InternalL4WakeDir: shortSockDir(t)},
	}
	if _, err := svc.ensureTLSWakeListener("tls-delay", 443); err != nil {
		t.Fatalf("ensureTLSWakeListener: %v", err)
	}
	key := tlsWakeKey("tls-delay", 443)
	svc.scheduleTLSWakeListenerClose("tls-delay", 443, 25*time.Millisecond)
	svc.l4WakeMu.Lock()
	_, listenerStillAlive := svc.l4WakeTLS[key]
	_, timerRegistered := svc.pendingTLSClose[key]
	svc.l4WakeMu.Unlock()
	if !listenerStillAlive {
		t.Fatalf("listener removed before grace window elapsed; would drop in-flight TLS handshake")
	}
	if !timerRegistered {
		t.Fatalf("pending close timer must be registered for the grace window")
	}
	// Wait past the delay; AfterFunc fires from its own goroutine, so
	// poll briefly rather than racing time.Sleep against the timer.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		svc.l4WakeMu.Lock()
		_, still := svc.l4WakeTLS[key]
		svc.l4WakeMu.Unlock()
		if !still {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("listener never closed after grace window elapsed")
}

// TestEnsureTLSWakeListenerCancelsPendingClose — the cold→warm→cold
// race: a delayed close from the previous warm transition must NOT
// tear down a socket that the new wake route depends on. Without this
// cancellation, the operator-observable failure is a stopped serverless
// sandbox whose first inbound TLS handshake silently goes nowhere
// (the socket vanished mid-route).
func TestEnsureTLSWakeListenerCancelsPendingClose(t *testing.T) {
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:    config.Config{InternalL4WakeDir: shortSockDir(t)},
	}
	if _, err := svc.ensureTLSWakeListener("tls-flip", 443); err != nil {
		t.Fatalf("ensureTLSWakeListener (initial cold): %v", err)
	}
	key := tlsWakeKey("tls-flip", 443)
	// Schedule a far-future close — long enough that if cancellation
	// fails to land, the test would still observe the timer present.
	svc.scheduleTLSWakeListenerClose("tls-flip", 443, time.Hour)
	svc.l4WakeMu.Lock()
	_, hadTimer := svc.pendingTLSClose[key]
	svc.l4WakeMu.Unlock()
	if !hadTimer {
		t.Fatalf("expected pending timer registered before flip-back")
	}
	// Simulate cold-again: ensureTLSWakeListener must cancel the timer.
	if _, err := svc.ensureTLSWakeListener("tls-flip", 443); err != nil {
		t.Fatalf("ensureTLSWakeListener (flip-back cold): %v", err)
	}
	svc.l4WakeMu.Lock()
	_, stillPending := svc.pendingTLSClose[key]
	_, listenerAlive := svc.l4WakeTLS[key]
	svc.l4WakeMu.Unlock()
	if stillPending {
		t.Fatalf("ensure-after-schedule must cancel pending close; would erase the new wake socket")
	}
	if !listenerAlive {
		t.Fatalf("listener missing after re-ensure")
	}
}
