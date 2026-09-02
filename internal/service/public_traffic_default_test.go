package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression tests for the private-by-default flip: a create that does not
// pass allow_public_traffic=true must install no public route (and make zero
// caddy admin calls at all — not even the defensive delete), while opting in
// restores the old behavior. Legacy nil specs replayed by the failover
// recreate path must stay public.

func TestCreateSandboxPrivateByDefault(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	var caddyHits int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&caddyHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.Domain = "sandbox.test"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.test",
		HTTPClientTimeout: time.Second,
	})

	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox() error = %v", err)
	}
	if resp.PublicURL != "" {
		t.Fatalf("PublicURL = %q, want empty for a default (private) create", resp.PublicURL)
	}
	if got := atomic.LoadInt64(&caddyHits); got != 0 {
		t.Fatalf("caddy admin calls = %d, want 0 on a private create", got)
	}
	stored, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.AllowPublicTraffic == nil || *stored.AllowPublicTraffic {
		t.Fatalf("stored AllowPublicTraffic = %v, want explicit false", stored.AllowPublicTraffic)
	}
}

// TestExposePortOptsPrivateSandboxIn verifies the post-create opt-in lever:
// exposing a port on a default (private) sandbox installs BOTH the root
// <id>.<domain> route and the port route, persists flag + public_url, and is
// idempotent on re-expose.
func TestExposePortOptsPrivateSandboxIn(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.probeContainerPortFn = func(_ context.Context, _ string, _ int) error { return nil }

	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.Domain = "sandbox.test"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.test",
		HTTPClientTimeout: time.Second,
	})

	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox() error = %v", err)
	}
	if fake.hasHTTPRoute(caddy.SandboxRouteID(resp.ID)) {
		t.Fatal("root route installed at create for a private sandbox")
	}

	exposed, err := svc.ExposePort(ctx, resp.ID, 8080, "http")
	if err != nil {
		t.Fatalf("ExposePort() on a private sandbox should opt it in, got: %v", err)
	}
	if exposed.PublicURL == "" {
		t.Fatal("ExposePort() returned empty PublicURL")
	}
	if !fake.hasHTTPRoute(caddy.SandboxRouteID(resp.ID)) {
		t.Fatalf("root route %q not installed by the expose flip", caddy.SandboxRouteID(resp.ID))
	}
	if !fake.hasHTTPRoute(caddy.PortRouteID(resp.ID, 8080)) {
		t.Fatalf("port route %q not installed", caddy.PortRouteID(resp.ID, 8080))
	}
	stored, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.AllowPublicTraffic == nil || !*stored.AllowPublicTraffic {
		t.Fatalf("stored AllowPublicTraffic = %v, want explicit true after expose", stored.AllowPublicTraffic)
	}
	if stored.PublicURL == "" {
		t.Fatal("stored PublicURL empty after the expose flip; SetAllowPublicTraffic must refresh it")
	}

	again, err := svc.ExposePort(ctx, resp.ID, 8080, "http")
	if err != nil {
		t.Fatalf("re-expose after flip: %v", err)
	}
	if again.PublicURL != exposed.PublicURL {
		t.Fatalf("re-expose URL = %q, want %q (idempotent)", again.PublicURL, exposed.PublicURL)
	}
}

// TestEnablePublicTrafficStoreFailureRollsBackRoute verifies the other half
// of the flip's rollback rule: when the store write fails after the root
// route went in, the route is torn down and the in-memory sandbox reverts to
// private — caddy and the store never disagree past the helper.
func TestEnablePublicTrafficStoreFailureRollsBackRoute(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.Domain = "sandbox.test"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.test",
		HTTPClientTimeout: time.Second,
	})

	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox() error = %v", err)
	}
	sandbox, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	// Make the store write fail with ErrNotFound by removing the row out from
	// under the helper — the cheapest deterministic store failure the real
	// sqlite store can produce.
	if err := st.Delete(ctx, resp.ID); err != nil {
		t.Fatalf("store.Delete: %v", err)
	}
	if err := svc.enableSandboxPublicTraffic(ctx, sandbox); err == nil {
		t.Fatal("enableSandboxPublicTraffic should surface the store failure")
	}
	if fake.hasHTTPRoute(caddy.SandboxRouteID(resp.ID)) {
		t.Fatal("root route left installed after the store write failed; rollback must remove it")
	}
	if sandbox.AllowPublicTraffic == nil || *sandbox.AllowPublicTraffic {
		t.Fatalf("in-memory AllowPublicTraffic = %v after failed flip, want reverted to explicit false", sandbox.AllowPublicTraffic)
	}
}

// TestExposePortFlipCaddyFailureStaysPrivate verifies the flip's rollback
// rule: if the root-route install fails, ExposePort surfaces the error and
// the sandbox stays private in the store (flag false, empty public_url) — no
// half-public state.
func TestExposePortFlipCaddyFailureStaysPrivate(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.probeContainerPortFn = func(_ context.Context, _ string, _ int) error { return nil }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.Domain = "sandbox.test"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.test",
		HTTPClientTimeout: time.Second,
	})

	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox() error = %v (private create must not touch caddy)", err)
	}
	if _, err := svc.ExposePort(ctx, resp.ID, 8080, "http"); err == nil {
		t.Fatal("ExposePort should fail when the root-route install fails")
	}
	stored, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.AllowPublicTraffic == nil || *stored.AllowPublicTraffic {
		t.Fatalf("stored AllowPublicTraffic = %v, want still explicit false after failed flip", stored.AllowPublicTraffic)
	}
	if stored.PublicURL != "" {
		t.Fatalf("stored PublicURL = %q, want empty after failed flip", stored.PublicURL)
	}
}

func TestCreateSandboxOptInPublicInstallsRoute(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.Domain = "sandbox.test"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.test",
		HTTPClientTimeout: time.Second,
	})

	allowPublic := true
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:              "alpine:3.20",
		AllowPublicTraffic: &allowPublic,
	})
	if err != nil {
		t.Fatalf("CreateSandbox() error = %v", err)
	}
	if resp.PublicURL == "" {
		t.Fatal("PublicURL empty, want the sandbox URL for an opted-in create")
	}
	if !fake.hasHTTPRoute(caddy.SandboxRouteID(resp.ID)) {
		t.Fatalf("route %q not installed for an opted-in create", caddy.SandboxRouteID(resp.ID))
	}
	stored, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.AllowPublicTraffic == nil || !*stored.AllowPublicTraffic {
		t.Fatalf("stored AllowPublicTraffic = %v, want explicit true", stored.AllowPublicTraffic)
	}
}

func TestRecreateSandboxNilPublicFlagFailsPrivate(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	err := svc.RecreateSandbox(ctx, "sb-nil-public-flag", models.CreateSandboxRequest{
		Image: "alpine:3.20",
	}, cluster.PlacementSecrets{}, nil)
	if err != nil {
		t.Fatalf("RecreateSandbox() error = %v", err)
	}
	stored, err := st.Get(ctx, "sb-nil-public-flag")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.AllowPublicTraffic == nil || *stored.AllowPublicTraffic {
		t.Fatalf("stored AllowPublicTraffic = %v, want explicit false", stored.AllowPublicTraffic)
	}
}
