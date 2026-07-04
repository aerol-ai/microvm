package service

import (
	"context"
	"errors"
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
	if _, err := svc.ExposePort(ctx, resp.ID, 8080, "http"); !errors.Is(err, ErrPublicTrafficDisabled) {
		t.Fatalf("ExposePort() error = %v, want ErrPublicTrafficDisabled", err)
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

func TestRecreateSandboxLegacyNilSpecStaysPublic(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	// A replicated spec written before the private-by-default flip has a nil
	// flag; failover recreate must pin it to public rather than letting the
	// createSandbox normalization silently flip reachability.
	err := svc.RecreateSandbox(ctx, "sb-legacy-nil-flag", models.CreateSandboxRequest{
		Image: "alpine:3.20",
	}, cluster.PlacementSecrets{}, nil)
	if err != nil {
		t.Fatalf("RecreateSandbox() error = %v", err)
	}
	stored, err := st.Get(ctx, "sb-legacy-nil-flag")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.AllowPublicTraffic == nil || !*stored.AllowPublicTraffic {
		t.Fatalf("stored AllowPublicTraffic = %v, want explicit true for a legacy nil spec", stored.AllowPublicTraffic)
	}
}
