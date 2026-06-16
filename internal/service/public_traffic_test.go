package service

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSyncPublicRoutesDeletesWhenPublicTrafficDisabled(t *testing.T) {
	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc := &Service{
		cfg:    config.Config{ToolboxPort: 2280},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy: caddy.New(config.Config{
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			Domain:            "example.test",
			EnableCaddy:       true,
			HTTPClientTimeout: 5 * time.Second,
		}),
	}

	deny := false
	sandbox := &models.Sandbox{
		ID:                 "sb-no-public",
		ContainerIP:        "10.0.0.2",
		AllowPublicTraffic: &deny,
		CustomDomains: []models.CustomDomain{
			{Hostname: "api.example.com"},
		},
	}
	defaultID := caddy.SandboxRouteID(sandbox.ID)
	customID := caddy.IngressCustomDomainHTTPRouteID(sandbox.ID, "api.example.com")
	fake.httpRouteIDs[defaultID] = struct{}{}
	fake.httpRouteIDs[customID] = struct{}{}

	if err := svc.syncSandboxPublicRoute(context.Background(), sandbox); err != nil {
		t.Fatalf("syncSandboxPublicRoute: %v", err)
	}
	if fake.hasHTTPRoute(defaultID) {
		t.Fatalf("default route %q should be deleted", defaultID)
	}
	if fake.hasHTTPRoute(customID) {
		t.Fatalf("custom-domain route %q should be deleted", customID)
	}
}

func TestSyncExposedPortRouteDeletesWhenPublicTrafficDisabled(t *testing.T) {
	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy: caddy.New(config.Config{
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			Domain:            "example.test",
			EnableCaddy:       true,
			HTTPClientTimeout: 5 * time.Second,
		}),
	}

	deny := false
	sandbox := &models.Sandbox{ID: "sb-no-public", AllowPublicTraffic: &deny}
	routeID := caddy.PortRouteID(sandbox.ID, 8080)
	fake.httpRouteIDs[routeID] = struct{}{}

	if err := svc.syncExposedPortRoute(context.Background(), sandbox, models.ExposedPort{
		SandboxID: sandbox.ID,
		Port:      8080,
		Protocol:  models.ExposedPortProtocolHTTP,
	}); err != nil {
		t.Fatalf("syncExposedPortRoute: %v", err)
	}
	if fake.hasHTTPRoute(routeID) {
		t.Fatalf("port route %q should be deleted", routeID)
	}
}

func TestCleanupPublicTrafficDisabledIngressStateDropsDataRows(t *testing.T) {
	ctx := context.Background()
	st, err := storepkg.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	deny := false
	now := time.Now().UTC()
	sandboxID := "sb-no-public-data"
	if err := st.Create(ctx, &models.Sandbox{
		ID:                 sandboxID,
		Image:              "alpine:3.20",
		Status:             models.SandboxStatusStarted,
		Runtime:            models.RuntimeDocker,
		AllowPublicTraffic: &deny,
		CreatedAt:          now,
		UpdatedAt:          now,
		LastActiveAt:       now,
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sandboxID,
		Port:      8080,
		Protocol:  models.ExposedPortProtocolHTTP,
		PublicURL: "https://sb-no-public-data-8080.example.test",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("store.UpsertPort: %v", err)
	}
	if err := st.AddCustomDomain(ctx, sandboxID, "api.example.com", 0); err != nil {
		t.Fatalf("store.AddCustomDomain: %v", err)
	}
	sandbox, err := st.Get(ctx, sandboxID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}

	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	defaultID := caddy.SandboxRouteID(sandboxID)
	portID := caddy.PortRouteID(sandboxID, 8080)
	customID := caddy.IngressCustomDomainHTTPRouteID(sandboxID, "api.example.com")
	fake.httpRouteIDs[defaultID] = struct{}{}
	fake.httpRouteIDs[portID] = struct{}{}
	fake.httpRouteIDs[customID] = struct{}{}

	svc := &Service{
		store:  st,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy: caddy.New(config.Config{
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			Domain:            "example.test",
			EnableCaddy:       true,
			HTTPClientTimeout: 5 * time.Second,
		}),
	}

	if err := svc.cleanupPublicTrafficDisabledIngressState(ctx, sandbox); err != nil {
		t.Fatalf("cleanupPublicTrafficDisabledIngressState: %v", err)
	}
	if fake.hasHTTPRoute(defaultID) || fake.hasHTTPRoute(portID) || fake.hasHTTPRoute(customID) {
		t.Fatalf("public routes should be deleted: default=%v port=%v custom=%v",
			fake.hasHTTPRoute(defaultID), fake.hasHTTPRoute(portID), fake.hasHTTPRoute(customID))
	}
	refreshed, err := st.Get(ctx, sandboxID)
	if err != nil {
		t.Fatalf("store.Get refreshed: %v", err)
	}
	if len(refreshed.ExposedPorts) != 0 {
		t.Fatalf("ExposedPorts = %+v, want empty", refreshed.ExposedPorts)
	}
	if len(refreshed.CustomDomains) != 0 {
		t.Fatalf("CustomDomains = %+v, want empty", refreshed.CustomDomains)
	}
	if len(sandbox.ExposedPorts) != 0 || len(sandbox.CustomDomains) != 0 {
		t.Fatalf("sandbox in-memory ingress state not cleared: ports=%+v domains=%+v", sandbox.ExposedPorts, sandbox.CustomDomains)
	}
}
