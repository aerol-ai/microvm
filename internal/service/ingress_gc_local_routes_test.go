package service

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestClusterIngressAuditKeepsALocalGatedPortsWakeRoute: the cluster ingress
// audit deletes every route in Caddy that neither a placement nor a local
// row explains. Its local list kept only the direct port route, so on the
// owner it deleted a token-gated port's wake route, the port's only route,
// and the gated URL answered Caddy's "Sandbox not found" for as long as the
// test waited (UC-426 on single-node-fc, 2026-11-07). It must keep that wake
// route, and like the zombie sweep it must not keep a direct route on the
// gated port, which would skip the token.
func TestClusterIngressAuditKeepsALocalGatedPortsWakeRoute(t *testing.T) {
	fake := newGCCaddyFake()
	const id = "sb-gated"
	fake.httpRouteIDs[caddy.SandboxRouteID(id)] = struct{}{}
	fake.httpRouteIDs[caddy.WakePortRouteID(id, 8080)] = struct{}{}
	fake.httpRouteIDs[caddy.PortRouteID(id, 8080)] = struct{}{} // skips the token: must go
	fake.httpRouteIDs[caddy.PortRouteID(id, 3000)] = struct{}{}
	fake.httpRouteIDs["sandbox-gone-port-1"] = struct{}{} // nothing explains it: must go
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	st, err := store.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: id, Image: "img", Status: models.SandboxStatusStarted,
		AllowPublicTraffic: privateFlag(true), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	for _, p := range []models.ExposedPort{
		{SandboxID: id, Port: 8080, Protocol: models.ExposedPortProtocolHTTP, Visibility: models.ExposedPortVisibilityToken},
		{SandboxID: id, Port: 3000, Protocol: models.ExposedPortProtocolHTTP},
	} {
		if err := st.UpsertPort(ctx, p); err != nil {
			t.Fatalf("store.UpsertPort %d: %v", p.Port, err)
		}
	}

	svc := &Service{
		cfg:    config.Config{EnableCluster: true},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		caddy: caddy.New(config.Config{
			CaddyAdminURL: server.URL, CaddyServerID: "srv0", EnableCaddy: true, HTTPClientTimeout: 5 * time.Second,
		}),
	}
	svc.AttachCluster(&stubIngressCluster{Noop: cluster.NewNoop("self", "http://self", "")})

	// The first pass is an audit pass (shouldRunClusterIngressFullGC).
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("ReconcileClusterIngress: %v", err)
	}
	want := []string{caddy.SandboxRouteID(id), caddy.PortRouteID(id, 3000), caddy.WakePortRouteID(id, 8080)}
	if got := fake.keys(fake.httpRouteIDs); !equalSorted(got, want) {
		t.Fatalf("http routes after the audit: got %v, want %v", got, want)
	}
}

// TestBothRouteSweepsKeepTheSameLocalRoutes: the zombie sweep and the
// cluster ingress audit keep one list for a local row (expectLocalSandboxRoutes),
// so a route kind one of them learns about can't be missing from the other:
// token-gated wake routes, serverless wake routes, custom-domain routes, L4.
func TestBothRouteSweepsKeepTheSameLocalRoutes(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableServerless: true}}
	rows := []*models.Sandbox{
		{
			ID: "sb-a", Status: models.SandboxStatusStarted, AllowPublicTraffic: privateFlag(true),
			ExposedPorts: []models.ExposedPort{
				{Port: 8080, Protocol: models.ExposedPortProtocolHTTP, Visibility: models.ExposedPortVisibilityToken},
				{Port: 3000},
				{Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 35432},
				{Port: 8443, Protocol: models.ExposedPortProtocolTLS},
			},
			CustomDomains: []models.CustomDomain{{Hostname: "app.example.com"}, {Hostname: ""}},
		},
		{
			ID: "sb-sls", Status: models.SandboxStatusStopped, AllowPublicTraffic: privateFlag(true),
			Lifecycle:    models.Lifecycle{Serverless: true},
			ExposedPorts: []models.ExposedPort{{Port: 9000, Protocol: models.ExposedPortProtocolHTTP}},
		},
	}
	h, tcp, tls := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	svc.addLocalIngressExpectedRoutes(h, tcp, tls, append(rows, nil, &models.Sandbox{ID: "gone", Status: models.SandboxStatusDestroyed}))

	wantHTTP := []string{
		caddy.SandboxRouteID("sb-a"),
		caddy.WakePortRouteID("sb-a", 8080),
		caddy.PortRouteID("sb-a", 3000),
		caddy.IngressCustomDomainHTTPRouteID("sb-a", "app.example.com"),
		caddy.SandboxRouteID("sb-sls"),
		caddy.PortRouteID("sb-sls", 9000),
		caddy.WakePortRouteID("sb-sls", 9000),
	}
	if got := keysOf(h); !equalSorted(got, sortedStrs(wantHTTP)) {
		t.Fatalf("http keep set: got %v, want %v", got, sortedStrs(wantHTTP))
	}
	if _, ok := h[caddy.PortRouteID("sb-a", 8080)]; ok {
		t.Fatal("a direct route on a token-gated port must not be kept")
	}
	if got := keysOf(tcp); !equalSorted(got, []string{"tcp-port-35432"}) {
		t.Fatalf("tcp keep set: %v", got)
	}
	if got := keysOf(tls); !equalSorted(got, []string{"sandbox-sb-a-port-8443-tls"}) {
		t.Fatalf("tls keep set: %v", got)
	}

	// The zombie sweep's list for the same rows is the same.
	zh, ztcp, ztls := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, sb := range rows {
		svc.expectLocalSandboxRoutes(zh, ztcp, ztls, sb)
	}
	if !equalSorted(keysOf(zh), keysOf(h)) || !equalSorted(keysOf(ztcp), keysOf(tcp)) || !equalSorted(keysOf(ztls), keysOf(tls)) {
		t.Fatalf("the two sweeps disagree: zombie %v %v %v, ingress %v %v %v", keysOf(zh), keysOf(ztcp), keysOf(ztls), keysOf(h), keysOf(tcp), keysOf(tls))
	}
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStrs(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
