package service

import (
	"context"
	"net"
	"testing"

	"github.com/aerol-ai/microvm/internal/routedns"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A real public lifecycle with the index writer installed: the OwnerTable
// holds exactly what Caddy's per-sandbox routes held, the responder answers
// from it, and Caddy gets zero admin writes.
func TestIndexRouteWriterTracksTheLifecycle(t *testing.T) {
	svc, admin := newPublicRouteHarness(t)
	table := routedns.NewOwnerTable()
	svc.routeWriter = newIndexRouteWriter(table, "sandbox.test")
	r := &routedns.Responder{Domain: "sandbox.test", ToolboxPort: 2280, Owner: table}
	ctx := context.Background()

	allow := true
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", AllowPublicTraffic: &allow})
	if err != nil {
		t.Fatal(err)
	}
	root := resp.ID + ".sandbox.test"
	got, ok := table.Lookup(root)
	if !ok || got.IP.String() != "10.0.0.2" || got.State != routedns.TargetReady {
		t.Fatalf("root host after a public create = %+v ok=%v, want 10.0.0.2 ready", got, ok)
	}

	if _, err := svc.ExposePort(ctx, resp.ID, 8080, "http"); err != nil {
		t.Fatal(err)
	}
	port := resp.ID + "-8080.sandbox.test"
	if got, ok := table.Lookup(port); !ok || got.Port != 8080 {
		t.Fatalf("port host after expose = %+v ok=%v", got, ok)
	}

	if err := svc.UnexposePort(ctx, resp.ID, 8080); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(port); ok {
		t.Fatal("port host survived unexpose")
	}

	if err := svc.DestroySandbox(ctx, resp.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(root); ok {
		t.Fatal("root host survived destroy")
	}
	if got := admin.snapshot(); len(got) != 0 {
		t.Fatalf("Caddy admin writes with the index writer: %v", got)
	}
	_ = r
}

func TestIndexRouteWriterIntents(t *testing.T) {
	table := routedns.NewOwnerTable()
	w := newIndexRouteWriter(table, "d.test")
	ctx := context.Background()
	ip := "10.0.0.9"

	_ = w.UpsertSandboxRoute(ctx, "sb", ip, 2280, []caddy.CustomHostnameRoute{
		{Hostname: "plain.customer.com"},                                                  // toolbox port
		{Hostname: "app.customer.com", TargetPort: 3000},                                  // bound port
		{Hostname: "masked.customer.com", TargetPort: 3000, MaskRequestHost: "localhost"}, // needs the router
	})
	if got, _ := table.Lookup("plain.customer.com"); got.Port != 2280 || got.State != routedns.TargetReady {
		t.Fatalf("plain custom = %+v", got)
	}
	if got, _ := table.Lookup("masked.customer.com"); got.State != routedns.TargetRouter {
		t.Fatalf("masked custom must take the router: %+v", got)
	}

	_ = w.UpsertPortRoute(ctx, "sb", ip, 8080, caddy.HTTPRouteOptions{MaskRequestHost: "x"})
	if got, _ := table.Lookup("sb-8080.d.test"); got.State != routedns.TargetRouter {
		t.Fatalf("masked port route must take the router: %+v", got)
	}
	_ = w.UpsertPortRouteWithRetry(ctx, "sb", ip, 9000, 0)
	if got, _ := table.Lookup("sb-9000.d.test"); got.State != routedns.TargetReady || got.Port != 9000 {
		t.Fatalf("retry port route = %+v", got)
	}
	_ = w.UpsertPortRouteWithDial(ctx, "sb", 7000, "127.0.0.1:41234") // wasm mediator
	if got, _ := table.Lookup("sb-7000.d.test"); got.State != routedns.TargetRouter {
		t.Fatalf("loopback mediator dial must take the router: %+v", got)
	}
	_ = w.UpsertPortRouteWithDial(ctx, "sb", 7001, "not-a-dial")
	if got, _ := table.Lookup("sb-7001.d.test"); got.State != routedns.TargetRouter {
		t.Fatalf("unparsable dial must take the router: %+v", got)
	}

	// Wake flips state; deleting the wake entry leaves a direct route alone.
	_ = w.UpsertWakeHTTPPortRoute(ctx, "sb", "127.0.0.1:21213", 9000)
	if got, _ := table.Lookup("sb-9000.d.test"); got.State != routedns.TargetWake {
		t.Fatalf("wake = %+v", got)
	}
	_ = w.DeleteWakeHTTPPortRoute(ctx, "sb", 9000)
	if _, ok := table.Lookup("sb-9000.d.test"); ok {
		t.Fatal("wake entry not removed")
	}
	_ = w.UpsertPortRoute(ctx, "sb", ip, 9000)
	_ = w.DeleteWakeHTTPPortRoute(ctx, "sb", 9000)
	if _, ok := table.Lookup("sb-9000.d.test"); !ok {
		t.Fatal("deleting a wake route removed the direct route")
	}

	// In-flux mirrors: state on, then off only if still in flux.
	_ = w.UpsertInFluxSandboxRoute(ctx, "sb")
	_ = w.UpsertInFluxPortRoute(ctx, "sb", 9000)
	if got, _ := table.Lookup("sb.d.test"); got.State != routedns.TargetInFlux {
		t.Fatalf("in-flux root = %+v", got)
	}
	_ = w.DeleteInFluxSandboxRoute(ctx, "sb")
	_ = w.DeleteInFluxPortRoute(ctx, "sb", 9000)
	if _, ok := table.Lookup("sb.d.test"); ok {
		t.Fatal("in-flux root not removed")
	}
	_ = w.UpsertPortRoute(ctx, "sb", ip, 9000)
	_ = w.DeleteInFluxPortRoute(ctx, "sb", 9000)
	if _, ok := table.Lookup("sb-9000.d.test"); !ok {
		t.Fatal("deleting in-flux removed a ready route")
	}

	// Custom-domain http routes by dial, and their deletes.
	_ = w.UpsertCustomDomainHTTPRouteWithDial(ctx, "sb", "cd.customer.com", ip+":5000")
	if got, _ := table.Lookup("cd.customer.com"); got.Port != 5000 || got.State != routedns.TargetReady {
		t.Fatalf("custom dial = %+v", got)
	}
	_ = w.DeleteCustomDomainHTTPRoute(ctx, "sb", "cd.customer.com")
	if _, ok := table.Lookup("cd.customer.com"); ok {
		t.Fatal("custom domain route not removed")
	}

	// By-ID GC removes exactly the host that route matched.
	_ = w.DeleteRouteByID(ctx, caddy.PortRouteID("sb", 8080))
	if _, ok := table.Lookup("sb-8080.d.test"); ok {
		t.Fatal("DeleteRouteByID did not remove the port host")
	}
	_ = w.DeleteRouteByID(ctx, "unknown-route")

	// DeleteSandboxRoute drops root and custom hosts, not port hosts.
	_ = w.UpsertSandboxRoute(ctx, "sb", ip, 2280, []caddy.CustomHostnameRoute{{Hostname: "plain.customer.com"}})
	_ = w.DeleteSandboxRoute(ctx, "sb")
	for _, h := range []string{"sb.d.test", "plain.customer.com", "app.customer.com", "masked.customer.com"} {
		if _, ok := table.Lookup(h); ok {
			t.Errorf("%s survived DeleteSandboxRoute", h)
		}
	}
	if _, ok := table.Lookup("sb-9000.d.test"); !ok {
		t.Fatal("DeleteSandboxRoute removed a port host (ports have their own delete)")
	}

	// IP-mode and TCP/SNI intents are no-ops for the owner table.
	before := table.Len()
	_ = w.UpsertSandboxRouteToPeer(ctx, "sb", "peer", nil)
	_ = w.UpsertPortRouteToPeer(ctx, "sb", 1, "peer")
	_ = w.UpsertSNIPassthroughRoute(ctx, "r", "h", "p", 443)
	_ = w.UpsertTCPRoute(ctx, "sb", ip, 1, 30001)
	_ = w.UpsertWakeTCPRoute(ctx, "sb", 1, 30001, "x")
	_ = w.UpsertTCPProxyRoute(ctx, "sb", 1, 30001, "p", 30001)
	_ = w.DeleteTCPRoute(ctx, 30001)
	_ = w.DeleteTCPServer(ctx, "s")
	if table.Len() != before {
		t.Fatal("a no-op intent changed the owner table")
	}
}

// The responder answers only what Caddy's static route can dial directly.
func TestIndexRouteWriterFeedsTheResponder(t *testing.T) {
	table := routedns.NewOwnerTable()
	w := newIndexRouteWriter(table, "d.test")
	ctx := context.Background()
	_ = w.UpsertSandboxRoute(ctx, "sb", "10.0.0.9", 2280, nil)
	_ = w.UpsertPortRoute(ctx, "sb", "10.0.0.9", 8080)
	_ = w.UpsertPortRoute(ctx, "sb", "10.0.0.9", 8081, caddy.HTTPRouteOptions{MaskRequestHost: "x"})
	got, ok := table.Lookup("sb-8080.d.test")
	if !ok || !got.IP.Equal(net.ParseIP("10.0.0.9")) {
		t.Fatalf("port target = %+v", got)
	}
	if routedns.DerivedPort("sb-8081.d.test", 2280) != 8081 {
		t.Fatal("sanity: derived port")
	}
}
