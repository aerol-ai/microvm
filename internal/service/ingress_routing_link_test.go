package service

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/routedns"
	"github.com/aerol-ai/microvm/pkg/caddy"
)

// newLinkIngress is a dedicated ingress for the route-responder link tests.
func newLinkIngress(t *testing.T) (*Service, IngressRoutingOptions, *bytes.Buffer) {
	t.Helper()
	svc, _, _, opts := newRoutingHarness(t)
	svc.cfg.EnableCluster = true
	svc.cfg.NodeRole = "ingress"
	svc.cfg.AutoReconcile = false
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: svc.cfg.CaddyAdminURL, CaddyServerID: "srv0",
		Domain: "sandbox.test", L4TLSListen: ":443", L4TLSFallback: "127.0.0.1:8443", HTTPClientTimeout: 5 * time.Second,
	})
	svc.AttachCluster(&fakeWatcherCluster{Noop: cluster.NewNoop("ing-1", "", "")})
	var logs bytes.Buffer
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
	return svc, opts, &logs
}

// The cluster-bank-flagship UC-171 drops (2026-11-01): systemd-resolved sends
// *.rt.internal to the responder through a socket pinned to the aerolvm-rt
// dummy link, so it must reach a listener on that link's address, not on
// loopback. With SB_ROUTE_DNS_LINK_ADDR set, the responder serves there too,
// the boot probe of the system resolver goes through it, and the loopback
// listener the static Caddy routes use keeps answering.
func TestStartIngressProxyRoutingServesTheLinkAddress(t *testing.T) {
	svc, opts, logs := newLinkIngress(t)
	svc.cfg.RouteDNSLinkAddr = freeLoopbackPort(t) // stands in for 169.254.53.53:53053
	opts.SystemResolver = directResolver(svc.cfg.RouteDNSLinkAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r, err := svc.StartIngressProxyRouting(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	for _, addr := range []string{svc.cfg.RouteDNSLinkAddr, svc.cfg.RouteDNSAddr} {
		got, err := directResolver(addr).LookupHost(ctx, routedns.ProbeName+".")
		if err != nil || len(got) != 1 || got[0] != routedns.ProbeIP {
			t.Fatalf("probe via %s = %v, %v; want %s", addr, got, err, routedns.ProbeIP)
		}
	}
	if strings.Contains(logs.String(), "no SB_ROUTE_DNS_LINK_ADDR") {
		t.Fatalf("warned about a missing link address that is set:\n%s", logs.String())
	}
}

// A link address the node does not have (networkd never brought aerolvm-rt
// up) cannot be bound, so the system resolver path is unproven and the
// ingress refuses the flag, keeping per-sandbox routes.
func TestStartIngressProxyRoutingRefusesAnUnbindableLinkAddress(t *testing.T) {
	svc, opts, _ := newLinkIngress(t)
	svc.cfg.RouteDNSLinkAddr = "192.0.2.53:53053" // TEST-NET-1: never a local address
	opts.SystemResolver = directResolver(svc.cfg.RouteDNSLinkAddr)
	opts.ProbeTimeout = time.Second

	r, err := svc.StartIngressProxyRouting(context.Background(), opts)
	if err == nil {
		r.Stop()
		t.Fatal("engaged with a link listener that cannot bind")
	}
	if !svc.routesWrittenToCaddy() {
		t.Fatal("a refused engage installed the index writer")
	}
}

// An ingress without a link address still engages (the resolver may route
// the zone some other way), but says how its lookups will stall if that
// route is systemd-resolved to loopback.
func TestStartIngressProxyRoutingWarnsWithoutALinkAddress(t *testing.T) {
	svc, opts, logs := newLinkIngress(t)
	opts.SystemResolver = directResolver(svc.cfg.RouteDNSAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r, err := svc.StartIngressProxyRouting(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	if !strings.Contains(logs.String(), "no SB_ROUTE_DNS_LINK_ADDR") {
		t.Fatalf("no warning about the missing link address:\n%s", logs.String())
	}
}
