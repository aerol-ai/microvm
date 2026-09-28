package service

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/routedns"
)

type fakeWatcherCluster struct {
	*cluster.Noop
	fn cluster.PlacementChangeHandler
}

func (f *fakeWatcherCluster) WatchPlacementChanges(_ context.Context, fn cluster.PlacementChangeHandler) bool {
	f.fn = fn
	return true
}

func (f *fakeWatcherCluster) PlacementOf(id string) (cluster.Placement, bool) {
	if id == "sbm" {
		return cluster.Placement{SandboxID: "sbm"}, true
	}
	return cluster.Placement{}, false
}

func TestWatchIngressRouteIndexAppliesFullViewAndDeltas(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.Domain = "d.test"
	fw := &fakeWatcherCluster{Noop: cluster.NewNoop("n", "", "")}
	svc.AttachCluster(fw)
	idx := routedns.NewIngressIndex()
	if !svc.watchIngressRouteIndex(context.Background(), idx) {
		t.Fatal("watcher not registered")
	}
	pub := func(id string) cluster.Placement {
		return cluster.Placement{SandboxID: id, OwnerNodeID: "w", OwnerDataPlaneHost: "10.0.0.1", PublicTraffic: true}
	}
	fw.fn([]cluster.Placement{pub("a"), pub("b")}, nil)
	if _, ok := idx.Lookup("a.d.test"); !ok {
		t.Fatal("full view not applied")
	}
	p := pub("c")
	fw.fn(nil, []cluster.PlacementChange{{SandboxID: "c", Placement: &p}, {SandboxID: "a", Deleted: true}, {SandboxID: "b"}})
	if _, ok := idx.Lookup("c.d.test"); !ok {
		t.Fatal("upsert delta not applied")
	}
	for _, gone := range []string{"a.d.test", "b.d.test"} {
		if _, ok := idx.Lookup(gone); ok {
			t.Fatalf("%s survived a delete (or a nil-placement change)", gone)
		}
	}
	if p, ok := svc.ingressMissLookup()(context.Background(), "sbm"); !ok || p.SandboxID != "sbm" {
		t.Fatalf("miss lookup = %+v %v", p, ok)
	}
}

func TestWatchIngressRouteIndexWithoutAWatcher(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n", "", "")) // single-node: no watcher
	if svc.watchIngressRouteIndex(context.Background(), routedns.NewIngressIndex()) {
		t.Fatal("a Noop cluster has no placement watcher")
	}
	if svc.watchIngressRouteIndex(context.Background(), nil) {
		t.Fatal("nil index accepted")
	}
	empty := &Service{cfg: config.Config{}}
	if _, ok := empty.ingressMissLookup()(context.Background(), "x"); ok {
		t.Fatal("miss lookup without a cluster resolved")
	}
}

func TestCheckRouteResolver(t *testing.T) {
	r := &routedns.Responder{Domain: "d.test", Owner: routedns.NewOwnerTable(), Ingress: routedns.NewIngressIndex()}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: r}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	resolverFor := func(addr string) *net.Resolver {
		return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := checkRouteResolver(ctx, resolverFor(pc.LocalAddr().String())); err != nil {
		t.Fatalf("routed resolver failed the probe: %v", err)
	}

	// A resolver that routes the zone somewhere else (answers another IP).
	other := &routedns.Responder{Domain: "d.test"}
	pc2, _ := net.ListenPacket("udp", "127.0.0.1:0")
	srv2 := &dns.Server{PacketConn: pc2, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(m)
		reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("10.9.9.9")})
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = srv2.ActivateAndServe() }()
	defer func() { _ = srv2.Shutdown() }()
	_ = other
	if err := checkRouteResolver(ctx, resolverFor(pc2.LocalAddr().String())); err == nil || !strings.Contains(err.Error(), "routed somewhere other") {
		t.Fatalf("misrouted zone: err = %v, want a misrouting error", err)
	}

	// Nothing answers at all.
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	deadAddr := dead.LocalAddr().String()
	_ = dead.Close()
	short, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()
	if err := checkRouteResolver(short, resolverFor(deadAddr)); err == nil {
		t.Fatal("an unreachable responder passed the probe")
	}
}
