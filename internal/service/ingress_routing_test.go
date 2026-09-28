package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/routedns"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// wholeCaddy is a fake Caddy admin over a whole config tree. It counts
// /load separately from per-object writes, since each of either is a full
// reload in real Caddy.
type wholeCaddy struct {
	mu     sync.Mutex
	emu    http.RoundTripper
	loads  int
	writes int
}

func (f *wholeCaddy) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/load" {
			var root any
			if err := json.NewDecoder(r.Body).Decode(&root); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			f.loads++
			f.emu = caddy.NewConfigEmulator(root)
			return
		}
		if r.Method != http.MethodGet {
			f.writes++
		}
		resp, _ := f.emu.RoundTrip(r)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func (f *wholeCaddy) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loads, f.writes
}

func (f *wholeCaddy) config(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	resp, _ := f.emu.RoundTrip(httptest.NewRequest(http.MethodGet, "http://caddy/config/", nil))
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, resp.Body)
	return buf.String()
}

type recordingHostPorts struct {
	recordingTCPForwarder
	mu         sync.Mutex
	prunes     int
	reconciled []map[int]hostport.Target
	pruneErr   error
}

func (f *recordingHostPorts) PruneUnasserted() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prunes++
	return f.pruneErr
}

func (f *recordingHostPorts) Reconcile(desired map[int]hostport.Target) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconciled = append(f.reconciled, desired)
	return nil
}

func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		if pc, err := net.ListenPacket("udp", addr); err == nil {
			_ = pc.Close()
			return addr
		}
	}
	t.Fatal("no free loopback port for tcp+udp")
	return ""
}

const baseCaddyConfig = `{"apps":{"http":{"servers":{"srv0":{"routes":[
  {"@id":"api","match":[{"host":["sandbox.test"]}]},
  {"handle":[{"handler":"static_response","body":"Sandbox not found"}]}]}}}}}`

func newRoutingHarness(t *testing.T) (*Service, *wholeCaddy, *recordingHostPorts, IngressRoutingOptions) {
	t.Helper()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}})
	svc.probeContainerPortFn = func(context.Context, string, int) error { return nil }
	var root any
	_ = json.Unmarshal([]byte(baseCaddyConfig), &root)
	fc := &wholeCaddy{emu: caddy.NewConfigEmulator(root)}
	server := httptest.NewServer(fc.handler())
	t.Cleanup(server.Close)
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.Domain = "sandbox.test"
	svc.cfg.IngressProxyRouting = true
	svc.cfg.AutoReconcile = true
	svc.cfg.RouteDNSAddr = freeLoopbackPort(t)
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0",
		Domain: "sandbox.test", HTTPClientTimeout: 5 * time.Second,
	})
	fwd := &recordingHostPorts{}
	opts := IngressRoutingOptions{
		Static:       caddy.StaticRouteSpec{RouteDNSAddr: svc.cfg.RouteDNSAddr, RouterAddr: "127.0.0.1:21213", ToolboxPort: 2280, LocalIP: "127.0.0.1"},
		Forwarder:    fwd,
		RedirectAddr: "127.0.0.1:0",
		ProbeTimeout: 3 * time.Second,
	}
	return svc, fc, fwd, opts
}

// The whole flag-on / flag-off cycle on an owner:
//   - Engaging makes zero Caddy writes: the boot reconcile fills the table.
//   - Commit is ONE load.
//   - Lifecycle afterwards makes zero writes.
//   - Rollback is ONE load that restores the per-sandbox routes.
func TestIngressProxyRoutingOwnerCycle(t *testing.T) {
	svc, fc, fwd, opts := newRoutingHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	allow := true
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", AllowPublicTraffic: &allow})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fc.config(t), `"sandbox-`+resp.ID+`"`) {
		t.Fatal("flag-off create did not write its Caddy route (harness broken)")
	}
	// The runtime reports it running, as a real restart would find it.
	svc.docker.(*recordingRuntime).managed[resp.ID] = &models.SandboxRuntimeState{
		SandboxID: resp.ID, ContainerID: resp.ID, ContainerIP: "10.0.0.2", Status: models.SandboxStatusStarted,
	}
	_, writesBefore := fc.counts()

	r, err := svc.StartIngressProxyRouting(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Owner.Lookup(resp.ID + ".sandbox.test"); !ok {
		t.Fatal("the boot reconcile did not fill the owner table")
	}
	// The responder answers from it, as Caddy's dynamic upstream asks.
	addrs, err := directResolver(svc.cfg.RouteDNSAddr).LookupHost(ctx, resp.ID+".sandbox.test.")
	if err != nil || len(addrs) != 1 || addrs[0] != "10.0.0.2" {
		t.Fatalf("responder answer = %v, %v", addrs, err)
	}
	if err := svc.CommitIngressProxyRouting(ctx, r, true); err != nil {
		t.Fatal(err)
	}
	loads, writes := fc.counts()
	if loads != 1 || writes != writesBefore {
		t.Fatalf("engage+commit: loads=%d writes=%d (before %d): want one load, no other write", loads, writes, writesBefore)
	}
	cfg := fc.config(t)
	if strings.Contains(cfg, `"sandbox-`+resp.ID+`"`) || !strings.Contains(cfg, caddy.StaticSandboxRouteID) {
		t.Fatalf("after commit the per-sandbox route must be gone and the static one present:\n%s", cfg)
	}
	if fwd.prunes != 1 {
		t.Fatalf("host-port prunes = %d, want 1 after a complete re-assert", fwd.prunes)
	}

	if _, err := svc.ExposePort(ctx, resp.ID, 8080, "http"); err != nil {
		t.Fatal(err)
	}
	if _, w := fc.counts(); w != writesBefore {
		t.Fatalf("expose under the flag wrote Caddy (%d writes)", w-writesBefore)
	}
	if _, ok := r.Owner.Lookup(resp.ID + "-8080.sandbox.test"); !ok {
		t.Fatal("expose under the flag missed the owner table")
	}

	r.Stop()
	if err := svc.RollbackIngressProxyRouting(ctx, fwd); err != nil {
		t.Fatal(err)
	}
	loads, writes = fc.counts()
	if loads != 2 || writes != writesBefore {
		t.Fatalf("rollback: loads=%d writes=%d: want one more load, no other write", loads, writes)
	}
	cfg = fc.config(t)
	if strings.Contains(cfg, caddy.StaticSandboxRouteID) ||
		!strings.Contains(cfg, `"sandbox-`+resp.ID+`"`) || !strings.Contains(cfg, `"sandbox-`+resp.ID+`-port-8080"`) {
		t.Fatalf("after rollback the per-sandbox routes must be back and the static one gone:\n%s", cfg)
	}
	if len(fwd.reconciled) != 1 || len(fwd.reconciled[0]) != 0 {
		t.Fatalf("rollback host-port reconcile = %v, want one empty reconcile", fwd.reconciled)
	}
	if _, isCaddy := svc.publicRoutes().(*caddy.Client); !isCaddy {
		t.Fatal("after rollback route writes must go to Caddy again")
	}
}

func TestCommitIngressProxyRoutingSkipsPruneAfterIncompleteReassert(t *testing.T) {
	svc, fc, fwd, opts := newRoutingHarness(t)
	ctx := context.Background()
	r, err := svc.StartIngressProxyRouting(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	if err := svc.CommitIngressProxyRouting(ctx, r, false); err != nil {
		t.Fatal(err)
	}
	if fwd.prunes != 0 {
		t.Fatal("pruned host-port rules after a failed boot reconcile (would cut live sessions)")
	}
	if loads, _ := fc.counts(); loads != 1 {
		t.Fatalf("loads = %d", loads)
	}

	fwd.pruneErr = errors.New("iptables gone")
	if err := svc.CommitIngressProxyRouting(ctx, r, true); err == nil {
		t.Fatal("want the prune error")
	}
	if err := svc.CommitIngressProxyRouting(ctx, nil, true); err != nil {
		t.Fatal(err)
	}
}

func TestStartIngressProxyRoutingRefusals(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(*Service, *IngressRoutingOptions){
		"no caddy":       func(s *Service, _ *IngressRoutingOptions) { s.caddy = caddy.New(config.Config{}) },
		"no domain":      func(s *Service, _ *IngressRoutingOptions) { s.cfg.Domain = "" },
		"no reconcile":   func(s *Service, _ *IngressRoutingOptions) { s.cfg.AutoReconcile = false },
		"no forwarder":   func(_ *Service, o *IngressRoutingOptions) { o.Forwarder = nil },
		"bad redirect":   func(_ *Service, o *IngressRoutingOptions) { o.RedirectAddr = "256.0.0.1:x" },
		"responder addr": func(s *Service, _ *IngressRoutingOptions) { s.cfg.RouteDNSAddr = "256.0.0.1:53" },
		"probe times out": func(s *Service, o *IngressRoutingOptions) {
			o.ProbeTimeout = time.Nanosecond
			s.cfg.RouteDNSAddr = "127.0.0.1:1"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			svc, _, _, opts := newRoutingHarness(t)
			mutate(svc, &opts)
			r, err := svc.StartIngressProxyRouting(ctx, opts)
			if err == nil {
				r.Stop()
				t.Fatal("want a refusal")
			}
			if r != nil {
				t.Fatal("a refusal returned a routing handle")
			}
			if _, isCaddy := svc.publicRoutes().(*caddy.Client); !isCaddy {
				t.Fatal("a refused engage swapped the route writer")
			}
		})
	}

	svc, _, _, opts := newRoutingHarness(t)
	svc.cfg.IngressProxyRouting = false
	if r, err := svc.StartIngressProxyRouting(ctx, opts); r != nil || err != nil {
		t.Fatalf("flag off: %v %v", r, err)
	}
	var nilRouting *IngressRouting
	nilRouting.Stop()
}

// Rollback with Caddy off still hands route writes back to Caddy.
func TestRollbackIngressProxyRoutingWithoutCaddy(t *testing.T) {
	svc, _, _, _ := newRoutingHarness(t)
	svc.setRouteWriter(noopRouteWriter{})
	svc.caddy = caddy.New(config.Config{})
	if err := svc.RollbackIngressProxyRouting(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, isCaddy := svc.publicRoutes().(*caddy.Client); !isCaddy {
		t.Fatal("writer not reset")
	}
}

// An ingress-only cluster node:
//   - Both resolver probes pass.
//   - The watcher's full view fills the index, and the responder answers
//     the SNI dial from it.
//   - Commit installs the tls-mux static routes and drops the
//     ingress-sni passthroughs in one load.
func TestIngressProxyRoutingIngressNode(t *testing.T) {
	svc, fc, fwd, opts := newRoutingHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.cfg.EnableCluster = true
	svc.cfg.NodeRole = "ingress"
	svc.cfg.AutoReconcile = false // not a worker: nothing to rebuild locally
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: svc.cfg.CaddyAdminURL, CaddyServerID: "srv0",
		Domain: "sandbox.test", L4TLSListen: ":443", L4TLSFallback: "127.0.0.1:8443", HTTPClientTimeout: 5 * time.Second,
	})
	var root any
	_ = json.Unmarshal([]byte(`{"apps":{"http":{"servers":{"srv0":{"routes":[{"handle":[]}]}}},
	  "layer4":{"servers":{"tls-mux":{"routes":[
	    {"@id":"sandbox-old-ingress-sni","match":[{"tls":{"sni":["old.sandbox.test"]}}]},
	    {"handle":[{"handler":"proxy","upstreams":[{"dial":["127.0.0.1:8443"]}]}]}]}}}}}`), &root)
	fc.mu.Lock()
	fc.emu = caddy.NewConfigEmulator(root)
	fc.mu.Unlock()
	fw := &fakeWatcherCluster{Noop: cluster.NewNoop("ing-1", "", "")}
	svc.AttachCluster(fw)
	opts.SystemResolver = directResolver(svc.cfg.RouteDNSAddr) // as if ~rt.internal routes here

	r, err := svc.StartIngressProxyRouting(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	if r.Ingress == nil || !r.ClusterMode || r.SelfNodeID != "ing-1" {
		t.Fatalf("routing = %+v", r)
	}
	go fw.fn([]cluster.Placement{{SandboxID: "sb1", OwnerNodeID: "w-1", OwnerDataPlaneHost: "10.2.0.7", PublicTraffic: true}}, nil)
	if err := svc.CommitIngressProxyRouting(ctx, r, true); err != nil {
		t.Fatal(err)
	}
	addrs, err := directResolver(svc.cfg.RouteDNSAddr).LookupHost(ctx, "sb1.sandbox.test."+routedns.IngressZone+".")
	if err != nil || len(addrs) != 1 || addrs[0] != "10.2.0.7" {
		t.Fatalf("SNI dial answer = %v, %v; want the owner", addrs, err)
	}
	if loads, _ := fc.counts(); loads != 1 {
		t.Fatalf("loads = %d, want 1", loads)
	}
	cfg := fc.config(t)
	for _, want := range []string{caddy.StaticLoopbackRouteID, caddy.StaticApexSNIRouteID, caddy.StaticSNIRouteID, caddy.StaticSandboxRouteID} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("static route %s missing:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "sandbox-old-ingress-sni") {
		t.Fatal("the ingress-sni passthrough survived the commit")
	}
	_ = fwd
}

// No change feed (and a first snapshot that never arrives): the index
// falls back to on-miss reads, and commit still goes ahead after the
// bounded wait.
func TestIngressProxyRoutingIngressWithoutFeed(t *testing.T) {
	svc, fc, _, opts := newRoutingHarness(t)
	ctx := context.Background()
	svc.cfg.EnableCluster = true
	svc.cfg.NodeRole = "ingress"
	svc.AttachCluster(cluster.NewNoop("ing-2", "", ""))
	opts.SystemResolver = directResolver(svc.cfg.RouteDNSAddr)
	r, err := svc.StartIngressProxyRouting(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	if err := svc.CommitIngressProxyRouting(ctx, r, true); err != nil {
		t.Fatal(err)
	}
	if loads, _ := fc.counts(); loads != 1 {
		t.Fatalf("loads = %d", loads)
	}

	// The system resolver not routing the zone: refused.
	svc2, _, _, opts2 := newRoutingHarness(t)
	svc2.cfg.EnableCluster = true
	svc2.cfg.NodeRole = "ingress"
	svc2.AttachCluster(cluster.NewNoop("ing-3", "", ""))
	opts2.ProbeTimeout = 200 * time.Millisecond
	opts2.SystemResolver = directResolver("127.0.0.1:1")
	if r2, err := svc2.StartIngressProxyRouting(ctx, opts2); err == nil {
		r2.Stop()
		t.Fatal("want a refusal when *.rt.internal isn't routed to the responder")
	}

	// A snapshot that never comes: commit waits out ProbeTimeout, then goes on.
	svc3, fc3, _, opts3 := newRoutingHarness(t)
	svc3.cfg.EnableCluster = true
	svc3.cfg.NodeRole = "ingress"
	svc3.AttachCluster(&fakeWatcherCluster{Noop: cluster.NewNoop("ing-4", "", "")})
	opts3.SystemResolver = directResolver(svc3.cfg.RouteDNSAddr)
	opts3.ProbeTimeout = 300 * time.Millisecond
	r3, err := svc3.StartIngressProxyRouting(ctx, opts3)
	if err != nil {
		t.Fatal(err)
	}
	defer r3.Stop()
	if err := svc3.CommitIngressProxyRouting(ctx, r3, true); err != nil {
		t.Fatal(err)
	}
	if loads, _ := fc3.counts(); loads != 1 {
		t.Fatalf("loads = %d", loads)
	}
	cctx, ccancel := context.WithCancel(ctx)
	ccancel()
	svc4, _, _, opts4 := newRoutingHarness(t)
	svc4.cfg.EnableCluster = true
	svc4.cfg.NodeRole = "ingress"
	svc4.AttachCluster(&fakeWatcherCluster{Noop: cluster.NewNoop("ing-5", "", "")})
	opts4.SystemResolver = directResolver(svc4.cfg.RouteDNSAddr)
	r4, err := svc4.StartIngressProxyRouting(ctx, opts4)
	if err != nil {
		t.Fatal(err)
	}
	defer r4.Stop()
	if err := svc4.CommitIngressProxyRouting(cctx, r4, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestRollbackIngressProxyRoutingIngressAndFailures(t *testing.T) {
	ctx := context.Background()
	svc, fc, fwd, _ := newRoutingHarness(t)
	svc.cfg.EnableCluster = true
	svc.cfg.NodeRole = "ingress"
	svc.AttachCluster(cluster.NewNoop("ing-r", "", ""))
	if err := svc.RollbackIngressProxyRouting(ctx, fwd); err != nil {
		t.Fatal(err)
	}
	if _, writes := fc.counts(); writes != 0 {
		t.Fatalf("ingress rollback wrote Caddy directly (%d writes)", writes)
	}
	if len(fwd.reconciled) != 1 {
		t.Fatal("host-port rules not removed")
	}

	// Caddy unreachable: the batch can't even read the config.
	svc2, _, _, _ := newRoutingHarness(t)
	svc2.caddy = caddy.New(config.Config{EnableCaddy: true, CaddyAdminURL: "http://127.0.0.1:1", Domain: "sandbox.test", HTTPClientTimeout: time.Second})
	if err := svc2.RollbackIngressProxyRouting(ctx, nil); err == nil {
		t.Fatal("want the batch error")
	}
	// Commit's batch failing is surfaced too.
	r := &IngressRouting{opts: IngressRoutingOptions{Forwarder: &recordingHostPorts{}}, indexSynced: make(chan struct{})}
	if err := svc2.CommitIngressProxyRouting(ctx, r, true); err == nil {
		t.Fatal("want the commit batch error")
	}
}
