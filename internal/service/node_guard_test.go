package service

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// guardRuntime is a runtime that records the node guard it is given.
type guardRuntime struct {
	*recordingRuntime
	mu        sync.Mutex
	sets      [][]netrules.NodePort
	reasserts int
	repaired  bool
	setErr    error
	reErr     error
}

func (g *guardRuntime) SetNodeGuard(_ context.Context, allow []netrules.NodePort) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sets = append(g.sets, slices.Clone(allow))
	return g.setErr
}

func (g *guardRuntime) ReassertNodeGuard(context.Context) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reasserts++
	return g.repaired, g.reErr
}

func (g *guardRuntime) counts() (int, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sets), g.reasserts
}

func (g *guardRuntime) last() []netrules.NodePort {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.sets) == 0 {
		return nil
	}
	return g.sets[len(g.sets)-1]
}

func newGuardRuntime() *guardRuntime { return &guardRuntime{recordingRuntime: &recordingRuntime{}} }

// listenersGateway reports the listeners a real gateway would.
type listenersGateway struct {
	*fakeGateway
	listeners []string
}

func (l *listenersGateway) Ready(ctx context.Context) (egress.ReadyStatus, error) {
	st, err := l.fakeGateway.Ready(ctx)
	st.Listeners = l.listeners
	return st, err
}

func portsOf(allow []netrules.NodePort) []string {
	out := make([]string, 0, len(allow))
	for _, p := range allow {
		out = append(out, p.String())
	}
	return out
}

func withResolvers(t *testing.T, local []string, bodies ...string) {
	t.Helper()
	var paths []string
	for _, b := range bodies {
		p := filepath.Join(t.TempDir(), "resolv.conf")
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	prevPaths, prevLocal := nodeGuardResolvConfs, localIPv4s
	nodeGuardResolvConfs = paths
	localIPv4s = func() []netip.Addr {
		var out []netip.Addr
		for _, a := range local {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	t.Cleanup(func() { nodeGuardResolvConfs, localIPv4s = prevPaths, prevLocal })
}

// TestSandboxNodeAllowlist: what sandboxes may still reach on their own
// node, per configuration.
func TestSandboxNodeAllowlist(t *testing.T) {
	withResolvers(t, []string{"10.0.1.5", "172.17.0.1"}, "nameserver 10.0.0.2\n")
	worker := config.Config{NodeRole: config.NodeRoleWorker, EnableCaddy: true, EgressDNSPort: 53054, EgressProxyPort: 15080}
	cases := []struct {
		name    string
		cfg     func(*config.Config)
		gateway bool
		want    []string
	}{
		{name: "worker, no gateway: nothing", want: nil},
		{name: "gateway on", gateway: true, want: []string{"tcp/15080", "tcp/53054", "udp/53054"}},
		{name: "gateway ports overridden", gateway: true, cfg: func(c *config.Config) { c.EgressDNSPort, c.EgressProxyPort = 5300, 8081 },
			want: []string{"tcp/5300", "tcp/8081", "udp/5300"}},
		{name: "privileged node: no gateway, no ports", gateway: true, cfg: func(c *config.Config) { c.ContainerPrivileged = true }, want: nil},
		{name: "ingress node serves 80 and 443", cfg: func(c *config.Config) { c.NodeRole = config.NodeRoleMixed }, want: []string{"tcp/443", "tcp/80"}},
		{name: "ingress without caddy", cfg: func(c *config.Config) { c.NodeRole, c.EnableCaddy = config.NodeRoleMixed, false }, want: nil},
		{name: "escape hatch", cfg: func(c *config.Config) {
			c.SandboxNodePortsAllow = []config.SandboxNodePort{{Proto: "tcp", Port: 8443}, {Proto: "udp", Port: 5353}}
		}, want: []string{"tcp/8443", "udp/5353"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{cfg: worker}
			if tc.cfg != nil {
				tc.cfg(&svc.cfg)
			}
			if tc.gateway {
				svc.cfg.EgressFQDNEnabled = true
				svc.SetEgressGateway(newFakeGateway(), nil)
			}
			got := portsOf(svc.SandboxNodeAllowlist())
			if !slices.Equal(got, tc.want) {
				t.Fatalf("allowlist = %v, want %v", got, tc.want)
			}
			// Never a control port: the gateway's control-port guard would
			// drop it, and the two guards must agree.
			for _, p := range svc.SandboxNodeAllowlist() {
				if slices.Contains(svc.cfg.NodeControlPorts(), p.Port) {
					t.Errorf("%s is a control port", p)
				}
			}
		})
	}

	// A resolver handed to sandboxes that is one of the node's addresses
	// gets DNS on that address only.
	withResolvers(t, []string{"10.0.1.5"}, "nameserver 127.0.0.53\n", "nameserver 10.0.1.5\nnameserver 10.0.0.2\n")
	svc := &Service{cfg: worker}
	if got, want := portsOf(svc.SandboxNodeAllowlist()), []string{"tcp/53@10.0.1.5", "udp/53@10.0.1.5"}; !slices.Equal(got, want) {
		t.Fatalf("local resolver: %v, want %v", got, want)
	}
}

// TestNodeGuardFollowsTheGatewayListeners: the gateway's own report of
// what it listens on wins over sandboxd's configuration.
func TestNodeGuardFollowsTheGatewayListeners(t *testing.T) {
	withResolvers(t, nil)
	svc, gw, _ := newEgressHarness(t)
	svc.cfg.EgressDNSPort, svc.cfg.EgressProxyPort = 53054, 15080
	lg := &listenersGateway{fakeGateway: gw, listeners: []string{"udp:172.17.0.1:5353", "tcp:172.17.0.1:5353", "proxy:172.17.0.1:3128", "bogus", "tcp:nope"}}
	svc.SetEgressGateway(lg, nil)
	ctx := context.Background()
	if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
		t.Fatal(err)
	}
	svc.learnGatewayPorts(ctx)
	if got, want := portsOf(svc.SandboxNodeAllowlist()), []string{"tcp/3128", "tcp/5353", "udp/5353"}; !slices.Equal(got, want) {
		t.Fatalf("allowlist = %v, want the gateway's %v", got, want)
	}
	// A report without both ports changes nothing.
	lg.listeners = []string{"udp:172.17.0.1:9999"}
	svc.learnGatewayPorts(ctx)
	if dns, proxy := svc.gatewayNodePorts(); dns != 5353 || proxy != 3128 {
		t.Fatalf("a partial report must not replace the ports: %d %d", dns, proxy)
	}
	gw.readyErr = errors.New("down")
	svc.learnGatewayPorts(ctx)
	if dns, _ := svc.gatewayNodePorts(); dns != 5353 {
		t.Fatal("an unreachable gateway keeps the last report")
	}
}

func TestHostMediatedNodePorts(t *testing.T) {
	cfg := config.Config{NodeRole: config.NodeRoleWorker, EnableCaddy: true}
	if got := HostMediatedNodePorts(cfg); len(got) != 0 {
		t.Fatalf("worker: %v", got)
	}
	cfg.NodeRole = "worker,ingress"
	cfg.SandboxNodePortsAllow = []config.SandboxNodePort{{Proto: "udp", Port: 443}, {Proto: "tcp", Port: 8443}}
	if got := HostMediatedNodePorts(cfg); !slices.Equal(got, []uint16{80, 443, 8443}) {
		t.Fatalf("ingress + hatch: %v", got)
	}
}

// TestNodeGuardInstallAndGate: the guard goes to every container and
// Firecracker runtime; a runtime whose guard failed refuses creates (fail
// closed) until a later sync installs it; network rules off is allowed
// outside enterprise mode only.
func TestNodeGuardInstallAndGate(t *testing.T) {
	withResolvers(t, nil)
	dockerRT, ctdRT, fcRT := newGuardRuntime(), newGuardRuntime(), newGuardRuntime()
	svc := &Service{cfg: config.Config{NodeRole: config.NodeRoleMixed, EnableCaddy: true}, logger: quietLogger(),
		docker: dockerRT, containerd: ctdRT, firecracker: fcRT}
	ctdRT.setErr = errors.New("iptables gone")
	fcRT.setErr = runtime.ErrNodeGuardUnavailable
	// Before the daemon ran it once, nothing is gated.
	if err := svc.requireNodeGuard(models.RuntimeFirecracker); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	svc.ApplyNodeGuard(ctx)
	if got := portsOf(dockerRT.last()); !slices.Equal(got, []string{"tcp/443", "tcp/80"}) {
		t.Fatalf("docker got %v", got)
	}
	gate := func(engine, rt string) error {
		svc.cfg.ContainerEngine = engine
		return svc.requireNodeGuard(rt)
	}
	if err := gate(models.ContainerEngineDocker, models.RuntimeDocker); err != nil {
		t.Fatalf("docker is guarded: %v", err)
	}
	if err := gate(models.ContainerEngineDocker, models.RuntimeGvisor); err != nil {
		t.Fatalf("gVisor rides docker's bridge: %v", err)
	}
	if err := gate(models.ContainerEngineContainerd, models.RuntimeDocker); !errors.Is(err, ErrNodeGuardNotReady) || !strings.Contains(err.Error(), "iptables gone") {
		t.Fatalf("containerd's guard failed: %v", err)
	}
	if err := gate(models.ContainerEngineContainerd, models.RuntimeWasm); err != nil {
		t.Fatalf("WASM is guarded in-process: %v", err)
	}
	if err := gate(models.ContainerEngineContainerd, models.RuntimeIsolate); err != nil {
		t.Fatalf("isolate is guarded in-process: %v", err)
	}
	if err := gate(models.ContainerEngineDocker, models.RuntimeFirecracker); err != nil {
		t.Fatalf("network rules off, outside enterprise mode: %v", err)
	}
	svc.cfg.EnterpriseMode = true
	if err := gate(models.ContainerEngineDocker, models.RuntimeFirecracker); !errors.Is(err, ErrNodeGuardNotReady) {
		t.Fatalf("enterprise mode needs the guard: %v", err)
	}
	svc.cfg.EnterpriseMode = false

	// The supervisor retries the failed runtime on its next tick and lifts
	// the gate; the healthy one is not touched before the re-assert is due.
	ctdRT.setErr = nil
	dSets, _ := dockerRT.counts()
	svc.syncNodeGuard(ctx, false)
	if err := gate(models.ContainerEngineContainerd, models.RuntimeDocker); err != nil {
		t.Fatalf("after a successful retry: %v", err)
	}
	if n, re := dockerRT.counts(); n != dSets || re != 0 {
		t.Fatalf("an installed guard is left alone between re-asserts: sets=%d reasserts=%d", n, re)
	}
	if v := nodeGuardReady.Get(models.ContainerEngineContainerd); v == nil || v.String() != "1" {
		t.Fatalf("ready gauge = %v", v)
	}

	// The re-assert is due: it runs, and one that had to repair is fine.
	svc.nodeGuard.checkedAt = time.Now().Add(-2 * nodeGuardReassertInterval)
	dockerRT.repaired = true
	svc.syncNodeGuard(ctx, false)
	if _, re := dockerRT.counts(); re != 1 {
		t.Fatalf("re-assert not run: %d", re)
	}
	// A re-assert that fails gates creates, and the next tick reinstalls.
	svc.nodeGuard.checkedAt = time.Now().Add(-2 * nodeGuardReassertInterval)
	dockerRT.reErr = errors.New("xtables lock")
	svc.syncNodeGuard(ctx, false)
	if err := gate(models.ContainerEngineDocker, models.RuntimeDocker); !errors.Is(err, ErrNodeGuardNotReady) {
		t.Fatalf("a failed re-assert gates: %v", err)
	}
	dockerRT.reErr = nil
	dSets, _ = dockerRT.counts()
	svc.syncNodeGuard(ctx, false)
	if n, _ := dockerRT.counts(); n != dSets+1 || gate(models.ContainerEngineDocker, models.RuntimeDocker) != nil {
		t.Fatal("a failed runtime is reinstalled on the next tick")
	}

	// A changed allowlist (the escape hatch here) reaches every runtime.
	svc.cfg.SandboxNodePortsAllow = []config.SandboxNodePort{{Proto: "tcp", Port: 8443}}
	svc.syncNodeGuard(ctx, false)
	for _, rt := range []*guardRuntime{dockerRT, ctdRT} {
		if !slices.Contains(portsOf(rt.last()), "tcp/8443") {
			t.Fatalf("the new allowlist did not reach a runtime: %v", rt.last())
		}
	}
}

// TestSuperviseNodeGuard: the loop retries until it is cancelled.
func TestSuperviseNodeGuard(t *testing.T) {
	withResolvers(t, nil)
	rt := newGuardRuntime()
	rt.setErr = errors.New("not yet")
	svc := &Service{cfg: config.Config{NodeRole: config.NodeRoleWorker}, logger: quietLogger(), docker: rt}
	svc.ApplyNodeGuard(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.SuperviseNodeGuard(ctx, time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, _ := rt.counts(); n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the supervisor did not retry")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	// A zero interval falls back to the default and still stops on cancel.
	go func() { svc.SuperviseNodeGuard(ctx, 0) }()
}

// TestCreateRefusedWithoutNodeGuard: a container create on a node whose
// guard failed never reaches the runtime.
func TestCreateRefusedWithoutNodeGuard(t *testing.T) {
	withResolvers(t, nil)
	rt := newGuardRuntime()
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	rt.setErr = errors.New("iptables gone")
	svc.ApplyNodeGuard(context.Background())
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"})
	if !errors.Is(err, ErrNodeGuardNotReady) {
		t.Fatalf("create err = %v, want node guard not ready", err)
	}
	if rt.createCalls != 0 {
		t.Fatal("the runtime must not be called")
	}
	rt.setErr = nil
	svc.syncNodeGuard(context.Background(), false)
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"}); err != nil {
		t.Fatalf("create after the guard is in: %v", err)
	}
}

// TestNodeControlAndNodeGuardAgree: the gateway's control-port guard
// (node_control) drops nothing the node guard opens, and the node guard
// opens no control port, in the widest configuration (gateway, ingress,
// escape hatch, a local resolver).
func TestNodeControlAndNodeGuardAgree(t *testing.T) {
	withResolvers(t, []string{"172.17.0.1"}, "nameserver 172.17.0.1\n")
	svc, gw, _ := newEgressHarness(t)
	svc.cfg.NodeRole, svc.cfg.EnableCaddy = config.NodeRoleMixed, true
	svc.cfg.APIPort, svc.cfg.SSHListenAddr, svc.cfg.RaftBindAddr = 21212, "0.0.0.0:2220", "0.0.0.0:7000"
	svc.cfg.EgressDNSPort, svc.cfg.EgressProxyPort = 53054, 15080
	svc.cfg.IngressProxyRouting, svc.cfg.HostPortRedirectPort = true, 21215
	svc.cfg.SandboxNodePortsAllow = []config.SandboxNodePort{{Proto: "tcp", Port: 8443}}
	ctx := context.Background()
	if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
		t.Fatal(err)
	}
	svc.syncNodeControl(ctx)
	if len(gw.control) == 0 {
		t.Fatal("the control-port guard was not pushed")
	}
	allow := svc.SandboxNodeAllowlist()
	if len(allow) == 0 {
		t.Fatal("empty allowlist")
	}
	for _, ep := range gw.control {
		for _, p := range allow {
			if p.Port == ep.Port() && p.Proto == "tcp" {
				t.Errorf("node_control drops %s, which the node guard opens (%s)", ep, p)
			}
		}
	}
}
