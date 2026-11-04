package service

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// floorRuntime is a container runtime that records the deny floor.
type floorRuntime struct {
	*holdRuntime
	fmu       sync.Mutex
	floor     [][]netip.Prefix
	err       error
	reasserts int
	repaired  bool
	reErr     error
}

func newFloorRuntime() *floorRuntime {
	return &floorRuntime{holdRuntime: &holdRuntime{recordingRuntime: &recordingRuntime{}}}
}

func (f *floorRuntime) SetEgressFloor(_ context.Context, cidrs []netip.Prefix) error {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	f.floor = append(f.floor, cidrs)
	return f.err
}

func (f *floorRuntime) ReassertEgressFloor(context.Context) (bool, error) {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	f.reasserts++
	return f.repaired, f.reErr
}

func (f *floorRuntime) counts() (sets, reasserts int) {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	return len(f.floor), f.reasserts
}

func (f *floorRuntime) set(err, reErr error, repaired bool) {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	f.err, f.reErr, f.repaired = err, reErr, repaired
}

// TestOperatorFloorReachesTheHostFirewall (§5.10 PC-2): loading or changing
// the operator file installs deny_cidrs on each container engine and the
// Firecracker TAP subnet (Phase 4). What a failure does to creates is
// egress_floor_test.go's.
func TestOperatorFloorReachesTheHostFirewall(t *testing.T) {
	svc, _, hr := newEgressHarness(t)
	rt := &floorRuntime{holdRuntime: hr}
	svc.docker = rt
	fc := &floorRuntime{holdRuntime: &holdRuntime{recordingRuntime: &recordingRuntime{}}}
	svc.SetFirecrackerRuntime(fc)
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\ndeny_cidrs: [10.20.0.0/16]\n"))
	want := egresspolicy.WithMetadataFloor([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	if len(rt.floor) != 1 || !slices.Equal(rt.floor[0], want) {
		t.Fatalf("floor = %v, want the file's deny_cidrs and the metadata endpoints", rt.floor)
	}
	if len(fc.floor) != 1 || !slices.Equal(fc.floor[0], want) {
		t.Fatalf("the Firecracker guests get the floor too: %v", fc.floor)
	}
	rt.err = errors.New("iptables gone")
	svc.OnEgressOperatorChange(operatorWatcher(t, "version: 1\n").Current())
	if len(rt.floor) != 2 || !slices.Equal(rt.floor[1], egresspolicy.MetadataPrefixes) {
		t.Fatalf("a changed file replaces the floor, keeping the metadata endpoints: %v", rt.floor)
	}
	// No file at all: the floor is the metadata endpoints alone, installed
	// at boot (ApplyEgressFloor), so no node runs without it.
	rt.err = nil
	svc.ApplyEgressFloor(context.Background())
	if last := rt.floor[len(rt.floor)-1]; !slices.Equal(last, egresspolicy.MetadataPrefixes) {
		t.Fatalf("the floor with no operator file = %v", last)
	}
}

type membersClient struct {
	cluster.Client
	members []cluster.Member
}

func (m membersClient) LocalMembers() []cluster.Member { return m.members }
func (m membersClient) Members() []cluster.Member      { return m.members }

// TestNodeControlEndpoints: every live member's advertised control
// endpoints plus this node's ports on member and local addresses; dead
// members, names, IPv6 and ingress ports are left out.
func TestNodeControlEndpoints(t *testing.T) {
	prev := localIPv4s
	localIPv4s = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("172.17.0.1")} }
	t.Cleanup(func() { localIPv4s = prev })
	svc := &Service{cfg: config.Config{APIPort: 21212, SSHListenAddr: "0.0.0.0:2220", RaftBindAddr: "0.0.0.0:7000",
		GossipBindAddr: "0.0.0.0:7001", ClusterInternalListenAddr: "bad"}}
	svc.cluster = membersClient{members: []cluster.Member{
		{Alive: true, APIURL: "http://10.0.0.5:21212", InternalURL: "https://10.0.0.5:7002", RaftAddr: "10.0.0.5:7000"},
		{Alive: true, APIURL: "https://api.example.com:443", RaftAddr: "[fd00::1]:7000"},
		{Alive: false, APIURL: "http://10.0.0.9:21212"},
	}}
	eps := svc.nodeControlEndpoints()
	has := func(s string) bool {
		for _, e := range eps {
			if e == netip.MustParseAddrPort(s) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"10.0.0.5:21212", "10.0.0.5:7002", "10.0.0.5:7000", "10.0.0.5:2220", "10.0.0.5:7001", "172.17.0.1:21212", "172.17.0.1:2220"} {
		if !has(want) {
			t.Errorf("missing %s in %v", want, eps)
		}
	}
	for _, not := range []string{"10.0.0.9:21212", "10.0.0.5:443", "10.0.0.5:80"} {
		if has(not) {
			t.Errorf("%s must not be guarded", not)
		}
	}
	if _, ok := endpointOf("http://api.example.com:21212"); ok {
		t.Fatal("names are not resolved")
	}
	if _, ok := endpointOf(""); ok {
		t.Fatal("empty")
	}
	if _, ok := endpointOf("http://[::1"); ok {
		t.Fatal("bad url")
	}
	if len(localIPv4s()) == 0 {
		t.Log("seam replaced")
	}
}

// TestSyncNodeControl: pushed with the operator guard on, only when the
// list changed, again after a full sync (gateway restart), cleared when the
// guard is turned off, and never without an operator file.
func TestSyncNodeControl(t *testing.T) {
	prev := localIPv4s
	localIPv4s = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("172.17.0.1")} }
	t.Cleanup(func() { localIPv4s = prev })
	svc, gw, _ := newEgressHarness(t)
	svc.cfg.APIPort = 21212
	ctx := context.Background()
	if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
		t.Fatal(err)
	}
	// No operator file: the guard is on, over the API and the node's own
	// SSH and rpcbind.
	want := []netip.AddrPort{netip.MustParseAddrPort("172.17.0.1:22"), netip.MustParseAddrPort("172.17.0.1:111"), netip.MustParseAddrPort("172.17.0.1:21212")}
	svc.syncNodeControl(ctx)
	if gw.controlCalls != 1 || !slices.Equal(gw.control, want) {
		t.Fatalf("no operator file: push = %d calls %v, want %v", gw.controlCalls, gw.control, want)
	}
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\n"))
	svc.syncNodeControl(ctx)
	svc.syncNodeControl(ctx)
	if gw.controlCalls != 1 || !slices.Equal(gw.control, want) {
		t.Fatalf("an unchanged list is not pushed again: %d calls %v", gw.controlCalls, gw.control)
	}
	if err := svc.ResyncEgressGateway(ctx); err != nil {
		t.Fatal(err)
	}
	svc.syncNodeControl(ctx)
	if gw.controlCalls != 2 {
		t.Fatal("a full sync must re-push the list to a restarted gateway")
	}
	// With ingress proxy routing on, the host-port redirect listener is a
	// control port too: sandboxes reached it on cluster-3-mixed-routing.
	svc.cfg.IngressProxyRouting, svc.cfg.HostPortRedirectPort = true, 21215
	svc.syncNodeControl(ctx)
	if !slices.Contains(gw.control, netip.MustParseAddrPort("172.17.0.1:21215")) {
		t.Fatalf("redirect listener not guarded: %v", gw.control)
	}
	svc.cfg.IngressProxyRouting = false
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\nnode_control_port_guard: false\n"))
	svc.syncNodeControl(ctx)
	if gw.controlCalls != 4 || len(gw.control) != 0 {
		t.Fatalf("turning the guard off must clear it: %v", gw.control)
	}
}

// tapPoolRuntime is a Firecracker runtime whose guests have a firewall on
// the TAP subnet.
type tapPoolRuntime struct {
	*holdRuntime
	subnet netip.Prefix
}

func (r *tapPoolRuntime) EgressTapSubnet() (netip.Prefix, bool) { return r.subnet, r.subnet.IsValid() }

// TestSyncNodeControlPools: with Firecracker guests, the TAP pool is
// guarded whole on the control ports and the TAP addresses are not listed,
// so guests starting and stopping (their TAP addresses coming and going)
// push nothing; the gateway rewrote the whole set at every such change. A
// gateway from before the pools op gets every address listed, as before,
// and is pushed again when that list changes; once the gateway is new
// (restarted, so a full sync), the pools push comes back.
func TestSyncNodeControlPools(t *testing.T) {
	prev := localIPv4s
	t.Cleanup(func() { localIPv4s = prev })
	setLocal := func(addrs ...string) {
		var out []netip.Addr
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		localIPv4s = func() []netip.Addr { return out }
	}
	setLocal("172.17.0.1", "172.16.0.1")
	svc, gw, hr := newEgressHarness(t)
	svc.cfg.APIPort = 21212
	svc.SetFirecrackerRuntime(&tapPoolRuntime{holdRuntime: hr, subnet: netip.MustParsePrefix("172.16.0.0/16")})
	ctx := context.Background()
	if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
		t.Fatal(err)
	}
	svc.syncNodeControl(ctx)
	wantPool := egress.ControlPool{Prefix: netip.MustParsePrefix("172.16.0.0/16"), Ports: svc.cfg.NodeControlPorts()}
	if gw.controlCalls != 1 || gw.listCalls != 0 || len(gw.pools) != 1 || gw.pools[0].Prefix != wantPool.Prefix {
		t.Fatalf("pools push: calls %d list %d pools %+v", gw.controlCalls, gw.listCalls, gw.pools)
	}
	for _, p := range wantPool.Ports {
		if !slices.Contains(gw.pools[0].Ports, p) {
			t.Fatalf("pool ports %v miss control port %d", gw.pools[0].Ports, p)
		}
	}
	for _, ep := range gw.control {
		if wantPool.Prefix.Contains(ep.Addr()) {
			t.Fatalf("a TAP address was listed: %s", ep)
		}
	}
	if !slices.Contains(gw.control, netip.MustParseAddrPort("172.17.0.1:21212")) {
		t.Fatalf("the bridge address is still listed one by one: %v", gw.control)
	}
	// Guests come and go: nothing to push.
	setLocal("172.17.0.1", "172.16.0.1", "172.16.0.5", "172.16.0.9")
	svc.syncNodeControl(ctx)
	setLocal("172.17.0.1")
	svc.syncNodeControl(ctx)
	if gw.controlCalls != 1 {
		t.Fatalf("TAP churn pushed the guard again: %d calls", gw.controlCalls)
	}

	// A gateway from before the op: the list, TAP addresses and all.
	gw.poolsUnknown = true
	setLocal("172.17.0.1", "172.16.0.1")
	if err := svc.ResyncEgressGateway(ctx); err != nil {
		t.Fatal(err)
	}
	svc.syncNodeControl(ctx)
	if gw.listCalls != 1 || len(gw.pools) != 0 || !slices.Contains(gw.control, netip.MustParseAddrPort("172.16.0.1:21212")) {
		t.Fatalf("old gateway: list calls %d pools %v control %v", gw.listCalls, gw.pools, gw.control)
	}
	svc.syncNodeControl(ctx)
	if gw.listCalls != 1 {
		t.Fatal("an unchanged list is not pushed again")
	}
	setLocal("172.17.0.1", "172.16.0.1", "172.16.0.5")
	svc.syncNodeControl(ctx)
	if gw.listCalls != 2 || !slices.Contains(gw.control, netip.MustParseAddrPort("172.16.0.5:21212")) {
		t.Fatalf("old gateway, a new TAP address: list calls %d control %v", gw.listCalls, gw.control)
	}
	// The gateway restarts on the new binary: pools again.
	gw.poolsUnknown = false
	if err := svc.ResyncEgressGateway(ctx); err != nil {
		t.Fatal(err)
	}
	svc.syncNodeControl(ctx)
	if len(gw.pools) != 1 || gw.listCalls != 2 {
		t.Fatalf("new gateway: pools %v list calls %d", gw.pools, gw.listCalls)
	}
	// The guard off clears endpoints and pools.
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\nnode_control_port_guard: false\n"))
	svc.syncNodeControl(ctx)
	if len(gw.control) != 0 || len(gw.pools) != 0 {
		t.Fatalf("guard off: %v %v", gw.control, gw.pools)
	}
	// Without Firecracker guests there is no pool: every endpoint listed.
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\n"))
	svc.SetFirecrackerRuntime(&tapPoolRuntime{holdRuntime: hr})
	setLocal("172.17.0.1", "172.16.0.1")
	svc.syncNodeControl(ctx)
	if len(gw.pools) != 0 || !slices.Contains(gw.control, netip.MustParseAddrPort("172.16.0.1:21212")) {
		t.Fatalf("no TAP pool: pools %v control %v", gw.pools, gw.control)
	}
	// A failing push is logged and retried on the next tick.
	gw.poolsUnknown = true
	svc.egressControlPushed.Store(nil)
	calls := gw.controlCalls + gw.listCalls
	svc.syncNodeControl(ctx)
	if gw.controlCalls+gw.listCalls == calls {
		t.Fatal("nothing pushed")
	}
}

// TestNodeControlPoolEdges: an IPv6 TAP subnet or no control ports gives no
// pool; an endpoint in the pool on a port the pool doesn't list stays.
func TestNodeControlPoolEdges(t *testing.T) {
	svc, _, hr := newEgressHarness(t)
	svc.SetFirecrackerRuntime(&tapPoolRuntime{holdRuntime: hr, subnet: netip.MustParsePrefix("fd00::/64")})
	all := []netip.AddrPort{netip.MustParseAddrPort("172.16.0.1:22")}
	if nc := svc.nodeControl(all); len(nc.Pools) != 0 || len(nc.Endpoints) != 1 {
		t.Fatalf("IPv6 pool: %+v", nc)
	}
	svc.SetFirecrackerRuntime(&tapPoolRuntime{holdRuntime: hr, subnet: netip.MustParsePrefix("172.16.0.0/16")})
	svc.cfg.APIPort = 21212
	all = append(all, netip.MustParseAddrPort("172.16.0.1:7000"), netip.MustParseAddrPort("172.16.0.1:21212"))
	nc := svc.nodeControl(all)
	if len(nc.Pools) != 1 || !slices.Equal(nc.Endpoints, []netip.AddrPort{netip.MustParseAddrPort("172.16.0.1:7000")}) {
		t.Fatalf("pool edges: %+v", nc)
	}
	if poolsKey(nc) == "list|"+controlKey(all) || poolsKey(nc) == poolsKey(egress.NodeControl{Endpoints: nc.Endpoints}) {
		t.Fatal("keys must tell a pools push from a list push and from one without the pool")
	}
}
