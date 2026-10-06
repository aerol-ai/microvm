package service

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

// floorRuntime is a container runtime that records the deny floor.
type floorRuntime struct {
	*holdRuntime
	floor [][]netip.Prefix
	err   error
}

func (f *floorRuntime) SetEgressFloor(_ context.Context, cidrs []netip.Prefix) error {
	f.floor = append(f.floor, cidrs)
	return f.err
}

// TestOperatorFloorReachesTheHostFirewall (§5.10 PC-2): loading or changing
// the operator file installs deny_cidrs on each container engine; a failure
// is logged, not fatal.
func TestOperatorFloorReachesTheHostFirewall(t *testing.T) {
	svc, _, hr := newEgressHarness(t)
	rt := &floorRuntime{holdRuntime: hr}
	svc.docker = rt
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\ndeny_cidrs: [10.20.0.0/16]\n"))
	if len(rt.floor) != 1 || len(rt.floor[0]) != 1 || rt.floor[0][0] != netip.MustParsePrefix("10.20.0.0/16") {
		t.Fatalf("floor = %v", rt.floor)
	}
	rt.err = errors.New("iptables gone")
	svc.OnEgressOperatorChange(operatorWatcher(t, "version: 1\n").Current())
	if len(rt.floor) != 2 || len(rt.floor[1]) != 0 {
		t.Fatalf("a changed file replaces the floor: %v", rt.floor)
	}
	svc.applyEgressFloor(context.Background(), nil) // no file: nothing to do
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
	svc.syncNodeControl(ctx)
	if gw.controlCalls != 0 {
		t.Fatal("no operator file: the guard is never pushed")
	}
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\n"))
	svc.syncNodeControl(ctx)
	svc.syncNodeControl(ctx)
	if gw.controlCalls != 1 || len(gw.control) != 1 || gw.control[0] != netip.MustParseAddrPort("172.17.0.1:21212") {
		t.Fatalf("push = %d calls %v", gw.controlCalls, gw.control)
	}
	if err := svc.ResyncEgressGateway(ctx); err != nil {
		t.Fatal(err)
	}
	svc.syncNodeControl(ctx)
	if gw.controlCalls != 2 {
		t.Fatal("a full sync must re-push the list to a restarted gateway")
	}
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\nnode_control_port_guard: false\n"))
	svc.syncNodeControl(ctx)
	if gw.controlCalls != 3 || len(gw.control) != 0 {
		t.Fatalf("turning the guard off must clear it: %v", gw.control)
	}
}
