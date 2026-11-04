package service

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// firewalledFC is a Firecracker runtime whose node has the guest firewall
// (egress Phase 4).
type firewalledFC struct{ *policyRuntime }

func (firewalledFC) NetRulesEnabled() bool { return true }

var fcTapSubnet = netip.MustParsePrefix("172.16.0.0/16")

func (firewalledFC) EgressTapSubnet() (netip.Prefix, bool) { return fcTapSubnet, true }

// TestFirecrackerEgress (Phase 4): with the guest firewall, block-all and
// CIDR lists reach the driver at create and change live; rules stay 501
// (CEO D14).
func TestFirecrackerEgress(t *testing.T) {
	ctx := context.Background()
	svc, _, rt := newPolicyHarness(t)
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	fc := firewalledFC{rt}
	svc.SetFirecrackerRuntime(fc)

	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
		NetworkAllowOut: []string{"1.1.1.0/24"}, NetworkDenyOut: []string{"0.0.0.0/0"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := rt.lastCreateReq; !slices.Equal(got.NetworkAllowOut, []string{"1.1.1.0/24"}) {
		t.Fatalf("driver got %+v", got)
	}
	rules := models.CreateSandboxRequest{Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
		NetworkAllowOut: []string{"1.1.1.0/24"}, NetworkEgressRules: []models.EgressRule{{Host: "1.1.1.1"}}}
	if _, err := svc.CreateSandbox(ctx, rules); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("rules: %v", err)
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
		NetworkAllowOut: []string{"bad entry"}}); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("a bad entry is a 400: %v", err)
	}

	// Live: block-all, then back to a CIDR list, through the guest firewall.
	row, _ := svc.store.Get(ctx, resp.ID)
	row.Status = models.SandboxStatusStarted
	if err := svc.store.Upsert(ctx, row); err != nil {
		t.Fatal(err)
	}
	before := rt.blockCalls
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkBlockAll: true}); err != nil {
		t.Fatal(err)
	}
	if rt.blockCalls == before {
		t.Fatal("block-all must reach the guest firewall")
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"8.8.8.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"},
		NetworkEgressRules: []models.EgressRule{{Host: "1.1.1.1"}}}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("rules live: %v", err)
	}

	// No firewall on the node: refused, as before.
	svc.SetFirecrackerRuntime(rt)
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeFirecracker, Image: "docker://alpine", NetworkBlockAll: true}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("no firewall: %v", err)
	}
}

func newFirecrackerGatewayHarness(t *testing.T) (*Service, *fakeGateway, *policyRuntime) {
	t.Helper()
	svc, gw, rt := newPolicyHarness(t)
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(firewalledFC{rt})
	return svc, gw, rt
}

func fcCreate(req models.CreateSandboxRequest) models.CreateSandboxRequest {
	req.Runtime, req.Image = models.RuntimeFirecracker, "docker://alpine"
	return req
}

// TestFirecrackerGatewayEgress (Phase 4 part 2): hostname entries, profiles
// and learn mode put a guest under the egress gateway the way they do a
// container. The driver boots it shut (block-all copy), the attach lifts
// that, and every failure fails closed.
func TestFirecrackerGatewayEgress(t *testing.T) {
	ctx := context.Background()
	svc, gw, rt := newFirecrackerGatewayHarness(t)
	putProfile(t, svc, ctx, "web", "files.pythonhosted.org")

	for name, req := range map[string]models.CreateSandboxRequest{
		"hostname": {NetworkAllowOut: []string{"pypi.org"}},
		"profiles": {EgressProfiles: []string{"web"}},
		"learn":    {NetworkEgressMode: models.NetworkEgressModeLearn},
	} {
		resp, err := svc.CreateSandbox(ctx, fcCreate(req))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d := rt.lastCreateReq; !d.NetworkBlockAll || len(d.NetworkAllowOut) != 0 || len(d.NetworkDenyOut) != 0 {
			t.Fatalf("%s: the driver must get the block-all copy: %+v", name, d)
		}
		gw.mu.Lock()
		spec, ok := gw.attached[resp.ID]
		gw.mu.Unlock()
		if !ok || spec.IP.String() != "10.0.0.2" {
			t.Fatalf("%s: not attached: %+v", name, spec)
		}
		if name == "learn" && !spec.Learn {
			t.Fatalf("learn: spec = %+v", spec)
		}
		if name == "profiles" && !slices.Contains(spec.AllowOut, "files.pythonhosted.org") {
			t.Fatalf("profiles: the effective list goes to the gateway: %+v", spec)
		}
		if !rt.lifted("10.0.0.2") {
			t.Fatalf("%s: the attach must lift the driver's block-all", name)
		}
		row, err := svc.store.Get(ctx, resp.ID)
		if err != nil || row.NetworkBlockAll {
			t.Fatalf("%s: row = %+v, %v", name, row, err)
		}
		if got := svc.EgressStatus(ctx, row); got != EgressStatusActive {
			t.Fatalf("%s: egress_status = %q", name, got)
		}
		if err := svc.DestroySandbox(ctx, resp.ID); err != nil {
			t.Fatalf("%s: destroy: %v", name, err)
		}
		if gw.isAttached(resp.ID) {
			t.Fatalf("%s: destroy must detach", name)
		}
	}

	// The gateway listens on the TAP pool too, and the pool is never probed
	// by the self-test (no bridge device to attach a probe to).
	gw.mu.Lock()
	bridges := append([]egress.Bridge(nil), gw.bridges...)
	gw.mu.Unlock()
	if !slices.Contains(bridges, egress.TapPoolBridge(fcTapSubnet)) || len(bridges) != 2 {
		t.Fatalf("bridges = %+v", bridges)
	}
	pn := &fakeSelfTestNet{}
	svc.SetEgressSelfTest(pn)
	if err := svc.runEgressSelfTests(ctx, bridges, true); err != nil {
		t.Fatal(err)
	}
	if pn.setups != 1 {
		t.Fatalf("probed %d bridges, want only docker0", pn.setups)
	}
	svc.SetEgressSelfTest(nil)

	// Live: a CIDR guest moves under the gateway and back off it.
	resp, err := svc.CreateSandbox(ctx, fcCreate(models.CreateSandboxRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}))
	if err != nil {
		t.Fatal(err)
	}
	if gw.isAttached(resp.ID) {
		t.Fatal("a CIDR guest stays off the gateway")
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	if !gw.isAttached(resp.ID) {
		t.Fatal("a hostname policy must attach the guest live")
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"8.8.8.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if gw.isAttached(resp.ID) {
		t.Fatal("back to CIDRs must detach the guest")
	}
}

// TestFirecrackerGatewayEgressFailsClosed: no gateway, a failed self-test
// or a failed attach never leaves a guest running unfiltered.
func TestFirecrackerGatewayEgressFailsClosed(t *testing.T) {
	ctx := context.Background()
	hostname := fcCreate(models.CreateSandboxRequest{NetworkAllowOut: []string{"pypi.org"}})

	svc, gw, rt := newFirecrackerGatewayHarness(t)
	gw.attachErr = egress.ErrUnavailable
	if _, err := svc.CreateSandbox(ctx, hostname); !errors.Is(err, ErrEgressGatewayUnavailable) {
		t.Fatalf("attach failure = %v, want 503", err)
	}
	if len(rt.destroyIDs) != 1 || !slices.Contains(gw.detached, rt.lastCreateID) {
		t.Fatalf("rollback: destroyed %v, detached %v", rt.destroyIDs, gw.detached)
	}
	if _, err := svc.store.Get(ctx, rt.lastCreateID); err == nil {
		t.Fatal("the row must be rolled back")
	}

	// A failover replay can't refuse its spec: it comes up shut and held.
	gw.attachErr = egress.ErrUnavailable
	replay := context.WithValue(ctx, storedSpecReplayKey{}, true)
	resp, err := svc.CreateSandbox(replay, hostname)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rt.holds, "10.0.0.2") || rt.lifted("10.0.0.2") {
		t.Fatalf("replay must hold the guest shut: holds %v", rt.holds)
	}
	if st, _ := svc.store.GetEgressState(ctx, resp.ID); st.HoldReason != egressHoldUnavailable {
		t.Fatalf("hold = %q", st.HoldReason)
	}

	// The driver itself can fail: nothing to attach, nothing left behind.
	gw.attachErr = nil
	rt.createErr = errors.New("vmm spawn failed")
	if _, err := svc.CreateSandbox(ctx, hostname); err == nil {
		t.Fatal("driver failure must surface")
	}
	rt.createErr = nil

	// No gateway on the node, or a failed self-test: 501 before the driver.
	calls := rt.createCalls
	svc.cfg.EgressFQDNEnabled = false
	if _, err := svc.CreateSandbox(ctx, hostname); !errors.Is(err, ErrEgressGatewayRequired) {
		t.Fatalf("no gateway = %v", err)
	}
	svc.cfg.EgressFQDNEnabled = true
	pn := &fakeSelfTestNet{}
	svc.SetEgressSelfTest(pn)
	if _, err := svc.CreateSandbox(ctx, hostname); !errors.Is(err, ErrEgressGatewayUnavailable) {
		t.Fatalf("self-test pending = %v, want 503", err)
	}
	svc.egressSelfTest.Load().tested.Store(true)
	svc.egressSelfTest.Load().failed.Store(true)
	if _, err := svc.CreateSandbox(ctx, hostname); !errors.Is(err, ErrEgressSelfTestFailed) {
		t.Fatalf("self-test failed = %v", err)
	}
	if rt.createCalls != calls {
		t.Fatal("a refused create must not reach the driver")
	}
}

// TestFirecrackerGatewayStopStart: a stopped gateway-mode guest keeps its
// IP, so it is shut at stop (a gateway re-Sync while it is down drops its
// entry, and the VM resumes before Start re-attaches it). Start re-attaches
// it, or, when its policy no longer needs the gateway, lifts that block.
func TestFirecrackerGatewayStopStart(t *testing.T) {
	ctx := context.Background()
	svc, gw, rt := newFirecrackerGatewayHarness(t)
	resp, err := svc.CreateSandbox(ctx, fcCreate(models.CreateSandboxRequest{NetworkAllowOut: []string{"pypi.org"}}))
	if err != nil {
		t.Fatal(err)
	}
	blocks := len(rt.applyNetworkBlockAllCalls)
	if _, err := svc.StopSandbox(ctx, resp.ID); err != nil {
		t.Fatal(err)
	}
	if len(rt.applyNetworkBlockAllCalls) != blocks+1 || rt.applyNetworkBlockAllCalls[blocks] != "10.0.0.2" {
		t.Fatalf("stop must shut the guest's IP: %v", rt.applyNetworkBlockAllCalls)
	}
	if _, err := svc.StartSandbox(ctx, resp.ID); err != nil {
		t.Fatal(err)
	}
	gw.mu.Lock()
	spec := gw.attached[resp.ID]
	gw.mu.Unlock()
	if spec.IP.String() != "10.0.0.3" || !rt.lifted("10.0.0.3") {
		t.Fatalf("start must re-attach and lift: %+v", spec)
	}

	// Stopped again, then moved to a CIDR list: Start lifts the stop-time
	// block and applies the list.
	if _, err := svc.StopSandbox(ctx, resp.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}); err != nil {
		t.Fatal(err)
	}
	lifts := len(rt.clearNetworkBlockEgresses)
	if _, err := svc.StartSandbox(ctx, resp.ID); err != nil {
		t.Fatal(err)
	}
	if len(rt.clearNetworkBlockEgresses) != lifts+1 {
		t.Fatalf("start must lift the stop-time block: %v", rt.clearNetworkBlockEgresses)
	}
	if got := rt.applied[len(rt.applied)-1]; !slices.Equal(got, []string{"1.1.1.0/24"}) {
		t.Fatalf("start must apply the CIDR list: %v", rt.applied)
	}
	// A CIDR guest is not shut at stop.
	blocks = len(rt.applyNetworkBlockAllCalls)
	if _, err := svc.StopSandbox(ctx, resp.ID); err != nil {
		t.Fatal(err)
	}
	if len(rt.applyNetworkBlockAllCalls) != blocks {
		t.Fatal("only a gateway-mode guest is shut at stop")
	}

	// Firewall errors there are logged, not fatal: Start re-shuts a gateway
	// guest anyway, and a block left in place fails closed.
	rt.liftErr = errors.New("iptables busy")
	if _, err := svc.StartSandbox(ctx, resp.ID); err != nil {
		t.Fatalf("a failed lift must not fail the start: %v", err)
	}
	rt.liftErr = nil
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	rt.blockErr = errors.New("iptables busy")
	if _, err := svc.StopSandbox(ctx, resp.ID); err != nil {
		t.Fatalf("a failed shut must not fail the stop: %v", err)
	}
}
