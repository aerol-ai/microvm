package containerd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// splitFirewall is a HostFirewall with CreateRules, as privilege mode
// split's (pkg/daemon helperFirewall): it records every call.
type splitFirewall struct {
	mu    sync.Mutex
	calls []string
	off   bool
}

func (f *splitFirewall) rec(format string, args ...any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
	return nil
}

func (f *splitFirewall) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *splitFirewall) Enabled() bool              { return !f.off }
func (f *splitFirewall) BridgeSubnet() netip.Prefix { return netip.MustParsePrefix("10.88.0.0/16") }
func (f *splitFirewall) BlockAllEgress(ip string) error {
	return f.rec("block %s", ip)
}
func (f *splitFirewall) BlockAllEgressReport(ip string) (bool, error) {
	return true, f.rec("block %s", ip)
}
func (f *splitFirewall) LiftBlockAllEgress(ip string) error   { return f.rec("lift %s", ip) }
func (f *splitFirewall) ClearBlockAllEgress(ip string) error  { return f.rec("clear-block %s", ip) }
func (f *splitFirewall) BlockAllIngress(ip string) error      { return f.rec("block-in %s", ip) }
func (f *splitFirewall) ClearBlockAllIngress(ip string) error { return f.rec("clear-in %s", ip) }
func (f *splitFirewall) ApplyEgressPolicy(ip string, a, d []string) error {
	return f.rec("policy %s %v %v", ip, a, d)
}
func (f *splitFirewall) ClearEgressPolicy(ip string, a, d []string) error {
	return f.rec("clear-policy %s %v %v", ip, a, d)
}
func (f *splitFirewall) HoldEgress(ip string) error      { return f.rec("hold %s", ip) }
func (f *splitFirewall) ClearHoldEgress(ip string) error { return f.rec("clear-hold %s", ip) }
func (f *splitFirewall) SetNodeGuard(netip.Prefix, []netrules.NodePort) error {
	return f.rec("guard")
}
func (f *splitFirewall) ReassertNodeGuard() (bool, error)            { return false, f.rec("reassert-guard") }
func (f *splitFirewall) SetFloor(netip.Prefix, []netip.Prefix) error { return f.rec("floor") }
func (f *splitFirewall) ReassertFloor() (bool, error)                { return false, f.rec("reassert-floor") }
func (f *splitFirewall) FoldsIntoBuild() bool                        { return true }
func (f *splitFirewall) ClearsOnRelease() bool                       { return true }
func (f *splitFirewall) ApplyCreateRules(_ context.Context, netns, ip string, block bool, a, d []string) error {
	return f.rec("create %s %s %v %v %v", netns, ip, block, a, d)
}

// foldingNetns is the split-mode pool: a cold build takes the create's
// rules (BuildRules) when it carries them.
type foldingNetns struct {
	harnessNetns
	cold  bool
	built []string
}

func (n *foldingNetns) Provision(ctx context.Context, id string) (string, string, error) {
	if r := BuildRulesFrom(ctx); r != nil && n.cold {
		r.MarkApplied()
		n.built = append(n.built, fmt.Sprintf("%s block=%v %v", id, r.BlockAll, r.Allow))
	}
	return n.harnessNetns.Provision(ctx, id)
}

func splitFirewallDriver(t *testing.T, cold bool) (*Driver, *fakeTransport, *foldingNetns, *splitFirewall) {
	t.Helper()
	stubToolboxProbe(t)
	d := newTestDriver(t)
	tr := newFakeTransport()
	d.SetClient(NewTestClient("aerolvm", tr))
	n := &foldingNetns{harnessNetns: harnessNetns{path: "/run/aerolvm-rootd/netns/sb", ip: "10.88.0.9"}, cold: cold}
	d.SetNetnsHandoff(n)
	fw := &splitFirewall{}
	d.SetHostFirewall(fw)
	return d, tr, n, fw
}

var splitReq = models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, NetworkBlockAll: true, NetworkAllowOut: []string{"1.2.3.4/32"}}

// TestCreateFoldsItsRulesIntoTheBuild (M1 PR 5): a cold create's rules go
// with its namespace build, one helper call for both; the create makes no
// rule call of its own after.
func TestCreateFoldsItsRulesIntoTheBuild(t *testing.T) {
	d, _, n, fw := splitFirewallDriver(t, true)
	if _, err := d.Create(context.Background(), splitReq, "sb", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(n.built, []string{"sb block=true [1.2.3.4/32]"}) || len(fw.recorded()) != 0 {
		t.Fatalf("built %v, rule calls %v", n.built, fw.recorded())
	}
}

// TestCreateOnAWarmSlotIsOneCall: a warm claim builds nothing, so the
// create puts its rules on in one call, for the slot it claimed, after
// NewContainer as in single mode.
func TestCreateOnAWarmSlotIsOneCall(t *testing.T) {
	d, _, n, fw := splitFirewallDriver(t, false)
	if _, err := d.Create(context.Background(), splitReq, "sb", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if len(n.built) != 0 || !slices.Equal(fw.recorded(), []string{"create sb 10.88.0.9 true [1.2.3.4/32] []"}) {
		t.Fatalf("built %v, rule calls %v", n.built, fw.recorded())
	}
	// No rules asked, or the firewall off: no call.
	d2, _, _, fw2 := splitFirewallDriver(t, false)
	if _, err := d2.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}}, "sb", "tok", nil); err != nil {
		t.Fatal(err)
	}
	d3, _, n3, fw3 := splitFirewallDriver(t, true)
	fw3.off = true
	if _, err := d3.Create(context.Background(), splitReq, "sb", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if len(fw2.recorded()) != 0 || len(fw3.recorded()) != 0 || len(n3.built) != 0 {
		t.Fatalf("calls without rules %v, with the firewall off %v %v", fw2.recorded(), fw3.recorded(), n3.built)
	}
}

// TestFailedCreateLeavesTheClearsToTheRelease: a create that fails after
// its rules went on makes no clears of its own; the slot's release (one
// ReleaseSandbox) clears the address's rules before the address is freed.
func TestFailedCreateLeavesTheClearsToTheRelease(t *testing.T) {
	for _, cold := range []bool{true, false} {
		d, tr, n, fw := splitFirewallDriver(t, cold)
		tr.pendingTaskErr = map[string]error{"sb": errors.New("runc: exec failed")}
		if _, err := d.Create(context.Background(), splitReq, "sb", "tok", nil); err == nil {
			t.Fatal("the create succeeded")
		}
		for _, c := range fw.recorded() {
			if strings.HasPrefix(c, "clear") {
				t.Fatalf("cold=%v: the failed create cleared rules itself: %v", cold, fw.recorded())
			}
		}
		if !n.released {
			t.Fatalf("cold=%v: the slot was not released", cold)
		}
	}
}

// TestDestroyLeavesTheClearsToTheRelease: likewise for a destroy; with no
// pool to release through, the destroy clears as before.
func TestDestroyLeavesTheClearsToTheRelease(t *testing.T) {
	d, _, n, fw := splitFirewallDriver(t, true)
	sb := &models.Sandbox{ID: "sb", ContainerIP: "10.88.0.9", NetworkAllowOut: []string{"1.2.3.4/32"}}
	_ = d.Destroy(context.Background(), sb)
	if len(fw.recorded()) != 0 || !n.released {
		t.Fatalf("calls %v, released %v", fw.recorded(), n.released)
	}
	d.SetNetnsHandoff(nil)
	_ = d.Destroy(context.Background(), sb)
	if got := fw.recorded(); len(got) != 3 || !strings.HasPrefix(got[0], "clear-block") {
		t.Fatalf("calls without a pool %v", got)
	}
}

// TestNoFirewallIsNil: a nil netrules manager is no firewall at all (one
// nil check in each rule method), and single mode's manager is used as it
// is.
func TestNoFirewallIsNil(t *testing.T) {
	d := New(Config{}, nil, nil)
	if d.networkRules != nil || d.NetRulesEnabled() || d.createRules() != nil || d.clearsOnRelease() {
		t.Fatal("a nil manager is a firewall")
	}
	if err := d.ApplyNetworkBlockAll("10.88.0.9"); err != nil {
		t.Fatal(err)
	}
	m := netrules.NewWithBackend(&ruleSet{})
	if d := New(Config{}, m, nil); d.networkRules != HostFirewall(m) || d.createRules() != nil {
		t.Fatal("single mode's manager was not used as it is")
	}
	ctx, r := d.buildRulesFor(context.Background(), splitReq)
	if r != nil || BuildRulesFrom(ctx) != nil || r.Applied() {
		t.Fatal("single mode carried rules into a build")
	}
}
