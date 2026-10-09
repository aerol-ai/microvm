package firecracker

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeNetRules records calls as "op ip [allow] [deny]".
type fakeNetRules struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeNetRules) rec(op, ip string, extra ...[]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := op + " " + ip
	for _, e := range extra {
		c += " " + strings.Join(e, ",")
	}
	f.calls = append(f.calls, c)
	return f.err
}

func (f *fakeNetRules) BlockAllEgress(ip string) error       { return f.rec("block-egress", ip) }
func (f *fakeNetRules) ClearBlockAllEgress(ip string) error  { return f.rec("clear-egress", ip) }
func (f *fakeNetRules) BlockAllIngress(ip string) error      { return f.rec("block-ingress", ip) }
func (f *fakeNetRules) ClearBlockAllIngress(ip string) error { return f.rec("clear-ingress", ip) }
func (f *fakeNetRules) HoldEgress(ip string) error           { return f.rec("hold", ip) }
func (f *fakeNetRules) ClearHoldEgress(ip string) error      { return f.rec("clear-hold", ip) }
func (f *fakeNetRules) ApplyEgressPolicy(ip string, a, d []string) error {
	return f.rec("policy", ip, a, d)
}
func (f *fakeNetRules) ClearEgressPolicy(ip string, a, d []string) error {
	return f.rec("clear-policy", ip, a, d)
}
func (f *fakeNetRules) SetFloor(subnet netip.Prefix, cidrs []netip.Prefix) error {
	return f.rec("floor", subnet.String())
}

func (f *fakeNetRules) has(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.ContainsFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, prefix) })
}

// TestCreateAppliesEgressBeforeBoot (Phase 4): the guest IP is filtered
// before the VM runs, and destroy clears every rule keyed by it.
func TestCreateAppliesEgressBeforeBoot(t *testing.T) {
	f := newDriverFixture(t)
	rules := &fakeNetRules{}
	f.driver.SetNetRules(rules)
	if !f.driver.NetRulesEnabled() {
		t.Fatal("enabled")
	}
	st, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
		NetworkAllowOut: []string{"1.1.1.0/24"}, NetworkDenyOut: []string{"0.0.0.0/0"}}, "sb-eg", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rules.has("policy " + st.ContainerIP + " 1.1.1.0/24 0.0.0.0/0") {
		t.Fatalf("calls = %v", rules.calls)
	}
	if err := f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-eg", NetworkAllowOut: []string{"1.1.1.0/24"}, NetworkDenyOut: []string{"0.0.0.0/0"}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"clear-egress " + st.ContainerIP, "clear-ingress " + st.ContainerIP, "clear-hold " + st.ContainerIP, "clear-policy " + st.ContainerIP} {
		if !rules.has(want) {
			t.Fatalf("missing %q in %v", want, rules.calls)
		}
	}

	// Block-all, and a firewall that refuses: the create fails and leaves
	// nothing behind.
	g := newDriverFixture(t)
	bad := &fakeNetRules{err: errors.New("iptables gone")}
	g.driver.SetNetRules(bad)
	if _, err := g.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128, NetworkBlockAll: true}, "sb-bad", "tok", nil); err == nil {
		t.Fatal("a refused rule must fail the create")
	}
	if !bad.has("block-egress ") {
		t.Fatalf("calls = %v", bad.calls)
	}
	if g.pool.release == 0 {
		t.Fatal("the slot must be released")
	}
	// No firewall: an egress create is refused, never run unfiltered.
	h := newDriverFixture(t)
	if _, err := h.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128, NetworkBlockAll: true}, "sb-none", "tok", nil); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("no firewall: %v", err)
	}
}

func TestNetRuleMethods(t *testing.T) {
	d := New(Config{}, nil)
	for name, fn := range map[string]func() error{
		"ClearNetworkRules":        func() error { return d.ClearNetworkRules("10.0.0.2") },
		"ApplyNetworkBlockAll":     func() error { return d.ApplyNetworkBlockAll("10.0.0.2") },
		"ApplyEgressPolicy":        func() error { return d.ApplyEgressPolicy("10.0.0.2", nil, nil) },
		"ClearEgressPolicy":        func() error { return d.ClearEgressPolicy("10.0.0.2", nil, nil) },
		"ApplyNetworkBlockIngress": func() error { return d.ApplyNetworkBlockIngress("10.0.0.2") },
		"ClearNetworkBlockIngress": func() error { return d.ClearNetworkBlockIngress("10.0.0.2") },
		"ClearNetworkBlockEgress":  func() error { return d.ClearNetworkBlockEgress("10.0.0.2") },
		"ApplyEgressHold":          func() error { return d.ApplyEgressHold("10.0.0.2") },
		"ClearEgressHold":          func() error { return d.ClearEgressHold("10.0.0.2") },
		"SetEgressFloor":           func() error { return d.SetEgressFloor(context.Background(), nil) },
	} {
		if err := fn(); !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("%s without a firewall: %v", name, err)
		}
	}
	rules := &fakeNetRules{}
	d.SetNetRules(rules)
	if err := d.SetEgressFloor(context.Background(), nil); err != nil || rules.has("floor") {
		t.Fatal("no TAP subnet, no floor")
	}
	d.SetTapSubnet(netip.MustParsePrefix("172.16.0.0/16"))
	calls := []func() error{
		func() error { return d.ClearNetworkRules("10.0.0.2") },
		func() error { return d.ApplyNetworkBlockAll("10.0.0.2") },
		func() error { return d.ApplyEgressPolicy("10.0.0.2", []string{"1.1.1.0/24"}, nil) },
		func() error { return d.ClearEgressPolicy("10.0.0.2", []string{"1.1.1.0/24"}, nil) },
		func() error { return d.ApplyNetworkBlockIngress("10.0.0.2") },
		func() error { return d.ClearNetworkBlockIngress("10.0.0.2") },
		func() error { return d.ClearNetworkBlockEgress("10.0.0.2") },
		func() error { return d.ApplyEgressHold("10.0.0.2") },
		func() error { return d.ClearEgressHold("10.0.0.2") },
		func() error { return d.SetEgressFloor(context.Background(), nil) },
	}
	for i, fn := range calls {
		if err := fn(); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	for _, want := range []string{"clear-egress", "clear-ingress", "block-egress", "policy", "clear-policy", "block-ingress", "hold", "clear-hold", "floor 172.16.0.0/16"} {
		if !rules.has(want) {
			t.Fatalf("missing %q in %v", want, rules.calls)
		}
	}
	if err := d.clearGuestRules("", nil, nil); err != nil {
		t.Fatal(err)
	}
}

// TestGatewayGuestRules (Phase 4 part 2): the gateway serves the guests
// only once the driver has their firewall, and a gateway-mode guest's
// hostname list is never handed to iptables on destroy.
func TestGatewayGuestRules(t *testing.T) {
	d := New(Config{}, nil)
	if _, ok := d.EgressTapSubnet(); ok {
		t.Fatal("no firewall, no gateway for the guests")
	}
	rules := &fakeNetRules{}
	d.SetNetRules(rules)
	if _, ok := d.EgressTapSubnet(); ok {
		t.Fatal("no TAP subnet, no gateway for the guests")
	}
	d.SetTapSubnet(netip.MustParsePrefix("172.16.0.0/16"))
	if p, ok := d.EgressTapSubnet(); !ok || p.String() != "172.16.0.0/16" {
		t.Fatalf("EgressTapSubnet = %v, %v", p, ok)
	}

	if err := d.clearGuestRules("172.16.0.2", []string{"pypi.org", "1.1.1.0/24"}, nil); err != nil {
		t.Fatal(err)
	}
	if !rules.has("clear-policy 172.16.0.2  ") || rules.has("clear-policy 172.16.0.2 pypi") {
		t.Fatalf("a hostname list must not reach the firewall: %v", rules.calls)
	}
	if err := d.clearGuestRules("172.16.0.6", []string{"1.1.1.0/24"}, []string{"0.0.0.0/0"}); err != nil {
		t.Fatal(err)
	}
	if !rules.has("clear-policy 172.16.0.6 1.1.1.0/24 0.0.0.0/0") {
		t.Fatalf("a CIDR list is cleared as applied: %v", rules.calls)
	}
	if firewallLists([]string{"bad entry"}, nil) {
		t.Fatal("an invalid list is never handed to the firewall")
	}
}
