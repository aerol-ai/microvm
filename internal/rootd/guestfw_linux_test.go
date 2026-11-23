//go:build linux

package rootd

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/ipv6fence"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// TestGuestKernelFirewall (M1 PR 14): the guests' firewall over in-memory
// backends. It keeps single mode's chain for guests, accepts the helper's
// own TAP base on it, puts a floor in at open, has no fence of its own,
// and writes each op's rules keyed by the guest's address.
func TestGuestKernelFirewall(t *testing.T) {
	rules := &memRules{rules: map[string][]string{}}
	origRules, origSysctls := newGuestRulesManager, ensureSysctls
	t.Cleanup(func() { newGuestRulesManager, ensureSysctls = origRules, origSysctls })
	var backend string
	newGuestRulesManager = func(b string) (*netrules.Manager, error) {
		backend = b
		return netrules.NewWithBackend(rules), nil
	}
	ensureSysctls = func() error { return nil }
	fc := &FirecrackerHostsConfig{TapBase: "172.16.0.0/20", TapPoolSize: 256}
	h, err := openGuestFirewall(Config{Firewall: FirewallConfig{Backend: "iptables"}}, fc)
	if err != nil {
		t.Fatal(err)
	}
	k := h.(*kernelFirewall)
	if backend != "iptables" || k.subnet != netip.MustParsePrefix("172.16.0.0/20") {
		t.Fatalf("backend %q, subnet %s", backend, k.subnet)
	}
	// The fake manager keeps netrules' default chain name; the kernel run
	// (the live box) shows AEROLVM-FC.
	if !rules.holds("-s 172.16.0.0/20 -j ACCEPT") || !rules.holds("-s 172.16.0.0/20 -d 169.254.169.254/32 -j DROP") {
		t.Fatalf("the guests' accepts and floor are not in: %v", rules.rules)
	}
	ctx := context.Background()
	if fence, err := k.EnsureHost(ctx); err != nil || fence != nil {
		t.Fatalf("EnsureHost = %v, %v", fence, err)
	}
	k.Reassert(ctx)
	if covered, _ := k.GuestFence(); covered {
		t.Fatal("the guests' firewall claims a fence of its own")
	}
	ip := "172.16.0.14"
	for _, op := range []rootdpb.SandboxRulesOp{rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS,
		rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY} {
		if _, err := k.Rules(ctx, op, ip, []string{"1.2.3.4/32"}, nil); err != nil {
			t.Fatalf("%v: %v", op, err)
		}
	}
	if !rules.holds("-s "+ip+" -j DROP") || !rules.holds("-s "+ip+" -d 1.2.3.4/32") {
		t.Fatalf("no rules for %s: %v", ip, rules.rules)
	}
	guard := []rootpolicy.NodePort{{Proto: "tcp", Port: 15080}}
	if _, err := k.SetNodeGuard(guard); err != nil {
		t.Fatal(err)
	}
	if !rules.holds("15080") {
		t.Fatalf("no guard rule: %v", rules.rules)
	}
	for _, bad := range []*FirecrackerHostsConfig{{TapBase: "x"}} {
		if _, err := openGuestFirewall(Config{}, bad); err == nil {
			t.Fatalf("a guest firewall opened on TAP base %q", bad.TapBase)
		}
	}
	newGuestRulesManager = func(string) (*netrules.Manager, error) { return nil, errors.New("no backend") }
	if _, err := openGuestFirewall(Config{}, fc); err == nil {
		t.Fatal("a guest firewall with no backend opened")
	}
	// The real one takes only the backends netrules knows.
	if _, err := origRules("bogus"); err == nil || !strings.Contains(err.Error(), "unknown netrules backend") {
		t.Fatalf("a bogus backend = %v", err)
	}
}

// TestFenceCoversGuestTaps: a helper that serves Firecracker fences every
// TAP in the same table as the bridge, and reports their state; one that
// serves none reports the TAPs uncovered.
func TestFenceCoversGuestTaps(t *testing.T) {
	rules, fence := &memRules{rules: map[string][]string{}}, &memFence{}
	origRules, origFence, origSysctls := newRulesManager, newFenceBackend, ensureSysctls
	t.Cleanup(func() { newRulesManager, newFenceBackend, ensureSysctls = origRules, origFence, origSysctls })
	newRulesManager = func(string) (*netrules.Manager, error) { return netrules.NewWithBackend(rules), nil }
	newFenceBackend = func() ipv6fence.Backend { return fence }
	ensureSysctls = func() error { return nil }
	h, err := openFirewall(Config{Hosts: HostsConfig{Firecracker: &FirecrackerHostsConfig{TapBase: "172.16.0.0/20", TapPoolSize: 256}}}, newFakeNet())
	if err != nil {
		t.Fatal(err)
	}
	k := h.(*kernelFirewall)
	if covered, state := k.GuestFence(); !covered || !errors.Is(state, ipv6fence.ErrNotSynced) {
		t.Fatalf("before a sync: %v, %v", covered, state)
	}
	if _, err := k.EnsureHost(context.Background()); err != nil {
		t.Fatal(err)
	}
	if covered, state := k.GuestFence(); !covered || state != nil {
		t.Fatalf("after a sync: %v, %v", covered, state)
	}
	taps := slices.ContainsFunc(fence.rules, func(r ipv6fence.Rule) bool { return strings.HasPrefix(r.Name, "fctap") })
	if !taps {
		t.Fatalf("the fence leaves the TAPs out: %+v", fence.rules)
	}
	plain, err := openFirewall(Config{}, newFakeNet())
	if err != nil {
		t.Fatal(err)
	}
	if covered, _ := plain.GuestFence(); covered {
		t.Fatal("a helper with no Firecracker claims to fence the TAPs")
	}
}
