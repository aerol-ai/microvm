//go:build linux

package rootd

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/ipv6fence"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// The helper's kernel firewall (firewall_linux.go) over in-memory
// backends, so its own logic runs without root: which netrules call each
// op makes, the lists a node guard and a floor keep, and the fence. The
// real kernel is firewall_kernel_linux_test.go's.

// memRules is netrules.RuleBackend in memory.
type memRules struct {
	mu    sync.Mutex
	rules map[string][]string // table/chain -> rulespecs
}

func (m *memRules) key(table, chain string) string { return table + "/" + chain }

func (m *memRules) Exists(table, chain string, spec ...string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Contains(m.rules[m.key(table, chain)], strings.Join(spec, " ")), nil
}

func (m *memRules) Insert(table, chain string, _ int, spec ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[m.key(table, chain)] = append(m.rules[m.key(table, chain)], strings.Join(spec, " "))
	return nil
}

// Delete removes one matching rule, and fails when there is none, as a
// kernel backend does (netrules deletes until that error).
func (m *memRules) Delete(table, chain string, spec ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, s := m.key(table, chain), strings.Join(spec, " ")
	i := slices.Index(m.rules[k], s)
	if i < 0 {
		return errors.New("no such rule")
	}
	m.rules[k] = slices.Delete(m.rules[k], i, i+1)
	return nil
}

// The chain calls a real backend makes: here each is a chain that exists.
func (m *memRules) EnsureUserChain(chain string) error   { return m.chain("filter", chain) }
func (m *memRules) EnsureForwardJump(chain string) error { return m.chain("filter", "FORWARD->"+chain) }
func (m *memRules) EnsureInputChain(chain string) error  { return m.chain("filter", "INPUT->"+chain) }
func (m *memRules) EnsureJumpChain(parent, child string) error {
	return m.chain("filter", parent+"->"+child)
}
func (m *memRules) FlushChain(chain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[m.key("filter", chain)] = nil
	return nil
}

func (m *memRules) chain(table, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rules[m.key(table, name)]; !ok {
		m.rules[m.key(table, name)] = nil
	}
	return nil
}

func (m *memRules) holds(sub string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rs := range m.rules {
		for _, r := range rs {
			if strings.Contains(r, sub) {
				return true
			}
		}
	}
	return false
}

// memFence is ipv6fence.Backend in memory.
type memFence struct {
	mu    sync.Mutex
	rules []ipv6fence.Rule
	err   error
}

func (f *memFence) Apply(rules []ipv6fence.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.rules = rules
	return nil
}

func (f *memFence) Check(rules []ipv6fence.Rule) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err == nil && slices.Equal(f.rules, rules), f.err
}

func memKernelFirewall(t *testing.T) (*kernelFirewall, *memRules, *memFence) {
	t.Helper()
	rules, fence := &memRules{rules: map[string][]string{}}, &memFence{}
	origRules, origFence, origSysctls := newRulesManager, newFenceBackend, ensureSysctls
	t.Cleanup(func() { newRulesManager, newFenceBackend, ensureSysctls = origRules, origFence, origSysctls })
	newRulesManager = func(string) (*netrules.Manager, error) { return netrules.NewWithBackend(rules), nil }
	newFenceBackend = func() ipv6fence.Backend { return fence }
	ensureSysctls = func() error { return nil }
	h, err := openFirewall(Config{}, newFakeNet())
	if err != nil {
		t.Fatal(err)
	}
	return h.(*kernelFirewall), rules, fence
}

func TestKernelFirewallLogic(t *testing.T) {
	k, rules, fence := memKernelFirewall(t)
	ctx := context.Background()
	fenceErr, err := k.EnsureHost(ctx)
	if err != nil || fenceErr != nil {
		t.Fatalf("EnsureHost = %v, %v", fenceErr, err)
	}
	if len(fence.rules) == 0 {
		t.Fatal("no fence rules applied")
	}
	k.Reassert(ctx)

	ip := "10.88.0.5"
	for _, op := range []rootdpb.SandboxRulesOp{
		rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_INGRESS,
		rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY,
	} {
		if _, err := k.Rules(op, ip, []string{"1.2.3.4/32"}, []string{"10.0.0.0/8"}); err != nil {
			t.Fatalf("%v: %v", op, err)
		}
	}
	if !rules.holds(ip) || !rules.holds("1.2.3.4/32") {
		t.Fatalf("rules %v", rules.rules)
	}
	for _, op := range []rootdpb.SandboxRulesOp{
		rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_LIFT_BLOCK_EGRESS, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_EGRESS,
		rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_INGRESS, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_HOLD_EGRESS,
		rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY,
	} {
		if _, err := k.Rules(op, ip, []string{"1.2.3.4/32"}, []string{"10.0.0.0/8"}); err != nil {
			t.Fatalf("%v: %v", op, err)
		}
	}
	if _, err := k.Rules(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_UNSPECIFIED, ip, nil, nil); err == nil {
		t.Fatal("an unknown op passed")
	}
	if err := k.ClearAddress(ip); err != nil {
		t.Fatal(err)
	}
	if rules.holds(ip) {
		t.Fatalf("rules of %s left: %v", ip, rules.rules)
	}

	// The node guard and the floor: set once, then re-asserted while the
	// list is the same.
	guard := []rootpolicy.NodePort{{Proto: "tcp", Port: 15080}, {Proto: "udp", Port: 53, Dst: "10.0.1.5"}}
	if _, err := k.SetNodeGuard(guard); err != nil || !k.guardSet {
		t.Fatalf("guard: %v (kept %v)", err, k.guardSet)
	}
	if _, err := k.SetNodeGuard(guard); err != nil {
		t.Fatal(err)
	}
	if !rules.holds("15080") {
		t.Fatalf("no guard rule: %v", rules.rules)
	}
	floor := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	if _, err := k.SetFloor(floor); err != nil || !slices.Contains(k.floor, netip.MustParsePrefix("169.254.169.254/32")) {
		t.Fatalf("floor: %v, %v lacks the metadata endpoint", err, k.floor)
	}
	if _, err := k.SetFloor(floor); err != nil {
		t.Fatal(err)
	}
	if !rules.holds("10.20.0.0/16") || !rules.holds("169.254.169.254") {
		t.Fatalf("no floor rules: %v", rules.rules)
	}

	// A fence the kernel refuses is a state, not a failure of the call.
	fence.mu.Lock()
	fence.err = errors.New("nf_tables: no such family")
	fence.mu.Unlock()
	if fenceErr, err := k.EnsureHost(ctx); err != nil || fenceErr == nil {
		t.Fatalf("a refused fence = %v, %v", fenceErr, err)
	}
	// Sysctls that cannot be set fail the call.
	ensureSysctls = func() error { return errors.New("read-only /proc/sys") }
	if _, err := k.EnsureHost(ctx); err == nil {
		t.Fatal("unset sysctls passed")
	}
	newRulesManager = func(string) (*netrules.Manager, error) { return nil, errors.New("no backend") }
	if _, err := openFirewall(Config{}, newFakeNet()); err == nil {
		t.Fatal("a firewall with no backend opened")
	}
}
