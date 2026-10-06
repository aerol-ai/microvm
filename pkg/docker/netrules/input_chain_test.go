package netrules

import (
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

func inputKey(spec ...string) string { return memKey("filter", ChainAerolvmInput, spec...) }

// TestBlockAllEgressGuardsHostInput covers P0-5: block-all must also drop the
// sandbox's new connections to the host itself, and the clear must lift it.
func TestBlockAllEgressGuardsHostInput(t *testing.T) {
	be := &memBackend{}
	mgr := NewWithBackend(be)
	const ip = "10.0.0.9"
	if err := mgr.BlockAllEgress(ip); err != nil {
		t.Fatal(err)
	}
	if !be.hasChain(ChainAerolvmInput) || !be.inputJump {
		t.Fatal("block-all must bootstrap AEROLVM-INPUT and its INPUT jump")
	}
	if ok, _ := be.Exists("filter", ChainAerolvmInput, inputBlockSpec(ip)...); !ok {
		t.Fatalf("missing input drop; rules=%v", be.rules)
	}
	if err := mgr.ClearBlockAllEgress(ip); err != nil {
		t.Fatal(err)
	}
	if be.ruleCount() != 0 {
		t.Fatalf("clear left rules behind: %v", be.rules)
	}
}

// TestInputRulesStayDisjoint: a quota-driven ClearBlockAllEgress must not
// lift an allowlist's input drop, and ClearEgressPolicy must not lift a block.
func TestInputRulesStayDisjoint(t *testing.T) {
	be := &memBackend{}
	mgr := NewWithBackend(be)
	const ip = "10.0.0.10"
	allow := []string{"10.88.0.1/32"}
	if err := mgr.ApplyEgressPolicy(ip, allow, nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.BlockAllEgress(ip); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ClearBlockAllEgress(ip); err != nil {
		t.Fatal(err)
	}
	for _, spec := range [][]string{inputPolicyDropSpec(ip), inputPolicyReturnSpec(ip, allow[0])} {
		if ok, _ := be.Exists("filter", ChainAerolvmInput, spec...); !ok {
			t.Fatalf("quota clear removed allowlist input rule %v", spec)
		}
	}
	if err := mgr.BlockAllEgress(ip); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ClearEgressPolicy(ip, allow, nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := be.Exists("filter", ChainAerolvmInput, inputBlockSpec(ip)...); !ok {
		t.Fatal("ClearEgressPolicy removed the block-all input drop")
	}
	if got := be.countMatching(inputPolicyComment + "|-j|"); got != 0 {
		t.Fatalf("policy input rules left after ClearEgressPolicy: %v", be.rules)
	}
}

// TestDenylistInstallsNoInputRules: a deny list is default-accept, so host
// services stay reachable exactly as before.
func TestDenylistInstallsNoInputRules(t *testing.T) {
	be := &memBackend{}
	mgr := NewWithBackend(be)
	if err := mgr.ApplyEgressPolicy("10.0.0.11", nil, []string{"1.2.3.0/24"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range be.rules {
		if strings.Contains(r, ChainAerolvmInput) {
			t.Fatalf("deny list installed an input rule: %s", r)
		}
	}
	if be.hasChain(ChainAerolvmInput) {
		t.Fatal("deny list must not bootstrap the input chain")
	}
}

// noBootstrap implements RuleBackend but neither bootstrap interface.
type noBootstrap struct{ inner *memBackend }

func (n noBootstrap) Exists(t, c string, s ...string) (bool, error) {
	return n.inner.Exists(t, c, s...)
}
func (n noBootstrap) Insert(t, c string, p int, s ...string) error {
	return n.inner.Insert(t, c, p, s...)
}
func (n noBootstrap) Delete(t, c string, s ...string) error { return n.inner.Delete(t, c, s...) }

// TestInputBootstrapFailsLoud: a backend that can't create AEROLVM-INPUT
// must fail block-all (never silently skip host protection), while clears
// stay a no-op because no input rule can exist.
func TestInputBootstrapFailsLoud(t *testing.T) {
	inner := &memBackend{}
	mgr := NewWithBackend(noBootstrap{inner: inner})
	if err := mgr.BlockAllEgress("10.0.0.12"); err == nil || !strings.Contains(err.Error(), ChainAerolvmInput) {
		t.Fatalf("BlockAllEgress err = %v, want input bootstrap failure", err)
	}
	if err := mgr.ApplyEgressPolicy("10.0.0.12", []string{"1.1.1.1/32"}, nil); err == nil {
		t.Fatal("allowlist must fail when the input chain can't be bootstrapped")
	}
	if err := mgr.ClearBlockAllEgress("10.0.0.12"); err != nil {
		t.Fatalf("clear must tolerate a missing input chain: %v", err)
	}
	if err := mgr.ClearEgressPolicy("10.0.0.12", []string{"1.1.1.1/32"}, nil); err != nil {
		t.Fatalf("policy clear must tolerate a missing input chain: %v", err)
	}
}

// TestInputChainBootstrapLatched: the bootstrap runs once per Manager.
func TestInputChainBootstrapLatched(t *testing.T) {
	be := &countingInputBackend{}
	mgr := NewWithBackend(be)
	for i := 0; i < 3; i++ {
		if err := mgr.BlockAllEgress("10.0.0.13"); err != nil {
			t.Fatal(err)
		}
	}
	if be.boots != 1 {
		t.Fatalf("input bootstrap ran %d times, want 1", be.boots)
	}
}

type countingInputBackend struct {
	memBackend
	boots int
}

func (c *countingInputBackend) EnsureInputChain(chain string) error {
	c.boots++
	return c.memBackend.EnsureInputChain(chain)
}

func TestExecBackendEnsureInputChain(t *testing.T) {
	script, state := writeBootstrapIPTables(t)
	t.Setenv("FAKE_IPTABLES_FAIL", "")
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatalf("iptables.New: %v", err)
	}
	be := newExecBackend(ipt)
	for i := 0; i < 2; i++ {
		if err := be.EnsureInputChain(ChainAerolvmInput); err != nil {
			t.Fatalf("EnsureInputChain #%d: %v", i, err)
		}
	}
	got := readStateFile(t, state)
	var ret, jump int
	for _, l := range got {
		if strings.Contains(l, ChainAerolvmInput+"|") && strings.Contains(l, "conntrack") && strings.Contains(l, "RETURN") {
			ret++
		}
		if strings.HasPrefix(l, "filter|INPUT|") && strings.Contains(l, ChainAerolvmInput) {
			jump++
		}
	}
	if ret != 1 || jump != 1 {
		t.Fatalf("want one established-return and one INPUT jump, got %v", got)
	}
}

func TestExecBackendEnsureInputChainErrors(t *testing.T) {
	for _, mode := range []string{"chain", "check", "insert"} {
		t.Run(mode, func(t *testing.T) {
			script, _ := writeBootstrapIPTables(t)
			t.Setenv("FAKE_IPTABLES_FAIL", mode)
			ipt, err := iptables.New(iptables.Path(script))
			if err != nil {
				t.Fatalf("iptables.New: %v", err)
			}
			if err := newExecBackend(ipt).EnsureInputChain(ChainAerolvmInput); err == nil {
				t.Fatalf("mode %s: want error", mode)
			}
		})
	}
}

func TestParseRulespecReturn(t *testing.T) {
	r, err := parseRulespec(inputPolicyReturnSpec("10.0.0.1", "10.88.0.1/32")...)
	if err != nil {
		t.Fatal(err)
	}
	if r.verdict != verdictReturn || r.comment != inputPolicyComment || r.dst == nil {
		t.Fatalf("parsed = %+v", r)
	}
}

// TestMixedListsAllowWins covers D4 on the netrules path: ACCEPTs above
// DROPs, no catch-all, no host-INPUT rules; the clear removes exactly that.
func TestMixedListsAllowWins(t *testing.T) {
	be := &memBackend{}
	mgr := NewWithBackend(be)
	const ip = "10.0.0.20"
	allow, deny := []string{"10.1.2.0/24"}, []string{"10.0.0.0/8"}
	if err := mgr.ApplyEgressPolicy(ip, allow, deny); err != nil {
		t.Fatal(err)
	}
	if ok, _ := be.Exists("filter", "DOCKER-USER", "-s", ip, "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"); ok {
		t.Fatal("mixed lists must not install a catch-all DROP")
	}
	if be.hasChain(ChainAerolvmInput) {
		t.Fatal("mixed lists are default-accept: no host-INPUT rules")
	}
	// Insert order is the rule order (each Insert lands at the top): the
	// ACCEPT must be inserted after the DROP so it sits above it.
	accept := memKey("filter", "DOCKER-USER", "-s", ip, "-d", allow[0], "-m", "comment", "--comment", egressPolicyComment, "-j", "ACCEPT")
	drop := memKey("filter", "DOCKER-USER", "-s", ip, "-d", deny[0], "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP")
	ai, di := -1, -1
	for i, r := range be.rules {
		if r == accept {
			ai = i
		}
		if r == drop {
			di = i
		}
	}
	if ai < 0 || di < 0 || ai < di {
		t.Fatalf("ACCEPT (inserted %d) must come after DROP (inserted %d) so it ends up above it: %v", ai, di, be.rules)
	}
	if err := mgr.ClearEgressPolicy(ip, allow, deny); err != nil {
		t.Fatal(err)
	}
	if be.ruleCount() != 0 {
		t.Fatalf("clear left rules: %v", be.rules)
	}
}

// TestAllowPlusDenyAllIsAllowlist: the E2B spelling "allowOut + denyOut
// 0.0.0.0/0" installs an allowlist, and a clear from the same stored lists
// removes exactly it.
func TestAllowPlusDenyAllIsAllowlist(t *testing.T) {
	be := &memBackend{}
	mgr := NewWithBackend(be)
	const ip = "10.0.0.21"
	allow, deny := []string{"1.1.1.1/32"}, []string{"0.0.0.0/0"}
	if err := mgr.ApplyEgressPolicy(ip, allow, deny); err != nil {
		t.Fatal(err)
	}
	if ok, _ := be.Exists("filter", "DOCKER-USER", "-s", ip, "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"); !ok {
		t.Fatal("allow + deny-all must be an allowlist with a catch-all DROP")
	}
	if ok, _ := be.Exists("filter", "DOCKER-USER", "-s", ip, "-d", "0.0.0.0/0", "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"); ok {
		t.Fatal("the 0.0.0.0/0 deny must not be installed as its own rule")
	}
	if err := mgr.ClearEgressPolicy(ip, allow, deny); err != nil {
		t.Fatal(err)
	}
	if be.ruleCount() != 0 {
		t.Fatalf("clear left rules: %v", be.rules)
	}
}

// TestHoldIsDisjoint covers D16: the hold DROP survives a quota clear and a
// policy clear, and only ClearHoldEgress removes it.
func TestHoldIsDisjoint(t *testing.T) {
	be := &memBackend{}
	mgr := NewWithBackend(be)
	const ip = "10.0.0.30"
	if err := mgr.HoldEgress(ip); err != nil {
		t.Fatal(err)
	}
	if err := mgr.HoldEgress(ip); err != nil {
		t.Fatal(err)
	}
	if be.countMatching(egressHoldComment) != 1 {
		t.Fatal("hold must be idempotent")
	}
	_ = mgr.BlockAllEgress(ip)
	_ = mgr.ClearBlockAllEgress(ip)
	_ = mgr.ClearEgressPolicy(ip, []string{"1.1.1.1/32"}, nil)
	if be.countMatching(egressHoldComment) != 1 {
		t.Fatal("quota/block and policy clears must not lift a hold")
	}
	if err := mgr.ClearHoldEgress(ip); err != nil {
		t.Fatal(err)
	}
	if be.countMatching(egressHoldComment) != 0 {
		t.Fatal("ClearHoldEgress must remove the hold")
	}
	disabled := NewWithBackend(nil)
	if disabled.HoldEgress(ip) != nil || disabled.ClearHoldEgress(ip) != nil || mgr.HoldEgress("") != nil {
		t.Fatal("disabled manager and empty IP are no-ops")
	}
}
