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
