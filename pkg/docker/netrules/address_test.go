package netrules

import (
	"slices"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

// addressRules are the rules a node can hold for 10.0.0.5, and for others.
var addressRules = []struct {
	chain string
	spec  []string
	ours  bool // keyed by 10.0.0.5
}{
	{ChainAerolvmUser, []string{"-s", "10.0.0.5", "-j", "DROP"}, true},
	{ChainAerolvmUser, []string{"-d", "10.0.0.5", "-j", "DROP"}, true},
	{ChainAerolvmUser, []string{"-s", "10.0.0.5", "-m", "comment", "--comment", egressHoldComment, "-j", "DROP"}, true},
	{ChainAerolvmUser, []string{"-s", "10.0.0.5", "-d", "1.1.1.0/24", "-m", "comment", "--comment", egressPolicyComment, "-j", "ACCEPT"}, true},
	{ChainAerolvmInput, []string{"-s", "10.0.0.5", "-m", "comment", "--comment", inputBlockComment, "-j", "DROP"}, true},
	// Another sandbox's allowlist names 10.0.0.5: its rule, not ours.
	{ChainAerolvmUser, []string{"-s", "10.0.0.9", "-d", "10.0.0.5", "-m", "comment", "--comment", egressPolicyComment, "-j", "ACCEPT"}, false},
	{ChainAerolvmUser, []string{"-s", "10.0.0.9", "-j", "DROP"}, false},
	// A subnet rule (the floor) is nobody's address.
	{ChainAerolvmUser, []string{"-s", "10.0.0.0/16", "-d", "169.254.169.254", "-j", "DROP"}, false},
}

func TestClearAddressExecBackend(t *testing.T) {
	script, state := writeBootstrapIPTables(t)
	t.Setenv("FAKE_IPTABLES_FAIL", "")
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatal(err)
	}
	be := newExecBackend(ipt)
	for _, c := range []string{ChainAerolvmUser, ChainAerolvmInput} {
		if err := be.EnsureUserChain(c); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range addressRules {
		if err := be.Insert("filter", r.chain, 1, r.spec...); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}
	m.inputReady.Store(true)
	if err := m.ClearAddress("10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	got := readStateFile(t, state)
	for _, r := range addressRules {
		present := slices.ContainsFunc(got, func(l string) bool { return strings.HasSuffix(l, "|"+r.chain+"|"+strings.Join(r.spec, " ")) })
		if present == r.ours {
			t.Fatalf("rule %v ours=%v present=%v after clear; state %v", r.spec, r.ours, present, got)
		}
	}
}

// TestClearAddressKnownSpecs: a backend that can't list clears the specs
// the manager knows: block-all, ingress block, hold.
func TestClearAddressKnownSpecs(t *testing.T) {
	be := &memBackend{}
	m := NewWithBackend(be)
	m.userChain = ChainAerolvmUser
	for _, r := range addressRules {
		_ = be.Insert("filter", r.chain, 1, r.spec...)
	}
	if err := m.ClearAddress("10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	for _, r := range addressRules[:3] {
		if ok, _ := be.Exists("filter", r.chain, r.spec...); ok {
			t.Fatalf("%v kept", r.spec)
		}
	}
	if ok, _ := be.Exists("filter", ChainAerolvmUser, "-s", "10.0.0.9", "-j", "DROP"); !ok {
		t.Fatal("another address's rule removed")
	}
	for _, ip := range []string{"", "  "} {
		if err := m.ClearAddress(ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.ClearAddress("fd00::1"); err == nil {
		t.Fatal("an IPv6 address accepted")
	}
	if err := (&Manager{}).ClearAddress("10.0.0.5"); err != nil {
		t.Fatal("disabled manager")
	}
}

func TestAddressRuleKeyed(t *testing.T) {
	for _, c := range []struct {
		spec []string
		want bool
	}{
		{[]string{"-s", "10.0.0.5/32", "-j", "DROP"}, true},
		{[]string{"--source", "10.0.0.5", "-j", "DROP"}, true},
		{[]string{"-d", "10.0.0.5/32", "-j", "DROP"}, true},
		{[]string{"--destination", "10.0.0.5", "-j", "DROP"}, true},
		{[]string{"-s", "10.0.0.6/32", "-d", "10.0.0.5/32", "-j", "ACCEPT"}, false},
		{[]string{"-j", "DROP"}, false},
		{[]string{"-s", "10.0.0.50/32", "-j", "DROP"}, false},
	} {
		if got := addressRuleKeyed(c.spec, "10.0.0.5"); got != c.want {
			t.Errorf("%v: got %v", c.spec, got)
		}
	}
}

// TestClearAddressExecBackendEdges: a chain that isn't there holds no rule;
// a listing or a delete that fails is reported.
func TestClearAddressExecBackendEdges(t *testing.T) {
	script, _ := writeBootstrapIPTables(t)
	t.Setenv("FAKE_IPTABLES_FAIL", "")
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatal(err)
	}
	be := newExecBackend(ipt)
	if err := be.ClearAddressRules([]string{"AEROLVM-NOPE"}, "10.0.0.5"); err != nil {
		t.Fatalf("missing chain: %v", err)
	}
	if err := be.EnsureUserChain(ChainAerolvmUser); err != nil {
		t.Fatal(err)
	}
	if err := be.Insert("filter", ChainAerolvmUser, 1, "-s", "10.0.0.5", "-j", "DROP"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_IPTABLES_FAIL", "delete")
	if err := be.ClearAddressRules([]string{ChainAerolvmUser}, "10.0.0.5"); err == nil {
		t.Fatal("delete failure hidden")
	}
	t.Setenv("FAKE_IPTABLES_FAIL", "chain")
	if err := be.ClearAddressRules([]string{ChainAerolvmUser}, "10.0.0.5"); err == nil {
		t.Fatal("listing failure hidden")
	}
}
