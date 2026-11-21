package netrules

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

// listedBackend is orderedBackend that can find an address's commented
// rules, as both kernel backends can, and optionally write a block at once.
type listedBackend struct {
	*orderedBackend
	blocks int // ReplaceBlock writes; 0 when batching is off
	batch  bool
}

func (l *listedBackend) ClearCommented(chains []string, ip, comment string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range chains {
		l.chains[c] = slices.DeleteFunc(l.chains[c], func(r string) bool {
			f := strings.Fields(r)
			return addressRuleKeyed(f, ip) && hasComment(f, comment)
		})
	}
	return nil
}

// PolicyState reads as the kernel backends do; clears counts ClearCommented
// calls, writes counts every rule written.
func (l *listedBackend) PolicyState(chain, ip, comment string, specs [][]string) (int, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var got []string
	for _, r := range l.chains[chain] {
		if f := strings.Fields(r); addressRuleKeyed(f, ip) && hasComment(f, comment) {
			got = append(got, r)
		}
	}
	want := make([]string, len(specs))
	for i, sp := range specs {
		want[i] = strings.Join(sp, " ")
	}
	return len(got), slices.Equal(got, want), nil
}

type batchListed struct{ *listedBackend }

// ReplaceBlock is netlinkBackend's: in place, or the new rules in at pos
// first and the old ones out after.
func (b batchListed) ReplaceBlock(_ context.Context, chain string, pos int, ip, comment string, specs [][]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.chains[chain]
	var old []int
	var have []string
	for i, r := range c {
		if f := strings.Fields(r); addressRuleKeyed(f, ip) && hasComment(f, comment) {
			old, have = append(old, i), append(have, r)
		}
	}
	add := make([]string, len(specs))
	for i, sp := range specs {
		add[i] = strings.Join(sp, " ")
	}
	if slices.Equal(have, add) {
		return nil
	}
	b.blocks++
	at := min(max(pos, 1)-1, len(c))
	c = slices.Insert(c, at, add...)
	for _, i := range slices.Backward(old) {
		if i >= at {
			i += len(add)
		}
		c = slices.Delete(c, i, i+1)
	}
	b.chains[chain] = c
	return nil
}

// TestReplaceEgressPolicy (PR 5 review, R4): a policy replaces the last,
// whatever wrote it, so lists sent one after another never pile up; its
// rules and their order are ApplyEgressPolicy's, written rule by rule or
// one block per chain.
func TestReplaceEgressPolicy(t *testing.T) {
	// AEROLVM-INPUT starts with its established-return rule, as the kernel
	// backends make it: position 2 is below it.
	est := "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"
	for _, batch := range []bool{false, true} {
		lb := &listedBackend{orderedBackend: &orderedBackend{chains: map[string][]string{ChainAerolvmInput: {est}}}}
		var be RuleBackend = lb
		if batch {
			be = batchListed{lb}
		}
		m := NewWithBackend(be)
		var ref *Manager
		ip := "10.88.0.5"
		ctx := context.Background()
		// An earlier writer's policy, and another address's, and a hold.
		if err := m.ApplyEgressPolicy(ip, []string{"9.9.9.9/32"}, nil); err != nil {
			t.Fatal(err)
		}
		if err := m.ApplyEgressPolicy("10.88.0.6", nil, []string{"8.8.8.8/32"}); err != nil {
			t.Fatal(err)
		}
		if err := m.HoldEgress(ip); err != nil {
			t.Fatal(err)
		}
		for _, lists := range [][2][]string{
			{{"1.2.3.4/32", "5.6.7.0/24"}, nil},
			{{"1.2.3.4/32"}, {"10.0.0.0/8"}},
			{nil, {"192.168.0.0/16", "172.16.0.0/12"}},
		} {
			if err := m.ReplaceEgressPolicy(ctx, ip, lists[0], lists[1]); err != nil {
				t.Fatal(err)
			}
			// The reference: the same policy on a clean manager.
			ref = NewWithBackend(&orderedBackend{chains: map[string][]string{ChainAerolvmInput: {est}}})
			if err := ref.ApplyEgressPolicy(ip, lists[0], lists[1]); err != nil {
				t.Fatal(err)
			}
			for _, chain := range []string{m.filterChain(), ChainAerolvmInput} {
				got := policyOf(lb.chains[chain], ip)
				want := policyOf(ref.ipt.(*orderedBackend).chains[chain], ip)
				if !slices.Equal(got, want) {
					t.Fatalf("batch=%v %s after %v:\n got %q\nwant %q", batch, chain, lists, got, want)
				}
			}
		}
		user := lb.chains[m.filterChain()]
		if !slices.Contains(user, strings.Join(holdSpec(ip), " ")) || len(policyOf(user, "10.88.0.6")) != 1 {
			t.Fatalf("batch=%v: a replace touched other rules: %q", batch, user)
		}
		if batch && lb.blocks == 0 {
			t.Fatal("the batching backend was written rule by rule")
		}
		if err := m.ClearEgressPolicyOf(ip); err != nil || len(policyOf(lb.chains[m.filterChain()], ip)) != 0 {
			t.Fatalf("batch=%v: clear: %v %q", batch, err, lb.chains[m.filterChain()])
		}
	}
}

// policyOf is ip's egress policy rules in a chain, in order.
func policyOf(rules []string, ip string) []string {
	var out []string
	for _, r := range rules {
		f := strings.Fields(r)
		if addressRuleKeyed(f, ip) && hasComment(f, egressPolicyComment) {
			out = append(out, r)
		}
	}
	return out
}

// TestReplaceEgressPolicyStopsWithItsContext: rule by rule, a replace whose
// context ends writes no further rule.
func TestReplaceEgressPolicyStopsWithItsContext(t *testing.T) {
	lb := &listedBackend{orderedBackend: &orderedBackend{chains: map[string][]string{}}}
	m := NewWithBackend(lb)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.ReplaceEgressPolicy(ctx, "10.88.0.5", []string{"1.2.3.4/32"}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled replace = %v", err)
	}
	if n := len(policyOf(lb.chains[m.filterChain()], "10.88.0.5")); n != 0 {
		t.Fatalf("%d rules written after the cancel", n)
	}
	// A backend that cannot list refuses, before anything.
	if err := NewWithBackend(&orderedBackend{chains: map[string][]string{}}).ReplaceEgressPolicy(context.Background(), "10.88.0.5", nil, []string{"1.2.3.4/32"}); err == nil {
		t.Fatal("a backend that cannot list replaced a policy")
	}
	if err := NewWithBackend(&orderedBackend{chains: map[string][]string{}}).ClearEgressPolicyOf("10.88.0.5"); err == nil {
		t.Fatal("a backend that cannot list cleared a policy")
	}
	var off *Manager
	if off.ReplaceEgressPolicy(context.Background(), "10.88.0.5", nil, nil) != nil || off.ClearEgressPolicyOf("x") != nil {
		t.Fatal("a nil manager is a no-op")
	}
}

func TestHasComment(t *testing.T) {
	if !hasComment(strings.Fields("-s 1.2.3.4/32 -m comment --comment sbx-egress -j DROP"), "sbx-egress") ||
		hasComment(strings.Fields("-s 1.2.3.4/32 -m comment --comment sbx-egress-hold -j DROP"), "sbx-egress") ||
		hasComment([]string{"--comment"}, "x") {
		t.Fatal("hasComment")
	}
}

// TestExecBackendPolicyAndJumpCalls: the exec backend's comment-keyed clear
// leaves other addresses' and uncommented rules alone, and its jump calls
// find and remove every jump; a failure is reported, a missing chain is not.
func TestExecBackendPolicyAndJumpCalls(t *testing.T) {
	script, _ := writeBootstrapIPTables(t)
	t.Setenv("FAKE_IPTABLES_FAIL", "")
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatal(err)
	}
	be := newExecBackend(ipt)
	if err := be.EnsureUserChain(ChainAerolvmUser); err != nil {
		t.Fatal(err)
	}
	for _, spec := range [][]string{
		{"-s", "10.0.0.5", "-d", "1.1.1.1/32", "-m", "comment", "--comment", "sbx-egress", "-j", "ACCEPT"},
		{"-s", "10.0.0.5", "-j", "DROP"},
		{"-s", "10.0.0.6", "-d", "1.1.1.1/32", "-m", "comment", "--comment", "sbx-egress", "-j", "ACCEPT"},
		{"-j", "AEROLVM-FLOOR-x"},
		{"-j", "AEROLVM-FLOOR-x"},
	} {
		if err := be.Insert("filter", ChainAerolvmUser, 1, spec...); err != nil {
			t.Fatal(err)
		}
	}
	if err := be.ClearCommented([]string{"AEROLVM-NOPE", ChainAerolvmUser}, "10.0.0.5", "sbx-egress"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := be.Exists("filter", ChainAerolvmUser, "-s", "10.0.0.5", "-d", "1.1.1.1/32", "-m", "comment", "--comment", "sbx-egress", "-j", "ACCEPT"); ok {
		t.Fatal("the address's policy rule is still there")
	}
	for _, spec := range [][]string{{"-s", "10.0.0.5", "-j", "DROP"}, {"-s", "10.0.0.6", "-d", "1.1.1.1/32", "-m", "comment", "--comment", "sbx-egress", "-j", "ACCEPT"}} {
		if ok, _ := be.Exists("filter", ChainAerolvmUser, spec...); !ok {
			t.Fatalf("clear removed %v", spec)
		}
	}
	if ok, err := be.HasJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); !ok || err != nil {
		t.Fatalf("HasJump = %v, %v", ok, err)
	}
	if err := be.DeleteJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); err != nil {
		t.Fatal(err)
	}
	if ok, err := be.HasJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); ok || err != nil {
		t.Fatalf("a jump is left: %v, %v", ok, err)
	}
	t.Setenv("FAKE_IPTABLES_FAIL", "chain")
	if err := be.ClearCommented([]string{ChainAerolvmUser}, "10.0.0.6", "sbx-egress"); err == nil {
		t.Fatal("listing failure hidden")
	}
	t.Setenv("FAKE_IPTABLES_FAIL", "delete")
	if err := be.ClearCommented([]string{ChainAerolvmUser}, "10.0.0.6", "sbx-egress"); err == nil {
		t.Fatal("delete failure hidden")
	}
	if err := be.DeleteJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); err == nil {
		t.Fatal("delete failure hidden")
	}
}

// countingListed counts the clears and rule writes a replace makes.
type countingListed struct {
	*listedBackend
	clears, writes int
}

func (c *countingListed) ClearCommented(chains []string, ip, comment string) error {
	c.clears++
	return c.listedBackend.ClearCommented(chains, ip, comment)
}

func (c *countingListed) Insert(table, chain string, pos int, spec ...string) error {
	c.writes++
	return c.listedBackend.Insert(table, chain, pos, spec...)
}

// TestReplaceEgressPolicyInPlaceWritesNothing: the routine reapply (start,
// reconcile) of the policy an address has writes nothing, so the address
// is never without it; a fresh address skips the clear; a change clears
// and writes.
func TestReplaceEgressPolicyInPlaceWritesNothing(t *testing.T) {
	est := "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"
	be := &countingListed{listedBackend: &listedBackend{orderedBackend: &orderedBackend{chains: map[string][]string{ChainAerolvmInput: {est}}}}}
	m := NewWithBackend(be)
	ctx := context.Background()
	ip := "10.88.0.5"
	for _, step := range []struct {
		name          string
		allow, deny   []string
		clears, write int
	}{
		{"fresh address", []string{"1.2.3.4/32", "5.6.7.0/24"}, nil, 0, 6},
		{"same policy", []string{"1.2.3.4/32", "5.6.7.0/24"}, nil, 0, 0},
		{"a change", []string{"1.2.3.4/32"}, []string{"10.0.0.0/8"}, 1, 2},
		{"the change again", []string{"1.2.3.4/32"}, []string{"10.0.0.0/8"}, 0, 0},
	} {
		be.clears, be.writes = 0, 0
		if err := m.ReplaceEgressPolicy(ctx, ip, step.allow, step.deny); err != nil {
			t.Fatal(err)
		}
		if be.clears != step.clears || be.writes != step.write {
			t.Fatalf("%s: %d clears, %d writes; want %d, %d", step.name, be.clears, be.writes, step.clears, step.write)
		}
	}
}

// TestExecPolicyState: the exec backend reads a policy back from
// `iptables -S`, where a host address carries its /32.
func TestExecPolicyState(t *testing.T) {
	script, _ := writeBootstrapIPTables(t)
	t.Setenv("FAKE_IPTABLES_FAIL", "")
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatal(err)
	}
	be := newExecBackend(ipt)
	if n, same, err := be.PolicyState("AEROLVM-NOPE", "10.0.0.5", "sbx-egress", nil); n != 0 || !same || err != nil {
		t.Fatalf("missing chain = %d %v %v", n, same, err)
	}
	if err := be.EnsureUserChain(ChainAerolvmUser); err != nil {
		t.Fatal(err)
	}
	spec := []string{"-s", "10.0.0.5", "-d", "1.1.1.1/32", "-m", "comment", "--comment", "sbx-egress", "-j", "ACCEPT"}
	// As the kernel prints it.
	if err := be.Insert("filter", ChainAerolvmUser, 1, listedForm(spec)...); err != nil {
		t.Fatal(err)
	}
	if n, same, err := be.PolicyState(ChainAerolvmUser, "10.0.0.5", "sbx-egress", [][]string{spec}); n != 1 || !same || err != nil {
		t.Fatalf("in place = %d %v %v", n, same, err)
	}
	other := slices.Clone(spec)
	other[3] = "2.2.2.2/32"
	if n, same, _ := be.PolicyState(ChainAerolvmUser, "10.0.0.5", "sbx-egress", [][]string{other}); n != 1 || same {
		t.Fatalf("a different policy read as in place: %d %v", n, same)
	}
	if _, same, _ := be.PolicyState(ChainAerolvmUser, "10.0.0.5", "sbx-egress", nil); same {
		t.Fatal("no policy read as in place over one rule")
	}
	t.Setenv("FAKE_IPTABLES_FAIL", "chain")
	if _, _, err := be.PolicyState(ChainAerolvmUser, "10.0.0.5", "sbx-egress", nil); err == nil {
		t.Fatal("listing failure hidden")
	}
}
