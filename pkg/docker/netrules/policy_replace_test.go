package netrules

import (
	"context"
	"errors"
	"net/netip"
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
// rules and their order are ApplyEgressPolicy's, one block per chain.
func TestReplaceEgressPolicy(t *testing.T) {
	// AEROLVM-INPUT starts with its established-return rule, as the kernel
	// backends make it: position 2 is below it.
	est := "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"
	for _, batch := range []bool{true} {
		lb := &listedBackend{orderedBackend: &orderedBackend{chains: map[string][]string{ChainAerolvmInput: {est}}}}
		m := NewWithBackend(batchListed{lb})
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
		if lb.blocks == 0 {
			t.Fatal("no block was written")
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

// TestReplaceEgressPolicyNeedsAWriter: a backend that cannot replace a
// policy whole, or list one to clear it, refuses before writing anything;
// a nil manager does nothing.
func TestReplaceEgressPolicyNeedsAWriter(t *testing.T) {
	if err := NewWithBackend(&orderedBackend{chains: map[string][]string{}}).ReplaceEgressPolicy(context.Background(), "10.88.0.5", nil, []string{"1.2.3.4/32"}); err == nil {
		t.Fatal("a backend that cannot replace replaced a policy")
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
	// A chain that was never made has no jump to it.
	if ok, err := be.HasJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); ok || err != nil {
		t.Fatalf("HasJump to a missing chain = %v, %v", ok, err)
	}
	if err := be.DeleteJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); err != nil {
		t.Fatalf("DeleteJump to a missing chain = %v", err)
	}
	if err := be.EnsureUserChain("AEROLVM-FLOOR-x"); err != nil {
		t.Fatal(err)
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

// TestReplaceEgressPolicyInPlaceWritesNothing: the routine reapply (start,
// reconcile) of the policy an address has writes nothing, so the address
// is never without it; a fresh address and a change write each chain
// that changes.
func TestReplaceEgressPolicyInPlaceWritesNothing(t *testing.T) {
	est := "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"
	lb := &listedBackend{orderedBackend: &orderedBackend{chains: map[string][]string{ChainAerolvmInput: {est}}}}
	m := NewWithBackend(batchListed{lb})
	ctx := context.Background()
	ip := "10.88.0.5"
	for _, step := range []struct {
		name        string
		allow, deny []string
		writes      int
	}{
		{"fresh address", []string{"1.2.3.4/32", "5.6.7.0/24"}, nil, 2},
		{"same policy", []string{"1.2.3.4/32", "5.6.7.0/24"}, nil, 0},
		{"a change (its host-input rules go)", []string{"1.2.3.4/32"}, []string{"10.0.0.0/8"}, 2},
		{"the change again", []string{"1.2.3.4/32"}, []string{"10.0.0.0/8"}, 0},
	} {
		lb.blocks = 0
		if err := m.ReplaceEgressPolicy(ctx, ip, step.allow, step.deny); err != nil {
			t.Fatal(err)
		}
		if lb.blocks != step.writes {
			t.Fatalf("%s: %d chains written, want %d", step.name, lb.blocks, step.writes)
		}
	}
}

// TestExecReplaceBlock: the exec backend swaps an address's policy in one
// iptables-restore transaction: the old rules (as listed) out first, then
// the new ones in at pos, bottom first; a policy in place writes nothing;
// a caller that gave up writes nothing.
func TestExecReplaceBlock(t *testing.T) {
	script, _ := writeBootstrapIPTables(t)
	t.Setenv("FAKE_IPTABLES_FAIL", "")
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatal(err)
	}
	be := newExecBackend(ipt)
	var restores []string
	var restoreErr error
	orig := runRestore
	runRestore = func(_ context.Context, input string) error { restores = append(restores, input); return restoreErr }
	t.Cleanup(func() { runRestore = orig })
	ctx := context.Background()
	ip := "10.0.0.5"
	rule := func(dst, verdict string) []string {
		return []string{"-s", ip, "-d", dst, "-m", "comment", "--comment", "sbx-egress", "-j", verdict}
	}
	// A chain that is not there yet: the new rules go in at its top.
	if err := be.ReplaceBlock(ctx, "AEROLVM-NOPE", 2, ip, "sbx-egress", [][]string{rule("1.1.1.1/32", "ACCEPT")}); err != nil {
		t.Fatal(err)
	}
	if want := "*filter\n-I AEROLVM-NOPE 1 -s 10.0.0.5 -d 1.1.1.1/32 -m comment --comment sbx-egress -j ACCEPT\nCOMMIT\n"; restores[0] != want {
		t.Fatalf("restore %q, want %q", restores[0], want)
	}
	if err := be.EnsureUserChain(ChainAerolvmUser); err != nil {
		t.Fatal(err)
	}
	for _, spec := range [][]string{{"-j", "AEROLVM-FLOOR-x"}, listedForm(rule("1.1.1.1/32", "ACCEPT")), listedForm(rule("2.2.2.2/32", "DROP"))} {
		if err := be.Insert("filter", ChainAerolvmUser, 1, spec...); err != nil {
			t.Fatal(err)
		}
	}
	old := [][]string{rule("1.1.1.1/32", "ACCEPT"), rule("2.2.2.2/32", "DROP")} // the fake lists in insertion order
	restores = nil
	if err := be.ReplaceBlock(ctx, ChainAerolvmUser, 2, ip, "sbx-egress", old); err != nil || len(restores) != 0 {
		t.Fatalf("a policy in place: %v, %q", err, restores)
	}
	next := [][]string{rule("3.3.3.3/32", "ACCEPT"), rule("4.4.4.4/32", "DROP")}
	if err := be.ReplaceBlock(ctx, ChainAerolvmUser, 2, ip, "sbx-egress", next); err != nil {
		t.Fatal(err)
	}
	want := "*filter\n" +
		"-D AEROLVM-USER -s 10.0.0.5/32 -d 1.1.1.1/32 -m comment --comment sbx-egress -j ACCEPT\n" +
		"-D AEROLVM-USER -s 10.0.0.5/32 -d 2.2.2.2/32 -m comment --comment sbx-egress -j DROP\n" +
		"-I AEROLVM-USER 2 -s 10.0.0.5 -d 4.4.4.4/32 -m comment --comment sbx-egress -j DROP\n" +
		"-I AEROLVM-USER 2 -s 10.0.0.5 -d 3.3.3.3/32 -m comment --comment sbx-egress -j ACCEPT\n" +
		"COMMIT\n"
	if len(restores) != 1 || restores[0] != want {
		t.Fatalf("restore %q, want %q", restores, want)
	}
	// Given up before: nothing; the restore's failure: reported.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	restores = nil
	if err := be.ReplaceBlock(cctx, ChainAerolvmUser, 2, ip, "sbx-egress", next); !errors.Is(err, context.Canceled) || len(restores) != 0 {
		t.Fatalf("cancelled = %v, %q", err, restores)
	}
	restoreErr = errors.New("restore")
	if err := be.ReplaceBlock(ctx, ChainAerolvmUser, 2, ip, "sbx-egress", next); err == nil {
		t.Fatal("restore failure hidden")
	}
	t.Setenv("FAKE_IPTABLES_FAIL", "chain")
	if err := be.ReplaceBlock(ctx, ChainAerolvmUser, 2, ip, "sbx-egress", next); err == nil {
		t.Fatal("listing failure hidden")
	}
}

// TestExecFloorDrops: the exec backend reads a floor chain's DROPs from a
// subnet by destination, a host as its /32.
func TestExecFloorDrops(t *testing.T) {
	script, _ := writeBootstrapIPTables(t)
	t.Setenv("FAKE_IPTABLES_FAIL", "")
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatal(err)
	}
	be := newExecBackend(ipt)
	src := netip.MustParsePrefix("10.79.0.0/16")
	if got, err := be.FloorDrops("AEROLVM-FLOOR-x", src); err != nil || len(got) != 0 {
		t.Fatalf("missing chain = %v %v", got, err)
	}
	if err := be.EnsureUserChain("AEROLVM-FLOOR-x"); err != nil {
		t.Fatal(err)
	}
	for _, spec := range [][]string{
		{"-s", "10.79.0.0/16", "-d", "203.0.113.0/24", "-j", "DROP"},
		{"-s", "10.79.0.0/16", "-d", "169.254.169.254", "-j", "DROP"},
		{"-s", "10.80.0.0/16", "-d", "198.51.100.0/24", "-j", "DROP"},
		{"-s", "10.79.0.0/16", "-d", "192.0.2.0/24", "-j", "ACCEPT"},
	} {
		if err := be.Insert("filter", "AEROLVM-FLOOR-x", 1, spec...); err != nil {
			t.Fatal(err)
		}
	}
	got, err := be.FloorDrops("AEROLVM-FLOOR-x", src)
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("169.254.169.254/32")}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("= %v %v, want %v", got, err, want)
	}
	t.Setenv("FAKE_IPTABLES_FAIL", "chain")
	if _, err := be.FloorDrops("AEROLVM-FLOOR-x", src); err == nil {
		t.Fatal("listing failure hidden")
	}
}
