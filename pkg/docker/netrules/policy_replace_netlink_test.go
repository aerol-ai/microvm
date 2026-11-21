//go:build linux

package netrules

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// bigPolicy is ip's allowlist of n /24s (salt picks the second octet's
// base), as ReplaceEgressPolicy writes it.
func bigPolicy(ip string, n, salt int) (fwd, input [][]string) {
	allow := make([]string, n)
	for i := range allow {
		allow[i] = fmt.Sprintf("%d.%d.%d.0/24", 21+salt, i/256, i%256)
	}
	return policySpecs(ip, allow, nil)
}

// addJump puts a bare jump rule (no rulespec the translator renders) at
// the end of chain.
func addJump(f *chainNFT, chain, child string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	tbl := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"}
	f.chains[chain] = append(f.chains[chain], &nftables.Rule{Table: tbl, Chain: &nftables.Chain{Name: chain, Table: tbl},
		Handle: f.next, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictJump, Chain: child}}})
}

// policyOfNFT is ip's policy rules in chain, in order, as exprs.
func policyOfNFT(f *chainNFT, chain, ip string) []*nftables.Rule {
	var out []*nftables.Rule
	for _, r := range f.chains[chain] {
		if ruleKeyedBy(r.Exprs, ip) && ruleHasComment(r.Exprs, egressPolicyComment) {
			out = append(out, r)
		}
	}
	return out
}

func sameRules(t *testing.T, got []*nftables.Rule, specs [][]string) bool {
	t.Helper()
	if len(got) != len(specs) {
		return false
	}
	for i, spec := range specs {
		want, err := exprsFromRulespec(spec...)
		if err != nil {
			t.Fatal(err)
		}
		if !exprsEqualIgnoringCounters(want, got[i].Exprs) {
			return false
		}
	}
	return true
}

// TestNetlinkReplaceBlock: more rules than one netlink message carries go
// in netlinkChunk to a commit, in order, below the floor's jump; a policy
// in place is left alone; a change writes the new rules before the old
// ones go, so after every commit the address still has its catch-all
// DROP; a cancelled write stops before its next commit.
func TestNetlinkReplaceBlock(t *testing.T) {
	f := newChainNFT()
	addJump(f, ChainAerolvmUser, "AEROLVM-FLOOR-x")
	f.add(ChainAerolvmUser, dropSpec("10.0.0.9")...)
	b := netlinkChainBackend(f)
	const ip = "10.0.0.5"
	one, _ := policySpecs(ip, []string{"1.1.1.1/32"}, nil)
	catchAll, _ := exprsFromRulespec(one[1]...)
	f.afterFlush = func() {
		// Checked from the first policy on: an allowlist's DROP is there
		// after every commit.
		rules := policyOfNFT(f, ChainAerolvmUser, ip)
		if len(rules) == 0 {
			return
		}
		for _, r := range rules {
			if exprsEqualIgnoringCounters(catchAll, r.Exprs) {
				return
			}
		}
		t.Errorf("a commit left %s with no catch-all DROP", ip)
	}
	ctx := context.Background()
	first, _ := bigPolicy(ip, 300, 0)
	if err := b.ReplaceBlock(ctx, ChainAerolvmUser, 2, ip, egressPolicyComment, first); err != nil {
		t.Fatal(err)
	}
	if f.flushes != 3 || !sameRules(t, policyOfNFT(f, ChainAerolvmUser, ip), first) {
		t.Fatalf("%d commits; policy in place: %v", f.flushes, sameRules(t, policyOfNFT(f, ChainAerolvmUser, ip), first))
	}
	// Below the floor's jump, above the other address's rule.
	if i := f.indexOf(ChainAerolvmUser, first[0]...); i != 1 {
		t.Fatalf("first rule at %d, want 1", i)
	}
	if i := f.indexOf(ChainAerolvmUser, dropSpec("10.0.0.9")...); i != len(first)+1 {
		t.Fatalf("the other address's rule at %d, want %d", i, len(first)+1)
	}
	// In place: no commit.
	f.flushes = 0
	if err := b.ReplaceBlock(ctx, ChainAerolvmUser, 2, ip, egressPolicyComment, first); err != nil || f.flushes != 0 {
		t.Fatalf("a reapply in place: %v, %d commits", err, f.flushes)
	}
	// A change: three commits in, three out.
	next, _ := bigPolicy(ip, 300, 1)
	if err := b.ReplaceBlock(ctx, ChainAerolvmUser, 2, ip, egressPolicyComment, next); err != nil {
		t.Fatal(err)
	}
	if f.flushes != 6 || !sameRules(t, policyOfNFT(f, ChainAerolvmUser, ip), next) {
		t.Fatalf("after a change: %d commits, policy %d rules", f.flushes, len(policyOfNFT(f, ChainAerolvmUser, ip)))
	}
	// Cancelled: nothing more goes in.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := b.ReplaceBlock(cctx, ChainAerolvmUser, 2, ip, egressPolicyComment, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write = %v", err)
	}
	if !sameRules(t, policyOfNFT(f, ChainAerolvmUser, ip), next) {
		t.Fatal("a cancelled write changed the policy")
	}
	// No policy: the old one goes.
	if err := b.ReplaceBlock(ctx, ChainAerolvmUser, 2, ip, egressPolicyComment, nil); err != nil || len(policyOfNFT(f, ChainAerolvmUser, ip)) != 0 {
		t.Fatalf("an empty policy: %v, %d rules left", err, len(policyOfNFT(f, ChainAerolvmUser, ip)))
	}
	if f.count(ChainAerolvmUser, dropSpec("10.0.0.9")...) != 1 {
		t.Fatal("the other address's rule went")
	}
	// At the top of a chain (pos 1), and into an empty one.
	small, _ := policySpecs(ip, []string{"1.1.1.1/32", "2.2.2.2/32"}, nil)
	if err := b.ReplaceBlock(ctx, ChainAerolvmUser, 1, ip, egressPolicyComment, small); err != nil {
		t.Fatal(err)
	}
	if i := f.indexOf(ChainAerolvmUser, small[0]...); i != 0 {
		t.Fatalf("pos 1: first rule at %d", i)
	}
	if err := b.ReplaceBlock(ctx, ChainAerolvmInput, 2, ip, egressPolicyComment, small); err != nil || !sameRules(t, policyOfNFT(f, ChainAerolvmInput, ip), small) {
		t.Fatalf("an empty chain: %v", err)
	}
}

// TestNetlinkReplaceBlockEdges: a stale commit is redone from a fresh
// listing; failures are reported.
func TestNetlinkReplaceBlockEdges(t *testing.T) {
	const ip = "10.0.0.5"
	small, _ := policySpecs(ip, []string{"1.1.1.1/32"}, nil)
	f := newChainNFT()
	addJump(f, ChainAerolvmUser, "AEROLVM-FLOOR-x")
	f.staleFlushes = 1
	b := netlinkChainBackend(f)
	if err := b.ReplaceBlock(context.Background(), ChainAerolvmUser, 2, ip, egressPolicyComment, small); err != nil ||
		!sameRules(t, policyOfNFT(f, ChainAerolvmUser, ip), small) {
		t.Fatalf("stale retry: %v", err)
	}
	f.getErr = errors.New("boom")
	if err := b.ReplaceBlock(context.Background(), ChainAerolvmUser, 2, ip, egressPolicyComment, nil); err == nil {
		t.Fatal("list error hidden")
	}
	f.getErr = nil
	f.flushErr = errors.New("flush boom")
	if err := b.ReplaceBlock(context.Background(), ChainAerolvmUser, 2, ip, egressPolicyComment, nil); err == nil {
		t.Fatal("commit error hidden")
	}
	f.flushErr = nil
	if err := b.ReplaceBlock(context.Background(), ChainAerolvmUser, 2, ip, egressPolicyComment, [][]string{{"-j", "DROP"}}); err == nil {
		t.Fatal("a rule the translator cannot render went through")
	}
}

// TestNetlinkClearInChunks: an address's policy bigger than one netlink
// message comes out netlinkChunk to a commit, and nothing else does.
func TestNetlinkClearInChunks(t *testing.T) {
	f := newChainNFT()
	addJump(f, ChainAerolvmUser, "AEROLVM-FLOOR-x")
	f.add(ChainAerolvmUser, dropSpec("10.0.0.9")...)
	b := netlinkChainBackend(f)
	const ip = "10.0.0.5"
	fwd, _ := bigPolicy(ip, 300, 0)
	if err := b.ReplaceBlock(context.Background(), ChainAerolvmUser, 2, ip, egressPolicyComment, fwd); err != nil {
		t.Fatal(err)
	}
	f.flushes = 0
	if err := b.ClearCommented([]string{ChainAerolvmUser, ChainAerolvmInput}, ip, egressPolicyComment); err != nil {
		t.Fatal(err)
	}
	if n := len(policyOfNFT(f, ChainAerolvmUser, ip)); n != 0 || f.flushes != 3 {
		t.Fatalf("after the clear: %d rules, %d commits", n, f.flushes)
	}
	if f.count(ChainAerolvmUser, dropSpec("10.0.0.9")...) != 1 {
		t.Fatal("the clear took another address's rule")
	}
	if err := b.ReplaceBlock(context.Background(), ChainAerolvmUser, 2, ip, egressPolicyComment, fwd); err != nil {
		t.Fatal(err)
	}
	if err := b.ClearAddressRules([]string{ChainAerolvmUser}, ip); err != nil || len(policyOfNFT(f, ChainAerolvmUser, ip)) != 0 {
		t.Fatalf("ClearAddress of a big policy: %v", err)
	}
}

// TestNetlinkJumpCalls: a jump is found and removed by its verdict.
func TestNetlinkJumpCalls(t *testing.T) {
	f := newChainNFT()
	addJump(f, ChainAerolvmUser, "AEROLVM-FLOOR-x")
	f.add(ChainAerolvmUser, dropSpec("10.0.0.9")...)
	addJump(f, ChainAerolvmUser, "AEROLVM-FLOOR-x")
	b := netlinkChainBackend(f)
	if ok, err := b.HasJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); !ok || err != nil {
		t.Fatalf("HasJump = %v %v", ok, err)
	}
	if err := b.DeleteJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := b.HasJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); ok || f.count(ChainAerolvmUser, dropSpec("10.0.0.9")...) != 1 {
		t.Fatal("a jump is left, or another rule went")
	}
	// None to remove: no commit.
	f.flushes = 0
	if err := b.DeleteJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); err != nil || f.flushes != 0 {
		t.Fatalf("nothing to delete: %v, %d commits", err, f.flushes)
	}
	// A parent that is not there has no jump; a listing that fails is
	// reported.
	f.getErr = syscall.ENOENT
	if ok, err := b.HasJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); ok || err != nil {
		t.Fatalf("missing parent: %v %v", ok, err)
	}
	f.getErr = errors.New("boom")
	if _, err := b.HasJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); err == nil {
		t.Fatal("list error hidden")
	}
	if err := b.DeleteJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); err == nil {
		t.Fatal("list error hidden")
	}
	f.getErr = nil
	addJump(f, ChainAerolvmUser, "AEROLVM-FLOOR-x")
	f.delErr = errors.New("del boom")
	if err := b.DeleteJump(ChainAerolvmUser, "AEROLVM-FLOOR-x"); err == nil {
		t.Fatal("delete error hidden")
	}
}

// TestNetlinkFloorDrops: a floor chain's DROPs from the subnet are read
// back by destination, from the netlink backend's own rules (a mask) and
// from iptables-nft's (whole bytes loaded, no mask).
func TestNetlinkFloorDrops(t *testing.T) {
	f := newChainNFT()
	chain := "AEROLVM-FLOOR-x"
	f.add(chain, "-s", "10.79.0.0/16", "-d", "203.0.113.0/24", "-j", "DROP")
	f.add(chain, "-s", "10.79.0.0/16", "-d", "169.254.169.254", "-j", "DROP")
	f.add(chain, "-s", "10.80.0.0/16", "-d", "198.51.100.0/24", "-j", "DROP")
	f.add(chain, "-s", "10.79.0.0/16", "-d", "192.0.2.0/24", "-j", "ACCEPT")
	// As iptables-nft writes -s 10.79.0.0/16 -d 100.64.0.0/10 -j DROP: the
	// source's two whole bytes, the destination's mask on its first byte.
	tbl := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"}
	f.mu.Lock()
	f.next++
	f.chains[chain] = append(f.chains[chain], &nftables.Rule{Table: tbl, Chain: &nftables.Chain{Name: chain, Table: tbl}, Handle: f.next,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 79}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 2},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2, Mask: []byte{255, 192}, Xor: []byte{0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{100, 64}},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}})
	f.mu.Unlock()
	b := netlinkChainBackend(f)
	got, err := b.FloorDrops(chain, netip.MustParsePrefix("10.79.0.0/16"))
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("169.254.169.254/32"), netip.MustParsePrefix("100.64.0.0/10")}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("= %v %v, want %v", got, err, want)
	}
	// Not prefixes: a mask with a hole, a compare of another length.
	for _, exprs := range [][]expr.Any{
		{&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, &expr.Bitwise{Len: 4, Mask: []byte{255, 0, 255, 0}}, &expr.Cmp{Op: expr.CmpOpEq, Data: []byte{1, 0, 1, 0}}},
		{&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, &expr.Cmp{Op: expr.CmpOpEq, Data: []byte{1, 2}}},
		{&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, &expr.Bitwise{Len: 4, Mask: []byte{255, 255, 255, 0}}},
		{&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}},
	} {
		if p, ok := rulePrefixAt(exprs, 16); ok {
			t.Errorf("%v read as %v", exprs, p)
		}
	}
	if got, err := b.FloorDrops("AEROLVM-NOPE", netip.MustParsePrefix("10.79.0.0/16")); err != nil || len(got) != 0 {
		t.Fatalf("an empty chain = %v %v", got, err)
	}
	f.getErr = syscall.ENOENT
	if got, err := b.FloorDrops(chain, netip.MustParsePrefix("10.79.0.0/16")); err != nil || len(got) != 0 {
		t.Fatalf("a missing chain = %v %v", got, err)
	}
	f.getErr = errors.New("boom")
	if _, err := b.FloorDrops(chain, netip.MustParsePrefix("10.79.0.0/16")); err == nil {
		t.Fatal("list error hidden")
	}
}
