//go:build linux

package hostport

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Against REAL iptables (root + iptables binary; skipped otherwise, so plain
// CI skips it). This is what proves the rule syntax and that Reconcile reads
// iptables' own normalized listing as "matching" (no churn), which the
// in-memory backend can only imitate.
func TestForwarderAgainstRealIPTables(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("needs iptables")
	}
	b, err := NewIPTablesBackend()
	if err != nil {
		t.Skipf("iptables backend: %v", err)
	}
	f := New(b, nil)
	d := dnat("10.1.0.9:22300", true)
	if err := f.Ensure(22300, d); err != nil {
		t.Fatal(err)
	}
	if err := f.Ensure(22301, Target{Kind: Redirect, RedirectPort: 21215}); err != nil {
		t.Fatal(err)
	}
	fwd, err := b.List("filter", ChainFwd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(fwd, "\n"), "--ctorigdstport 22300") {
		t.Fatalf("real accept rule:\n%s", strings.Join(fwd, "\n"))
	}
	// A fresh forwarder reconciling the same desired state must see
	// iptables' normalized rules as matching: nothing deleted or re-added.
	count := func() int {
		n := 0
		for _, c := range []struct{ table, chain string }{{"nat", ChainNAT}, {"nat", ChainPost}, {"filter", ChainFwd}} {
			rules, _ := b.List(c.table, c.chain)
			n += len(rules)
		}
		return n
	}
	before := count()
	g := New(b, nil)
	desired := map[int]Target{22300: d, 22301: {Kind: Redirect, RedirectPort: 21215}}
	if err := g.Reconcile(desired); err != nil {
		t.Fatal(err)
	}
	if after := count(); after != before {
		t.Fatalf("steady-state reconcile against real iptables changed the rule count %d -> %d", before, after)
	}
	if err := g.Reconcile(map[int]Target{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ table, chain string }{{"nat", ChainNAT}, {"nat", ChainPost}, {"filter", ChainFwd}} {
		rules, _ := b.List(c.table, c.chain)
		for _, r := range rules {
			if strings.Contains(r, commentPrefix) {
				t.Fatalf("rule survived an empty reconcile: %s", r)
			}
		}
	}
	if ok, _ := b.ChainExists("nat", ChainNAT); !ok {
		t.Fatal("chain missing")
	}
	_ = b.NewChain("filter", "AEROLVM-HOSTPORT-TEST")
	_ = b.Append("filter", "AEROLVM-HOSTPORT-TEST", "-j", "RETURN")
	_ = b.Delete("filter", "AEROLVM-HOSTPORT-TEST", "-j", "RETURN")
}
