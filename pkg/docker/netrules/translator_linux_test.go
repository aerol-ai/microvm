//go:build linux

package netrules

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

func TestExprsFromRulespecRoundTrip(t *testing.T) {
	spec := []string{"-s", "10.0.0.5", "-d", "1.1.1.1/32", "-m", "comment", "--comment", egressPolicyComment, "-j", "ACCEPT"}
	exprs, err := exprsFromRulespec(spec...)
	if err != nil {
		t.Fatal(err)
	}
	if !exprsEqual(exprs, exprs) {
		t.Fatal("exprs not equal to self")
	}
	last, ok := exprs[len(exprs)-1].(*expr.Verdict)
	if !ok || last.Kind != expr.VerdictAccept {
		t.Fatalf("last = %#v", exprs[len(exprs)-1])
	}
	found := false
	for _, e := range exprs {
		m, ok := e.(*expr.Match)
		if !ok || m.Name != "comment" {
			continue
		}
		c, ok := m.Info.(*xt.Comment)
		if ok && string(*c) == egressPolicyComment {
			found = true
		}
	}
	if !found {
		t.Fatal("comment match missing")
	}
}
