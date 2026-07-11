//go:build linux

package netrules

import (
	"net"
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
	// iptables-nft parity: a counter expr must precede the verdict so rules
	// we create are deletable via the exec backend and vice versa.
	if _, ok := exprs[len(exprs)-2].(*expr.Counter); !ok {
		t.Fatalf("penultimate expr = %#v, want *expr.Counter", exprs[len(exprs)-2])
	}
}

func TestExprsEqualIgnoringCounters(t *testing.T) {
	ours, err := exprsFromRulespec("-s", "10.0.0.5", "-j", "DROP")
	if err != nil {
		t.Fatal(err)
	}
	// Same rule as the kernel would return it after traffic: non-zero totals.
	live := make([]expr.Any, len(ours))
	copy(live, ours)
	for i, e := range live {
		if _, ok := e.(*expr.Counter); ok {
			live[i] = &expr.Counter{Packets: 9, Bytes: 512}
		}
	}
	if !exprsEqualIgnoringCounters(ours, live) {
		t.Fatal("counter totals must not affect rule identity")
	}
	if !exprsEqualIgnoringCounters(ours, stripCounters(ours)) {
		t.Fatal("counter presence must not affect rule identity")
	}
	other, _ := exprsFromRulespec("-s", "10.0.0.6", "-j", "DROP")
	if exprsEqualIgnoringCounters(ours, other) {
		t.Fatal("different src must not match")
	}
}

func TestExprsFromRulespecCIDRUsesBitwise(t *testing.T) {
	exprs, err := exprsFromRulespec("-s", "10.0.0.0/8", "-j", "DROP")
	if err != nil {
		t.Fatal(err)
	}
	foundBitwise := false
	for _, e := range exprs {
		if _, ok := e.(*expr.Bitwise); ok {
			foundBitwise = true
		}
	}
	if !foundBitwise {
		t.Fatal("CIDR match must use Bitwise+Cmp, not bare Cmp")
	}
}

func TestExprsFromRulespecDropAndParseError(t *testing.T) {
	exprs, err := exprsFromRulespec("-d", "10.0.0.9", "-j", "DROP")
	if err != nil {
		t.Fatal(err)
	}
	last := exprs[len(exprs)-1].(*expr.Verdict)
	if last.Kind != expr.VerdictDrop {
		t.Fatalf("kind = %v, want drop", last.Kind)
	}
	if _, err := exprsFromRulespec("-p", "tcp"); err == nil {
		t.Fatal("want parse error")
	}
}

func TestIPv4MatchExprsMaskFallback(t *testing.T) {
	// Non-4-byte mask forces CIDRMask(32) path inside ipv4MatchExprs.
	n := &net.IPNet{IP: net.IPv4(1, 2, 3, 4), Mask: net.IPMask{0xff}}
	got := ipv4MatchExprs(12, n)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (/32 Cmp path after mask normalize)", len(got))
	}
}

func TestExprsEqualAndExprEqualBranches(t *testing.T) {
	a, err := exprsFromRulespec("-s", "10.0.0.1", "-j", "ACCEPT")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := exprsFromRulespec("-s", "10.0.0.1", "-j", "ACCEPT")
	if !exprsEqual(a, b) {
		t.Fatal("identical specs must equal")
	}
	c, _ := exprsFromRulespec("-s", "10.0.0.2", "-j", "ACCEPT")
	if exprsEqual(a, c) {
		t.Fatal("different src must not equal")
	}
	if exprsEqual(a, a[:len(a)-1]) {
		t.Fatal("length mismatch")
	}

	cmt := xt.Comment("x")
	cmt2 := xt.Comment("y")
	cases := []struct {
		name string
		x, y expr.Any
		want bool
	}{
		{
			name: "payload_mismatch",
			x:    &expr.Payload{DestRegister: 1, Offset: 12, Len: 4},
			y:    &expr.Payload{DestRegister: 1, Offset: 16, Len: 4},
			want: false,
		},
		{
			name: "cmp_ok",
			x:    &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 2, 3, 4}},
			y:    &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 2, 3, 4}},
			want: true,
		},
		{
			name: "bitwise_mask_diff",
			x:    &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{255, 0, 0, 0}, Xor: []byte{0, 0, 0, 0}},
			y:    &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{255, 255, 0, 0}, Xor: []byte{0, 0, 0, 0}},
			want: false,
		},
		{
			name: "verdict_diff",
			x:    &expr.Verdict{Kind: expr.VerdictDrop},
			y:    &expr.Verdict{Kind: expr.VerdictAccept},
			want: false,
		},
		{
			name: "comment_match",
			x:    &expr.Match{Name: "comment", Info: &cmt},
			y:    &expr.Match{Name: "comment", Info: &cmt},
			want: true,
		},
		{
			name: "comment_diff",
			x:    &expr.Match{Name: "comment", Info: &cmt},
			y:    &expr.Match{Name: "comment", Info: &cmt2},
			want: false,
		},
		{
			name: "match_name_diff",
			x:    &expr.Match{Name: "comment", Info: &cmt},
			y:    &expr.Match{Name: "other", Info: &cmt},
			want: false,
		},
		{
			name: "unknown_type",
			x:    &expr.Counter{},
			y:    &expr.Counter{},
			want: false,
		},
		{
			name: "type_mismatch",
			x:    &expr.Verdict{Kind: expr.VerdictDrop},
			y:    &expr.Cmp{},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exprEqual(tc.x, tc.y); got != tc.want {
				t.Fatalf("exprEqual = %v, want %v", got, tc.want)
			}
		})
	}
	if bytesEqual([]byte{1}, []byte{1, 2}) {
		t.Fatal("bytesEqual length")
	}
	if bytesEqual([]byte{1, 2}, []byte{1, 3}) {
		t.Fatal("bytesEqual content")
	}
	if !bytesEqual(nil, nil) {
		t.Fatal("bytesEqual nil")
	}
}

func TestNewWithOptionsUnknownAndNetlink(t *testing.T) {
	if _, err := NewWithOptions(true, "mystery"); err == nil {
		t.Fatal("want unknown backend error")
	}
	// Netlink may fail without CAP_NET_ADMIN — either success or wrapped error.
	m, err := NewWithOptions(true, BackendNetlink)
	if err != nil {
		if m != nil {
			t.Fatalf("err=%v but manager=%v", err, m)
		}
		return
	}
	if !m.Enabled() {
		t.Fatal("netlink Manager should be enabled when NewNetlinkBackend succeeds")
	}
}

func TestNewWithOptionsExec(t *testing.T) {
	m, err := NewWithOptions(true, BackendExec)
	if err != nil {
		// iptables.New can fail in restricted CI; that's still a covered path.
		t.Logf("exec backend unavailable: %v", err)
		return
	}
	if !m.Enabled() {
		t.Fatal("exec Manager should be enabled")
	}
	m2, err := NewWithOptions(true, "")
	if err != nil {
		t.Logf("default exec unavailable: %v", err)
		return
	}
	if !m2.Enabled() {
		t.Fatal("empty backend should select exec")
	}
}
