//go:build linux

package netrules

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"golang.org/x/sys/unix"
)

// TestTranslateNodeGuardPortRule: -p tcp|udp --dport N becomes meta l4proto
// and the xt tcp/udp match iptables-nft writes, before the comment.
func TestTranslateNodeGuardPortRule(t *testing.T) {
	for _, tc := range []struct {
		proto string
		num   byte
	}{{"tcp", unix.IPPROTO_TCP}, {"udp", unix.IPPROTO_UDP}} {
		exprs, err := exprsFromRulespec(NodePort{Proto: tc.proto, Port: 15080}.spec("10.88.0.0/16")...)
		if err != nil {
			t.Fatal(err)
		}
		var meta, cmp, port bool
		for i, e := range exprs {
			switch x := e.(type) {
			case *expr.Meta:
				meta = x.Key == expr.MetaKeyL4PROTO
				c, ok := exprs[i+1].(*expr.Cmp)
				cmp = ok && len(c.Data) == 1 && c.Data[0] == tc.num
			case *expr.Match:
				switch info := x.Info.(type) {
				case *xt.Tcp:
					port = tc.proto == "tcp" && info.DstPorts == [2]uint16{15080, 15080} && info.SrcPorts == [2]uint16{0, 0xffff}
				case *xt.Udp:
					port = tc.proto == "udp" && info.DstPorts == [2]uint16{15080, 15080} && info.SrcPorts == [2]uint16{0, 0xffff}
				}
			}
		}
		if !meta || !cmp || !port {
			t.Fatalf("%s: meta=%v cmp=%v port=%v in %#v", tc.proto, meta, cmp, port, exprs)
		}
		if v, ok := exprs[len(exprs)-1].(*expr.Verdict); !ok || v.Kind != expr.VerdictReturn {
			t.Fatalf("%s: last = %#v", tc.proto, exprs[len(exprs)-1])
		}
	}
	// Protocol without a port: only the meta match.
	exprs, err := exprsFromRulespec("-s", "10.88.0.0/16", "-p", "udp", "-j", "DROP")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range exprs {
		if _, ok := e.(*expr.Match); ok {
			t.Fatalf("no port, no xt match: %#v", exprs)
		}
	}
}

// TestTranslateJumpAndIdentity: a jump names its chain, and rule identity
// tells jumps to different chains, ports and protocols apart, so Exists for
// the A chain's jump never finds the B chain's.
func TestTranslateJumpAndIdentity(t *testing.T) {
	a, err := exprsFromRulespec(nodeJumpSpec("10.88.0.0/16", "AEROLVM-NODE-00000000-A")...)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := a[len(a)-1].(*expr.Verdict); !ok || v.Kind != expr.VerdictJump || v.Chain != "AEROLVM-NODE-00000000-A" {
		t.Fatalf("jump = %#v", a[len(a)-1])
	}
	b, _ := exprsFromRulespec(nodeJumpSpec("10.88.0.0/16", "AEROLVM-NODE-00000000-B")...)
	if exprsEqual(a, b) {
		t.Fatal("jumps to different chains must differ")
	}
	tcp1, _ := exprsFromRulespec(NodePort{Proto: "tcp", Port: 1}.spec("10.88.0.0/16")...)
	tcp2, _ := exprsFromRulespec(NodePort{Proto: "tcp", Port: 2}.spec("10.88.0.0/16")...)
	udp1, _ := exprsFromRulespec(NodePort{Proto: "udp", Port: 1}.spec("10.88.0.0/16")...)
	if !exprsEqualIgnoringCounters(tcp1, tcp1) || exprsEqual(tcp1, tcp2) || exprsEqual(tcp1, udp1) {
		t.Fatal("port rules must compare by protocol and port")
	}
	udp2, _ := exprsFromRulespec(NodePort{Proto: "udp", Port: 2}.spec("10.88.0.0/16")...)
	if exprsEqual(udp1, udp2) {
		t.Fatal("udp ports must differ")
	}
	if exprEqual(&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Meta{Key: expr.MetaKeyMARK, Register: 1}) ||
		exprEqual(&expr.Meta{Key: expr.MetaKeyL4PROTO}, &expr.Counter{}) {
		t.Fatal("meta identity")
	}
	if matchInfoEqual(&xt.ConntrackMtinfo3{}, &xt.ConntrackMtinfo3{}) {
		t.Fatal("unknown match payloads never compare equal")
	}
}
