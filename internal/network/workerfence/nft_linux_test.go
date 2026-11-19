//go:build linux

package workerfence

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func testRules(t *testing.T) []Rule {
	t.Helper()
	rules, err := Plan(Spec{UID: 61000, Allow: []Allow{
		{Proto: "tcp", Prefix: netip.MustParsePrefix("127.0.0.1/32"), PortLo: 4100, PortHi: 4100, Why: "audit ingest"},
		{Proto: "tcp", Prefix: netip.MustParsePrefix(GuestListenHost + "/32"), PortLo: 32768, PortHi: 60999, Why: "guest listeners"},
		{Proto: "udp", Prefix: netip.MustParsePrefix("::1/128"), PortLo: 53, PortHi: 53, Why: "name server"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

// TestRuleExprs pins the bytecode: the sending socket's uid, the address
// family, the protocol and ports for an exception, the destination under
// its mask, a counter and the verdict.
func TestRuleExprs(t *testing.T) {
	uid := binaryutil.NativeEndian.PutUint32(61000)
	for _, tc := range []struct {
		name   string
		rule   Rule
		family byte
		offset uint32
		mask   []byte // nil: no bitwise (a single address)
		ports  []expr.CmpOp
		accept bool
	}{
		{"loopback drop", Rule{UID: 61000, Prefix: netip.MustParsePrefix("127.0.0.0/8")}, unix.NFPROTO_IPV4, 16, []byte{0xff, 0, 0, 0}, nil, false},
		{"link-local v6 drop", Rule{UID: 61000, Prefix: netip.MustParsePrefix("fe80::/10")}, unix.NFPROTO_IPV6, 24, append([]byte{0xff, 0xc0}, make([]byte, 14)...), nil, false},
		{"metadata v6 drop", Rule{UID: 61000, Prefix: netip.MustParsePrefix("fd00:ec2::254/128")}, unix.NFPROTO_IPV6, 24, nil, nil, false},
		{"one port", Rule{UID: 61000, Accept: true, Proto: "tcp", Prefix: netip.MustParsePrefix("127.0.0.1/32"), PortLo: 4100, PortHi: 4100}, unix.NFPROTO_IPV4, 16, nil, []expr.CmpOp{expr.CmpOpEq}, true},
		{"port range", Rule{UID: 61000, Accept: true, Proto: "udp", Prefix: netip.MustParsePrefix("127.0.97.1/32"), PortLo: 32768, PortHi: 60999}, unix.NFPROTO_IPV4, 16, nil, []expr.CmpOp{expr.CmpOpGte, expr.CmpOpLte}, true},
	} {
		exprs, err := ruleExprs(tc.rule)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		i := 0
		next := func() expr.Any { e := exprs[i]; i++; return e }
		if m, ok := next().(*expr.Meta); !ok || m.Key != expr.MetaKeySKUID {
			t.Fatalf("%s: does not start with meta skuid", tc.name)
		}
		if c, ok := next().(*expr.Cmp); !ok || !bytes.Equal(c.Data, uid) {
			t.Fatalf("%s: uid cmp = %#v", tc.name, c)
		}
		if m, ok := next().(*expr.Meta); !ok || m.Key != expr.MetaKeyNFPROTO {
			t.Fatalf("%s: no nfproto", tc.name)
		}
		if c, ok := next().(*expr.Cmp); !ok || !bytes.Equal(c.Data, []byte{tc.family}) {
			t.Fatalf("%s: family = %#v", tc.name, c)
		}
		if tc.rule.Proto != "" {
			if m, ok := next().(*expr.Meta); !ok || m.Key != expr.MetaKeyL4PROTO {
				t.Fatalf("%s: no l4proto", tc.name)
			}
			next()
		}
		if p, ok := next().(*expr.Payload); !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != tc.offset {
			t.Fatalf("%s: daddr load = %#v", tc.name, p)
		}
		if tc.mask != nil {
			if b, ok := next().(*expr.Bitwise); !ok || !bytes.Equal(b.Mask, tc.mask) {
				t.Fatalf("%s: mask = %#v", tc.name, b)
			}
		}
		if c, ok := next().(*expr.Cmp); !ok || !bytes.Equal(c.Data, tc.rule.Prefix.Masked().Addr().AsSlice()) {
			t.Fatalf("%s: daddr cmp = %#v", tc.name, c)
		}
		if tc.ports != nil {
			if p, ok := next().(*expr.Payload); !ok || p.Base != expr.PayloadBaseTransportHeader || p.Offset != 2 || p.Len != 2 {
				t.Fatalf("%s: dport load = %#v", tc.name, p)
			}
			for _, op := range tc.ports {
				if c, ok := next().(*expr.Cmp); !ok || c.Op != op {
					t.Fatalf("%s: port cmp = %#v", tc.name, c)
				}
			}
		}
		if _, ok := next().(*expr.Counter); !ok {
			t.Fatalf("%s: no counter", tc.name)
		}
		want := expr.VerdictDrop
		if tc.accept {
			want = expr.VerdictAccept
		}
		if v, ok := next().(*expr.Verdict); !ok || v.Kind != want || i != len(exprs) {
			t.Fatalf("%s: verdict = %#v (%d of %d exprs)", tc.name, v, i, len(exprs))
		}
	}
	for _, bad := range []Rule{
		{Prefix: netip.MustParsePrefix("127.0.0.0/8")},
		{UID: 1},
		{UID: 1, Proto: "sctp", Prefix: netip.MustParsePrefix("127.0.0.1/32"), PortLo: 1, PortHi: 1},
		{UID: 1, Proto: "tcp", Prefix: netip.MustParsePrefix("127.0.0.1/32")},
	} {
		if _, err := ruleExprs(bad); err == nil {
			t.Errorf("rule %+v accepted", bad)
		}
	}
}

func TestMask(t *testing.T) {
	for _, tc := range []struct {
		p    string
		want []byte
	}{
		{"127.0.0.0/8", []byte{0xff, 0, 0, 0}},
		{"169.254.0.0/16", []byte{0xff, 0xff, 0, 0}},
		{"10.0.0.0/12", []byte{0xff, 0xf0, 0, 0}},
		{"1.2.3.4/32", []byte{0xff, 0xff, 0xff, 0xff}},
	} {
		if got := mask(netip.MustParsePrefix(tc.p)); !bytes.Equal(got, tc.want) {
			t.Errorf("mask(%s) = %x", tc.p, got)
		}
	}
}

// fakeDial acks every message of a batch and keeps them.
type fakeDial struct {
	sent []netlink.Message
	err  error
}

func (f *fakeDial) dial(req []netlink.Message) ([]netlink.Message, error) {
	if f.err != nil {
		return nil, f.err
	}
	if len(req) == 0 {
		return nil, io.EOF
	}
	f.sent = append(f.sent, req...)
	out := make([]netlink.Message, 0, len(req))
	for _, m := range req {
		acks, err := nltest.Error(0, []netlink.Message{m})
		if err != nil {
			return nil, err
		}
		out = append(out, acks...)
	}
	return out, nil
}

func (f *fakeDial) install(t *testing.T) {
	t.Helper()
	orig := newConn
	newConn = func() (*nftables.Conn, error) { return nftables.New(nftables.WithTestDial(f.dial)) }
	t.Cleanup(func() { newConn = orig })
}

func (f *fakeDial) ops() map[uint16]int {
	count := map[uint16]int{}
	for _, m := range f.sent {
		if uint16(m.Header.Type)>>8 == unix.NFNL_SUBSYS_NFTABLES {
			count[uint16(m.Header.Type)&0xff]++
		}
	}
	return count
}

// Apply replaces the table in one batch: add, delete, add, the chain, then
// every rule with its comment. Remove deletes it the same safe way.
func TestApplyAndRemove(t *testing.T) {
	f := &fakeDial{}
	f.install(t)
	rules := testRules(t)
	if err := NewBackend().Apply(rules); err != nil {
		t.Fatal(err)
	}
	if c := f.ops(); c[unix.NFT_MSG_NEWTABLE] != 2 || c[unix.NFT_MSG_DELTABLE] != 1 || c[unix.NFT_MSG_NEWCHAIN] != 1 || c[unix.NFT_MSG_NEWRULE] != len(rules) {
		t.Fatalf("apply ops = %v", c)
	}
	comments := 0
	for _, m := range f.sent {
		if uint16(m.Header.Type)&0xff == unix.NFT_MSG_NEWRULE && bytes.Contains(m.Data, []byte("uid 61000 ")) {
			comments++
		}
	}
	if comments != len(rules) {
		t.Fatalf("%d of %d rules carry their comment", comments, len(rules))
	}
	f.sent = nil
	if err := NewBackend().Remove(); err != nil {
		t.Fatal(err)
	}
	if c := f.ops(); c[unix.NFT_MSG_NEWTABLE] != 1 || c[unix.NFT_MSG_DELTABLE] != 1 || c[unix.NFT_MSG_NEWRULE] != 0 {
		t.Fatalf("remove ops = %v", c)
	}

	if err := NewBackend().Apply([]Rule{{UID: 1}}); err == nil {
		t.Fatal("a rule with no destination was installed")
	}
	f.err = errors.New("netlink: operation not permitted")
	if err := NewBackend().Apply(rules); err == nil {
		t.Fatal("a refused batch must fail Apply")
	}
	if err := NewBackend().Remove(); err == nil {
		t.Fatal("a refused batch must fail Remove")
	}
	orig := newConn
	newConn = func() (*nftables.Conn, error) { return nil, errors.New("no netlink") }
	defer func() { newConn = orig }()
	if NewBackend().Apply(nil) == nil || NewBackend().Remove() == nil {
		t.Fatal("Apply or Remove without netlink")
	}
	if _, err := NewBackend().Check(nil); err == nil {
		t.Fatal("Check without netlink")
	}
}

// fakeKernel answers check with the table Apply builds.
type fakeKernel struct {
	chains   []*nftables.Chain
	rules    []*nftables.Rule
	listErr  error
	rulesErr error
}

func (k *fakeKernel) ListChainsOfTableFamily(nftables.TableFamily) ([]*nftables.Chain, error) {
	return k.chains, k.listErr
}

func (k *fakeKernel) GetRules(*nftables.Table, *nftables.Chain) ([]*nftables.Rule, error) {
	return k.rules, k.rulesErr
}

func installedKernel(t *testing.T, rules []Rule) *fakeKernel {
	t.Helper()
	// Another table's chain of the same name is not ours.
	k := &fakeKernel{chains: []*nftables.Chain{{Name: ChainName, Table: &nftables.Table{Name: "filter"}}, chain(table())}}
	for _, r := range rules {
		exprs, err := ruleExprs(r)
		if err != nil {
			t.Fatal(err)
		}
		k.rules = append(k.rules, &nftables.Rule{Exprs: exprs, UserData: userdata.AppendString(nil, userdata.TypeComment, r.Comment())})
	}
	return k
}

func TestCheck(t *testing.T) {
	rules := testRules(t)
	if ok, err := check(installedKernel(t, rules), rules); err != nil || !ok {
		t.Fatalf("intact fence: ok=%v err=%v", ok, err)
	}
	for name, tamper := range map[string]func(k *fakeKernel){
		"table flushed":                   func(k *fakeKernel) { k.chains = k.chains[:1] },
		"rule deleted":                    func(k *fakeKernel) { k.rules = k.rules[1:] },
		"accept inserted above the drops": func(k *fakeKernel) { k.rules = append([]*nftables.Rule{{}}, k.rules[:len(k.rules)-1]...) },
		"rule rewritten": func(k *fakeKernel) {
			k.rules[len(k.rules)-1].UserData = userdata.AppendString(nil, userdata.TypeComment, "something else")
		},
		"chain moved to another hook": func(k *fakeKernel) { k.chains[1].Hooknum = nftables.ChainHookInput },
		"chain priority changed":      func(k *fakeKernel) { k.chains[1].Priority = nftables.ChainPriorityFilter },
		"chain lost its hook":         func(k *fakeKernel) { k.chains[1].Hooknum = nil },
		"chain policy drop":           func(k *fakeKernel) { drop := nftables.ChainPolicyDrop; k.chains[1].Policy = &drop },
	} {
		k := installedKernel(t, rules)
		tamper(k)
		if ok, err := check(k, rules); err != nil || ok {
			t.Errorf("%s: check = %v, %v; want a mismatch", name, ok, err)
		}
	}
	k := installedKernel(t, rules)
	k.listErr = errors.New("busy")
	if _, err := check(k, rules); err == nil {
		t.Fatal("a failed chain list passed")
	}
	k = installedKernel(t, rules)
	k.rulesErr = errors.New("busy")
	if _, err := check(k, rules); err == nil {
		t.Fatal("a failed rule list passed")
	}
	// Through the backend, against a kernel that lists nothing.
	f := &fakeDial{}
	f.install(t)
	if _, err := NewBackend().Check(rules); err == nil {
		// The fake acks with no chains: either an error or a mismatch,
		// never a fence that is in.
		if ok, _ := NewBackend().Check(rules); ok {
			t.Fatal("an empty kernel holds the fence")
		}
	}
}
