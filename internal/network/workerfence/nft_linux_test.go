//go:build linux

package workerfence

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
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
		{Proto: "udp", Prefix: netip.MustParsePrefix("::1/128"), PortLo: 53, PortHi: 53, Why: "name server"},
	}, Floor: []netip.Prefix{netip.MustParsePrefix("10.96.0.1/32")}, NodePorts: []uint16{443}})
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

// kinds names each expression of a rule, in order, so a test can pin the
// shape of its bytecode.
func kinds(exprs []expr.Any) []string {
	out := make([]string, len(exprs))
	for i, e := range exprs {
		switch e := e.(type) {
		case *expr.Meta:
			out[i] = map[expr.MetaKey]string{expr.MetaKeySKUID: "skuid", expr.MetaKeyNFPROTO: "nfproto", expr.MetaKeyL4PROTO: "l4proto"}[e.Key]
		case *expr.Ct:
			out[i] = map[expr.CtKey]string{expr.CtKeyDIRECTION: "ct-direction", expr.CtKeySTATUS: "ct-status", expr.CtKeyDST: "ct-orig-daddr", expr.CtKeyPROTODST: "ct-orig-dport"}[e.Key]
		case *expr.Fib:
			if e.FlagDADDR && e.ResultADDRTYPE {
				out[i] = "fib-daddr-type"
			}
		case *expr.Payload:
			out[i] = map[expr.PayloadBase]string{expr.PayloadBaseNetworkHeader: "daddr", expr.PayloadBaseTransportHeader: "dport"}[e.Base]
			if e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 12 {
				out[i] = "saddr"
			}
		case *expr.Bitwise:
			out[i] = "mask"
		case *expr.Cmp:
			out[i] = "cmp"
		case *expr.Counter:
			out[i] = "counter"
		case *expr.Verdict:
			out[i] = map[expr.VerdictKind]string{expr.VerdictAccept: "accept", expr.VerdictDrop: "drop"}[e.Kind]
		}
	}
	return out
}

// TestRuleExprs pins the bytecode of each kind of rule: the sending
// socket's uid first, then what the kind matches, a counter and the
// verdict.
func TestRuleExprs(t *testing.T) {
	uid := binaryutil.NativeEndian.PutUint32(61000)
	pfx := netip.MustParsePrefix
	for _, tc := range []struct {
		name string
		rule Rule
		want string
		// checks on particular expressions, by index
		check func(t *testing.T, exprs []expr.Any)
	}{
		{"loopback drop", Rule{UID: 61000, Prefix: pfx("127.0.0.0/8")},
			"skuid cmp nfproto cmp daddr mask cmp counter drop", func(t *testing.T, e []expr.Any) {
				if c := e[3].(*expr.Cmp); !bytes.Equal(c.Data, []byte{unix.NFPROTO_IPV4}) {
					t.Fatalf("family = %v", c.Data)
				}
				if p := e[4].(*expr.Payload); p.Offset != 16 || p.Len != 4 {
					t.Fatalf("daddr = %+v", p)
				}
				if b := e[5].(*expr.Bitwise); !bytes.Equal(b.Mask, []byte{0xff, 0, 0, 0}) {
					t.Fatalf("mask = %x", b.Mask)
				}
			}},
		{"metadata v6 drop", Rule{UID: 61000, Prefix: pfx("fd00:ec2::254/128")},
			"skuid cmp nfproto cmp daddr cmp counter drop", func(t *testing.T, e []expr.Any) {
				if p := e[4].(*expr.Payload); p.Offset != 24 || p.Len != 16 {
					t.Fatalf("daddr = %+v", p)
				}
			}},
		{"reply from the guest listen host", Rule{UID: 61000, Kind: KindReply, From: netip.MustParseAddr("127.0.97.1"), Prefix: pfx("127.0.0.0/8")},
			"skuid cmp nfproto cmp ct-direction cmp saddr cmp daddr mask cmp counter accept", func(t *testing.T, e []expr.Any) {
				if c := e[5].(*expr.Cmp); !bytes.Equal(c.Data, []byte{1}) {
					t.Fatalf("direction = %v, want reply (1)", c.Data)
				}
				if p := e[6].(*expr.Payload); p.Offset != 12 || p.Len != 4 {
					t.Fatalf("saddr load = %+v", p)
				}
				if c := e[7].(*expr.Cmp); !bytes.Equal(c.Data, []byte{127, 0, 97, 1}) {
					t.Fatalf("saddr = %v", c.Data)
				}
			}},
		{"one port", Rule{UID: 61000, Kind: KindAllow, Proto: "tcp", Prefix: pfx("127.0.0.1/32"), PortLo: 4100, PortHi: 4100},
			"skuid cmp nfproto cmp l4proto cmp daddr cmp dport cmp counter accept", func(t *testing.T, e []expr.Any) {
				if c := e[5].(*expr.Cmp); !bytes.Equal(c.Data, []byte{unix.IPPROTO_TCP}) {
					t.Fatalf("proto = %v", c.Data)
				}
				if c := e[9].(*expr.Cmp); c.Op != expr.CmpOpEq || !bytes.Equal(c.Data, []byte{0x10, 0x04}) {
					t.Fatalf("port = %+v", c)
				}
			}},
		{"port range", Rule{UID: 61000, Kind: KindAllow, Proto: "udp", Prefix: pfx("::1/128"), PortLo: 53, PortHi: 54},
			"skuid cmp nfproto cmp l4proto cmp daddr cmp dport cmp cmp counter accept", func(t *testing.T, e []expr.Any) {
				if e[9].(*expr.Cmp).Op != expr.CmpOpGte || e[10].(*expr.Cmp).Op != expr.CmpOpLte {
					t.Fatal("range not lo..hi")
				}
			}},
		{"nat'd, by the original destination", Rule{UID: 61000, Kind: KindAllowNAT, Proto: "udp", Prefix: pfx("127.0.0.11/32"), PortLo: 53, PortHi: 53},
			"skuid cmp nfproto cmp l4proto cmp ct-status mask cmp ct-orig-daddr cmp ct-orig-dport cmp counter accept", func(t *testing.T, e []expr.Any) {
				if b := e[7].(*expr.Bitwise); !bytes.Equal(b.Mask, binaryutil.NativeEndian.PutUint32(1<<5)) {
					t.Fatalf("status mask = %x, want IPS_DST_NAT", b.Mask)
				}
				if c := e[8].(*expr.Cmp); c.Op != expr.CmpOpNeq {
					t.Fatalf("status cmp = %+v", c)
				}
				if ct := e[9].(*expr.Ct); ct.Direction != 0 {
					t.Fatalf("daddr direction %d, want original", ct.Direction)
				}
				// The address's own 4 bytes, as nft writes it.
				if c := e[10].(*expr.Cmp); !bytes.Equal(c.Data, []byte{127, 0, 0, 11}) {
					t.Fatalf("original daddr = %v", c.Data)
				}
				if ct := e[11].(*expr.Ct); ct.Direction != 0 {
					t.Fatalf("dport direction %d, want original", ct.Direction)
				}
				if c := e[12].(*expr.Cmp); !bytes.Equal(c.Data, []byte{0, 53}) {
					t.Fatalf("original dport = %v", c.Data)
				}
			}},
		{"nat'd v6 range", Rule{UID: 61000, Kind: KindAllowNAT, Proto: "tcp", Prefix: pfx("::1/128"), PortLo: 53, PortHi: 54},
			"skuid cmp nfproto cmp l4proto cmp ct-status mask cmp ct-orig-daddr cmp ct-orig-dport cmp cmp counter accept", nil},
		{"broadcast drop", Rule{UID: 61000, Kind: KindBroadcastDrop}, "skuid cmp fib-daddr-type cmp counter drop", func(t *testing.T, e []expr.Any) {
			if c := e[3].(*expr.Cmp); !bytes.Equal(c.Data, binaryutil.NativeEndian.PutUint32(unix.RTN_BROADCAST)) {
				t.Fatalf("fib type = %v, want broadcast", c.Data)
			}
		}},
		{"node port", Rule{UID: 61000, Kind: KindLocalPort, PortLo: 443, PortHi: 443},
			"skuid cmp l4proto cmp fib-daddr-type cmp dport cmp counter accept", func(t *testing.T, e []expr.Any) {
				if c := e[5].(*expr.Cmp); !bytes.Equal(c.Data, binaryutil.NativeEndian.PutUint32(unix.RTN_LOCAL)) {
					t.Fatalf("fib type = %v, want local", c.Data)
				}
			}},
		{"local drop", Rule{UID: 61000, Kind: KindLocalDrop}, "skuid cmp fib-daddr-type cmp counter drop", nil},
	} {
		exprs, err := ruleExprs(tc.rule)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := strings.Join(kinds(exprs), " "); got != tc.want {
			t.Fatalf("%s:\n got %s\nwant %s", tc.name, got, tc.want)
		}
		if c := exprs[1].(*expr.Cmp); !bytes.Equal(c.Data, uid) {
			t.Fatalf("%s: uid cmp = %#v", tc.name, c)
		}
		if tc.check != nil {
			tc.check(t, exprs)
		}
	}
	for _, bad := range []Rule{
		{Prefix: netip.MustParsePrefix("127.0.0.0/8")},
		{UID: 1},
		{UID: 1, Kind: KindAllow, Proto: "sctp", Prefix: netip.MustParsePrefix("127.0.0.1/32"), PortLo: 1, PortHi: 1},
		{UID: 1, Kind: KindAllow, Proto: "tcp", Prefix: netip.MustParsePrefix("127.0.0.1/32")},
		{UID: 1, Kind: KindLocalPort},
		{UID: 1, Kind: KindAllowNAT, Proto: "tcp", Prefix: netip.MustParsePrefix("127.0.0.1/32")},
		{UID: 1, Kind: KindReply, Prefix: netip.MustParsePrefix("127.0.0.0/8")},
		{UID: 1, Kind: KindReply, From: netip.MustParseAddr("127.0.97.1"), Prefix: netip.MustParsePrefix("::1/128")},
		{UID: 1, Kind: RuleKind(99), Prefix: netip.MustParsePrefix("127.0.0.1/32")},
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
	comments []string
	listErr  error
	rulesErr error
}

func (k *fakeKernel) ListChainsOfTableFamily(nftables.TableFamily) ([]*nftables.Chain, error) {
	return k.chains, k.listErr
}

func (k *fakeKernel) RuleComments() ([]string, error) {
	return k.comments, k.rulesErr
}

func installedKernel(t *testing.T, rules []Rule) *fakeKernel {
	t.Helper()
	// Another table's chain of the same name is not ours.
	k := &fakeKernel{chains: []*nftables.Chain{{Name: ChainName, Table: &nftables.Table{Name: "filter"}}, chain(table())}}
	for _, r := range rules {
		if _, err := ruleExprs(r); err != nil {
			t.Fatal(err)
		}
		k.comments = append(k.comments, r.Comment())
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
		"rule deleted":                    func(k *fakeKernel) { k.comments = k.comments[1:] },
		"accept inserted above the drops": func(k *fakeKernel) { k.comments = append([]string{""}, k.comments[:len(k.comments)-1]...) },
		"rule rewritten":                  func(k *fakeKernel) { k.comments[len(k.comments)-1] = "something else" },
		"chain moved to another hook":     func(k *fakeKernel) { k.chains[1].Hooknum = nftables.ChainHookInput },
		"chain back before conntrack":     func(k *fakeKernel) { k.chains[1].Priority = nftables.ChainPriorityRaw },
		"chain lost its hook":             func(k *fakeKernel) { k.chains[1].Hooknum = nil },
		"chain policy drop":               func(k *fakeKernel) { drop := nftables.ChainPolicyDrop; k.chains[1].Policy = &drop },
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

// The chain runs after conntrack, so the reply rule can see a direction:
// before it (raw) every packet would look new and guest listeners could
// not answer anyone.
func TestChainAfterConntrack(t *testing.T) {
	c := chain(table())
	if *c.Priority != *nftables.ChainPriorityFilter || *c.Hooknum != *nftables.ChainHookOutput {
		t.Fatalf("chain hook %v priority %v", *c.Hooknum, *c.Priority)
	}
}

// Check reads the rule comments straight off a netlink rule dump, without
// the library's expression parsing (which cannot read back a ct
// expression with a direction), keeping only the fence chain's rules.
func TestRuleComments(t *testing.T) {
	rule := func(tbl, ch, comment string) netlink.Message {
		attrs := []netlink.Attribute{
			{Type: unix.NFTA_RULE_TABLE, Data: append([]byte(tbl), 0)},
			{Type: unix.NFTA_RULE_CHAIN, Data: append([]byte(ch), 0)},
		}
		if comment != "" {
			attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_RULE_USERDATA, Data: userdata.AppendString(nil, userdata.TypeComment, comment)})
		}
		b, err := netlink.MarshalAttributes(attrs)
		if err != nil {
			t.Fatal(err)
		}
		return netlink.Message{Data: append([]byte{unix.NFPROTO_INET, 0, 0, 0}, b...)}
	}
	var asked netlink.Message
	r := nftReader{dump: func(req netlink.Message) ([]netlink.Message, error) {
		asked = req
		return []netlink.Message{
			rule(TableName, ChainName, "uid 1 drop 127.0.0.0/8"),
			rule("other", ChainName, "not ours"),
			rule(TableName, ChainName, ""),
			{Data: []byte{1}}, // too short to be a rule
			rule(TableName, ChainName, "uid 1 drop local"),
		}, nil
	}}
	got, err := r.RuleComments()
	if err != nil || strings.Join(got, "|") != "uid 1 drop 127.0.0.0/8||uid 1 drop local" {
		t.Fatalf("comments = %q, %v", got, err)
	}
	if uint16(asked.Header.Type) != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETRULE || asked.Header.Flags&netlink.Dump == 0 || !bytes.Contains(asked.Data, []byte(TableName)) {
		t.Fatalf("request = %+v", asked)
	}
	r.dump = func(netlink.Message) ([]netlink.Message, error) { return nil, errors.New("netlink busy") }
	if _, err := r.RuleComments(); err == nil {
		t.Fatal("a failed dump passed")
	}
	r.dump = func(netlink.Message) ([]netlink.Message, error) {
		return []netlink.Message{{Data: []byte{1, 0, 0, 0, 0xff, 0xff}}}, nil
	}
	if _, err := r.RuleComments(); err == nil {
		t.Fatal("a garbled dump passed")
	}
}
