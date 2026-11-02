//go:build linux

package ipv6fence

import (
	"bytes"
	"errors"
	"io"
	"os"
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

func TestNameData(t *testing.T) {
	if got := nameData("aerolvm0"); !bytes.Equal(got, []byte("aerolvm0\x00")) {
		t.Fatalf("exact = %q (the NUL makes it match only this name)", got)
	}
	if got := nameData("fctap*"); !bytes.Equal(got, []byte("fctap")) {
		t.Fatalf("prefix = %q", got)
	}
}

// TestRuleExprs pins the bytecode: match the bridge or interface, match
// IPv6 in the bridge family (which sees every ethertype), count, drop.
func TestRuleExprs(t *testing.T) {
	for _, tc := range []struct {
		rule Rule
		key  expr.MetaKey
	}{
		{Rule{FamilyBridge, ChainForward, MatchInBridge, "cni0"}, expr.MetaKeyBRIIIFNAME},
		{Rule{FamilyBridge, ChainOutput, MatchOutBridge, "cni0"}, expr.MetaKeyBRIOIFNAME},
		{Rule{FamilyIP6, ChainInput, MatchIn, "fctap*"}, expr.MetaKeyIIFNAME},
		{Rule{FamilyIP6, ChainOutput, MatchOut, "docker0"}, expr.MetaKeyOIFNAME},
	} {
		exprs, err := ruleExprs(tc.rule)
		if err != nil {
			t.Fatal(err)
		}
		if m, ok := exprs[0].(*expr.Meta); !ok || m.Key != tc.key || m.Register != 1 {
			t.Fatalf("%+v: first expr = %#v", tc.rule, exprs[0])
		}
		if c, ok := exprs[1].(*expr.Cmp); !ok || c.Op != expr.CmpOpEq || !bytes.Equal(c.Data, nameData(tc.rule.Name)) {
			t.Fatalf("%+v: name cmp = %#v", tc.rule, exprs[1])
		}
		n := len(exprs)
		if _, ok := exprs[n-2].(*expr.Counter); !ok {
			t.Fatalf("%+v: no counter before the verdict", tc.rule)
		}
		if v, ok := exprs[n-1].(*expr.Verdict); !ok || v.Kind != expr.VerdictDrop {
			t.Fatalf("%+v: verdict = %#v", tc.rule, exprs[n-1])
		}
		if tc.rule.Family == FamilyBridge {
			if n != 6 {
				t.Fatalf("bridge rule has %d exprs", n)
			}
			m, _ := exprs[2].(*expr.Meta)
			c, _ := exprs[3].(*expr.Cmp)
			if m == nil || m.Key != expr.MetaKeyPROTOCOL || c == nil || !bytes.Equal(c.Data, binaryutil.BigEndian.PutUint16(unix.ETH_P_IPV6)) {
				t.Fatalf("bridge rule must match ethertype 0x86dd: %#v %#v", exprs[2], exprs[3])
			}
		} else if n != 4 {
			t.Fatalf("ip6 rule has %d exprs", n)
		}
	}
	if _, err := ruleExprs(Rule{FamilyIP6, ChainInput, "ether", "x"}); err == nil {
		t.Fatal("unknown match accepted")
	}
}

// fakeDial acks every message of a batch and keeps them, so a test can
// read what Apply sent.
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

func msgOp(m netlink.Message) uint16 { return uint16(m.Header.Type) & 0xff }

// TestApplyReplacesBothTablesInOneBatch: add, delete, re-add each table,
// its three chains, then every rule with its comment, all in one Flush.
func TestApplyReplacesBothTablesInOneBatch(t *testing.T) {
	f := &fakeDial{}
	f.install(t)
	spec, _ := Spec{Bridges: []string{"aerolvm0"}, Links: []string{"fctap*"}}.Normalize()
	rules := Plan(spec)
	if err := NewBackend().Apply(rules); err != nil {
		t.Fatal(err)
	}
	var ops []uint16
	for _, m := range f.sent {
		if uint16(m.Header.Type)>>8 == unix.NFNL_SUBSYS_NFTABLES {
			ops = append(ops, msgOp(m))
		}
	}
	count := map[uint16]int{}
	for _, op := range ops {
		count[op]++
	}
	if count[unix.NFT_MSG_NEWTABLE] != 4 || count[unix.NFT_MSG_DELTABLE] != 2 || count[unix.NFT_MSG_NEWCHAIN] != 6 || count[unix.NFT_MSG_NEWRULE] != len(rules) {
		t.Fatalf("ops = %v", count)
	}
	// Each table: add, delete, add, before any of its chains.
	if ops[0] != unix.NFT_MSG_NEWTABLE || ops[1] != unix.NFT_MSG_DELTABLE || ops[2] != unix.NFT_MSG_NEWTABLE {
		t.Fatalf("first ops = %v", ops[:3])
	}
	comments := 0
	for _, m := range f.sent {
		if msgOp(m) == unix.NFT_MSG_NEWRULE && bytes.Contains(m.Data, []byte("aerolvm ipv6 fence:")) {
			comments++
		}
	}
	if comments != len(rules) {
		t.Fatalf("%d of %d rules carry the fence comment", comments, len(rules))
	}
}

func TestApplyErrors(t *testing.T) {
	f := &fakeDial{}
	f.install(t)
	if err := NewBackend().Apply([]Rule{{FamilyIP6, "prerouting", MatchIn, "x"}}); err == nil {
		t.Fatal("a rule for a chain the fence does not have was accepted")
	}
	if err := NewBackend().Apply([]Rule{{FamilyIP6, ChainInput, "ether", "x"}}); err == nil {
		t.Fatal("an unknown match was accepted")
	}
	f.err = errors.New("netlink: operation not permitted")
	if err := NewBackend().Apply(nil); err == nil {
		t.Fatal("a refused batch must fail Apply")
	}
	orig := newConn
	newConn = func() (*nftables.Conn, error) { return nil, errors.New("no netlink") }
	defer func() { newConn = orig }()
	if err := NewBackend().Apply(nil); err == nil {
		t.Fatal("Apply without netlink")
	}
	if _, err := NewBackend().Check(nil); err == nil {
		t.Fatal("Check without netlink")
	}
}

// fakeKernel answers check from chains and rules built the way Apply
// builds them.
type fakeKernel struct {
	chains   map[nftables.TableFamily][]*nftables.Chain
	rules    map[string][]*nftables.Rule // family/chain
	listErr  error
	rulesErr error
}

func famName(f nftables.TableFamily) string {
	if f == nftables.TableFamilyBridge {
		return FamilyBridge
	}
	return FamilyIP6
}

func (k *fakeKernel) ListChainsOfTableFamily(f nftables.TableFamily) ([]*nftables.Chain, error) {
	return k.chains[f], k.listErr
}

func (k *fakeKernel) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	return k.rules[famName(t.Family)+"/"+c.Name], k.rulesErr
}

func installedKernel(t *testing.T, rules []Rule) *fakeKernel {
	t.Helper()
	k := &fakeKernel{chains: map[nftables.TableFamily][]*nftables.Chain{}, rules: map[string][]*nftables.Rule{}}
	for _, fam := range families {
		tb := table(fam)
		// Another table's chain of the same name is not ours.
		k.chains[tb.Family] = append(k.chains[tb.Family], &nftables.Chain{Name: ChainInput, Table: &nftables.Table{Name: "filter", Family: tb.Family}})
		for _, name := range chainOrder {
			k.chains[tb.Family] = append(k.chains[tb.Family], chain(tb, name))
		}
	}
	for _, r := range rules {
		exprs, err := ruleExprs(r)
		if err != nil {
			t.Fatal(err)
		}
		key := r.Family + "/" + r.Chain
		k.rules[key] = append(k.rules[key], &nftables.Rule{Exprs: exprs, UserData: userdata.AppendString(nil, userdata.TypeComment, r.Comment())})
	}
	return k
}

func TestCheck(t *testing.T) {
	spec, _ := Spec{Bridges: []string{"cni0"}, Links: []string{"fctap*"}}.Normalize()
	rules := Plan(spec)

	ok, err := check(installedKernel(t, rules), rules, families)
	if err != nil || !ok {
		t.Fatalf("intact fence: ok=%v err=%v", ok, err)
	}

	for name, tamper := range map[string]func(k *fakeKernel){
		"tables flushed": func(k *fakeKernel) { k.chains = nil },
		"rule deleted": func(k *fakeKernel) {
			k.rules["bridge/forward"] = nil
		},
		"accept inserted above a drop": func(k *fakeKernel) {
			k.rules["ip6/input"] = append([]*nftables.Rule{{}}, k.rules["ip6/input"]...)
		},
		"rule rewritten": func(k *fakeKernel) {
			k.rules["ip6/output"][0].UserData = userdata.AppendString(nil, userdata.TypeComment, "something else")
		},
		"chain moved to another hook": func(k *fakeKernel) {
			for _, c := range k.chains[nftables.TableFamilyIPv6] {
				if c.Table.Name == TableName && c.Name == ChainInput {
					c.Hooknum = nftables.ChainHookPrerouting
				}
			}
		},
		"chain priority changed": func(k *fakeKernel) {
			for _, c := range k.chains[nftables.TableFamilyBridge] {
				if c.Table.Name == TableName && c.Name == ChainForward {
					c.Priority = nftables.ChainPriorityFilter
				}
			}
		},
		"chain lost its hook": func(k *fakeKernel) {
			for _, c := range k.chains[nftables.TableFamilyBridge] {
				if c.Table.Name == TableName && c.Name == ChainOutput {
					c.Hooknum = nil
				}
			}
		},
		"chain type changed": func(k *fakeKernel) {
			for _, c := range k.chains[nftables.TableFamilyIPv6] {
				if c.Table.Name == TableName && c.Name == ChainForward {
					c.Type = nftables.ChainTypeRoute
				}
			}
		},
		"chain policy changed": func(k *fakeKernel) {
			drop := nftables.ChainPolicyDrop
			for _, c := range k.chains[nftables.TableFamilyIPv6] {
				if c.Table.Name == TableName && c.Name == ChainOutput {
					c.Policy = &drop
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			k := installedKernel(t, rules)
			tamper(k)
			ok, err := check(k, rules, families)
			if err != nil || ok {
				t.Fatalf("tampered fence read as intact: ok=%v err=%v", ok, err)
			}
		})
	}

	k := installedKernel(t, rules)
	k.listErr = errors.New("netlink: no buffer space")
	if _, err := check(k, rules, families); err == nil {
		t.Fatal("a list error must surface")
	}
	k = installedKernel(t, rules)
	k.rulesErr = errors.New("netlink: interrupted")
	if _, err := check(k, rules, families); err == nil {
		t.Fatal("a rules error must surface")
	}
	// A kernel that reports no type or policy (older kernels) still matches.
	k = installedKernel(t, rules)
	for _, cs := range k.chains {
		for _, c := range cs {
			c.Type, c.Policy = "", nil
		}
	}
	if ok, err := check(k, rules, families); err != nil || !ok {
		t.Fatalf("chains without type/policy: ok=%v err=%v", ok, err)
	}
}

func TestCheckRealConnFakeDial(t *testing.T) {
	// Check over the netlink path: an empty kernel reads as missing.
	f := &emptyDumpDial{}
	orig := newConn
	newConn = func() (*nftables.Conn, error) { return nftables.New(nftables.WithTestDial(f.dial)) }
	defer func() { newConn = orig }()
	ok, err := NewBackend().Check(Plan(Spec{Links: []string{"fctap*"}}))
	if err != nil || ok {
		t.Fatalf("empty kernel: ok=%v err=%v", ok, err)
	}
}

// emptyDumpDial answers every dump with nothing.
type emptyDumpDial struct{}

func (emptyDumpDial) dial(req []netlink.Message) ([]netlink.Message, error) {
	if len(req) == 1 && req[0].Header.Flags&netlink.Dump != 0 {
		return []netlink.Message{{Header: netlink.Header{Type: netlink.Done, Flags: netlink.Multi, Sequence: req[0].Header.Sequence}}}, nil
	}
	return nil, io.EOF
}

// bridgeRefusingDial acks every batch that touches only the ip6 family and
// refuses one with a bridge-family message: a kernel without nft bridge
// metadata support.
type bridgeRefusingDial struct {
	fakeDial
	refusals int
}

func (f *bridgeRefusingDial) dial(req []netlink.Message) ([]netlink.Message, error) {
	for _, m := range req {
		if uint16(m.Header.Type)>>8 == unix.NFNL_SUBSYS_NFTABLES && len(m.Data) > 0 && m.Data[0] == unix.NFPROTO_BRIDGE {
			f.refusals++
			return nil, errors.New("netlink receive: operation not supported")
		}
	}
	return f.fakeDial.dial(req)
}

func brNF(t *testing.T, value string, ensureErr error) {
	t.Helper()
	path := t.TempDir() + "/bridge-nf-call-ip6tables"
	origPath, origEnsure := bridgeNFCallIP6Tables, ensureBridgeNetfilter
	bridgeNFCallIP6Tables = path
	ensureBridgeNetfilter = func() error {
		if ensureErr != nil {
			return ensureErr
		}
		return os.WriteFile(path, []byte(value+"\n"), 0o644)
	}
	t.Cleanup(func() { bridgeNFCallIP6Tables, ensureBridgeNetfilter = origPath, origEnsure })
}

// TestApplyFallsBackToIP6WithBrNetfilter: a kernel that refuses the
// bridge-family table still gets the ip6 table, and bridged frames are
// sent through it by br_netfilter, which Apply turns on.
func TestApplyFallsBackToIP6WithBrNetfilter(t *testing.T) {
	f := &bridgeRefusingDial{}
	orig := newConn
	newConn = func() (*nftables.Conn, error) { return nftables.New(nftables.WithTestDial(f.dial)) }
	t.Cleanup(func() { newConn = orig })
	brNF(t, "1", nil)

	be := &NFTBackend{}
	spec, _ := Spec{Bridges: []string{"aerolvm0"}}.Normalize()
	rules := Plan(spec)
	if err := be.Apply(rules); err != nil {
		t.Fatal(err)
	}
	if f.refusals != 1 || be.bridgeLayer.Load() || !strings.Contains(be.Layers(), "br_netfilter") {
		t.Fatalf("refusals=%d bridgeLayer=%v layers=%q", f.refusals, be.bridgeLayer.Load(), be.Layers())
	}
	ip6Rules := 0
	for _, m := range f.sent {
		if msgOp(m) == unix.NFT_MSG_NEWRULE {
			if m.Data[0] != unix.NFPROTO_IPV6 {
				t.Fatalf("fallback sent a rule for family %d", m.Data[0])
			}
			ip6Rules++
		}
	}
	if ip6Rules != len(onlyFamily(rules, FamilyIP6)) {
		t.Fatalf("fallback sent %d ip6 rules, want %d", ip6Rules, len(onlyFamily(rules, FamilyIP6)))
	}
	// Check in fallback reads only the ip6 table (an empty kernel here) and
	// first that br_netfilter is still on.
	newConn = func() (*nftables.Conn, error) { return nftables.New(nftables.WithTestDial(emptyDumpDial{}.dial)) }
	if ok, err := be.Check(rules); ok || err != nil {
		t.Fatalf("Check on an empty kernel = %v, %v", ok, err)
	}
	if err := os.WriteFile(bridgeNFCallIP6Tables, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, err := be.Check(rules); ok || err != nil {
		t.Fatalf("Check with br_netfilter off = %v, %v; want missing", ok, err)
	}
}

func TestApplyFallbackFailures(t *testing.T) {
	f := &bridgeRefusingDial{}
	orig := newConn
	newConn = func() (*nftables.Conn, error) { return nftables.New(nftables.WithTestDial(f.dial)) }
	t.Cleanup(func() { newConn = orig })
	rules := Plan(Spec{Bridges: []string{"cni0"}})

	brNF(t, "1", errors.New("modprobe br_netfilter: not found"))
	if err := (&NFTBackend{}).Apply(rules); err == nil || !strings.Contains(err.Error(), "br_netfilter is off") {
		t.Fatalf("no br_netfilter = %v", err)
	}
	brNF(t, "0", nil)
	if err := (&NFTBackend{}).Apply(rules); err == nil || !strings.Contains(err.Error(), "is not 1") {
		t.Fatalf("bridge-nf-call-ip6tables stuck at 0 = %v", err)
	}
	f.err = errors.New("netlink: permission denied")
	if err := (&NFTBackend{}).Apply(rules); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("both batches refused = %v", err)
	}
}

func TestLayersFull(t *testing.T) {
	f := &fakeDial{}
	f.install(t)
	be := &NFTBackend{}
	if err := be.Apply(Plan(Spec{Bridges: []string{"docker0"}})); err != nil {
		t.Fatal(err)
	}
	if be.Layers() != "bridge+ip6" {
		t.Fatalf("Layers = %q", be.Layers())
	}
}
