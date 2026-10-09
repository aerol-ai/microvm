//go:build linux

package egress

import (
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func TestNFTSetsAndEncoding(t *testing.T) {
	cfg := LayoutConfig{DNSPort: 53054, ProxyPort: 15080, FlowSetSize: 128}
	if markerSetName(cfg) == markerSetName(LayoutConfig{}) {
		t.Fatal("marker must change with the ports and the flow-set size")
	}
	if flowSize(LayoutConfig{}) != flowSetSize || flowSize(cfg) != 128 {
		t.Fatal("flow size")
	}

	b := NewNFTBackend()
	if b.sets[SetLearnFlows].Timeout != flowSetTTL || b.sets[setRejectMeter].Timeout != meterTTL {
		t.Fatal("dynamic sets must carry their TTL")
	}
	if b.sets[SetAllowCIDR].Size != 0 || !b.sets[SetAllowCIDR].Interval {
		t.Fatal("cidr set shape")
	}

	src := netip.MustParseAddr("10.1.0.2")
	dst := netip.MustParseAddr("1.2.3.4")
	end := netip.MustParseAddr("1.2.3.255")
	srcRange := netip.MustParseAddr("10.1.0.255")
	cases := []struct {
		set  string
		elem Elem
	}{
		{SetFQDNSrc, Elem{Src: src}},
		{SetSrcDenyDefault, Elem{Src: src}},
		{SetSrcAccept, Elem{Src: src}},
		{SetLearnSrc, Elem{Src: src}},
		{SetBlockedSrc, Elem{Src: src}},
		{SetAllowCIDR, Elem{Src: src, Dst: dst, DstEnd: end}},
		{SetDenyCIDR, Elem{Src: src, SrcEnd: srcRange, Dst: dst}},
		{SetDenyFloor, Elem{Src: src, SrcEnd: srcRange, Dst: dst, DstEnd: end}},
		{SetNodeControl, Elem{Src: src, SrcEnd: srcRange, Dst: dst, Port: 443}},
		{SetAllowLearned, Elem{Src: src, Dst: dst, Port: 443, Timeout: time.Minute}},
		{SetBinLearned, Elem{Src: src, Dst: dst, Port: 80}},
		{SetLearnFlows, Elem{Src: src, Dst: dst, Port: 53}},
		{SetRejectedFlows, Elem{Src: src, Dst: dst, Port: 853}},
	}
	for _, c := range cases {
		els, err := encodeElems(c.set, []Elem{c.elem})
		if err != nil || len(els) != 1 || len(els[0].Key) == 0 {
			t.Fatalf("%s encode: %v %+v", c.set, err, els)
		}
		raw := els
		if c.elem.Timeout != 0 {
			if els[0].Timeout != c.elem.Timeout {
				t.Fatalf("%s timeout not encoded", c.set)
			}
			raw[0].Expires = c.elem.Timeout
		}
		got := decodeElems(c.set, append([]nftables.SetElement{{IntervalEnd: true, Key: els[0].Key}}, raw...))
		if len(got) != 1 || got[0].Src != src {
			t.Fatalf("%s decode = %+v", c.set, got)
		}
		if c.elem.Port != 0 && got[0].Port != c.elem.Port {
			t.Fatalf("%s port = %d", c.set, got[0].Port)
		}
		if c.elem.SrcEnd.IsValid() && got[0].SrcEnd != c.elem.SrcEnd {
			t.Fatalf("%s src end = %s", c.set, got[0].SrcEnd)
		}
	}

	if _, err := encodeElems(SetFQDNSrc, []Elem{{Src: netip.MustParseAddr("2001:db8::1")}}); err == nil {
		t.Fatal("IPv6 source must be rejected")
	}
	if _, err := encodeElems("no-such-set", []Elem{{Src: src}}); err == nil {
		t.Fatal("unknown set must be rejected")
	}
	if got := decodeElems(SetNodeControl, []nftables.SetElement{{Key: ip4(src)}}); got[0].Port != 0 || got[0].Dst.IsValid() {
		t.Fatalf("short node-control key = %+v", got)
	}
	if addrAt(nil, 0).IsValid() {
		t.Fatal("short key must not decode as an address")
	}
	if srcEnd(Elem{Src: src}) != src || srcEnd(Elem{Src: src, SrcEnd: srcRange}) != srcRange {
		t.Fatal("srcEnd")
	}
}

func TestNFTRuleBuilders(t *testing.T) {
	if len(ipv4Only()) != 2 || len(notIPv4Return()) != 3 {
		t.Fatal("proto guards")
	}
	if _, ok := loadSaddr(reg1).(*expr.Payload); !ok {
		t.Fatal("loadSaddr")
	}
	if _, ok := loadDaddr(reg32_1).(*expr.Payload); !ok {
		t.Fatal("loadDaddr")
	}
	if _, ok := loadDport(reg32_2).(*expr.Payload); !ok {
		t.Fatal("loadDport")
	}
	if len(saddrIn(SetFQDNSrc)) != 2 || len(saddrNotIn(SetFQDNSrc)) != 2 || len(pairIn(SetAllowCIDR)) != 3 {
		t.Fatal("lookups")
	}
	if len(l4proto(unix.IPPROTO_TCP)) != 2 || len(dportEq(443)) != 2 || len(flowKey()) != 3 || len(ctEstablished()) != 3 {
		t.Fatal("matches")
	}
	if _, ok := verdict(expr.VerdictDrop).(*expr.Verdict); !ok || len(redirectTo(15080)) != 2 {
		t.Fatal("verdicts")
	}
	rules := auditThenReject(saddrIn(SetBlockedSrc))
	if len(rules) != 4 {
		t.Fatalf("audit+reject rules = %d, want 4", len(rules))
	}
	if got := cat([]expr.Any{verdict(expr.VerdictAccept)}, nil, ipv4Only()); len(got) != 3 {
		t.Fatalf("cat = %d exprs", len(got))
	}

	// Rules are queued on the connection and sent only by Flush, so the
	// whole layout can be built without a netlink socket.
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	NewNFTBackend().addChains(c, LayoutConfig{DNSPort: 53054, ProxyPort: 15080})
}

// nftDialMode chooses what the fake kernel already contains. Dumps that
// the mode does not answer are empty, and every other message is acked,
// so none of this dials a real netlink socket.
type nftDialMode int

const (
	nftEmpty nftDialMode = iota
	nftTable
	nftMarker
	nftSets
	nftChains
	nftFail
)

func nftOp(m netlink.Message) uint16 { return uint16(m.Header.Type) & 0xff }

func nftGen(attrs []netlink.Attribute, kind uint16) netlink.Message {
	return netlink.Message{
		Header: netlink.Header{
			Type: netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | kind),
		},
		Data: append([]byte{unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0}, nltest.MustMarshalAttributes(attrs)...),
	}
}

// withDone marks a dump reply as multipart and trails it with NLMSG_DONE.
// nltest keeps that trailer for the next read, so it must not be one of the
// objects the caller parses. The sequence has to match the request or
// netlink rejects the reply.
func withDone(req netlink.Message, msgs []netlink.Message) []netlink.Message {
	for i := range msgs {
		msgs[i].Header.Flags |= netlink.Multi
		msgs[i].Header.Sequence = req.Header.Sequence
	}
	return append(msgs, netlink.Message{Header: netlink.Header{
		Type: netlink.Done, Flags: netlink.Multi, Sequence: req.Header.Sequence,
	}})
}

func (m nftDialMode) dial(req []netlink.Message) ([]netlink.Message, error) {
	if m == nftFail {
		return nil, errors.New("netlink down")
	}
	dump := len(req) == 1 && req[0].Header.Flags&netlink.Dump != 0
	if len(req) == 0 || dump {
		if !dump {
			return nil, io.EOF
		}
		switch nftOp(req[0]) {
		case unix.NFT_MSG_GETTABLE:
			if m != nftEmpty {
				return withDone(req[0], []netlink.Message{nftGen([]netlink.Attribute{
					{Type: unix.NFTA_TABLE_NAME, Data: append([]byte(TableName), 0)},
				}, unix.NFT_MSG_NEWTABLE)}), nil
			}
		case unix.NFT_MSG_GETSET:
			if m == nftSets || m == nftChains {
				msgs := make([]netlink.Message, 0, len(setDefs))
				for _, d := range setDefs {
					msgs = append(msgs, nftGen([]netlink.Attribute{
						{Type: unix.NFTA_SET_NAME, Data: append([]byte(d.name), 0)},
					}, unix.NFT_MSG_NEWSET))
				}
				return withDone(req[0], msgs), nil
			}
		case unix.NFT_MSG_GETCHAIN:
			if m == nftChains {
				msgs := make([]netlink.Message, 0, 3)
				for _, name := range []string{"prerouting", "forward", "input"} {
					msgs = append(msgs, nftGen([]netlink.Attribute{
						{Type: unix.NFTA_CHAIN_NAME, Data: append([]byte(name), 0)},
						{Type: unix.NFTA_TABLE_NAME, Data: append([]byte(TableName), 0)},
					}, unix.NFT_MSG_NEWCHAIN))
				}
				return withDone(req[0], msgs), nil
			}
		}
		return nil, io.EOF
	}
	if m == nftMarker && nftOp(req[0]) == unix.NFT_MSG_GETSET {
		msg := nftGen([]netlink.Attribute{
			{Type: unix.NFTA_SET_NAME, Data: append([]byte("marker"), 0)},
		}, unix.NFT_MSG_NEWSET)
		msg.Header.Sequence = req[0].Header.Sequence
		return []netlink.Message{msg}, nil
	}
	out := make([]netlink.Message, 0, len(req))
	for _, msg := range req {
		acks, err := nltest.Error(0, []netlink.Message{msg})
		if err != nil {
			return nil, err
		}
		out = append(out, acks...)
	}
	return out, nil
}

func useFakeNFT(t *testing.T, mode nftDialMode) {
	t.Helper()
	orig := newConn
	t.Cleanup(func() { newConn = orig })
	newConn = func() (*nftables.Conn, error) {
		return nftables.New(nftables.WithTestDial(mode.dial))
	}
}

func TestNFTBackendFakeNetlink(t *testing.T) {
	useFakeNFT(t, nftEmpty)
	b := NewNFTBackend()
	cfg := LayoutConfig{DNSPort: 53054, ProxyPort: 15080, FlowSetSize: 64}
	if err := b.EnsureLayout(cfg); err != nil {
		t.Fatal(err)
	}
	if err := b.CheckLayout(); !errors.Is(err, ErrLayoutMissing) {
		t.Fatalf("empty kernel CheckLayout = %v", err)
	}
	src := netip.MustParseAddr("10.9.0.2")
	if err := b.Apply([]Op{{Set: SetFQDNSrc, Elems: []Elem{{Src: src}}}}); err != nil {
		t.Fatal(err)
	}
	if err := b.Apply([]Op{{Set: SetFQDNSrc, Del: true, Elems: []Elem{{Src: src}}}}); err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Apply([]Op{{Set: "missing"}}); err == nil {
		t.Fatal("unknown set was applied")
	}
	if err := b.Apply([]Op{{Set: SetFQDNSrc, Elems: []Elem{{Src: netip.MustParseAddr("2001:db8::2")}}}}); err == nil {
		t.Fatal("IPv6 element was applied")
	}
	if err := b.Replace(map[string][]Elem{
		SetFQDNSrc:   {{Src: src}},
		SetAllowCIDR: nil,
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Replace(map[string][]Elem{"missing": nil}); err == nil {
		t.Fatal("unknown set was replaced")
	}
	if err := b.Replace(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.List("missing"); err == nil {
		t.Fatal("unknown set was listed")
	}
	if _, err := b.List(SetFQDNSrc); err != nil {
		t.Fatal(err)
	}

	orig := newConn
	newConn = func() (*nftables.Conn, error) { return nil, errors.New("no netlink") }
	if err := b.EnsureLayout(cfg); err == nil {
		t.Fatal("EnsureLayout without netlink")
	}
	if err := b.CheckLayout(); err == nil {
		t.Fatal("CheckLayout without netlink")
	}
	if err := b.Apply(nil); err == nil {
		t.Fatal("Apply without netlink")
	}
	if err := b.Replace(nil); err == nil {
		t.Fatal("Replace without netlink")
	}
	if _, err := b.List(SetFQDNSrc); err == nil {
		t.Fatal("List without netlink")
	}
	newConn = orig

	_ = (NetlinkConntrack{}).FlushSource(src)
	_ = (NetlinkConntrack{}).FlushSource(netip.MustParseAddr("2001:db8::3"))

	// The production opener never dials until a later call. Exercising it
	// here keeps that body covered on the unprivileged runner; the kernel
	// suite is not part of the coverage job.
	if _, err := orig(); err != nil {
		t.Fatal(err)
	}
}

func TestNFTLayoutAlreadyPresent(t *testing.T) {
	cfg := LayoutConfig{DNSPort: 53054, ProxyPort: 15080, FlowSetSize: 64}
	b := NewNFTBackend()

	useFakeNFT(t, nftTable)
	if err := b.EnsureLayout(cfg); err != nil {
		t.Fatal(err)
	}

	useFakeNFT(t, nftMarker)
	if err := b.EnsureLayout(cfg); err != nil {
		t.Fatalf("matching marker: %v", err)
	}

	useFakeNFT(t, nftSets)
	if err := b.EnsureLayout(cfg); err == nil {
		t.Fatal("a set whose key type changed must keep the old table")
	}
	if err := b.CheckLayout(); !errors.Is(err, ErrLayoutMissing) {
		t.Fatalf("sets without chains: %v", err)
	}

	useFakeNFT(t, nftChains)
	if err := b.CheckLayout(); err != nil {
		t.Fatal(err)
	}

	useFakeNFT(t, nftFail)
	if err := b.EnsureLayout(cfg); err == nil {
		t.Fatal("list tables")
	}
	if err := b.CheckLayout(); err == nil {
		t.Fatal("list sets")
	}
	if err := b.Apply([]Op{{Set: SetFQDNSrc, Elems: []Elem{{Src: netip.MustParseAddr("10.1.0.9")}}}}); err == nil {
		t.Fatal("flush")
	}
	if err := b.Replace(map[string][]Elem{SetFQDNSrc: {{Src: netip.MustParseAddr("10.1.0.9")}}}); err == nil {
		t.Fatal("replace flush")
	}
	if _, err := b.List(SetFQDNSrc); err == nil {
		t.Fatal("list elements")
	}
	c, err := nftables.New(nftables.WithTestDial(nftFail.dial))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.carriedElements(c); err == nil {
		t.Fatal("carried elements without a dump")
	}
}
