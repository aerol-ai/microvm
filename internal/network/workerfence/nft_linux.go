//go:build linux

package workerfence

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// priority runs the chain after conntrack (raw -300, conntrack -200,
// filter 0), so a rule can ask whether a packet replies on a connection
// someone else opened (ct direction reply): that is how a worker answers
// root's connections to its guest's listeners while it may open none to
// loopback itself. A drop is final whatever another chain on the hook
// says.
//
// A NOTRACK rule for loopback (a raw chain "notrack" on lo) leaves those
// packets without a direction, so the reply rule does not match and the
// drop below it does: guest listeners then fail closed (unreachable), never
// open. The exceptions match the packet as sent at this priority, which is
// after destination NAT; KindAllowNAT covers a resolver a NAT rule
// redirects (Docker's embedded DNS).
var priority = nftables.ChainPriorityFilter

// newConn opens one netlink connection per call. Tests replace it with a
// connection whose TestDial never touches the kernel.
var newConn = func() (*nftables.Conn, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables conn: %w", err)
	}
	return c, nil
}

// NFTBackend drives the inet TableName table over netlink.
type NFTBackend struct{}

// NewBackend returns the netlink backend.
func NewBackend() Backend { return NFTBackend{} }

func table() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
}

func chain(t *nftables.Table) *nftables.Chain {
	accept := nftables.ChainPolicyAccept
	return &nftables.Chain{
		Name:     ChainName,
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: priority,
		Policy:   &accept,
	}
}

// Values the rules compare against.
const (
	ctDirOriginal = 0      // IP_CT_DIR_ORIGINAL
	ctDirReply    = 1      // IP_CT_DIR_REPLY
	ipsDstNAT     = 1 << 5 // IPS_DST_NAT in ct status
	rtnLocal      = 2      // RTN_LOCAL, a fib address type
	rtnBroadcast  = 3      // RTN_BROADCAST
)

// ruleExprs is, for one rule (every rule starts with meta skuid <uid>: the
// uid of the process that made the socket the packet leaves from, which is
// why sandboxd never hands a worker a socket of its own):
//
//	KindDrop:          meta nfproto <f> <ip|ip6> daddr <prefix> counter drop
//	KindReply:         meta nfproto ipv4 ct direction reply ip saddr <from> ip daddr <prefix> counter accept
//	KindAllow:         meta nfproto <f> meta l4proto <p> <ip|ip6> daddr <addr> th dport <lo>[-<hi>] counter accept
//	KindAllowNAT:      meta nfproto <f> meta l4proto <p> ct status dnat ct original daddr <addr> ct original proto-dst <lo>[-<hi>] counter accept
//	KindLocalPort:     meta l4proto tcp fib daddr type local th dport <port> counter accept
//	KindLocalDrop:     fib daddr type local counter drop
//	KindBroadcastDrop: fib daddr type broadcast counter drop
func ruleExprs(r Rule) ([]expr.Any, error) {
	if r.UID <= 0 {
		return nil, fmt.Errorf("rule %q: no uid", r.Comment())
	}
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(r.UID))},
	}
	verdict := expr.VerdictDrop
	if r.Accepts() {
		verdict = expr.VerdictAccept
	}
	tail := []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: verdict}}
	switch r.Kind {
	case KindLocalDrop:
		return append(append(exprs, fibTypeExprs(rtnLocal)...), tail...), nil
	case KindBroadcastDrop:
		return append(append(exprs, fibTypeExprs(rtnBroadcast)...), tail...), nil
	case KindLocalPort:
		if r.PortLo == 0 {
			return nil, fmt.Errorf("rule %q: port", r.Comment())
		}
		exprs = append(exprs, l4Exprs("tcp")...)
		exprs = append(exprs, fibTypeExprs(rtnLocal)...)
		exprs = append(exprs, portExprs(r.PortLo, r.PortLo)...)
		return append(exprs, tail...), nil
	case KindDrop, KindReply, KindAllow, KindAllowNAT:
	default:
		return nil, fmt.Errorf("rule %q: kind %d", r.Comment(), r.Kind)
	}
	if !r.Prefix.IsValid() {
		return nil, fmt.Errorf("rule %q: no destination", r.Comment())
	}
	p := r.Prefix.Masked()
	family, offset := byte(unix.NFPROTO_IPV4), uint32(16)
	if p.Addr().Is6() {
		family, offset = unix.NFPROTO_IPV6, 24
	}
	if (r.Kind == KindAllow || r.Kind == KindAllowNAT) && (r.PortLo == 0 || r.PortHi < r.PortLo) {
		return nil, fmt.Errorf("rule %q: ports", r.Comment())
	}
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
	)
	switch r.Kind {
	case KindReply:
		if !r.From.Is4() || family != unix.NFPROTO_IPV4 {
			return nil, fmt.Errorf("rule %q: a reply rule needs an IPv4 source and destination", r.Comment())
		}
		from := r.From.As4()
		exprs = append(exprs,
			&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{ctDirReply}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: from[:]},
		)
	case KindAllow, KindAllowNAT:
		l4 := l4Exprs(r.Proto)
		if l4 == nil {
			return nil, fmt.Errorf("rule %q: protocol %q", r.Comment(), r.Proto)
		}
		exprs = append(exprs, l4...)
		if r.Kind == KindAllowNAT {
			return append(append(exprs, natOriginalExprs(p, r.PortLo, r.PortHi)...), tail...), nil
		}
	}
	addr := p.Addr().AsSlice()
	exprs = append(exprs, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(addr))})
	if p.Bits() < len(addr)*8 {
		exprs = append(exprs, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(addr)), Mask: mask(p), Xor: make([]byte, len(addr))})
	}
	exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr})
	if r.Kind == KindAllow {
		exprs = append(exprs, portExprs(r.PortLo, r.PortHi)...)
	}
	return append(exprs, tail...), nil
}

// natOriginalExprs matches a connection a NAT rule changed (ct status
// dnat) whose original destination, before NAT, was the one address p on
// lo..hi. In an inet table the conntrack address loads 16 bytes, an IPv4
// one in the first 4 (the rest zero): the compare reads only the
// address's own bytes, which is also how nft writes the rule, so nft
// prints it (nft's own printer overruns on a 16-byte IPv4 compare).
func natOriginalExprs(p netip.Prefix, lo, hi uint16) []expr.Any {
	out := []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATUS},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(ipsDstNAT), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
		&expr.Ct{Register: 1, Key: expr.CtKeyDST, Direction: ctDirOriginal},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Addr().AsSlice()},
		&expr.Ct{Register: 1, Key: expr.CtKeyPROTODST, Direction: ctDirOriginal},
	}
	if lo == hi {
		return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(lo)})
	}
	return append(out,
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(lo)},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(hi)},
	)
}

// l4Exprs matches the transport protocol; nil for one the fence does not
// know.
func l4Exprs(proto string) []expr.Any {
	p := map[string]byte{"tcp": unix.IPPROTO_TCP, "udp": unix.IPPROTO_UDP}[proto]
	if p == 0 {
		return nil
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{p}},
	}
}

// fibTypeExprs matches a destination of the given address type (one of
// the node's own addresses, or one of its broadcast addresses), as the
// kernel's routing tables say now.
func fibTypeExprs(rtn uint32) []expr.Any {
	return []expr.Any{
		&expr.Fib{Register: 1, FlagDADDR: true, ResultADDRTYPE: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(rtn)},
	}
}

// portExprs matches the destination port, lo to hi.
func portExprs(lo, hi uint16) []expr.Any {
	out := []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}}
	if lo == hi {
		return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(lo)})
	}
	return append(out,
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(lo)},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(hi)},
	)
}

// mask is p's netmask in bytes.
func mask(p netip.Prefix) []byte {
	n := p.Addr().BitLen() / 8
	out := make([]byte, n)
	for i, bits := 0, p.Bits(); i < n && bits > 0; i++ {
		if bits >= 8 {
			out[i], bits = 0xff, bits-8
			continue
		}
		out[i], bits = byte(0xff<<(8-bits)), 0
	}
	return out
}

// Apply implements Backend: the table replaced with rules in one batch
// (add, delete, add: the first add makes the delete safe when the table is
// not there yet), so the uid is never left without the fence mid-change.
func (NFTBackend) Apply(rules []Rule) error {
	c, err := newConn()
	if err != nil {
		return err
	}
	t := table()
	c.AddTable(t)
	c.DelTable(t)
	c.AddTable(t)
	ch := c.AddChain(chain(t))
	for _, r := range rules {
		exprs, err := ruleExprs(r)
		if err != nil {
			return err
		}
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: exprs, UserData: userdata.AppendString(nil, userdata.TypeComment, r.Comment())})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// kernelReader is what Check reads: the inet chains, and the comments of
// the fence chain's rules in order. Tests hand check a fake kernel.
type kernelReader interface {
	ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error)
	RuleComments() ([]string, error)
}

// nftReader reads chains through the nftables library and rule comments
// straight off a netlink rule dump: the library cannot read back a ct
// expression with a direction (the kernel writes the direction as one
// byte, the library wants four), and the comments are all Check compares.
type nftReader struct {
	*nftables.Conn
	dump func(netlink.Message) ([]netlink.Message, error)
}

func (r nftReader) RuleComments() ([]string, error) {
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: append([]byte(TableName), 0)},
		{Type: unix.NFTA_RULE_CHAIN, Data: append([]byte(ChainName), 0)},
	})
	if err != nil {
		return nil, err
	}
	msgs, err := r.dump(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETRULE), Flags: netlink.Request | netlink.Dump},
		Data:   append([]byte{unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0}, attrs...),
	})
	if err != nil {
		return nil, err
	}
	return parseRuleComments(msgs)
}

// parseRuleComments takes each rule's comment out of a rule dump, keeping
// only the fence chain's rules (an older kernel may not filter the dump).
func parseRuleComments(msgs []netlink.Message) ([]string, error) {
	var out []string
	for _, m := range msgs {
		if len(m.Data) < 4 {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[4:])
		if err != nil {
			return nil, err
		}
		var tbl, ch, comment string
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_RULE_TABLE:
				tbl = ad.String()
			case unix.NFTA_RULE_CHAIN:
				ch = ad.String()
			case unix.NFTA_RULE_USERDATA:
				comment, _ = userdata.GetString(ad.Bytes(), userdata.TypeComment)
			}
		}
		if err := ad.Err(); err != nil {
			return nil, err
		}
		if tbl == TableName && ch == ChainName {
			out = append(out, comment)
		}
	}
	return out, nil
}

// dialDump runs one netlink dump on a netfilter socket of its own.
var dialDump = func(req netlink.Message) ([]netlink.Message, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Execute(req)
}

// Check implements Backend: the chain on its hook and priority, holding
// rules in order (by their comments).
func (NFTBackend) Check(rules []Rule) (bool, error) {
	c, err := newConn()
	if err != nil {
		return false, err
	}
	return check(nftReader{Conn: c, dump: dialDump}, rules)
}

func check(c kernelReader, rules []Rule) (bool, error) {
	listed, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, fmt.Errorf("list chains: %w", err)
	}
	var got *nftables.Chain
	for _, ch := range listed {
		if ch.Table != nil && ch.Table.Name == TableName && ch.Name == ChainName {
			got = ch
		}
	}
	want := chain(table())
	if got == nil || got.Hooknum == nil || got.Priority == nil || *got.Hooknum != *want.Hooknum || *got.Priority != *want.Priority ||
		got.Policy != nil && *got.Policy != *want.Policy {
		return false, nil
	}
	kernel, err := c.RuleComments()
	if err != nil {
		return false, fmt.Errorf("list rules: %w", err)
	}
	if len(kernel) != len(rules) {
		return false, nil
	}
	for i, comment := range kernel {
		if comment != rules[i].Comment() {
			return false, nil
		}
	}
	return true, nil
}

// Remove implements Backend: the table goes, and the fence with it. A
// table that is not there is not an error.
func (NFTBackend) Remove() error {
	c, err := newConn()
	if err != nil {
		return err
	}
	t := table()
	c.AddTable(t)
	c.DelTable(t)
	if err := c.Flush(); err != nil {
		return fmt.Errorf("remove: %w", err)
	}
	return nil
}
