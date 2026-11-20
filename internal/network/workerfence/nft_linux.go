//go:build linux

package workerfence

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
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
	ctDirReply = 1      // IP_CT_DIR_REPLY
	ipsDstNAT  = 1 << 5 // IPS_DST_NAT in ct status
	rtnLocal   = 2      // RTN_LOCAL, a fib address type
)

// ruleExprs is, for one rule (every rule starts with meta skuid <uid>: the
// uid of the socket that sent the packet, which every packet a process
// sends from its own sockets carries on the output hook):
//
//	KindDrop:      meta nfproto <f> <ip|ip6> daddr <prefix> counter drop
//	KindReply:     meta nfproto <f> ct direction reply <ip|ip6> daddr <prefix> counter accept
//	KindAllow:     meta nfproto <f> meta l4proto <p> <ip|ip6> daddr <addr> th dport <lo>[-<hi>] counter accept
//	KindAllowNAT:  meta nfproto <f> meta l4proto <p> ct status dnat <ip|ip6> daddr <addr> counter accept
//	KindLocalPort: meta l4proto tcp fib daddr type local th dport <port> counter accept
//	KindLocalDrop: fib daddr type local counter drop
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
		return append(append(exprs, localExprs()...), tail...), nil
	case KindLocalPort:
		if r.PortLo == 0 {
			return nil, fmt.Errorf("rule %q: port", r.Comment())
		}
		exprs = append(exprs, l4Exprs("tcp")...)
		exprs = append(exprs, localExprs()...)
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
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
	)
	switch r.Kind {
	case KindReply:
		exprs = append(exprs,
			&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{ctDirReply}},
		)
	case KindAllow, KindAllowNAT:
		l4 := l4Exprs(r.Proto)
		if l4 == nil {
			return nil, fmt.Errorf("rule %q: protocol %q", r.Comment(), r.Proto)
		}
		exprs = append(exprs, l4...)
		if r.Kind == KindAllowNAT {
			exprs = append(exprs,
				&expr.Ct{Register: 1, Key: expr.CtKeySTATUS},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
					Mask: binaryutil.NativeEndian.PutUint32(ipsDstNAT), Xor: make([]byte, 4)},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
			)
		}
	}
	addr := p.Addr().AsSlice()
	exprs = append(exprs, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(addr))})
	if p.Bits() < len(addr)*8 {
		exprs = append(exprs, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(addr)), Mask: mask(p), Xor: make([]byte, len(addr))})
	}
	exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr})
	if r.Kind == KindAllow {
		if r.PortLo == 0 || r.PortHi < r.PortLo {
			return nil, fmt.Errorf("rule %q: ports", r.Comment())
		}
		exprs = append(exprs, portExprs(r.PortLo, r.PortHi)...)
	}
	return append(exprs, tail...), nil
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

// localExprs matches a destination that is one of the node's own
// addresses, as the kernel's routing tables say now.
func localExprs() []expr.Any {
	return []expr.Any{
		&expr.Fib{Register: 1, FlagDADDR: true, ResultADDRTYPE: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(rtnLocal)},
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

// kernelReader is the slice of *nftables.Conn Check reads with; tests hand
// check a fake kernel.
type kernelReader interface {
	ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error)
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)
}

// Check implements Backend: the chain on its hook and priority, holding
// rules in order (by their comments).
func (NFTBackend) Check(rules []Rule) (bool, error) {
	c, err := newConn()
	if err != nil {
		return false, err
	}
	return check(c, rules)
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
	kernel, err := c.GetRules(table(), got)
	if err != nil {
		return false, fmt.Errorf("list rules: %w", err)
	}
	if len(kernel) != len(rules) {
		return false, nil
	}
	for i, r := range kernel {
		if comment, _ := userdata.GetString(r.UserData, userdata.TypeComment); comment != rules[i].Comment() {
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
