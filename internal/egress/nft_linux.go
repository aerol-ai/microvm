//go:build linux

package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TableName is the gateway's own table. It never touches DOCKER-USER,
// AEROLVM-USER or AEROLVM-INPUT (§5.2).
const TableName = "aerolvm_egress"

// layoutVersion is bumped whenever the static layout changes. A table carrying
// another version's marker is replaced in one transaction.
const layoutVersion = 1

// Dynamic flow sets are sized explicitly so a full set is a known state (S10).
const (
	flowSetSize   = 65536
	flowSetTTL    = 2 * time.Minute
	meterTTL      = 10 * time.Second
	meterRate     = 20
	meterBurst    = 100
	chainPrioNAT  = -110 // dstnat - 10
	chainPrioFilt = -10  // filter - 10
)

// 32-bit registers for concatenated set keys (each field padded to 4 bytes).
const (
	reg1    = 1 // NFT_REG_1, aliases NFT_REG32_00
	reg32_1 = 9 // NFT_REG32_01
	reg32_2 = 10
)

type setDef struct {
	name     string
	key      nftables.SetDatatype
	interval bool
	timeout  bool
	dynamic  bool
	size     uint32
	concat   bool
}

var setDefs = []setDef{
	{name: SetFQDNSrc, key: nftables.TypeIPAddr},
	{name: SetSrcDenyDefault, key: nftables.TypeIPAddr},
	{name: SetSrcAccept, key: nftables.TypeIPAddr},
	{name: SetLearnSrc, key: nftables.TypeIPAddr},
	{name: SetBlockedSrc, key: nftables.TypeIPAddr},
	{name: SetAllowCIDR, key: nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeIPAddr), interval: true, concat: true},
	{name: SetDenyCIDR, key: nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeIPAddr), interval: true, concat: true},
	{name: SetDenyFloor, key: nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeIPAddr), interval: true, concat: true},
	{name: SetNodeControl, key: nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeInetService), concat: true},
	{name: SetAllowLearned, key: nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeIPAddr, nftables.TypeInetService), timeout: true, concat: true},
	{name: SetLearnFlows, key: nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeIPAddr, nftables.TypeInetService), timeout: true, dynamic: true, size: flowSetSize, concat: true},
	{name: SetRejectedFlows, key: nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeIPAddr, nftables.TypeInetService), timeout: true, dynamic: true, size: flowSetSize, concat: true},
	{name: setRejectMeter, key: nftables.TypeIPAddr, timeout: true, dynamic: true, size: flowSetSize},
}

const setRejectMeter = "reject_meter"

func markerSetName(cfg LayoutConfig) string {
	return fmt.Sprintf("layout_v%d_%d_%d_%d", layoutVersion, cfg.DNSPort, cfg.ProxyPort, flowSize(cfg))
}

func flowSize(cfg LayoutConfig) uint32 {
	if cfg.FlowSetSize == 0 {
		return flowSetSize
	}
	return cfg.FlowSetSize
}

// NFTBackend drives the inet aerolvm_egress table over netlink. Every call is
// one transaction on its own connection (no shared Conn, no global mutex: the
// 348b21f3 lesson, D18).
type NFTBackend struct {
	table *nftables.Table
	sets  map[string]*nftables.Set
}

// NewNFTBackend returns the netlink backend.
func NewNFTBackend() *NFTBackend {
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	b := &NFTBackend{table: t, sets: map[string]*nftables.Set{}}
	for _, d := range setDefs {
		b.sets[d.name] = d.build(t)
	}
	return b
}

func (d setDef) build(t *nftables.Table) *nftables.Set {
	s := &nftables.Set{
		Table:         t,
		Name:          d.name,
		KeyType:       d.key,
		Interval:      d.interval,
		HasTimeout:    d.timeout,
		Dynamic:       d.dynamic,
		Concatenation: d.concat,
		Size:          d.size,
	}
	switch d.name {
	case SetLearnFlows, SetRejectedFlows:
		s.Timeout = flowSetTTL
	case setRejectMeter:
		s.Timeout = meterTTL
	}
	return s
}

func newConn() (*nftables.Conn, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables conn: %w", err)
	}
	return c, nil
}

// EnsureLayout implements Backend.
func (b *NFTBackend) EnsureLayout(cfg LayoutConfig) error {
	c, err := newConn()
	if err != nil {
		return err
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	exists := false
	for _, t := range tables {
		if t.Name == TableName {
			exists = true
		}
	}
	if exists {
		if _, err := c.GetSetByName(b.table, markerSetName(cfg)); err == nil {
			return nil // matching layout: keep set contents (D13)
		}
		// Another version: replace it in the same transaction, so the
		// sandboxes never see a table-less window (layout changes are always
		// one batch).
		c.DelTable(b.table)
	}
	c.AddTable(b.table)
	if err := c.AddSet(&nftables.Set{Table: b.table, Name: markerSetName(cfg), KeyType: nftables.TypeIPAddr}, nil); err != nil {
		return fmt.Errorf("add marker set: %w", err)
	}
	for _, d := range setDefs {
		set := b.sets[d.name]
		if d.dynamic {
			set.Size = flowSize(cfg)
		}
		if err := c.AddSet(set, nil); err != nil {
			return fmt.Errorf("add set %s: %w", d.name, err)
		}
	}
	b.addChains(c, cfg)
	if err := c.Flush(); err != nil {
		return fmt.Errorf("create egress layout: %w", err)
	}
	return nil
}

// CheckLayout implements Backend: the table, its marker, every set and the
// three base chains must exist.
func (b *NFTBackend) CheckLayout() error {
	c, err := newConn()
	if err != nil {
		return err
	}
	sets, err := c.GetSets(b.table)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLayoutMissing, err)
	}
	have := map[string]bool{}
	for _, s := range sets {
		have[s.Name] = true
	}
	for _, d := range setDefs {
		if !have[d.name] {
			return fmt.Errorf("%w: set %s", ErrLayoutMissing, d.name)
		}
	}
	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLayoutMissing, err)
	}
	want := map[string]bool{"prerouting": false, "forward": false, "input": false}
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == TableName {
			if _, ok := want[ch.Name]; ok {
				want[ch.Name] = true
			}
		}
	}
	for name, ok := range want {
		if !ok {
			return fmt.Errorf("%w: chain %s", ErrLayoutMissing, name)
		}
	}
	return nil
}

// Apply implements Backend.
func (b *NFTBackend) Apply(ops []Op) error {
	c, err := newConn()
	if err != nil {
		return err
	}
	for _, op := range ops {
		s, ok := b.sets[op.Set]
		if !ok {
			return fmt.Errorf("egress: unknown set %q", op.Set)
		}
		elems, err := encodeElems(op.Set, op.Elems)
		if err != nil {
			return err
		}
		if op.Del {
			err = c.SetDeleteElements(s, elems)
		} else {
			err = c.SetAddElements(s, elems)
		}
		if err != nil {
			return fmt.Errorf("queue %s: %w", op.Set, err)
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("egress apply: %w", err)
	}
	return nil
}

// Replace implements Backend: flush and re-add each set in one transaction.
func (b *NFTBackend) Replace(contents map[string][]Elem) error {
	c, err := newConn()
	if err != nil {
		return err
	}
	for name, list := range contents {
		s, ok := b.sets[name]
		if !ok {
			return fmt.Errorf("egress: unknown set %q", name)
		}
		c.FlushSet(s)
		if len(list) == 0 {
			continue
		}
		elems, err := encodeElems(name, list)
		if err != nil {
			return err
		}
		if err := c.SetAddElements(s, elems); err != nil {
			return fmt.Errorf("queue %s: %w", name, err)
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("egress replace: %w", err)
	}
	return nil
}

// List implements Backend.
func (b *NFTBackend) List(name string) ([]Elem, error) {
	s, ok := b.sets[name]
	if !ok {
		return nil, fmt.Errorf("egress: unknown set %q", name)
	}
	c, err := newConn()
	if err != nil {
		return nil, err
	}
	raw, err := c.GetSetElements(s)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", name, err)
	}
	return decodeElems(name, raw), nil
}

func ip4(a netip.Addr) []byte { v := a.As4(); return v[:] }

func port4(p uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, p)
	return b
}

func encodeElems(set string, list []Elem) ([]nftables.SetElement, error) {
	out := make([]nftables.SetElement, 0, len(list))
	for _, e := range list {
		if !e.Src.Is4() {
			return nil, fmt.Errorf("egress: %s element without IPv4 source", set)
		}
		var el nftables.SetElement
		switch set {
		case SetFQDNSrc, SetSrcDenyDefault, SetSrcAccept, SetLearnSrc, SetBlockedSrc:
			el.Key = ip4(e.Src)
		case SetAllowCIDR, SetDenyCIDR:
			end := e.DstEnd
			if !end.IsValid() {
				end = e.Dst
			}
			el.Key = append(ip4(e.Src), ip4(e.Dst)...)
			el.KeyEnd = append(ip4(e.Src), ip4(end)...)
		case SetAllowLearned, SetLearnFlows, SetRejectedFlows:
			el.Key = append(append(ip4(e.Src), ip4(e.Dst)...), port4(e.Port)...)
			el.Timeout = e.Timeout
		default:
			return nil, fmt.Errorf("egress: set %q has no element encoding", set)
		}
		out = append(out, el)
	}
	return out, nil
}

func addrAt(b []byte, off int) netip.Addr {
	if len(b) < off+4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte{b[off], b[off+1], b[off+2], b[off+3]})
}

func decodeElems(set string, raw []nftables.SetElement) []Elem {
	out := make([]Elem, 0, len(raw))
	for _, r := range raw {
		if r.IntervalEnd {
			continue
		}
		e := Elem{Src: addrAt(r.Key, 0)}
		switch set {
		case SetAllowCIDR, SetDenyCIDR:
			e.Dst = addrAt(r.Key, 4)
			e.DstEnd = addrAt(r.KeyEnd, 4)
		case SetAllowLearned, SetLearnFlows, SetRejectedFlows:
			e.Dst = addrAt(r.Key, 4)
			if len(r.Key) >= 10 {
				e.Port = binary.BigEndian.Uint16(r.Key[8:10])
			}
			e.Timeout = r.Expires
		}
		out = append(out, e)
	}
	return out
}

// ---- rule construction ----

func ipv4Only() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: reg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{unix.NFPROTO_IPV4}},
	}
}

func notIPv4Return() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: reg1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: reg1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Verdict{Kind: expr.VerdictReturn},
	}
}

func loadSaddr(reg uint32) expr.Any {
	return &expr.Payload{DestRegister: reg, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}
}

func loadDaddr(reg uint32) expr.Any {
	return &expr.Payload{DestRegister: reg, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}
}

func loadDport(reg uint32) expr.Any {
	return &expr.Payload{DestRegister: reg, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}
}

func saddrIn(set string) []expr.Any {
	return []expr.Any{loadSaddr(reg1), &expr.Lookup{SourceRegister: reg1, SetName: set}}
}

func saddrNotIn(set string) []expr.Any {
	return []expr.Any{loadSaddr(reg1), &expr.Lookup{SourceRegister: reg1, SetName: set, Invert: true}}
}

func pairIn(set string) []expr.Any {
	return []expr.Any{loadSaddr(reg1), loadDaddr(reg32_1), &expr.Lookup{SourceRegister: reg1, SetName: set}}
}

func l4proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: reg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{proto}},
	}
}

func dportEq(port uint16) []expr.Any {
	return []expr.Any{loadDport(reg1), &expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: binaryutil.BigEndian.PutUint16(port)}}
}

func flowKey() []expr.Any {
	return []expr.Any{loadSaddr(reg1), loadDaddr(reg32_1), loadDport(reg32_2)}
}

func ctEstablished() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: reg1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: reg1, DestRegister: reg1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:  binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: reg1, Data: []byte{0, 0, 0, 0}},
	}
}

func verdict(k expr.VerdictKind) expr.Any { return &expr.Verdict{Kind: k} }

func redirectTo(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: reg1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Redir{RegisterProtoMin: reg1},
	}
}

// auditThenReject returns the S10 pair for one deny condition: a verdict-less
// audit rule (per-source meter, then the rejected_flows insert) and the
// reject rule itself. A full dynamic set makes the audit rule break, which
// is harmless because the reject is a separate rule.
func auditThenReject(cond []expr.Any) [][]expr.Any {
	var rules [][]expr.Any
	for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		r := cat(cond, l4proto(proto),
			[]expr.Any{loadSaddr(reg1), &expr.Dynset{SrcRegKey: reg1, SetName: setRejectMeter, Operation: uint32(unix.NFT_DYNSET_OP_UPDATE),
				Exprs: []expr.Any{&expr.Limit{Type: expr.LimitTypePkts, Rate: meterRate, Unit: expr.LimitTimeSecond, Burst: meterBurst}}}},
			flowKey(),
			[]expr.Any{&expr.Dynset{SrcRegKey: reg1, SetName: SetRejectedFlows, Operation: uint32(unix.NFT_DYNSET_OP_UPDATE), Timeout: flowSetTTL}})
		rules = append(rules, r)
	}
	rules = append(rules,
		cat(cond, l4proto(unix.IPPROTO_TCP), []expr.Any{&expr.Counter{}, &expr.Reject{Type: unix.NFT_REJECT_TCP_RST}}),
		cat(cond, []expr.Any{&expr.Counter{}, &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED}}),
	)
	return rules
}

func cat(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func (b *NFTBackend) addChains(c *nftables.Conn, cfg LayoutConfig) {
	accept := nftables.ChainPolicyAccept
	pre := c.AddChain(&nftables.Chain{Name: "prerouting", Table: b.table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(chainPrioNAT), Policy: &accept})
	fwd := c.AddChain(&nftables.Chain{Name: "forward", Table: b.table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityRef(chainPrioFilt), Policy: &accept})
	in := c.AddChain(&nftables.Chain{Name: "input", Table: b.table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityRef(chainPrioFilt), Policy: &accept})

	add := func(ch *nftables.Chain, rules ...[]expr.Any) {
		for _, r := range rules {
			c.AddRule(&nftables.Rule{Table: b.table, Chain: ch, Exprs: r})
		}
	}
	tcp, udp := byte(unix.IPPROTO_TCP), byte(unix.IPPROTO_UDP)

	// prerouting: DNS first, so a CIDR-allowed resolver can't bypass the
	// filter; then CIDR-allowed destinations skip the proxy; then 80/443.
	add(pre,
		notIPv4Return(),
		cat(saddrNotIn(SetFQDNSrc), []expr.Any{verdict(expr.VerdictReturn)}),
		cat(l4proto(udp), dportEq(53), redirectTo(cfg.DNSPort)),
		cat(l4proto(tcp), dportEq(53), redirectTo(cfg.DNSPort)),
		cat(pairIn(SetAllowCIDR), []expr.Any{verdict(expr.VerdictAccept)}),
		cat(l4proto(tcp), dportEq(80), redirectTo(cfg.ProxyPort)),
		cat(l4proto(tcp), dportEq(443), redirectTo(cfg.ProxyPort)),
	)

	// forward: only gateway-mode sources are filtered here.
	add(fwd,
		notIPv4Return(),
		cat(saddrNotIn(SetFQDNSrc), []expr.Any{verdict(expr.VerdictReturn)}),
		cat(saddrIn(SetBlockedSrc), []expr.Any{&expr.Counter{}, verdict(expr.VerdictDrop)}),
		cat(pairIn(SetDenyFloor), []expr.Any{&expr.Counter{}, verdict(expr.VerdictDrop)}),
		cat(ctEstablished(), []expr.Any{verdict(expr.VerdictAccept)}),
	)
	add(fwd, auditThenReject(cat(l4proto(udp), dportEq(53)))...)
	add(fwd, auditThenReject(cat(l4proto(tcp), dportEq(53)))...)
	add(fwd, auditThenReject(cat(l4proto(udp), dportEq(443)))...)
	add(fwd, auditThenReject(cat(l4proto(tcp), dportEq(853)))...)
	for _, proto := range []byte{tcp, udp} {
		add(fwd, cat(saddrIn(SetLearnSrc), l4proto(proto), flowKey(),
			[]expr.Any{&expr.Dynset{SrcRegKey: reg1, SetName: SetLearnFlows, Operation: uint32(unix.NFT_DYNSET_OP_UPDATE), Timeout: flowSetTTL}}))
	}
	add(fwd,
		cat(saddrIn(SetLearnSrc), []expr.Any{verdict(expr.VerdictAccept)}),
		cat(pairIn(SetAllowCIDR), []expr.Any{verdict(expr.VerdictAccept)}),
	)
	for _, proto := range []byte{tcp, udp} {
		add(fwd, cat(l4proto(proto), flowKey(), []expr.Any{&expr.Lookup{SourceRegister: reg1, SetName: SetAllowLearned}, verdict(expr.VerdictAccept)}))
	}
	add(fwd, auditThenReject(pairIn(SetDenyCIDR))...)
	add(fwd, auditThenReject(saddrIn(SetSrcDenyDefault))...)

	// input: replies first, then blocked drop, then the redirected listeners,
	// then nothing else on the host from a gateway-mode source (D7), and the
	// listeners stay unreachable from any other source.
	add(in,
		notIPv4Return(),
		cat(ctEstablished(), []expr.Any{verdict(expr.VerdictAccept)}),
		cat(saddrIn(SetBlockedSrc), []expr.Any{&expr.Counter{}, verdict(expr.VerdictDrop)}),
		cat(saddrIn(SetFQDNSrc), l4proto(udp), dportEq(cfg.DNSPort), []expr.Any{verdict(expr.VerdictAccept)}),
		cat(saddrIn(SetFQDNSrc), l4proto(tcp), dportEq(cfg.DNSPort), []expr.Any{verdict(expr.VerdictAccept)}),
		cat(saddrIn(SetFQDNSrc), l4proto(tcp), dportEq(cfg.ProxyPort), []expr.Any{verdict(expr.VerdictAccept)}),
	)
	add(in, auditThenReject(saddrIn(SetFQDNSrc))...)
	add(in,
		cat(l4proto(udp), dportEq(cfg.DNSPort), []expr.Any{verdict(expr.VerdictDrop)}),
		cat(l4proto(tcp), dportEq(cfg.DNSPort), []expr.Any{verdict(expr.VerdictDrop)}),
		cat(l4proto(tcp), dportEq(cfg.ProxyPort), []expr.Any{verdict(expr.VerdictDrop)}),
	)
}

// NetlinkConntrack flushes conntrack entries by original source address.
type NetlinkConntrack struct{}

// FlushSource implements ConntrackFlusher.
func (NetlinkConntrack) FlushSource(ip netip.Addr) error {
	f := &netlink.ConntrackFilter{}
	if err := f.AddIP(netlink.ConntrackOrigSrcIP, net.IP(ip.AsSlice())); err != nil {
		return err
	}
	_, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, netlink.FAMILY_V4, f)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}
