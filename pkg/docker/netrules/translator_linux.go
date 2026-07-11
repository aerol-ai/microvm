//go:build linux

package netrules

import (
	"fmt"
	"net"

	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

// exprsFromRulespec builds the nft expression list for a Manager rule shape.
// Address matches use native payload+cmp (iptables-nft stores the same for
// simple -s/-d); the comment uses the xt comment match so iptables -L still
// lists the tag that keeps selective egress disjoint from the blanket DROP.
// A counter expr precedes the verdict because iptables-nft puts one on every
// rule — emitting it keeps our rules byte-compatible with rules the exec
// backend created, so `iptables -D` can remove ours and (via the
// counter-insensitive match below) we can remove theirs after an operator
// flips SB_NETRULES_BACKEND.
func exprsFromRulespec(rulespec ...string) ([]expr.Any, error) {
	parsed, err := parseRulespec(rulespec...)
	if err != nil {
		return nil, err
	}
	var exprs []expr.Any
	if parsed.src != nil {
		exprs = append(exprs, ipv4MatchExprs(12, parsed.src)...)
	}
	if parsed.dst != nil {
		exprs = append(exprs, ipv4MatchExprs(16, parsed.dst)...)
	}
	if parsed.comment != "" {
		cmt := xt.Comment(parsed.comment)
		exprs = append(exprs, &expr.Match{
			Name: "comment",
			Rev:  0,
			Info: &cmt,
		})
	}
	var kind expr.VerdictKind
	switch parsed.verdict {
	case verdictDrop:
		kind = expr.VerdictDrop
	case verdictAccept:
		kind = expr.VerdictAccept
	default:
		return nil, fmt.Errorf("netrules: internal: unset verdict after parse")
	}
	exprs = append(exprs, &expr.Counter{}, &expr.Verdict{Kind: kind})
	return exprs, nil
}

// ipv4MatchExprs matches an IPv4 address/CIDR at the given network-header
// offset (12 = saddr, 16 = daddr). Host-bit-cleared network address + mask
// via Bitwise so /32 and wider CIDRs share one code path. Callers must feed
// it IPv4 only — parseAddrOrCIDR/v4Only guarantee that for every rulespec.
func ipv4MatchExprs(offset uint32, n *net.IPNet) []expr.Any {
	ip4 := n.IP.To4()
	mask := n.Mask
	if len(mask) != 4 {
		mask = net.CIDRMask(32, 32)
	}
	network := make([]byte, 4)
	for i := 0; i < 4; i++ {
		network[i] = ip4[i] & mask[i]
	}
	ones, _ := mask.Size()
	if ones == 32 {
		return []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          4,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     network,
			},
		}
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte(mask),
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     network,
		},
	}
}

// exprsEqualIgnoringCounters is the backend's rule-identity check: counters
// are runtime state (packet/byte totals), not identity, and their presence
// varies by author — iptables-nft always adds one, older netlink-backend
// builds never did. Stripping both sides lets Exists/Delete match rules
// created by either backend, which is what makes an in-place
// SB_NETRULES_BACKEND flip safe on iptables-nft hosts.
func exprsEqualIgnoringCounters(a, b []expr.Any) bool {
	return exprsEqual(stripCounters(a), stripCounters(b))
}

func stripCounters(exprs []expr.Any) []expr.Any {
	out := make([]expr.Any, 0, len(exprs))
	for _, e := range exprs {
		if _, ok := e.(*expr.Counter); ok {
			continue
		}
		out = append(out, e)
	}
	return out
}

// exprsEqual reports whether two expression lists are semantically equal for
// the Manager rule shapes we emit. Used by Exists against GetRules.
func exprsEqual(a, b []expr.Any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !exprEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func exprEqual(a, b expr.Any) bool {
	switch x := a.(type) {
	case *expr.Payload:
		y, ok := b.(*expr.Payload)
		return ok && x.DestRegister == y.DestRegister && x.Base == y.Base && x.Offset == y.Offset && x.Len == y.Len
	case *expr.Cmp:
		y, ok := b.(*expr.Cmp)
		return ok && x.Op == y.Op && x.Register == y.Register && bytesEqual(x.Data, y.Data)
	case *expr.Bitwise:
		y, ok := b.(*expr.Bitwise)
		return ok && x.SourceRegister == y.SourceRegister && x.DestRegister == y.DestRegister &&
			x.Len == y.Len && bytesEqual(x.Mask, y.Mask) && bytesEqual(x.Xor, y.Xor)
	case *expr.Verdict:
		y, ok := b.(*expr.Verdict)
		return ok && x.Kind == y.Kind
	case *expr.Match:
		y, ok := b.(*expr.Match)
		if !ok || x.Name != y.Name || x.Rev != y.Rev {
			return false
		}
		xc, xok := x.Info.(*xt.Comment)
		yc, yok := y.Info.(*xt.Comment)
		return xok && yok && *xc == *yc
	default:
		return false
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
