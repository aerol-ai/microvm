package netrules

import (
	"fmt"
	"net"
	"strings"
)

// verdictKind is a portable stand-in for expr.VerdictKind so rulespec
// parsing compiles off linux (google/nftables is linux-only via x/sys).
type verdictKind int

const (
	verdictUnset verdictKind = iota
	verdictDrop
	verdictAccept
)

// parsedRule is the Manager's iptables-shaped argv decoded into the fields
// the netlink backend needs. Only the shapes Manager emits are supported:
// -s/-d address-or-CIDR, optional -m comment --comment, and -j DROP|ACCEPT.
type parsedRule struct {
	src     *net.IPNet
	dst     *net.IPNet
	comment string
	verdict verdictKind
}

// parseRulespec translates iptables argv into a structured rule. Unknown
// tokens fail closed — better to refuse than install a silent no-op.
func parseRulespec(rulespec ...string) (parsedRule, error) {
	var out parsedRule
	out.verdict = verdictUnset
	for i := 0; i < len(rulespec); i++ {
		tok := rulespec[i]
		need := func(flag string) (string, error) {
			if i+1 >= len(rulespec) {
				return "", fmt.Errorf("netrules: %s missing value", flag)
			}
			i++
			return rulespec[i], nil
		}
		switch tok {
		case "-s":
			v, err := need("-s")
			if err != nil {
				return parsedRule{}, err
			}
			n, err := parseAddrOrCIDR(v)
			if err != nil {
				return parsedRule{}, fmt.Errorf("netrules: -s %q: %w", v, err)
			}
			out.src = n
		case "-d":
			v, err := need("-d")
			if err != nil {
				return parsedRule{}, err
			}
			n, err := parseAddrOrCIDR(v)
			if err != nil {
				return parsedRule{}, fmt.Errorf("netrules: -d %q: %w", v, err)
			}
			out.dst = n
		case "-m":
			mod, err := need("-m")
			if err != nil {
				return parsedRule{}, err
			}
			if mod != "comment" {
				return parsedRule{}, fmt.Errorf("netrules: unsupported match module %q", mod)
			}
			if i+1 >= len(rulespec) || rulespec[i+1] != "--comment" {
				return parsedRule{}, fmt.Errorf("netrules: -m comment requires --comment")
			}
			i++
			cmt, err := need("--comment")
			if err != nil {
				return parsedRule{}, err
			}
			out.comment = cmt
		case "-j":
			v, err := need("-j")
			if err != nil {
				return parsedRule{}, err
			}
			switch strings.ToUpper(v) {
			case "DROP":
				out.verdict = verdictDrop
			case "ACCEPT":
				out.verdict = verdictAccept
			default:
				return parsedRule{}, fmt.Errorf("netrules: unsupported verdict %q", v)
			}
		default:
			return parsedRule{}, fmt.Errorf("netrules: unsupported rulespec token %q", tok)
		}
	}
	if out.verdict == verdictUnset {
		return parsedRule{}, fmt.Errorf("netrules: rulespec missing -j verdict")
	}
	if out.src == nil && out.dst == nil {
		return parsedRule{}, fmt.Errorf("netrules: rulespec needs -s and/or -d")
	}
	return out, nil
}

func parseAddrOrCIDR(s string) (*net.IPNet, error) {
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		return n, err
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid address")
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}
