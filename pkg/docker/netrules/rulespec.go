package netrules

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// verdictKind is a portable stand-in for expr.VerdictKind so rulespec
// parsing compiles off linux (google/nftables is linux-only via x/sys).
type verdictKind int

const (
	verdictUnset verdictKind = iota
	verdictDrop
	verdictAccept
	verdictReturn
	verdictJump
)

// parsedRule is the Manager's iptables-shaped argv decoded into the fields
// the netlink backend needs. Only the shapes Manager emits are supported:
// -s/-d address-or-CIDR, optional -p tcp|udp with --dport, optional -m
// comment --comment, and -j DROP|ACCEPT|RETURN or a jump to one of our own
// chains (RETURN is used by the AEROLVM-INPUT allowlist rules; the node
// guard's ports and jumps by AEROLVM-NODE).
type parsedRule struct {
	src     *net.IPNet
	dst     *net.IPNet
	proto   string // "tcp" or "udp"; "" matches every protocol
	dport   uint16 // 0 matches every port; needs proto
	comment string
	verdict verdictKind
	jump    string // the chain a verdictJump goes to
}

// ownChainPrefix is what every chain a rule may jump to starts with: a jump
// to anything else (a target such as LOG, or another tool's chain) is
// refused rather than translated into something it is not.
const ownChainPrefix = "AEROLVM-"

// validJumpChain reports whether name is one of our chains, spelled within
// iptables' limits (28 characters, no spaces or quotes).
func validJumpChain(name string) bool {
	if !strings.HasPrefix(name, ownChainPrefix) || len(name) > 28 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
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
		case "-p":
			v, err := need("-p")
			if err != nil {
				return parsedRule{}, err
			}
			if v != "tcp" && v != "udp" {
				return parsedRule{}, fmt.Errorf("netrules: unsupported protocol %q", v)
			}
			out.proto = v
		case "--dport":
			v, err := need("--dport")
			if err != nil {
				return parsedRule{}, err
			}
			if out.proto == "" {
				// iptables refuses a port without -p before it; so do we.
				return parsedRule{}, fmt.Errorf("netrules: --dport needs -p tcp|udp before it")
			}
			n, err := strconv.ParseUint(v, 10, 16)
			if err != nil || n == 0 {
				return parsedRule{}, fmt.Errorf("netrules: --dport %q: want 1-65535", v)
			}
			out.dport = uint16(n)
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
			case "RETURN":
				out.verdict = verdictReturn
			default:
				if !validJumpChain(v) {
					return parsedRule{}, fmt.Errorf("netrules: unsupported verdict %q", v)
				}
				out.verdict, out.jump = verdictJump, v
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
		if err != nil {
			return nil, err
		}
		return v4Only(n)
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid address")
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return nil, fmt.Errorf("IPv6 not supported: the netlink backend drives the IPv4 filter table")
}

// v4Only rejects IPv6 and normalizes the rest to 4-byte form. This is the
// single enforcement point that keeps 16-byte addresses away from
// ipv4MatchExprs, which indexes IP[0..3] and would panic the daemon —
// NetworkAllowOut/DenyOut CIDRs are user input, so failing closed here turns
// a crash into a create error (the exec backend gets the same clean error
// from the iptables binary).
func v4Only(n *net.IPNet) (*net.IPNet, error) {
	v4 := n.IP.To4()
	if v4 == nil || len(n.Mask) != 4 {
		return nil, fmt.Errorf("IPv6 not supported: the netlink backend drives the IPv4 filter table")
	}
	return &net.IPNet{IP: v4, Mask: n.Mask}, nil
}
