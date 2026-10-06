package egresspolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/net/publicsuffix"
)

// Dial control (§5.5 step 3, §5.10 PC-1): the SSRF guard every egress dialer
// shares. It runs on the RESOLVED address, so it holds even when an allowed
// name resolves (or is rebound) into the host's own services, the cloud
// metadata endpoint or an internal network. The DNS filter applies the same
// check before inserting learned (ip, port) elements.

// ErrDialRefused is matched (errors.Is) by every DialError.
var ErrDialRefused = errors.New("egress dial refused")

// Dial refusal reasons, stable for audit and metrics.
const (
	DialReasonInvalid     = "invalid_address"
	DialReasonLoopback    = "loopback"
	DialReasonLinkLocal   = "link_local"
	DialReasonUnspecified = "unspecified"
	DialReasonMulticast   = "multicast"
	DialReasonPrivate     = "private"
	DialReasonDenyFloor   = "deny_floor"
	DialReasonDenyCIDR    = "deny_cidr"
	DialReasonBlockAll    = "block_all"
	DialReasonNotAllowed  = "not_allowed"
)

// DialError says which address was refused and why. Its message names only
// the refused address and the deciding rule, never the rest of the policy
// (CEO D4).
type DialError struct {
	Addr   string
	Reason string
	Rule   string // the deny CIDR that refused, when one did
}

func (e *DialError) Error() string {
	if e.Rule != "" {
		return fmt.Sprintf("egress denied: destination %s is blocked (%s %s)", e.Addr, e.Reason, e.Rule)
	}
	return fmt.Sprintf("egress denied: destination %s is blocked (%s)", e.Addr, e.Reason)
}

// Is makes every DialError match ErrDialRefused.
func (e *DialError) Is(target error) bool { return target == ErrDialRefused }

var (
	// thisNetwork is 0.0.0.0/8: Linux routes a connect to 0.0.0.0 to the
	// local host, so it is loopback in disguise.
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	broadcast   = netip.MustParseAddr("255.255.255.255")
	// sharedAddress is RFC 6598 carrier-grade NAT space. Clouds put internal
	// services there (Alibaba's metadata endpoint is 100.100.100.200), so it
	// is treated as private.
	sharedAddress = netip.MustParsePrefix("100.64.0.0/10")
	// internalSpace is where an operator internal zone may point (PC-1).
	internalSpace = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		sharedAddress,
		netip.MustParsePrefix("fc00::/7"),
	}
)

// isPrivate covers RFC 1918, ULA and RFC 6598.
func isPrivate(ip netip.Addr) bool { return ip.IsPrivate() || sharedAddress.Contains(ip) }

// DialTarget is one connection attempt as the guard sees it.
type DialTarget struct {
	// Name is the hostname being dialed; "" for a raw-IP dial.
	Name string
	// NameAllowed reports that Name matched an allow rule. Allow wins (D4):
	// the policy's deny CIDRs and default verdict are then skipped; the
	// always-on blocks, the operator floor and the private-range rule still
	// apply.
	NameAllowed bool
	// Addr is the resolved address and port.
	Addr netip.AddrPort
}

// DialGuard is the operator-side dial configuration. The zero value is the
// container-gateway posture with no operator file: loopback, link-local,
// unspecified and multicast always refused; private ranges refused unless a
// policy CIDR allows them.
type DialGuard struct {
	// Strict refuses private, unspecified and multicast destinations no
	// matter what the policy's CIDRs say. It is isolate's posture (D15):
	// isolate egress leaves from the host's own network namespace, so a CIDR
	// allow must not open the host's neighbours.
	Strict bool
	// Zone is the operator internal zone (§5.10 PC-1), or nil.
	Zone *InternalZone
	// ZoneInStrict applies Zone in Strict mode too (operator
	// internal_zone.isolate: true, an explicit opt-in).
	ZoneInStrict bool
	// DenyFloor is the operator deny_cidrs floor: refused for every sandbox,
	// above every allow and the zone.
	DenyFloor []netip.Prefix
}

// Check decides whether a connection may proceed. p is the sandbox's policy,
// or nil when only the guard's own rules apply. The order is: always-on
// blocks, the operator floor, the internal zone, the private-range rule, and
// finally the policy (skipped when the name matched an allow rule).
func (g DialGuard) Check(p *Policy, t DialTarget) error {
	ip := t.Addr.Addr().Unmap() // a v4-mapped v6 address must not dodge the v4 rules
	refuse := func(reason, rule string) error {
		return &DialError{Addr: ip.String(), Reason: reason, Rule: rule}
	}
	switch {
	case !ip.IsValid():
		return &DialError{Addr: t.Addr.String(), Reason: DialReasonInvalid}
	case ip.IsLoopback():
		return refuse(DialReasonLoopback, "")
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return refuse(DialReasonLinkLocal, "")
	case ip.IsUnspecified() || thisNetwork.Contains(ip):
		return refuse(DialReasonUnspecified, "")
	case ip.IsMulticast() || ip == broadcast:
		return refuse(DialReasonMulticast, "")
	}
	if pfx, ok := firstContaining(g.DenyFloor, ip); ok {
		return refuse(DialReasonDenyFloor, pfx.String())
	}
	zoned := g.Zone != nil && (!g.Strict || g.ZoneInStrict) && g.Zone.Covers(t.Name, ip)
	if isPrivate(ip) && !zoned {
		if g.Strict || p == nil || !p.allowCIDRContains(ip) {
			return refuse(DialReasonPrivate, "")
		}
	}
	if p == nil || t.NameAllowed {
		return nil
	}
	if allowed, rule := p.MatchIP(ip, t.Addr.Port()); !allowed {
		switch rule {
		case "":
			return refuse(DialReasonNotAllowed, "")
		case RuleBlockAll:
			return refuse(DialReasonBlockAll, "")
		default:
			return refuse(DialReasonDenyCIDR, rule)
		}
	}
	return nil
}

// Control returns a net.Dialer.Control hook that applies Check to every
// resolved address the dialer tries. The hook only ever sees the resolved
// "ip:port", so bind it per dial with the name and match result the caller
// already computed.
func (g DialGuard) Control(p *Policy, name string, nameAllowed bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			// Control always gets ip:port; accept a bare IP for callers that
			// probe without one, and refuse anything else (fail closed).
			ip, ierr := netip.ParseAddr(address)
			if ierr != nil {
				return &DialError{Addr: address, Reason: DialReasonInvalid}
			}
			ap = netip.AddrPortFrom(ip, 0)
		}
		return g.Check(p, DialTarget{Name: name, NameAllowed: nameAllowed, Addr: ap})
	}
}

// StrictDialControl is a ready net.Dialer.Control for isolate's shared egress
// transport: DialGuard{Strict: true} with no per-sandbox policy, so it is
// safe to share across sandboxes and pooled connections.
func StrictDialControl(network, address string, c syscall.RawConn) error {
	return strictGuard.Control(nil, "", false)(network, address, c)
}

var strictGuard = DialGuard{Strict: true}

// InternalZone is the operator's internal zone (§5.10 PC-1): names under its
// suffixes may resolve into its CIDRs, and only those names. A name outside
// the suffixes that resolves into private space stays refused, which keeps
// the DNS-rebinding protection.
type InternalZone struct {
	suffixes []Entry // KindHost: the name and everything under it; KindWildcard: strictly under
	cidrs    []netip.Prefix
}

// NewInternalZone validates the operator's internal_zone. A suffix
// "corp.example.internal" covers that name and every name under it;
// "*.corp.example.internal" covers only names under it. CIDRs must sit inside
// RFC 1918, RFC 6598 or ULA space: loopback, link-local and public ranges
// are rejected, since the zone exists to open internal hosts, not to unblock
// the host itself or the internet.
func NewInternalZone(suffixes, cidrs []string) (*InternalZone, error) {
	z := &InternalZone{}
	for _, raw := range suffixes {
		// Strip the wildcard before parsing: parseEntry's user-wildcard rule
		// would reject "*.internal", which is a legitimate operator scope.
		s, wildcard := strings.TrimSpace(raw), false
		if rest, ok := strings.CutPrefix(s, "*."); ok {
			s, wildcard = rest, true
		}
		e, reason := parseEntry(s)
		switch {
		case reason != "":
		case e.Kind != KindHost:
			reason = "must be a hostname suffix"
		case e.Port != 0:
			reason = "must not carry a port"
		case isICANNSuffix(e.Host):
			reason = fmt.Sprintf("%q is a public suffix", e.Host)
		}
		if reason != "" {
			return nil, &EntryError{Field: "internal_zone.suffixes", Entry: raw, Reason: reason}
		}
		if wildcard {
			e.Kind = KindWildcard
		}
		z.suffixes = append(z.suffixes, e)
	}
	for _, raw := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, &EntryError{Field: "internal_zone.cidrs", Entry: raw, Reason: "not a valid CIDR"}
		}
		p = p.Masked()
		if !insideInternalSpace(p) {
			return nil, &EntryError{Field: "internal_zone.cidrs", Entry: raw, Reason: "must be inside RFC 1918, RFC 6598 or ULA space"}
		}
		z.cidrs = append(z.cidrs, p)
	}
	if len(z.suffixes) == 0 || len(z.cidrs) == 0 {
		return nil, invalidf("internal_zone needs at least one suffix and one CIDR")
	}
	return z, nil
}

// isICANNSuffix rejects suffixes like "com" or "co.uk". Unlike user
// wildcards, operator zones may name unlisted TLDs ("internal", "corp"),
// which private clouds use and which publicsuffix's default rule would
// otherwise report as public.
func isICANNSuffix(name string) bool {
	ps, icann := publicsuffix.PublicSuffix(name)
	return icann && ps == name
}

func insideInternalSpace(p netip.Prefix) bool {
	for _, s := range internalSpace {
		if s.Addr().BitLen() == p.Addr().BitLen() && s.Bits() <= p.Bits() && s.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// CoversName reports whether name sits under one of the zone's suffixes.
func (z *InternalZone) CoversName(name string) bool {
	if z == nil {
		return false
	}
	c := canonicalName(name)
	if c == "" {
		return false
	}
	for _, s := range z.suffixes {
		if s.Kind == KindHost && c == s.Host {
			return true
		}
		if (Entry{Kind: KindWildcard, Host: s.Host}).coversName(c) {
			return true
		}
	}
	return false
}

// Covers reports whether name may reach ip through the zone.
func (z *InternalZone) Covers(name string, ip netip.Addr) bool {
	if z == nil || !z.CoversName(name) {
		return false
	}
	_, ok := firstContaining(z.cidrs, ip.Unmap())
	return ok
}
