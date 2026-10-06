// Package egresspolicy is the one grammar, matcher and enforcement toolkit
// for sandbox egress policy (plans/egress-domain-filtering.md §5.1, §5.6).
//
// Every enforcer uses it so the same policy means the same thing everywhere:
// service-side validation, the egress gateway's DNS filter and SNI/Host proxy,
// the WASM network mediator, and isolate's host egress proxy. It lives in pkg/
// because pkg/isolate and pkg/wasm/worker cannot import internal/.
//
// The pieces:
//   - grammar: ParseEntry, ParseAllowList, ParseDenyList (entry.go)
//   - compiled policy with allow-wins precedence: Compile, Policy (policy.go)
//   - the policy check endpoint's evaluator: Check (check.go)
//   - TLS ClientHello SNI peek: PeekClientHello, ParseClientHello (sni.go)
//   - SSRF dial control and the operator internal zone: DialGuard (dial.go)
//   - operator ceiling coverage: Ceiling (ceiling.go)
//   - learn-mode recording and suggestions: Recorder (recorder.go)
package egresspolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Mode is the sandbox's egress mode (Phase 2 wire field network_egress_mode).
type Mode string

const (
	// ModeEnforce applies the lists. It is the default ("" normalizes to it).
	ModeEnforce Mode = "enforce"
	// ModeLearn allows everything and records it (CEO D2). Trusted runs only.
	ModeLearn Mode = "learn"
)

// Verdict is the outcome for a destination no rule decides.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

// RuleBlockAll is the matched-rule string reported when network_block_all
// (or a deny-all list with no allow list) decides.
const RuleBlockAll = "network_block_all"

// Spec is the raw policy as it arrives on the wire.
type Spec struct {
	AllowOut []string
	DenyOut  []string
	BlockAll bool
	Mode     Mode
}

// Policy is a compiled, immutable egress policy. It is safe for concurrent
// use; share one *Policy across goroutines (and across sandboxes with the
// same Hash).
type Policy struct {
	blockAll bool
	mode     Mode
	verdict  Verdict

	allow []Entry
	deny  []Entry

	// exact and wild index hostname allow entries by name and by wildcard
	// suffix. Each slice is ordered bare-first, then by port, so the rule
	// reported for a match is deterministic.
	exact map[string][]Entry
	wild  map[string][]Entry

	// allowCIDRs and denyCIDRs are ordered most-specific first so the rule
	// reported for an IP is the narrowest one that decided it.
	allowCIDRs []netip.Prefix
	denyCIDRs  []netip.Prefix

	hostnames int
	hash      string
}

// Compile validates spec and builds a Policy with the D4 precedence:
//
//   - allow list alone: allowlist, default deny;
//   - deny list alone: deny list, default accept;
//   - both: an allow match accepts, then a deny match denies, then accept;
//   - a deny list containing 0.0.0.0/0 with a non-empty allow list:
//     allowlist (the portable "allow these, deny everything" form);
//   - 0.0.0.0/0 denied with no allow list, or BlockAll: block-all.
//
// Hostnames are allowed only in AllowOut (at most MaxInlineHostnames). Learn
// mode requires empty lists and no block-all. Every error matches ErrInvalid
// and names the offending entry or field.
func Compile(spec Spec) (*Policy, error) {
	mode, err := normalizeMode(spec.Mode)
	if err != nil {
		return nil, err
	}
	allow, err := ParseAllowList(FieldAllowOut, spec.AllowOut, MaxInlineHostnames)
	if err != nil {
		return nil, err
	}
	deny, err := ParseDenyList(FieldDenyOut, spec.DenyOut)
	if err != nil {
		return nil, err
	}
	if mode == ModeLearn && (len(allow) > 0 || len(deny) > 0 || spec.BlockAll) {
		return nil, invalidf("network_egress_mode %q requires empty network_allow_out and network_deny_out and network_block_all=false", ModeLearn)
	}
	return build(spec.BlockAll, mode, allow, deny), nil
}

func normalizeMode(m Mode) (Mode, error) {
	switch m {
	case "", ModeEnforce:
		return ModeEnforce, nil
	case ModeLearn:
		return ModeLearn, nil
	}
	return "", invalidf("network_egress_mode %q: must be %q or %q", string(m), ModeEnforce, ModeLearn)
}

var blockAllPolicy = build(true, ModeEnforce, nil, nil)

// BlockAllPolicy returns a shared policy that denies everything: the
// fail-closed fallback when a stored policy no longer compiles.
func BlockAllPolicy() *Policy { return blockAllPolicy }

func build(blockAll bool, mode Mode, allow, deny []Entry) *Policy {
	p := &Policy{
		mode:  mode,
		allow: allow,
		deny:  deny,
		exact: make(map[string][]Entry),
		wild:  make(map[string][]Entry),
	}
	denyAll := false
	for _, e := range deny {
		if isDenyAll(e.Prefix) {
			denyAll = true
		}
		p.denyCIDRs = append(p.denyCIDRs, e.Prefix)
	}
	for _, e := range allow {
		switch e.Kind {
		case KindCIDR:
			p.allowCIDRs = append(p.allowCIDRs, e.Prefix)
		case KindHost:
			p.exact[e.Host] = append(p.exact[e.Host], e)
			p.hostnames++
		case KindWildcard:
			p.wild[e.Host] = append(p.wild[e.Host], e)
			p.hostnames++
		}
	}
	for _, m := range []map[string][]Entry{p.exact, p.wild} {
		for _, es := range m {
			sort.Slice(es, func(i, j int) bool { return es[i].Port < es[j].Port })
		}
	}
	sortMostSpecific(p.allowCIDRs)
	sortMostSpecific(p.denyCIDRs)

	p.blockAll = blockAll || (denyAll && len(allow) == 0)
	switch {
	case p.blockAll:
		p.verdict = VerdictDeny
	case mode == ModeLearn:
		p.verdict = VerdictAllow
	case len(allow) > 0 && (len(deny) == 0 || denyAll):
		p.verdict = VerdictDeny
	default:
		p.verdict = VerdictAllow
	}
	p.hash = p.computeHash()
	return p
}

// isDenyAll reports the IPv4 "everything" network. IPv6 is out of scope for
// Phase 1 (§3 non-goals), so ::/0 stays an ordinary deny CIDR.
func isDenyAll(p netip.Prefix) bool { return p.Bits() == 0 && p.Addr().Is4() }

func sortMostSpecific(ps []netip.Prefix) {
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Bits() > ps[j].Bits() })
}

// computeHash digests the canonical, order-independent content. Precedence
// never depends on list order, and aliases (".x" vs "*.x") canonicalize
// first, so equal policies hash equal: the gateway caches compiled apply
// plans by this key (latency amendment, §8.2).
func (p *Policy) computeHash() string {
	canon := func(es []Entry) string {
		ss := make([]string, len(es))
		for i, e := range es {
			ss[i] = e.String()
		}
		sort.Strings(ss)
		return strings.Join(ss, ",")
	}
	h := sha256.New()
	h.Write([]byte("egresspolicy/v1\nblock_all=" + strconv.FormatBool(p.blockAll) +
		"\nmode=" + string(p.mode) +
		"\nallow=" + canon(p.allow) +
		"\ndeny=" + canon(p.deny) + "\n"))
	return hex.EncodeToString(h.Sum(nil))
}

// Hash is a hex SHA-256 of the policy's canonical content.
func (p *Policy) Hash() string { return p.hash }

// BlockAll reports whether every destination is denied.
func (p *Policy) BlockAll() bool { return p.blockAll }

// Mode returns the normalized egress mode.
func (p *Policy) Mode() Mode { return p.mode }

// DefaultVerdict is the outcome for destinations no rule matches: deny in
// allowlist mode and for block-all, allow in deny-list and learn mode.
func (p *Policy) DefaultVerdict() Verdict { return p.verdict }

// HasHostnames reports whether the allow list names any host.
func (p *Policy) HasHostnames() bool { return p.hostnames > 0 }

// GatewayMode reports whether a container sandbox with this policy needs the
// egress gateway (§5.1): hostname entries or learn mode, and not block-all
// (block-all wins and nothing is redirected, EF-14). Profile references
// (Phase 2) will also turn it on.
func (p *Policy) GatewayMode() bool {
	return !p.blockAll && (p.hostnames > 0 || p.mode == ModeLearn)
}

// AllowEntries returns the deduplicated allow entries in input order.
func (p *Policy) AllowEntries() []Entry { return append([]Entry(nil), p.allow...) }

// DenyEntries returns the deduplicated deny entries (always CIDRs).
func (p *Policy) DenyEntries() []Entry { return append([]Entry(nil), p.deny...) }

// AllowCIDRs returns the allow networks, most specific first (nft allow_cidr).
func (p *Policy) AllowCIDRs() []netip.Prefix { return append([]netip.Prefix(nil), p.allowCIDRs...) }

// DenyCIDRs returns the deny networks, most specific first (nft deny_cidr).
func (p *Policy) DenyCIDRs() []netip.Prefix { return append([]netip.Prefix(nil), p.denyCIDRs...) }

// HostRules returns every hostname allow entry (exact and wildcard, with or
// without a port) in input order.
func (p *Policy) HostRules() []Entry {
	var out []Entry
	for _, e := range p.allow {
		if e.IsHostname() {
			out = append(out, e)
		}
	}
	return out
}

// HostPortRules returns the hostname entries that carry an explicit port:
// the ones whose DNS answers open learned (src, ip, port) elements (§5.4).
func (p *Policy) HostPortRules() []Entry {
	var out []Entry
	for _, e := range p.allow {
		if e.IsHostname() && e.Port != 0 {
			out = append(out, e)
		}
	}
	return out
}

// MatchHost answers the name-level question the DNS filter asks: is name
// allowed on any port? An IP literal is matched as MatchIP with no port.
// rule is the canonical entry that decided, RuleBlockAll, or "" when the
// default verdict decided.
func (p *Policy) MatchHost(name string) (allowed bool, rule string) {
	return p.MatchHostPort(name, 0)
}

// MatchHostPort decides a connection to name:port with port semantics: a
// bare host admits 80 and 443, host:port admits exactly that port. port 0
// means any port. Hostnames never appear in deny lists, so a name that no
// allow rule covers falls to the default verdict; deny CIDRs are applied to
// the resolved IP at dial time (DialGuard).
func (p *Policy) MatchHostPort(name string, port uint16) (allowed bool, rule string) {
	if ip, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
		return p.MatchIP(ip, port)
	}
	if p.blockAll {
		return false, RuleBlockAll
	}
	if p.mode == ModeLearn {
		return true, ""
	}
	if c := canonicalName(name); c != "" {
		if e, ok := p.matchName(c, port); ok {
			return true, e.String()
		}
	}
	return p.verdict == VerdictAllow, ""
}

// matchName prefers an exact entry, then the closest wildcard suffix.
func (p *Policy) matchName(name string, port uint16) (Entry, bool) {
	if p.hostnames == 0 {
		return Entry{}, false
	}
	for _, e := range p.exact[name] {
		if e.coversPort(port) {
			return e, true
		}
	}
	for rest := name; ; {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			return Entry{}, false
		}
		rest = rest[i+1:]
		for _, e := range p.wild[rest] {
			if e.coversPort(port) {
				return e, true
			}
		}
	}
}

// MatchIP decides a connection to ip. CIDR entries cover every port; port is
// accepted so callers pass what they have and so the signature stays stable
// if per-port CIDR rules are ever added. Allow wins over deny (D4).
func (p *Policy) MatchIP(ip netip.Addr, port uint16) (allowed bool, rule string) {
	if p.blockAll {
		return false, RuleBlockAll
	}
	if p.mode == ModeLearn {
		return true, ""
	}
	ip = ip.Unmap()
	if pfx, ok := firstContaining(p.allowCIDRs, ip); ok {
		return true, pfx.String()
	}
	if pfx, ok := firstContaining(p.denyCIDRs, ip); ok {
		return false, pfx.String()
	}
	return p.verdict == VerdictAllow, ""
}

// allowCIDRContains reports whether an allow CIDR covers ip: the explicit
// opt-in the dial control needs before a private address is reachable.
func (p *Policy) allowCIDRContains(ip netip.Addr) bool {
	_, ok := firstContaining(p.allowCIDRs, ip)
	return ok
}

func firstContaining(ps []netip.Prefix, ip netip.Addr) (netip.Prefix, bool) {
	for _, pfx := range ps {
		if pfx.Contains(ip) {
			return pfx, true
		}
	}
	return netip.Prefix{}, false
}
