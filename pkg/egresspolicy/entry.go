package egresspolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Caps from plans/egress-domain-filtering.md §5.1. Only hostname entries
// (exact, wildcard, host:port) count: CIDRs never reach the DNS filter or the
// proxy, and their size is already bounded by the request body.
const (
	// MaxInlineHostnames bounds hostname entries written inline on a create or
	// policy PUT. 64 is what fits the 4 KB inline cluster recovery spec
	// (internal/cluster/recovery_replication.go inlineRecoveryMaxBytes) next to
	// the rest of a create request; bigger lists go in a named profile.
	MaxInlineHostnames = 64
	// MaxProfileHostnames bounds one named egress profile (Phase 2, D21).
	MaxProfileHostnames = 512
	// MaxUnionHostnames bounds the effective union of inline entries and every
	// referenced profile, so one sandbox can't make the gateway hold an
	// unbounded matcher.
	MaxUnionHostnames = 1024
	// MaxHostnameLength is the DNS presentation-format limit (RFC 1035 §2.3.4).
	MaxHostnameLength = 253

	maxLabelLength = 63
	// maxRawEntryLength rejects pathological input before IDNA mapping runs. A
	// U-label host can take ~4 bytes per A-label byte, so this leaves room for
	// any host that could normalize to MaxHostnameLength.
	maxRawEntryLength = 1024
)

// Field names used in errors. Callers turn errors into 400s, and naming the
// wire field next to the entry tells the user exactly what to fix.
const (
	FieldAllowOut = "network_allow_out"
	FieldDenyOut  = "network_deny_out"
)

// ErrInvalid is matched (errors.Is) by every grammar, cap and policy-shape
// error this package returns, so API layers can map them to 400 without
// string matching.
var ErrInvalid = errors.New("invalid egress policy")

// EntryError names the offending entry. Its message is safe to return to the
// caller verbatim.
type EntryError struct {
	Field  string // wire field, e.g. "network_allow_out"; empty for ParseEntry
	Entry  string // the entry as written
	Reason string
}

func (e *EntryError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("egress entry %q: %s", e.Entry, e.Reason)
	}
	return fmt.Sprintf("%s entry %q: %s", e.Field, e.Entry, e.Reason)
}

// Is makes every EntryError match ErrInvalid.
func (e *EntryError) Is(target error) bool { return target == ErrInvalid }

// policyError is a whole-policy problem (a cap, a mode combination) rather
// than one bad entry.
type policyError string

func (e policyError) Error() string        { return string(e) }
func (e policyError) Is(target error) bool { return target == ErrInvalid }

func invalidf(format string, args ...any) error {
	return policyError(fmt.Sprintf(format, args...))
}

// Kind is the shape of a policy entry.
type Kind uint8

const (
	// KindCIDR is an IP network ("10.0.0.0/8"); it covers every port.
	KindCIDR Kind = iota + 1
	// KindHost is one exact hostname ("pypi.org"), optionally with a port.
	KindHost
	// KindWildcard is "*.suffix": any name one or more labels under suffix,
	// at any depth, but NOT the apex itself (E2B semantics, review S3).
	KindWildcard
)

func (k Kind) String() string {
	switch k {
	case KindCIDR:
		return "cidr"
	case KindHost:
		return "host"
	case KindWildcard:
		return "wildcard"
	}
	return "unknown"
}

// Entry is one parsed, normalized policy entry. The zero value is invalid.
type Entry struct {
	Kind Kind
	// Prefix is the masked network for KindCIDR.
	Prefix netip.Prefix
	// Host is the normalized (lowercase, punycode, no trailing dot) name for
	// KindHost, or the suffix without the leading "*." for KindWildcard.
	Host string
	// Port is the one extra port of a host:port entry. 0 means a bare host,
	// which is TCP 80/443 on every runtime (§5.1). CIDRs always have 0.
	Port uint16
}

// IsHostname reports whether the entry names hosts (exact or wildcard, with
// or without a port) rather than an IP network.
func (e Entry) IsHostname() bool { return e.Kind == KindHost || e.Kind == KindWildcard }

// String returns the canonical form. Parsing it again yields the same Entry,
// so it doubles as a stable key for dedupe and hashing.
func (e Entry) String() string {
	var host string
	switch e.Kind {
	case KindCIDR:
		return e.Prefix.String()
	case KindHost:
		host = e.Host
	case KindWildcard:
		host = "*." + e.Host
	default:
		return ""
	}
	if e.Port != 0 {
		return host + ":" + strconv.Itoa(int(e.Port))
	}
	return host
}

// coversName reports whether the host part of a hostname entry matches the
// canonical name, ignoring ports.
func (e Entry) coversName(name string) bool {
	switch e.Kind {
	case KindHost:
		return name == e.Host
	case KindWildcard:
		return len(name) > len(e.Host)+1 &&
			strings.HasSuffix(name, e.Host) &&
			name[len(name)-len(e.Host)-1] == '.'
	}
	return false
}

// coversPort reports whether a hostname entry admits a connection to port.
// A bare entry is HTTP+HTTPS; a host:port entry is exactly that port. port 0
// means "any port" (a name-level question such as the DNS filter's).
func (e Entry) coversPort(port uint16) bool {
	if port == 0 {
		return true
	}
	if e.Port == 0 {
		return port == 80 || port == 443
	}
	return port == e.Port
}

// lookupProfile maps U-labels to punycode the way resolvers do (UTS 46
// non-transitional), but leaves ASCII policy to validateLabels: STD3 would
// reject '_' (used by real hosts and SRV names) and the hyphen check would
// reject live CDN names such as "r3---sn-abc.googlevideo.com".
var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
	idna.CheckHyphens(false),
)

// ParseEntry parses and normalizes one allow-list entry. It accepts a CIDR,
// an exact hostname, a "*.suffix" wildcard (".suffix" is the legacy isolate
// alias), and either host form with ":port". It never accepts a bare IP: that
// must be written as a CIDR so it is unambiguous which layer enforces it.
func ParseEntry(raw string) (Entry, error) {
	e, reason := parseEntry(raw)
	if reason != "" {
		return Entry{}, &EntryError{Entry: raw, Reason: reason}
	}
	return e, nil
}

func parseEntry(raw string) (Entry, string) {
	s := strings.TrimSpace(raw)
	switch {
	case s == "":
		return Entry{}, "empty entry"
	case len(s) > maxRawEntryLength:
		return Entry{}, fmt.Sprintf("longer than %d bytes", maxRawEntryLength)
	case !utf8.ValidString(s):
		// strings.ToLower and the IDNA mapper both turn invalid bytes into
		// U+FFFD, which can then encode as a valid punycode label.
		return Entry{}, "not valid UTF-8"
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Entry{}, "not a valid CIDR"
		}
		// An IPv4-mapped IPv6 prefix would never match the unmapped IPv4
		// addresses the kernel and resolvers actually use; store it as IPv4
		// so a deny like "::ffff:10.0.0.0/104" really denies 10.0.0.0/8.
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return Entry{Kind: KindCIDR, Prefix: p.Masked()}, ""
	}
	if isIPLiteral(s) {
		return Entry{}, "IP literals must be written as a CIDR (for example 203.0.113.7/32)"
	}

	host, portStr, hasPort := strings.Cut(s, ":")
	if strings.Contains(portStr, ":") {
		return Entry{}, "not a hostname, host:port or CIDR"
	}
	var port uint16
	if hasPort {
		p, reason := parsePort(portStr)
		if reason != "" {
			return Entry{}, reason
		}
		if p == 80 || p == 443 {
			return Entry{}, fmt.Sprintf("port %d is redundant: a bare hostname already allows TCP 80 and 443", p)
		}
		port = p
	}

	lower := strings.ToLower(host)
	kind := KindHost
	switch {
	case strings.HasPrefix(lower, "*."):
		kind, lower = KindWildcard, lower[2:]
	case strings.HasPrefix(lower, "."):
		kind, lower = KindWildcard, lower[1:]
	}
	if strings.Contains(lower, "*") {
		return Entry{}, `a wildcard is only allowed as a leading "*."`
	}
	name, reason := normalizeHostname(lower)
	if reason != "" {
		return Entry{}, reason
	}
	if kind == KindWildcard && isPublicSuffix(name) {
		return Entry{}, fmt.Sprintf("a wildcard on the public suffix %q would match every site under it", name)
	}
	return Entry{Kind: kind, Host: name, Port: port}, ""
}

// parsePort accepts 1-65535 in plain decimal (no sign, no whitespace).
func parsePort(s string) (uint16, string) {
	if s == "" {
		return 0, "empty port"
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, "port must be 1-65535"
	}
	return uint16(n), ""
}

// isIPLiteral catches every IP spelling a user might write in a hostname
// slot: v4, v6, bracketed v6, and either with a port.
func isIPLiteral(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParseAddrPort(s); err == nil {
		return true
	}
	if strings.HasPrefix(s, "[") {
		return true // "[v6]" or "[v6]:port" (or junk that is not a host either)
	}
	host, _, ok := strings.Cut(s, ":")
	if ok {
		if _, err := netip.ParseAddr(host); err == nil {
			return true
		}
	}
	return false
}

// normalizeHostname strictly validates a host written in a policy and
// returns its canonical A-label form.
func normalizeHostname(s string) (string, string) {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", "empty hostname"
	}
	ascii, err := lookupProfile.ToASCII(s)
	if err != nil {
		return "", "not a valid hostname"
	}
	if len(ascii) > MaxHostnameLength {
		return "", fmt.Sprintf("hostname longer than %d characters", MaxHostnameLength)
	}
	if reason := validateLabels(ascii, true); reason != "" {
		return "", reason
	}
	return ascii, ""
}

// validateLabels checks LDH-plus-underscore labels. strict additionally
// rejects a leading or trailing hyphen; matching (non-strict) stays lenient
// so live names never fail to match a rule that covers them.
func validateLabels(name string, strict bool) string {
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" {
			return "empty label"
		}
		if len(l) > maxLabelLength {
			return fmt.Sprintf("label longer than %d characters", maxLabelLength)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Sprintf("invalid character %q", c)
			}
		}
		if strict && (l[0] == '-' || l[len(l)-1] == '-') {
			return "label starts or ends with a hyphen"
		}
	}
	// An all-numeric last label is never a real TLD, and inet_aton-style
	// parsers read names such as "127.1" as IP addresses.
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return "looks like an IP address, not a hostname"
	}
	return ""
}

// isPublicSuffix reports whether name is itself a public suffix ("com",
// "co.uk", "github.io"), where a wildcard would cover unrelated tenants.
// publicsuffix's default rule also reports unlisted single-label TLDs
// ("internal", "corp") as public suffixes, which is the right answer for a
// user wildcard: "*.internal" is never a deliberate scope.
func isPublicSuffix(name string) bool {
	ps, _ := publicsuffix.PublicSuffix(name)
	return ps == name
}

// canonicalName normalizes a name observed on the wire (SNI, Host header,
// DNS qname, dial host) for matching. It is lenient about hyphen placement
// but returns "" for anything that is not a plausible hostname, so garbage
// such as "evil.com\x00.pypi.org" can never match "*.pypi.org".
func canonicalName(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" || len(name) > maxRawEntryLength {
		return ""
	}
	if isASCII(name) {
		name = strings.ToLower(name)
	} else {
		if !utf8.ValidString(name) {
			return ""
		}
		ascii, err := lookupProfile.ToASCII(name)
		if err != nil {
			return ""
		}
		name = ascii
	}
	if len(name) > MaxHostnameLength || validateLabels(name, false) != "" {
		return ""
	}
	return name
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// ParseAllowList parses an allow list, dedupes it (canonical form) and
// enforces maxHostnames: MaxInlineHostnames inline, MaxProfileHostnames for
// one profile, MaxUnionHostnames for an effective union. field names the list
// in errors. Order is preserved for the first occurrence of each entry.
func ParseAllowList(field string, entries []string, maxHostnames int) ([]Entry, error) {
	out, err := parseList(field, entries, true)
	if err != nil {
		return nil, err
	}
	if n := CountHostnames(out); n > maxHostnames {
		return nil, invalidf("%s has %d hostname entries; the limit is %d (use a named egress profile for larger lists)", field, n, maxHostnames)
	}
	return out, nil
}

// ParseDenyList parses a deny list. Hostnames are rejected on every runtime
// (D15, as in E2B): on a container a hostname deny is trivially bypassed by
// connecting to an IP, so only CIDRs can be honestly enforced.
func ParseDenyList(field string, entries []string) ([]Entry, error) {
	return parseList(field, entries, false)
}

func parseList(field string, entries []string, hostnamesOK bool) ([]Entry, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make([]Entry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, raw := range entries {
		e, reason := parseEntry(raw)
		if reason == "" && !hostnamesOK && e.Kind != KindCIDR {
			reason = "hostnames are not allowed in deny lists; use a CIDR, or list only the hosts you want in network_allow_out"
		}
		if reason != "" {
			return nil, &EntryError{Field: field, Entry: raw, Reason: reason}
		}
		key := e.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	return out, nil
}

// CountHostnames returns how many entries count toward the hostname caps.
func CountHostnames(entries []Entry) int {
	n := 0
	for _, e := range entries {
		if e.IsHostname() {
			n++
		}
	}
	return n
}
