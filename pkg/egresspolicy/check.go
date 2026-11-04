package egresspolicy

import (
	"fmt"
	"net/netip"
	"strings"
)

// CheckResult is the policy check endpoint's response body (P2-9, CEO D5).
type CheckResult struct {
	Allowed        bool    `json:"allowed"`
	MatchedRule    string  `json:"matched_rule"`
	DefaultVerdict Verdict `json:"default_verdict"`
}

// Check evaluates destination against p without resolving DNS, so deny CIDRs
// that would apply to a hostname's resolved IP at connect time are not
// evaluated (the docs say so). destination is "host", "host:port", "IP",
// "IP:port" or "[IPv6]:port".
//
// A host without a port is checked as the web ports, which is what a bare
// hostname means in the grammar: "github.com" against a policy holding only
// "github.com:22" is not allowed. A destination that cannot be parsed returns
// an error matching ErrInvalid.
func Check(p *Policy, destination string) (CheckResult, error) {
	res := CheckResult{DefaultVerdict: p.DefaultVerdict()}
	host, ip, port, err := ParseDestination(destination)
	if err != nil {
		return res, err
	}
	if ip.IsValid() {
		res.Allowed, res.MatchedRule = p.MatchIP(ip, port)
		return res, nil
	}
	if port == 0 {
		port = 443 // bare rules cover 80 and 443 together; port rules never name either
	}
	res.Allowed, res.MatchedRule = p.MatchHostPort(host, port)
	return res, nil
}

// ParseDestination splits a check destination. Exactly one of host and ip is
// set; port is 0 when the destination names none.
func ParseDestination(destination string) (host string, ip netip.Addr, port uint16, err error) {
	d := strings.TrimSpace(destination)
	bad := func(reason string) error {
		return &EntryError{Field: "destination", Entry: destination, Reason: reason}
	}
	if d == "" {
		return "", netip.Addr{}, 0, bad("empty destination")
	}
	if a, perr := netip.ParseAddr(strings.Trim(d, "[]")); perr == nil {
		return "", a.Unmap(), 0, nil
	}
	if ap, perr := netip.ParseAddrPort(d); perr == nil {
		if ap.Port() == 0 {
			return "", netip.Addr{}, 0, bad("port must be 1-65535")
		}
		return "", ap.Addr().Unmap(), ap.Port(), nil
	}
	h, portStr, hasPort := strings.Cut(d, ":")
	if hasPort {
		p, reason := parsePort(portStr)
		if reason != "" {
			return "", netip.Addr{}, 0, bad(reason)
		}
		port = p
	}
	c := canonicalName(h)
	if c == "" {
		return "", netip.Addr{}, 0, bad(fmt.Sprintf("%q is not a hostname or IP address", h))
	}
	return c, netip.Addr{}, port, nil
}
