package isolate

import (
	"net"
	"strings"
)

// EgressPolicy is the per-sandbox outbound policy the host-side egress proxy
// enforces (plans/isolate-runtime.md §4 Phase 3). Mapped from existing
// CreateSandboxRequest fields (NetworkBlockAll / NetworkAllowOut /
// NetworkDenyOut) — net-new grant fields wait for the §10.1 checkpoint.
type EgressPolicy struct {
	BlockAll bool
	Allow    []string // CIDRs / hosts; empty + !BlockAll = allow-all (self-host default)
	Deny     []string
}

// EgressPolicySetter is implemented by GroupHost production adapters so the
// driver can push per-sandbox policy after Load. Fakes used in unit tests need
// not implement it (egress is fail-closed until policy is set on a real host).
type EgressPolicySetter interface {
	SetEgressPolicy(sandboxID string, p EgressPolicy)
}

// egressAllowed reports whether an outbound request to host (hostname or IP)
// is permitted under p. Deny wins over allow; BlockAll denies everything;
// empty Allow with !BlockAll allows all (operator/self-host default).
func egressAllowed(p EgressPolicy, host string) bool {
	if p.BlockAll {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, d := range p.Deny {
		if hostMatches(host, d) {
			return false
		}
	}
	if len(p.Allow) == 0 {
		return true
	}
	for _, a := range p.Allow {
		if hostMatches(host, a) {
			return true
		}
	}
	return false
}

func hostMatches(host, rule string) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	if rule == "" {
		return false
	}
	// CIDR form.
	if strings.Contains(rule, "/") {
		_, n, err := net.ParseCIDR(rule)
		if err != nil {
			return false
		}
		ip := net.ParseIP(host)
		return ip != nil && n.Contains(ip)
	}
	if host == rule {
		return true
	}
	// Suffix match for "*.example.com" style rules expressed as ".example.com".
	if strings.HasPrefix(rule, ".") && strings.HasSuffix(host, rule) {
		return true
	}
	return false
}

// policyFromCreate maps CreateSandboxRequest network fields onto EgressPolicy.
func policyFromCreate(blockAll bool, allow, deny []string) EgressPolicy {
	return EgressPolicy{
		BlockAll: blockAll,
		Allow:    append([]string(nil), allow...),
		Deny:     append([]string(nil), deny...),
	}
}
