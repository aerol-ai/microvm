package isolate

import (
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// EgressPolicy is the per-sandbox outbound policy the host-side egress proxy
// enforces (plans/isolate-runtime.md §4 Phase 3). Mapped from existing
// CreateSandboxRequest fields (NetworkBlockAll / NetworkAllowOut /
// NetworkDenyOut) — net-new grant fields wait for the §10.1 checkpoint. The
// driver only carries it: matching lives in pkg/isolate on the shared
// pkg/egresspolicy grammar (plans/egress-domain-filtering.md §5.6, CQ4).
type EgressPolicy struct {
	BlockAll bool
	Allow    []string // CIDRs / hosts; empty + !BlockAll = allow-all (self-host default)
	Deny     []string // CIDRs only (hostnames are rejected at create, D15)
	Learn    bool     // learn mode (P2-7): open egress, recorded by the driver
	// Rules are method and path rules (P3-1), checked on the plaintext
	// requests the host proxies.
	Rules []egresspolicy.RuleSpec
}

// EgressPolicySetter is implemented by GroupHost production adapters so the
// driver can push per-sandbox policy after Load. Fakes used in unit tests need
// not implement it (egress is fail-closed until policy is set on a real host).
type EgressPolicySetter interface {
	SetEgressPolicy(sandboxID string, p EgressPolicy)
}

// policyFromCreate maps CreateSandboxRequest network fields onto EgressPolicy.
func policyFromCreate(blockAll bool, allow, deny []string, learn bool, rules []egresspolicy.RuleSpec) EgressPolicy {
	return EgressPolicy{
		BlockAll: blockAll,
		Allow:    append([]string(nil), allow...),
		Deny:     append([]string(nil), deny...),
		Learn:    learn,
		Rules:    append([]egresspolicy.RuleSpec(nil), rules...),
	}
}

// ruleSpecs converts the wire rules (the service does the same for the
// gateway).
func ruleSpecs(rules []models.EgressRule) []egresspolicy.RuleSpec {
	out := make([]egresspolicy.RuleSpec, 0, len(rules))
	for _, r := range rules {
		out = append(out, egresspolicy.RuleSpec{Host: r.Host, Ports: r.Ports, Methods: r.Methods, Paths: r.Paths, Inspect: r.Inspect})
	}
	return out
}
