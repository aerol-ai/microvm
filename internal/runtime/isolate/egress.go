package isolate

import (
	"maps"

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
	// Secrets are the values inject rules set, by env key (P3-2). An
	// isolate never sees its env, so nothing is withheld from it; the host
	// adds them to the requests it proxies.
	Secrets map[string]string
}

// EgressPolicySetter is implemented by GroupHost production adapters so the
// driver can push per-sandbox policy after Load. Fakes used in unit tests need
// not implement it (egress is fail-closed until policy is set on a real host).
type EgressPolicySetter interface {
	SetEgressPolicy(sandboxID string, p EgressPolicy)
}

// policyFromCreate maps CreateSandboxRequest network fields onto EgressPolicy.
func policyFromCreate(blockAll bool, allow, deny []string, learn bool, rules []egresspolicy.RuleSpec, secrets map[string]string) EgressPolicy {
	return EgressPolicy{
		BlockAll: blockAll,
		Allow:    append([]string(nil), allow...),
		Deny:     append([]string(nil), deny...),
		Learn:    learn,
		Rules:    append([]egresspolicy.RuleSpec(nil), rules...),
		Secrets:  maps.Clone(secrets),
	}
}

// injectSecrets picks the values a rule set injects from a sandbox's env.
func injectSecrets(rules []egresspolicy.RuleSpec, env map[string]string) map[string]string {
	keys := egresspolicy.InjectEnvKeys(rules)
	if len(keys) == 0 {
		return nil
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if v, ok := env[k]; ok {
			out[k] = v
		}
	}
	return out
}

// ruleSpecs converts the wire rules (the service does the same for the
// gateway).
func ruleSpecs(rules []models.EgressRule) []egresspolicy.RuleSpec {
	out := make([]egresspolicy.RuleSpec, 0, len(rules))
	for _, r := range rules {
		spec := egresspolicy.RuleSpec{Host: r.Host, Ports: r.Ports, Methods: r.Methods, Paths: r.Paths, Inspect: r.Inspect}
		if r.Inject != nil {
			spec.Inject = &egresspolicy.InjectSpec{Header: r.Inject.Header, SecretRef: r.Inject.SecretRef}
		}
		out = append(out, spec)
	}
	return out
}
