package harness

// Scenario is the runtime description of the deployment under test: where to
// reach it, the PAT, and which capabilities it has. Capabilities come from the
// scenario's caps.yml (loaded by LoadScenario); BaseURL/PAT come from env.
type Scenario struct {
	Name    string
	BaseURL string
	PAT     string
	// Domain is the leased apex domain for domain-bearing scenarios (empty in
	// local-mode). Tests that build hostnames under the wildcard zone — e.g.
	// the custom-domain reachability use case — read it. The wildcard
	// *.<Domain> record already points at ingress, so any label resolves.
	Domain string
	caps   map[Capability]bool
}

// Has reports whether the scenario advertises a capability.
func (s *Scenario) Has(c Capability) bool { return s.caps[c] }

// Satisfies reports whether the scenario has every capability a use case needs.
// This is the load-bearing predicate behind every skip decision and the report
// classification, so it is kept pure (no I/O, no testing import) and is unit-
// tested offline in skip_test.go. A bug here silently turns an un-runnable use
// case green, which is why it gets its own test.
func (s *Scenario) Satisfies(uc UseCase) bool {
	for _, need := range uc.Requires {
		if !s.caps[need] {
			return false
		}
	}
	return true
}

// MissingCaps returns the capabilities a use case needs that the scenario lacks.
// Used for human-readable skip messages.
func (s *Scenario) MissingCaps(uc UseCase) []Capability {
	var missing []Capability
	for _, need := range uc.Requires {
		if !s.caps[need] {
			missing = append(missing, need)
		}
	}
	return missing
}
