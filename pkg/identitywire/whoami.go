package identitywire

// Request and response pieces of the API that the CLI sends or reads beyond
// the models package: the team-selection header (CEO review D13) and the
// `whoami --explain` answer (CEO review D22, plans/identity-and-access.md
// §5.15).

// TeamHeader selects which of a credential's teams a request acts for. It
// picks among the bindings the verified credential already matches and
// never grants one (§5.3). sandboxd's internal/cluster.HeaderTeam is the
// same string.
const TeamHeader = "X-AerolVM-Team"

// WhoAmIExplainQuery is the query parameter that asks GET /v1/whoami to
// explain its answer: GET /v1/whoami?explain=1. A sandboxd that predates it
// ignores the parameter and sends no Explain, and the CLI then explains
// from the caller's own token alone.
const WhoAmIExplainQuery = "explain"

// WhoAmIExplain is the `explain` object of an explained whoami. It
// describes only the caller: the bindings its own claims matched and the
// claims that were considered, never another principal's (D22).
type WhoAmIExplain struct {
	// BindingsApply is true for an identity-provider token, whose role
	// comes from identity-file bindings. It is false for a credential that
	// carries its own role (the operator token, an API token, a managed
	// account), and Note then says where the role comes from.
	BindingsApply bool   `json:"bindings_apply"`
	Note          string `json:"note,omitempty"`
	// Matched lists every identity-file binding the caller's claims
	// matched, in file order, one per role and team granted. Empty when
	// bindings don't apply.
	Matched []ExplainBinding `json:"matched"`
	// Claims are the caller's own claims the bindings were matched against.
	// Absent for a credential that is not an identity-provider token.
	Claims *ExplainClaims `json:"claims,omitempty"`
}

// ExplainBinding is one identity-file binding.
type ExplainBinding struct {
	// Index is the binding's 1-based position in the identity file's
	// bindings list, so "binding 3" is the third entry.
	Index int `json:"index"`
	// Text is the binding's canonical line, the form identity_config audit
	// records use: `okta group="payments-eng" -> runner/payments`.
	Text string `json:"text"`
	// InEffect marks the binding this request acts under: the first match,
	// or the one X-AerolVM-Team selected.
	InEffect bool `json:"in_effect,omitempty"`
}

// ExplainClaims are the claims a binding is matched against.
type ExplainClaims struct {
	// Issuer is the identity-file name of the issuer that signed the token.
	Issuer string `json:"issuer"`
	// Username is the value of the issuer's username claim.
	Username string   `json:"username,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	// GroupOverage is set when the provider left the groups out and sent an
	// overage pointer instead (Entra above 200 groups).
	GroupOverage bool `json:"group_overage,omitempty"`
}
