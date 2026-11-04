package v1

import (
	"net/http"

	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// whoami answers GET /v1/whoami with the caller's own resolved principal,
// role, team and credential expiry (plans/identity-and-access.md §5.2). The
// CLI, the dashboard and support tickets read it. It needs only a valid
// principal: every caller may ask who it is, and the answer only ever
// describes that caller. Read-only and node-local, so retries are free and
// it is never forwarded.
//
// With ?explain=1 it adds `explain` (`aerolvm whoami --explain`, CEO review
// D22): the identity-file bindings the caller's token matched and the
// caller's own claims they were matched against. Never another
// principal's, and never the identity file as a whole. Without the
// parameter the body is exactly what it always was.
func (h *handlers) whoami(w http.ResponseWriter, r *http.Request) {
	access, ok := controlplane.AccessFromContext(r.Context())
	if !ok {
		// Mounted behind Deps.Auth, so a request always carries Access. A
		// route wired without auth must not answer as the fleet.
		apihttp.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch r.URL.Query().Get(identitywire.WhoAmIExplainQuery) {
	case "1", "true":
		apihttp.WriteJSON(w, http.StatusOK, explainedWhoAmI{WhoAmI: whoAmIFrom(access), Explain: explainFor(r, access)})
	default:
		apihttp.WriteJSON(w, http.StatusOK, whoAmIFrom(access))
	}
}

func whoAmIFrom(access controlplane.Access) models.WhoAmI {
	out := models.WhoAmI{
		Principal: models.WhoAmIPrincipal{
			Kind: string(access.Principal.Kind),
			ID:   access.Principal.ID,
			Name: access.Principal.Name,
		},
		Role: string(access.Role),
		Team: access.Team(),
	}
	if !access.ExpiresAt.IsZero() {
		expires := access.ExpiresAt.UTC()
		out.ExpiresAt = &expires
	}
	return out
}

// explainedWhoAmI is the ?explain=1 body. The explanation stays out of
// models.WhoAmI, which every surface and SDK shares.
type explainedWhoAmI struct {
	models.WhoAmI
	Explain *identitywire.WhoAmIExplain `json:"explain"`
}

// explainFor builds the explanation from what authentication already
// resolved for this request: the matched bindings the Access carries (the
// verified-token cache's binding set, with each binding's file index and
// canonical line), which one team selection put in effect, and the claims
// read back out of the caller's own bearer.
func explainFor(r *http.Request, access controlplane.Access) *identitywire.WhoAmIExplain {
	out := &identitywire.WhoAmIExplain{Matched: []identitywire.ExplainBinding{}}
	if access.Principal.Kind != controlplane.PrincipalOIDC {
		out.Note = notApplicable(access.Principal.Kind)
		return out
	}
	out.BindingsApply = true
	team, inEffect := access.Team(), false
	for _, b := range access.Bindings {
		eb := identitywire.ExplainBinding{Index: b.Index, Text: b.Rule}
		// Bindings are one per role and team, so exactly one is in effect.
		if !inEffect && b.Role == access.Role && b.Team == team {
			eb.InEffect, inEffect = true, true
		}
		out.Matched = append(out.Matched, eb)
	}
	out.Claims = identity.ExplainClaims(apihttp.BearerToken(r), access.ClaimNames)
	return out
}

// notApplicable says where a credential's role comes from when no
// identity-file binding is involved.
func notApplicable(kind controlplane.PrincipalKind) string {
	switch kind {
	case controlplane.PrincipalOperator:
		return "the operator token (SB_PAT_TOKEN) acts as admin on every team; identity-file bindings don't apply"
	case controlplane.PrincipalToken:
		return "an API token carries its own role and team; identity-file bindings don't apply"
	case controlplane.PrincipalControlPlane:
		return "the managed control plane sets this account's role; identity-file bindings don't apply"
	case controlplane.PrincipalNode:
		return "a cluster peer's certificate acts as admin on every team; identity-file bindings don't apply"
	}
	return "identity-file bindings don't apply to this credential"
}
