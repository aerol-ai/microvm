package v1

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// whoami answers GET /v1/whoami with the caller's own resolved principal,
// role, team and credential expiry (plans/identity-and-access.md §5.2). The
// CLI, the dashboard and support tickets read it. It needs only a valid
// principal: every caller may ask who it is, and the answer only ever
// describes that caller. Read-only and node-local, so retries are free and
// it is never forwarded.
func (h *handlers) whoami(w http.ResponseWriter, r *http.Request) {
	access, ok := controlplane.AccessFromContext(r.Context())
	if !ok {
		// Mounted behind Deps.Auth, so a request always carries Access. A
		// route wired without auth must not answer as the fleet.
		apihttp.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, whoAmIFrom(access))
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
