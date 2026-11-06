package v1

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Sandbox tokens (plans/agent-sandbox-feature-parity.md §5.9, A1; threat
// model in pkg/sandboxtoken).
//
//	POST /v1/sandboxes/{id}/tokens  sandbox.exec  201 {token once, token_id, scope, expires_at}
//
// sandbox.exec, because a toolbox token reaches exec and files, which is
// sandbox.exec, and a port token reaches the sandbox's own web server; no
// role holds sandbox.write without sandbox.exec, so the one permission
// covers both and a token never holds more than its issuer. The route is
// owner-forwarded (the owner node holds the sandbox row); the token it
// returns verifies on every node.
//
// Not idempotent by nature: each call mints a new token with a new id, and
// nothing is stored. A retry after a lost answer mints another; the lost
// one simply expires. A sandbox token presented here is refused at the edge
// (it covers only the toolbox), so a token cannot mint, extend or widen one.
func (h *handlers) createSandboxToken(w http.ResponseWriter, r *http.Request) {
	var req models.CreateSandboxTokenRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	created, err := h.deps.Service.IssueSandboxToken(r.Context(), r.PathValue("id"), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	// The call's api record names the token's id, never the token.
	auditlog.NoteTarget(r.Context(), created.TokenID)
	// The body holds a credential: never cache it anywhere on the way.
	w.Header().Set("Cache-Control", "no-store")
	apihttp.WriteJSON(w, http.StatusCreated, created)
}
