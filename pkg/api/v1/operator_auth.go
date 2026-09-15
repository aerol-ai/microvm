package v1

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// requireOperatorAccess rejects non-operator callers with 403.
//
// Must sit *inside* Deps.Auth so PAT / peer calls (Operator: true) pass and
// managed tenant tokens (OwnerRef scoped) cannot hit cluster-internal
// surfaces. Peer fan-out uses the fleet PAT, which stamps Operator.
func requireOperatorAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, ok := controlplane.AccessFromContext(r.Context())
		if !ok || !access.Operator {
			apihttp.WriteError(w, http.StatusForbidden, "operator authorization required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withAuthOperator is Auth then operator gate — the contract for
// /v1/cluster/internal/secrets and peer-local audit.
func withAuthOperator(d Deps, next http.Handler) http.Handler {
	auth := d.Auth
	if auth == nil {
		auth = func(h http.Handler) http.Handler { return h }
	}
	return auth(requireOperatorAccess(next))
}
