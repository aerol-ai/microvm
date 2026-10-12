package v1

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// requireOperatorAccess rejects non-operator callers with 403
// (apihttp.RequireOperator). Must sit *inside* Deps.Auth. Peer fan-out uses
// the fleet PAT, which stamps Operator.
func requireOperatorAccess(next http.Handler) http.Handler {
	return apihttp.RequireOperator(next)
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
