package e2b

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
)

func (h *handlers) clusterForwardWrap(local http.Handler) http.Handler {
	return clusterroute.Wrap(h.deps.Service, clusterroute.Options{WriteError: WriteError}, local)
}
