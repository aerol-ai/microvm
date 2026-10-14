package daytona

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
)

func (h *handlers) clusterForwardWrap(pathKey string, local http.Handler) http.Handler {
	return clusterroute.Wrap(h.deps.Service, clusterroute.Options{
		PathKey:     pathKey,
		ResolveName: pathKey == "idOrName",
		WriteError:  apihttp.WriteError,
	}, local)
}
