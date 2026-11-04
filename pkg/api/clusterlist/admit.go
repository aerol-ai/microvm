package clusterlist

import (
	"net/http"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// Admit takes one of this node's cluster-list slots for a list that is about
// to fan out across the cluster (ListMode): a placement-page read and one
// request per owner node. Past the gate's limit it returns
// apihttp.ErrOverloaded, which every surface's store-aware error writer
// answers 503 + Retry-After, so a storm of lists is refused fast instead of
// queueing until each takes 30 s and the node falls over.
//
// A list that does not fan out is never gated: a single node (the local
// store is the whole answer) and a peer's forwarded hop (the node that fanned
// out already holds a slot for it; refusing the hop would only turn its list
// partial). When err is nil, release is never nil and must be called.
func Admit(gate *apihttp.Gate, c cluster.Client, r *http.Request) (release func(), err error) {
	if gate == nil || !ListMode(c, r) {
		return func() {}, nil
	}
	return gate.Acquire(r.Context())
}
