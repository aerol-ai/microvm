package daytona

import (
	"crypto/sha256"
	"encoding/binary"
	"net/http"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// clusterVolumeForwardWrap routes platform-volume CRUD to a deterministic owner
// node in cluster mode. Volume metadata (the id↔name row and per-tenant quota)
// lives in each node's local SQLite, so without routing a create on node A and a
// get-by-id on node B (behind a load balancer) would disagree. We pin all of a
// tenant's volume CRUD to one node chosen by highest-random-weight (rendezvous)
// hashing over live members, so every node forwards a given tenant to the same
// owner and the metadata stays single-writer per tenant.
//
// NOTE — this is forwarding, not replication. The *data* is always reachable
// from any node (volume sources are deterministic, see pkg/volumes), so mounts
// never depend on this. Only the metadata view follows the owner; when
// membership changes the HRW owner for a tenant can move to a node that does not
// hold its rows, so CRUD/quota can briefly regress after a join/leave until the
// tenant is recreated. Replicating the rows via the Raft FSM is the follow-up
// that removes that window (tracked in plans/e2b-volume-mounts.md).
//
// No-op (runs locally) when clustering is off, the service/cluster is absent, or
// only this node is a candidate.
func (h *handlers) clusterVolumeForwardWrap(local http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.deps.Service == nil {
			local.ServeHTTP(w, r)
			return
		}
		c := h.deps.Service.Cluster()
		if c == nil {
			local.ServeHTTP(w, r)
			return
		}
		tenant, err := h.deps.Service.VolumeTenantScope(r.Context())
		if err != nil {
			// Can't scope the caller → can't route. Run locally; the handler
			// surfaces the same scoping error to the client.
			local.ServeHTTP(w, r)
			return
		}

		owner, ok := pickVolumeOwner(c.Members(), tenant)
		if !ok || owner.NodeID == c.SelfNodeID() {
			local.ServeHTTP(w, r)
			return
		}
		if owner.APIURL == "" && owner.InternalURL == "" {
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: volume owner "+owner.NodeID+" URL unknown")
			return
		}
		if r.Header.Get("X-Cluster-Forwarded") == "1" {
			// A peer already forwarded this to us but our HRW view disagrees —
			// membership is mid-convergence. Serve locally rather than bounce.
			local.ServeHTTP(w, r)
			return
		}
		c.ForwardHTTP(cluster.Endpoint{InternalURL: owner.InternalURL, APIURL: owner.APIURL}, w, r)
	})
}

// pickVolumeOwner selects the rendezvous-hash owner of tenant among members.
// The member with the highest hash(nodeID|tenant) wins; this is stable across
// nodes (everyone computes the same winner) and minimally disruptive when the
// member set changes (only tenants mapped to a departed node move). Only Alive
// members are candidates — routing a tenant to a node gossip has marked dead
// would forward into a black hole. Returns false when there are no live
// candidates (caller then serves locally). The self node, if present in
// members, must be passed with Alive=true by the caller's gossip view.
func pickVolumeOwner(members []cluster.Member, tenant string) (cluster.Member, bool) {
	var best cluster.Member
	var bestScore uint64
	found := false
	for _, m := range members {
		if m.NodeID == "" || !m.Alive {
			continue
		}
		score := rendezvousScore(m.NodeID, tenant)
		if !found || score > bestScore || (score == bestScore && m.NodeID < best.NodeID) {
			best, bestScore, found = m, score, true
		}
	}
	return best, found
}

func rendezvousScore(nodeID, tenant string) uint64 {
	sum := sha256.Sum256([]byte(nodeID + "\x00" + tenant))
	return binary.BigEndian.Uint64(sum[:8])
}
