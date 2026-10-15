package clusterroute

import (
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
)

// WrapSnapshot routes a snapshot-by-id request to the node that holds the
// snapshot's image, serving it locally when this node holds it, there is no
// cluster, or no home entry is registered. A snapshot lives in per-node SQLite
// with no node column, so — unlike Wrap, which forwards by the sandbox owner —
// this forwards by the replicated snapshot name → node index (a snapshot
// outlives its source sandbox, so OwnerOf cannot answer for it).
//
// Each facade's snapshot id shape differs (Daytona's is the name; E2B's is a
// derived id), so the caller supplies a name resolver that maps its request to
// the snapshot's canonical name without a local store read. A resolver that
// returns "" (an id this node cannot map, e.g. a custom alias whose row is not
// local) falls through to local serving — the pre-index behaviour, no regression.
func WrapSnapshot(svc *service.Service, name func(*http.Request) string, write ErrorWriter, local http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			local.ServeHTTP(w, r)
			return
		}
		c := svc.Cluster()
		if c == nil {
			local.ServeHTTP(w, r)
			return
		}
		snapshotName := strings.TrimSpace(name(r))
		if snapshotName == "" {
			local.ServeHTTP(w, r)
			return
		}
		node, ok, err := c.SnapshotHomeNode(r.Context(), snapshotName)
		if err != nil {
			write(w, http.StatusServiceUnavailable, "cluster: snapshot home lookup: "+err.Error())
			return
		}
		if !ok || node == c.SelfNodeID() {
			// No entry (single-node, pre-index, or node gone) or we hold it:
			// serve locally. The local handler decides 404 vs a local row.
			local.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-Cluster-Forwarded") == "1" {
			cluster.RecordOwnerForwardStale()
			write(w, http.StatusMisdirectedRequest, "cluster: forwarding loop detected")
			return
		}
		for _, m := range c.Members() {
			if m.NodeID != node {
				continue
			}
			if !m.Alive || (m.APIURL == "" && m.InternalURL == "") {
				service.RecordRouteMiss()
				write(w, http.StatusServiceUnavailable, "cluster: node "+node+" holding this snapshot is unavailable")
				return
			}
			c.ForwardHTTP(cluster.Endpoint{NodeID: m.NodeID, InternalURL: m.InternalURL, APIURL: m.APIURL}, w, r)
			return
		}
		// The holding node left the cluster between the index read and the
		// member lookup: its snapshot went with it, so retrying changes nothing.
		w.Header().Set("x-should-retry", "false")
		write(w, http.StatusServiceUnavailable, "cluster: the node holding this snapshot ("+node+") has left the cluster")
	})
}
