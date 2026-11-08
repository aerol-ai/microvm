package v1

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// staleReadStubCluster is a server whose placement view holds sandbox sb-x
// owned by worker-a. stale says whether this server has lost contact with
// the raft leader (cluster.LeaderContactReporter); staleAfterPark flips it
// while a change-feed poll is parked, which is a partition starting in the
// middle of a long poll.
type staleReadStubCluster struct {
	*cluster.Noop
	stale          bool
	staleAfterPark bool
}

func (c *staleReadStubCluster) PlacementViewStale() bool { return c.stale }

func (c *staleReadStubCluster) placement() cluster.Placement {
	return cluster.Placement{SandboxID: "sb-x", OwnerNodeID: "worker-a", OwnerAPIURL: "http://worker-a", IncarnationID: "inc-x", State: cluster.PlacementStatePlaced}
}

func (c *staleReadStubCluster) PlacementOf(id string) (cluster.Placement, bool) {
	if id != "sb-x" {
		return cluster.Placement{}, false
	}
	return c.placement(), true
}

func (c *staleReadStubCluster) OwnerOf(id string) (cluster.OwnerInfo, error) {
	if id != "sb-x" {
		return cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
	}
	return cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a"}, nil
}

func (c *staleReadStubCluster) OwnerOfNameKey(string) (string, cluster.OwnerInfo, error) {
	return "sb-x", cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a"}, nil
}

func (c *staleReadStubCluster) Placements() []cluster.Placement {
	return []cluster.Placement{c.placement()}
}

func (c *staleReadStubCluster) PlacementsForShards(cluster.PlacementShardFilter) []cluster.Placement {
	return c.Placements()
}

func (c *staleReadStubCluster) PlacementPage(cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	return cluster.PlacementPageResponse{Placements: c.Placements()}
}

func (c *staleReadStubCluster) PlacementsByIDs([]string) map[string]cluster.Placement {
	return map[string]cluster.Placement{"sb-x": c.placement()}
}

func (c *staleReadStubCluster) PlacementChanges(context.Context, uint64, time.Duration) cluster.PlacementChangesResponse {
	if c.staleAfterPark {
		c.stale = true
	}
	return cluster.PlacementChangesResponse{Next: 7}
}

func (c *staleReadStubCluster) OwnedRecoveryPlacements(string, int, string) cluster.OwnedRecoveryResponse {
	return cluster.OwnedRecoveryResponse{Placements: c.Placements(), Authoritative: true}
}

// staleReadCalls are every internal placement read a worker or ingress agent
// makes against a server. Each one used to be answered from the server's own
// FSM whether or not that server could still hear its leader.
func staleReadCalls() []struct {
	name string
	call func(h *handlers) *httptest.ResponseRecorder
} {
	encodedName := base64.RawURLEncoding.EncodeToString([]byte("my-box"))
	return []struct {
		name string
		call func(h *handlers) *httptest.ResponseRecorder
	}{
		{name: "placement by id", call: func(h *handlers) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementPath+"sb-x", nil)
			r.SetPathValue("id", "sb-x")
			rr := httptest.NewRecorder()
			h.clusterInternalPlacement(rr, r)
			return rr
		}},
		{name: "placement by name", call: func(h *handlers) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementByNamePath+encodedName, nil)
			r.SetPathValue("name", encodedName)
			rr := httptest.NewRecorder()
			h.clusterInternalPlacementByName(rr, r)
			return rr
		}},
		{name: "all placements", call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.clusterInternalPlacements(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementsPath, nil))
			return rr
		}},
		{name: "placements query", call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.clusterInternalPlacementsQuery(rr, httptest.NewRequest(http.MethodPost, cluster.PublicInternalPlacementsQueryPath, strings.NewReader(`{}`)))
			return rr
		}},
		{name: "placements page", call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.clusterInternalPlacementsPage(rr, httptest.NewRequest(http.MethodPost, cluster.PublicInternalPlacementsPagePath, strings.NewReader(`{}`)))
			return rr
		}},
		{name: "placements by ids", call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.clusterInternalPlacementsByIDs(rr, httptest.NewRequest(http.MethodPost, cluster.PublicInternalPlacementsByIDsPath, strings.NewReader(`{"ids":["sb-x"]}`)))
			return rr
		}},
		{name: "placement changes", call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.clusterInternalPlacementChanges(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementChangesPath+"?since=3", nil))
			return rr
		}},
		{name: "owned recovery", call: func(h *handlers) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, cluster.PublicInternalOwnedRecoveryPath, strings.NewReader(`{}`))
			r = r.WithContext(context.WithValue(r.Context(), clusterPeerNodeIDContextKey{}, "worker-a"))
			rr := httptest.NewRecorder()
			h.clusterInternalOwnedRecovery(rr, r)
			return rr
		}},
	}
}

func assertStaleRead503(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 from a server cut off from its leader; body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want %q", got, "2")
	}
	if strings.Contains(rr.Body.String(), "worker-a") {
		t.Fatalf("body = %s: a refused read must not carry the stale owner", rr.Body.String())
	}
}

// TestStaleFollowerRefusesInternalPlacementReads is the I7 regression: a
// follower cut off from the leader answered every internal placement read
// from its own FSM, so a worker or ingress on its side of a partition kept
// routing to the owner it last knew, even after the leader moved the sandbox.
// It must answer 503, so the agent asks the next server (doControlPlaneBytes
// moves on after a 503) and stops trusting this one.
func TestStaleFollowerRefusesInternalPlacementReads(t *testing.T) {
	for _, tc := range staleReadCalls() {
		t.Run(tc.name, func(t *testing.T) {
			h := placementChangesHandlers(t, &staleReadStubCluster{Noop: cluster.NewNoop("srv-b", "", ""), stale: true})
			assertStaleRead503(t, tc.call(h))
		})
	}
}

// A server in contact with its leader (and the leader itself, which never
// reports stale) serves the same reads as before.
func TestFreshServerStillServesInternalPlacementReads(t *testing.T) {
	for _, tc := range staleReadCalls() {
		t.Run(tc.name, func(t *testing.T) {
			h := placementChangesHandlers(t, &staleReadStubCluster{Noop: cluster.NewNoop("srv-a", "", "")})
			rr := tc.call(h)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 from a server in contact with its leader; body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// A change-feed poll parks for up to its wait. If the server loses its leader
// while the poll is parked, the "nothing changed" it would answer is exactly
// the stale view the gate exists to refuse.
func TestPlacementChangesRefusedWhenServerGoesStaleDuringThePark(t *testing.T) {
	h := placementChangesHandlers(t, &staleReadStubCluster{Noop: cluster.NewNoop("srv-b", "", ""), staleAfterPark: true})
	rr := httptest.NewRecorder()
	h.clusterInternalPlacementChanges(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementChangesPath+"?since=3&wait=1s", nil))
	assertStaleRead503(t, rr)
}
