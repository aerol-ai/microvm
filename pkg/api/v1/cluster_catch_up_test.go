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
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// catchUpStubCluster is a server-role cluster client whose placement view is
// (or is not) caught up after a restart. A view that has not caught up does
// not yet hold the placement: OwnerOf says unknown, exactly what the
// restarted node's FSM said for sb-46779d2f94047af2 in UC-337.
type catchUpStubCluster struct {
	*cluster.Noop
	caughtUp     bool
	owner        cluster.OwnerInfo
	ownerErr     error
	placement    cluster.Placement
	hasPlacement bool
}

func (c *catchUpStubCluster) PlacementViewCaughtUp() bool { return c.caughtUp }
func (c *catchUpStubCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return c.owner, c.ownerErr
}
func (c *catchUpStubCluster) OwnerOfName(string, string) (string, cluster.OwnerInfo, error) {
	return "", c.owner, c.ownerErr
}
func (c *catchUpStubCluster) OwnerOfNameKey(string) (string, cluster.OwnerInfo, error) {
	return "", c.owner, c.ownerErr
}
func (c *catchUpStubCluster) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.hasPlacement
}

// laggingView is a restarted node whose FSM has not replayed the placement.
func laggingView() *catchUpStubCluster {
	return &catchUpStubCluster{Noop: cluster.NewNoop("node3", "http://node3", ""), ownerErr: cluster.ErrUnknownSandbox}
}

// caughtUpView is the same node after catch-up: unknown now means absent.
func caughtUpView() *catchUpStubCluster {
	v := laggingView()
	v.caughtUp = true
	return v
}

func sandboxRequest(method, id string) *http.Request {
	r := httptest.NewRequest(method, "/v1/sandboxes/"+id, nil)
	r.SetPathValue("id", id)
	return r
}

func createLocalSandboxRow(t *testing.T, st *storepkg.Store, id string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		AuditIncarnationID: "inc-" + id,
		ContainerID:        "ctr-" + id, ContainerIP: "10.0.0.7",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func assertCatchingUp503(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (retry), never a 404 from a view still catching up; body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want %q", got, "1")
	}
	if strings.Contains(rr.Body.String(), "not found") {
		t.Fatalf("body = %s, must not say not found", rr.Body.String())
	}
}

// The UC-337 regression: 0.45s after `systemctl restart sandboxd` node3 took
// DELETE /v1/sandboxes/sb-46779d2f94047af2, its FSM did not hold the
// placement yet, the router fell through to the local store (which never held
// a sandbox owned by another node) and answered 404 in 0.5ms. The sandbox was
// alive; a client that trusts the 404 leaks it, its secrets and its capacity.
func TestClusterDestroyWhileCatchingUpIsRetryableNotNotFound(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, laggingView())

	rr := httptest.NewRecorder()
	h.clusterForwardWrap(http.HandlerFunc(h.clusterDestroyWrap)).ServeHTTP(rr, sandboxRequest(http.MethodDelete, "sb-46779d2f94047af2"))

	assertCatchingUp503(t, rr)
	if len(rt.destroyIDs) != 0 {
		t.Fatalf("runtime destroy ran for a request answered 503: %+v", rt.destroyIDs)
	}
}

// The same reads and lifecycle calls the churn test makes, all routed by the
// one cluster wrapper: none may answer 404 while the view is catching up.
func TestClusterSandboxRoutesWhileCatchingUpAreRetryable(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, laggingView())
	routes := map[string]struct {
		method  string
		handler http.HandlerFunc
	}{
		"get":     {http.MethodGet, h.getSandbox},
		"stop":    {http.MethodPost, h.stopSandbox},
		"start":   {http.MethodPost, h.startSandbox},
		"toolbox": {http.MethodPost, h.toolboxProxy},
	}
	for name, route := range routes {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.clusterForwardWrap(route.handler).ServeHTTP(rr, sandboxRequest(route.method, "sb-placed-elsewhere"))
			assertCatchingUp503(t, rr)
		})
	}
}

// Once the view has caught up, an id it does not hold is truly absent: 404.
func TestClusterMissingSandboxCaughtUpStill404(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, caughtUpView())
	for _, tc := range []struct {
		method  string
		handler http.HandlerFunc
	}{
		{http.MethodGet, h.getSandbox},
		{http.MethodDelete, h.clusterDestroyWrap},
	} {
		rr := httptest.NewRecorder()
		h.clusterForwardWrap(tc.handler).ServeHTTP(rr, sandboxRequest(tc.method, "sb-truly-gone"))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404 once caught up; body=%s", tc.method, rr.Code, rr.Body.String())
		}
		if rr.Header().Get("Retry-After") != "" {
			t.Fatalf("%s: a definite 404 carries no Retry-After", tc.method)
		}
	}
}

// Only the not-found answer is gated: a sandbox this node holds is served
// while the view catches up, whether the stale view says "unknown" (placed
// after the restored snapshot) or "self".
func TestClusterLocalRowServedWhileCatchingUp(t *testing.T) {
	selfView := laggingView()
	selfView.ownerErr = nil
	selfView.owner = cluster.OwnerInfo{NodeID: "node3", IsSelf: true}
	for name, view := range map[string]*catchUpStubCluster{"unknown placement": laggingView(), "self-owned": selfView} {
		t.Run(name, func(t *testing.T) {
			rt := &apiRecordingRuntime{}
			h, st := newClusterCreateHarness(t, rt, view)

			rr := httptest.NewRecorder()
			h.clusterForwardWrap(http.HandlerFunc(h.getSandbox)).ServeHTTP(rr, sandboxRequest(http.MethodGet, "sb-local"))
			assertCatchingUp503(t, rr)

			createLocalSandboxRow(t, st, "sb-local")
			rr = httptest.NewRecorder()
			h.clusterForwardWrap(http.HandlerFunc(h.getSandbox)).ServeHTTP(rr, sandboxRequest(http.MethodGet, "sb-local"))
			if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "sb-local") {
				t.Fatalf("status = %d body=%s, want the local row served", rr.Code, rr.Body.String())
			}
		})
	}
}

// Single-node mode has no placement view to catch up: the store is the whole
// truth, opened before the listener, so a missing id is a 404 as before.
func TestSingleNodeMissingSandboxStill404(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("standalone", "", ""))
	rr := httptest.NewRecorder()
	h.clusterForwardWrap(http.HandlerFunc(h.clusterDestroyWrap)).ServeHTTP(rr, sandboxRequest(http.MethodDelete, "sb-missing"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

// A worker or ingress agent asks a server for the placement and reads 404 as
// "no such sandbox"; a server still catching up must answer 503 so the agent
// asks the next server instead (cluster.Agent.doControlPlaneBytes).
func TestClusterInternalLookupsWhileCatchingUp(t *testing.T) {
	encodedName := base64.RawURLEncoding.EncodeToString([]byte("my-box"))
	calls := []struct {
		name string
		call func(h *handlers) *httptest.ResponseRecorder
		// caughtUp is the status once the view has caught up.
		caughtUp int
	}{
		{name: "placement by id", caughtUp: http.StatusNotFound, call: func(h *handlers) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementPath+"sb-x", nil)
			r.SetPathValue("id", "sb-x")
			rr := httptest.NewRecorder()
			h.clusterInternalPlacement(rr, r)
			return rr
		}},
		{name: "placement by name", caughtUp: http.StatusNotFound, call: func(h *handlers) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementByNamePath+encodedName, nil)
			r.SetPathValue("name", encodedName)
			rr := httptest.NewRecorder()
			h.clusterInternalPlacementByName(rr, r)
			return rr
		}},
		{name: "placements by ids", caughtUp: http.StatusOK, call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.clusterInternalPlacementsByIDs(rr, httptest.NewRequest(http.MethodPost, cluster.PublicInternalPlacementsByIDsPath, strings.NewReader(`{"ids":["sb-x"]}`)))
			return rr
		}},
		{name: "placements page", caughtUp: http.StatusOK, call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.clusterInternalPlacementsPage(rr, httptest.NewRequest(http.MethodPost, cluster.PublicInternalPlacementsPagePath, strings.NewReader(`{}`)))
			return rr
		}},
		{name: "all placements", caughtUp: http.StatusOK, call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.clusterInternalPlacements(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementsPath, nil))
			return rr
		}},
		{name: "snapshot home node", caughtUp: http.StatusOK, call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.clusterInternalSnapshotNode(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalSnapshotNodePath+"?name=snap-a", nil))
			return rr
		}},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newClusterCreateHarness(t, &apiRecordingRuntime{}, laggingView())
			assertCatchingUp503(t, tc.call(h))

			h, _ = newClusterCreateHarness(t, &apiRecordingRuntime{}, caughtUpView())
			if rr := tc.call(h); rr.Code != tc.caughtUp {
				t.Fatalf("caught up: status = %d, want %d; body=%s", rr.Code, tc.caughtUp, rr.Body.String())
			}
		})
	}
}

// Lists and operator reads built on the placement view: a view still catching
// up would answer "no such sandbox" (an empty name match, a 404 placement, a
// fleet index that skips rows).
func TestClusterListAndOperatorReadsWhileCatchingUp(t *testing.T) {
	calls := []struct {
		name     string
		call     func(h *handlers) *httptest.ResponseRecorder
		caughtUp int
	}{
		{name: "list by name", caughtUp: http.StatusOK, call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.clusterListWrap(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes?name=my-box", nil))
			return rr
		}},
		{name: "placement", caughtUp: http.StatusNotFound, call: func(h *handlers) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, "/v1/cluster/placements/sb-x", nil)
			r.SetPathValue("id", "sb-x")
			rr := httptest.NewRecorder()
			h.clusterPlacement(rr, r)
			return rr
		}},
		{name: "sandbox index", caughtUp: http.StatusOK, call: func(h *handlers) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.writeClusterSandboxIndex(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/sandbox-index", nil))
			return rr
		}},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newClusterCreateHarness(t, &apiRecordingRuntime{}, laggingView())
			assertCatchingUp503(t, tc.call(h))

			h, _ = newClusterCreateHarness(t, &apiRecordingRuntime{}, caughtUpView())
			if rr := tc.call(h); rr.Code != tc.caughtUp {
				t.Fatalf("caught up: status = %d, want %d; body=%s", rr.Code, tc.caughtUp, rr.Body.String())
			}
		})
	}
}
