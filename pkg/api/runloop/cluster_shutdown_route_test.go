package runloop

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A Runloop shutdown of a devbox left on a node an operator deleted
// (clusterroute abandoned.go). A gateway or worker sends it to a server;
// the server, which has no row for it, deletes the placement and answers
// with the terminal devbox view the SDKs parse, and records it as its
// tombstone.

const shutdownDeletedNode = "wkr-deleted"

// shutdownGateway is a gateway's view of the cluster: placements and the
// deleted node. It may not delete another node's placement, so it sends
// such a shutdown to a server.
type shutdownGateway struct {
	*cluster.Noop
	mu         sync.Mutex
	placements map[string]cluster.Placement
	toServer   int
}

func newShutdownGateway(ps ...cluster.Placement) *shutdownGateway {
	c := &shutdownGateway{Noop: cluster.NewNoop("gw-1", "http://gw-1", ""), placements: map[string]cluster.Placement{}}
	for _, p := range ps {
		c.placements[p.SandboxID] = p
	}
	return c
}

func (c *shutdownGateway) PlacementOf(id string) (cluster.Placement, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.placements[id]
	return p, ok
}

func (c *shutdownGateway) OwnerOf(id string) (cluster.OwnerInfo, error) {
	p, ok := c.PlacementOf(id)
	switch {
	case !ok:
		return cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
	case p.IsOrphaned():
		return cluster.OwnerInfo{}, cluster.ErrOrphaned
	}
	return cluster.OwnerInfo{NodeID: p.OwnerNodeID, APIURL: "http://" + p.OwnerNodeID}, nil
}

func (c *shutdownGateway) IsNodeDenied(id string) bool { return id == shutdownDeletedNode }

func (c *shutdownGateway) ForwardToServer(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	c.toServer++
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// shutdownServer is a server: it reads the leader's placements and deletes
// an abandoned one (an exact delete of that lifetime).
type shutdownServer struct {
	*shutdownGateway
	readErr error
	deletes int
}

func (c *shutdownServer) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	if c.readErr != nil {
		return nil, c.readErr
	}
	out := map[string]cluster.Placement{}
	for _, id := range ids {
		if p, ok := c.PlacementOf(id); ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *shutdownServer) DeleteAbandonedPlacement(_ context.Context, p cluster.Placement) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur, ok := c.placements[p.SandboxID]; ok && cur.IncarnationID == p.IncarnationID {
		delete(c.placements, p.SandboxID)
		c.deletes++
	}
	return nil
}

var shutdownCreated = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)

func shutdownPlacement(id, owner string, edit func(*cluster.Placement)) cluster.Placement {
	p := cluster.Placement{
		SandboxID: id, OwnerNodeID: shutdownDeletedNode, IncarnationID: "inc-" + id, OwnerRef: owner,
		CreatedUnix: shutdownCreated.Unix(),
		Spec: &models.CreateSandboxRequest{Image: "python:3.12", Tags: map[string]string{"team": "a"},
			CompatState: map[string]string{models.FacadeRunloop: `{"name":"dev","blueprint_id":"bpt-python"}`}},
	}
	if edit != nil {
		edit(&p)
	}
	return p
}

// shutdownNode is the test env as a cluster node in front of c.
func shutdownNode(t *testing.T, c cluster.Client) *testEnv {
	t.Helper()
	env := newTestEnvWithConfig(t, func(cfg *config.Config) { cfg.EnableCluster = true })
	env.svc.AttachCluster(c)
	return env
}

// call sends a devbox call as owner ("" for the fleet operator), with the
// caller's own bearer credential, as the SDKs send it.
func call(t *testing.T, env *testEnv, owner, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	access := controlplane.Access{Fleet: true}
	if owner != "" {
		access = controlplane.Access{Identity: controlplane.Identity{OwnerRef: owner}}
	}
	req := httptest.NewRequest(method, devboxesPath+path, nil)
	req.Header.Set("Authorization", "Bearer tok")
	req = req.WithContext(controlplane.ContextWithAccess(req.Context(), access))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	return rr
}

// On a gateway the shutdown is the delete (clusterShutdownForwardWrap,
// Destroy: true): a devbox left on a deleted node goes to a server once.
// Any other call for it is not a delete: it waits (503) or is gone (410),
// and is never sent.
func TestRunloopShutdownRouteSendsAnAbandonedDevboxToAServer(t *testing.T) {
	for name, edit := range map[string]func(*cluster.Placement){
		"still on the deleted node": nil,
		"orphaned from the deleted node": func(p *cluster.Placement) {
			p.OwnerNodeID, p.OwnerState, p.OrphanedOwnerNodeID = "", cluster.PlacementOwnerStateOrphaned, shutdownDeletedNode
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newShutdownGateway(shutdownPlacement("dbx-gone-1", "acct-a", edit))
			env := shutdownNode(t, c)
			if rr := call(t, env, "acct-a", http.MethodPost, "/dbx-gone-1/shutdown"); rr.Code != http.StatusOK || c.toServer != 1 {
				t.Fatalf("shutdown = %d %q, sent to a server %d times; want it sent once", rr.Code, rr.Body.String(), c.toServer)
			}
			for _, path := range []string{"/dbx-gone-1/suspend", "/dbx-gone-1/keep_alive"} {
				rr := call(t, env, "acct-a", http.MethodPost, path)
				if c.toServer != 1 || (rr.Code != http.StatusServiceUnavailable && rr.Code != http.StatusGone) {
					t.Fatalf("%s = %d, sent to a server %d times; want 503 or 410 and no send", path, rr.Code, c.toServer)
				}
			}
		})
	}
}

// On the server, which has no row: the shutdown removes the placement and
// answers with the terminal view, its name and blueprint from the
// replicated facade state; a retry on this server replays it (the
// tombstone). Another tenant's devbox is 404 and stays.
func TestRunloopShutdownOfAnAbandonedDevboxOnAServer(t *testing.T) {
	t.Run("as its tenant, then a retry", func(t *testing.T) {
		c := &shutdownServer{shutdownGateway: newShutdownGateway(shutdownPlacement("dbx-gone-1", "acct-a", nil))}
		env := shutdownNode(t, c)
		rr := call(t, env, "acct-a", http.MethodPost, "/dbx-gone-1/shutdown")
		if rr.Code != http.StatusOK {
			t.Fatalf("shutdown = %d %q, want 200", rr.Code, rr.Body.String())
		}
		var view devboxView
		if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if view.ID != "dbx-gone-1" || view.Status != statusShutdown || view.ShutdownReason == nil || *view.ShutdownReason != "api_shutdown" ||
			view.EndTimeMs == nil || view.CreateTimeMs != shutdownCreated.UnixMilli() || view.Name == nil || *view.Name != "dev" ||
			view.BlueprintID == nil || *view.BlueprintID != "bpt-python" || view.Metadata["team"] != "a" {
			t.Fatalf("view = %s", rr.Body.String())
		}
		if _, ok := c.PlacementOf("dbx-gone-1"); ok || c.deletes != 1 {
			t.Fatalf("placement left, or deleted %d times; want it deleted once", c.deletes)
		}
		retry := call(t, env, "acct-a", http.MethodPost, "/dbx-gone-1/shutdown")
		if retry.Code != http.StatusOK || retry.Body.String() != rr.Body.String() || c.deletes != 1 {
			t.Fatalf("retry = %d %q, want the same view replayed", retry.Code, retry.Body.String())
		}
	})

	t.Run("another tenant's", func(t *testing.T) {
		c := &shutdownServer{shutdownGateway: newShutdownGateway(shutdownPlacement("dbx-gone-2", "acct-a", nil))}
		env := shutdownNode(t, c)
		if rr := call(t, env, "acct-b", http.MethodPost, "/dbx-gone-2/shutdown"); rr.Code != http.StatusNotFound {
			t.Fatalf("another tenant's shutdown = %d %q, want 404", rr.Code, rr.Body.String())
		}
		if _, ok := c.PlacementOf("dbx-gone-2"); !ok || c.deletes != 0 {
			t.Fatal("another tenant's shutdown touched the placement")
		}
	})

	t.Run("no facade state, or one that does not decode", func(t *testing.T) {
		for _, state := range []map[string]string{nil, {models.FacadeRunloop: "{not json"}} {
			c := &shutdownServer{shutdownGateway: newShutdownGateway(shutdownPlacement("dbx-gone-3", "acct-a", func(p *cluster.Placement) {
				p.Spec.CompatState = state
			}))}
			env := shutdownNode(t, c)
			rr := call(t, env, "", http.MethodPost, "/dbx-gone-3/shutdown")
			var view devboxView
			if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &view) != nil || view.ID != "dbx-gone-3" || view.Status != statusShutdown || view.Name != nil {
				t.Fatalf("shutdown = %d %q, want the view without a name", rr.Code, rr.Body.String())
			}
		}
	})

	t.Run("no leader to read from", func(t *testing.T) {
		c := &shutdownServer{shutdownGateway: newShutdownGateway(shutdownPlacement("dbx-gone-4", "acct-a", nil)),
			readErr: errors.New("cluster: no leader")}
		env := shutdownNode(t, c)
		if rr := call(t, env, "", http.MethodPost, "/dbx-gone-4/shutdown"); rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("shutdown = %d %q, want 503", rr.Code, rr.Body.String())
		}
		if _, ok := c.PlacementOf("dbx-gone-4"); !ok {
			t.Fatal("a failed shutdown lost the placement")
		}
	})

	t.Run("an unknown devbox", func(t *testing.T) {
		env := shutdownNode(t, &shutdownServer{shutdownGateway: newShutdownGateway()})
		if rr := call(t, env, "", http.MethodPost, "/dbx-nobody/shutdown"); rr.Code != http.StatusNotFound {
			t.Fatalf("shutdown = %d %q, want 404", rr.Code, rr.Body.String())
		}
	})
}
