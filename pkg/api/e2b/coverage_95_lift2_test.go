package e2b

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// e2bFacadeListCluster is not *cluster.Noop so listFacadeClusterItems runs the
// placement-page merge instead of the standalone short-circuit.
type e2bFacadeListCluster struct {
	*cluster.Noop
	members       []cluster.Member
	placements    []cluster.Placement
	authoritative bool
	next          string
	byID          map[string]cluster.Member
}

func (c *e2bFacadeListCluster) Members() []cluster.Member { return c.members }
func (c *e2bFacadeListCluster) PlacementPage(req cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	out := make([]cluster.Placement, 0, limit)
	for _, p := range c.placements {
		if req.OwnerRef != "" && p.OwnerRef != req.OwnerRef {
			continue
		}
		out = append(out, p)
		if len(out) >= limit {
			break
		}
	}
	return cluster.PlacementPageResponse{Placements: out, Authoritative: c.authoritative, NextPageToken: c.next}
}
func (c *e2bFacadeListCluster) LookupMember(id string) (cluster.Member, bool) {
	if c.byID != nil {
		m, ok := c.byID[id]
		return m, ok
	}
	for _, m := range c.members {
		if m.NodeID == id {
			return m, true
		}
	}
	return cluster.Member{}, false
}

func e2bItoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

func TestListFacadeClusterItemsE2BBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	local := []listedSandboxResponse{{SandboxID: "sb-local"}, {SandboxID: "sb-other"}}

	t.Run("forwarded_and_nil_service", func(t *testing.T) {
		h := newHandlers(Deps{Logger: logger})
		fwd := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil)
		fwd.Header.Set("X-Cluster-Forwarded", "1")
		items, _, _, ready := h.listFacadeClusterItems(fwd, local)
		if !ready || len(items) != 2 {
			t.Fatalf("forwarded: items=%d ready=%v", len(items), ready)
		}
		items, _, _, ready = h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil), local)
		if !ready || len(items) != 2 {
			t.Fatalf("nil service: items=%d ready=%v", len(items), ready)
		}
	})

	t.Run("nil_cluster", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.ClearClusterForTest()
		h := newHandlers(Deps{Service: svc, Logger: logger})
		items, _, _, ready := h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil), local)
		if !ready || len(items) != 2 {
			t.Fatalf("nil cluster: items=%d ready=%v", len(items), ready)
		}
	})

	t.Run("view_not_ready", func(t *testing.T) {
		members := []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}}
		for i := 0; i < 270; i++ {
			members = append(members, cluster.Member{
				NodeID: "w-" + e2bItoa(i), Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://w",
			})
		}
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&e2bFacadeListCluster{Noop: cluster.NewNoop("self", "http://self", ""), members: members})
		h := newHandlers(Deps{Service: svc, Logger: logger})
		items, cov, _, ready := h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil), local)
		if ready || items != nil || !cov.Partial {
			t.Fatalf("want view not ready, ready=%v partial=%v", ready, cov.Partial)
		}
	})

	t.Run("merge_and_missing_owners", func(t *testing.T) {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]listedSandboxResponse{{SandboxID: "sb-peer"}})
		}))
		t.Cleanup(peer.Close)
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		c := &e2bFacadeListCluster{
			Noop:          cluster.NewNoop("self", "http://self", ""),
			authoritative: true,
			next:          "e2b-next",
			members: []cluster.Member{
				{NodeID: "self", Alive: true, Role: config.NodeRoleMixed},
				{NodeID: "peer-a", Alive: true, Role: config.NodeRoleWorker, InternalURL: peer.URL},
			},
			placements: []cluster.Placement{
				{SandboxID: "sb-local", OwnerNodeID: "self"},
				{SandboxID: "sb-peer", OwnerNodeID: "peer-a"},
				{SandboxID: "sb-ghost", OwnerNodeID: "missing-owner"},
			},
			byID: map[string]cluster.Member{
				"peer-a": {NodeID: "peer-a", Alive: true, Role: config.NodeRoleWorker, InternalURL: peer.URL},
			},
		}
		svc.AttachCluster(c)
		h := newHandlers(Deps{Service: svc, Logger: logger})
		req := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil)
		req.Header.Set("Authorization", "Bearer t")
		items, cov, next, ready := h.listFacadeClusterItems(req, local)
		if !ready || next != "e2b-next" || !cov.Partial {
			t.Fatalf("ready=%v next=%q cov=%+v items=%+v", ready, next, cov, items)
		}
	})
}

func TestListSandboxesClusterModeAndFilters(t *testing.T) {
	svc, _, handler := newE2BHandlerTestEnv(t)
	ctx := context.Background()
	created, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "ubuntu:22.04"})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}

	members := []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}}
	for i := 0; i < 270; i++ {
		members = append(members, cluster.Member{
			NodeID: "w-" + e2bItoa(i), Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://w",
		})
	}
	svc.AttachCluster(&e2bFacadeListCluster{Noop: cluster.NewNoop("self", "http://self", ""), members: members})

	notReady := httptest.NewRecorder()
	handler.ServeHTTP(notReady, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	if notReady.Code != http.StatusServiceUnavailable {
		t.Fatalf("not ready status=%d body=%s", notReady.Code, notReady.Body.String())
	}

	numeric := httptest.NewRecorder()
	handler.ServeHTTP(numeric, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?nextToken=10", nil))
	if numeric.Code != http.StatusBadRequest {
		t.Fatalf("numeric nextToken status=%d body=%s", numeric.Code, numeric.Body.String())
	}

	svc.AttachCluster(&e2bFacadeListCluster{
		Noop:          cluster.NewNoop("self", "http://self", ""),
		authoritative: true,
		next:          "more",
		members:       []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}},
		placements:    []cluster.Placement{{SandboxID: created.ID, OwnerNodeID: "self"}},
	})
	okRR := httptest.NewRecorder()
	handler.ServeHTTP(okRR, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?nextToken=opaque-cursor", nil))
	if okRR.Code != http.StatusOK {
		t.Fatalf("opaque nextToken status=%d body=%s", okRR.Code, okRR.Body.String())
	}
	if okRR.Header().Get("x-next-token") != "more" {
		t.Fatalf("x-next-token = %q", okRR.Header().Get("x-next-token"))
	}

	peerRR := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?ids="+created.ID, nil)
	req.Header.Set("X-Cluster-Forwarded", "1")
	handler.ServeHTTP(peerRR, req)
	if peerRR.Code != http.StatusOK {
		t.Fatalf("forwarded ids filter status=%d", peerRR.Code)
	}

	if clusterListMode(nil, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("nil service")
	}
	fwd := httptest.NewRequest(http.MethodGet, "/", nil)
	fwd.Header.Set("X-Cluster-Forwarded", "1")
	if clusterListMode(svc, fwd) {
		t.Fatal("forwarded hop")
	}
}

func TestListSandboxesNilService(t *testing.T) {
	h := newHandlers(Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	rr := httptest.NewRecorder()
	h.listSandboxes(rr, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("nil service status=%d", rr.Code)
	}
}
