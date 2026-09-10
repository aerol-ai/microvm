package daytona

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

// facadeListCluster is intentionally not *cluster.Noop so listFacadeClusterItems
// takes the real placement-page merge instead of the standalone short-circuit.
type facadeListCluster struct {
	*cluster.Noop
	members       []cluster.Member
	placements    []cluster.Placement
	authoritative bool
	byID          map[string]cluster.Member
}

func (c *facadeListCluster) Members() []cluster.Member { return c.members }
func (c *facadeListCluster) PlacementPage(req cluster.PlacementPageRequest) cluster.PlacementPageResponse {
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
	return cluster.PlacementPageResponse{Placements: out, Authoritative: c.authoritative, NextPageToken: "next-tok"}
}
func (c *facadeListCluster) LookupMember(id string) (cluster.Member, bool) {
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

func TestListFacadeClusterItemsBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	local := []sandboxResponse{{ID: "sb-local"}, {ID: "sb-other"}}

	t.Run("forwarded_and_nil_service", func(t *testing.T) {
		h := newHandlers(Deps{Logger: logger})
		fwd := httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil)
		fwd.Header.Set("X-Cluster-Forwarded", "1")
		items, _, _, ready := h.listFacadeClusterItems(fwd, local)
		if !ready || len(items) != 2 {
			t.Fatalf("forwarded: items=%d ready=%v", len(items), ready)
		}
		items, _, _, ready = h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil), local)
		if !ready || len(items) != 2 {
			t.Fatalf("nil service: items=%d ready=%v", len(items), ready)
		}
	})

	t.Run("nil_cluster", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.ClearClusterForTest()
		h := newHandlers(Deps{Service: svc, Logger: logger})
		items, _, _, ready := h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil), local)
		if !ready || len(items) != 2 {
			t.Fatalf("nil cluster: items=%d ready=%v", len(items), ready)
		}
	})

	t.Run("view_not_ready", func(t *testing.T) {
		members := make([]cluster.Member, 0, 300)
		members = append(members, cluster.Member{NodeID: "self", Alive: true, Role: config.NodeRoleMixed})
		for i := 0; i < 270; i++ {
			members = append(members, cluster.Member{
				NodeID: "w-" + string(rune('a'+(i%26))) + string(rune('0'+i%10)),
				Alive:  true, Role: config.NodeRoleWorker, InternalURL: "https://w",
			})
		}
		// Distinct IDs so SelectPeersForPage counts >256 alive owners.
		members = members[:1]
		for i := 0; i < 270; i++ {
			members = append(members, cluster.Member{
				NodeID:      "owner-" + itoa(i),
				Alive:       true,
				Role:        config.NodeRoleWorker,
				InternalURL: "https://owner-" + itoa(i),
			})
		}
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&facadeListCluster{
			Noop:    cluster.NewNoop("self", "http://self", ""),
			members: members,
		})
		h := newHandlers(Deps{Service: svc, Logger: logger})
		items, cov, _, ready := h.listFacadeClusterItems(httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil), local)
		if ready || items != nil || !cov.Partial {
			t.Fatalf("want view not ready, ready=%v items=%v partial=%v", ready, items, cov.Partial)
		}
	})

	t.Run("merge_and_missing_owners", func(t *testing.T) {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]sandboxResponse{{ID: "sb-peer"}})
		}))
		t.Cleanup(peer.Close)

		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		c := &facadeListCluster{
			Noop:          cluster.NewNoop("self", "http://self", ""),
			authoritative: true,
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
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil)
		req.Header.Set("Authorization", "Bearer t")
		items, cov, next, ready := h.listFacadeClusterItems(req, local)
		if !ready || next != "next-tok" {
			t.Fatalf("ready=%v next=%q", ready, next)
		}
		if !cov.Partial {
			t.Fatalf("missing owner should mark partial: %+v", cov)
		}
		ids := map[string]bool{}
		for _, it := range items {
			ids[it.ID] = true
		}
		if !ids["sb-local"] {
			t.Fatalf("items = %+v, want local page row", items)
		}
	})
}

func TestListSandboxesClusterViewNotReadyAndPageToken(t *testing.T) {
	handler, svc, _ := newDaytonaVolumesTestEnv(t)
	members := []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}}
	for i := 0; i < 270; i++ {
		members = append(members, cluster.Member{
			NodeID: "w-" + itoa(i), Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://w",
		})
	}
	svc.AttachCluster(&facadeListCluster{
		Noop:    cluster.NewNoop("self", "http://self", ""),
		members: members,
	})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil))
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("list status=%d retry=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
	}

	pageRR := httptest.NewRecorder()
	handler.ServeHTTP(pageRR, httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?page=2", nil))
	if pageRR.Code != http.StatusBadRequest {
		t.Fatalf("page>1 without cursor status=%d body=%s", pageRR.Code, pageRR.Body.String())
	}
}

func TestClusterListModeGuards(t *testing.T) {
	if clusterListMode(nil, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("nil service")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fwd := httptest.NewRequest(http.MethodGet, "/", nil)
	fwd.Header.Set("X-Cluster-Forwarded", "1")
	if clusterListMode(svc, fwd) {
		t.Fatal("forwarded hop")
	}
	svc.ClearClusterForTest()
	if clusterListMode(svc, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("nil cluster")
	}
	svc.AttachCluster(&facadeListCluster{Noop: cluster.NewNoop("self", "http://self", "")})
	if !clusterListMode(svc, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("wrapped cluster should enable cluster list mode")
	}
}

func TestListSandboxesPaginatedClusterReady(t *testing.T) {
	handler, svc, _ := newDaytonaVolumesTestEnv(t)
	ctx := context.Background()
	sb, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	svc.AttachCluster(&facadeListCluster{
		Noop:          cluster.NewNoop("self", "http://self", ""),
		authoritative: true,
		members:       []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}},
		placements:    []cluster.Placement{{SandboxID: sb.ID, OwnerNodeID: "self"}},
	})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?page=1&limit=10", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func itoa(i int) string {
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

func TestPersistSandboxMetaAndReplaceLabelsErrors(t *testing.T) {
	handler, svc, st := newDaytonaVolumesTestEnv(t)
	sb, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	_ = st.Close()
	h := newHandlers(Deps{Service: svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := h.persistSandboxMeta(context.Background(), sb.ID, sandboxMeta{}); err == nil {
		t.Fatal("expected persist failure on closed store")
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/daytona/sandbox/"+sb.ID+"/labels", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected replace-labels failure after store close")
	}
}
