package v1

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func newNameLookupEnv(t *testing.T) (*handlers, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}, st
}

func seedNamedSandbox(t *testing.T, st *store.Store, id, ownerRef, name string, tags map[string]string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		PublicURL: "https://" + id + ".example.test", ContainerID: "ctr-" + id, ContainerIP: "10.0.0.10",
		CPU: 1, MemoryMB: 512, DiskGB: 10, OSUser: "root", Name: name, OwnerRef: ownerRef, Tags: tags,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("create %s: %v", id, err)
	}
}

func tenantRequest(r *http.Request, ownerRef string) *http.Request {
	access := controlplane.Access{Operator: true}
	if ownerRef != "" {
		access = controlplane.Access{Identity: controlplane.Identity{OwnerRef: ownerRef}}
	}
	return r.WithContext(controlplane.ContextWithAccess(r.Context(), access))
}

func decodeSandboxList(t *testing.T, rr *httptest.ResponseRecorder) []models.Sandbox {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var out []models.Sandbox
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v (body %s)", err, rr.Body.String())
	}
	return out
}

func TestListSandboxesByNameSingleNode(t *testing.T) {
	h, st := newNameLookupEnv(t)
	seedNamedSandbox(t, st, "sb-a", "acct-a", "agent", map[string]string{"team": "x"})
	seedNamedSandbox(t, st, "sb-b", "acct-b", "agent", nil)
	seedNamedSandbox(t, st, "sb-op", "", "agent", nil)
	seedNamedSandbox(t, st, "sb-other", "acct-a", "other", nil)

	tests := []struct {
		name     string
		query    string
		ownerRef string
		wantIDs  []string
	}{
		{name: "tenant a", query: "?name=agent", ownerRef: "acct-a", wantIDs: []string{"sb-a"}},
		{name: "tenant b same name", query: "?name=agent", ownerRef: "acct-b", wantIDs: []string{"sb-b"}},
		{name: "operator namespace", query: "?name=agent", wantIDs: []string{"sb-op"}},
		{name: "other tenant's name reads as empty", query: "?name=other", ownerRef: "acct-b", wantIDs: []string{}},
		{name: "missing name", query: "?name=nope", ownerRef: "acct-a", wantIDs: []string{}},
		{name: "tag filter still applies", query: "?name=agent&tag.team=y", ownerRef: "acct-a", wantIDs: []string{}},
		{name: "tag filter match", query: "?name=agent&tag.team=x", ownerRef: "acct-a", wantIDs: []string{"sb-a"}},
		{name: "blank name is no filter", query: "?name=%20", ownerRef: "acct-a", wantIDs: []string{"sb-a", "sb-other"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tenantRequest(httptest.NewRequest(http.MethodGet, "/v1/sandboxes"+tt.query, nil), tt.ownerRef)
			rr := httptest.NewRecorder()
			h.clusterListWrap(rr, req)
			got := decodeSandboxList(t, rr)
			ids := make(map[string]bool, len(got))
			for _, sb := range got {
				ids[sb.ID] = true
			}
			if len(got) != len(tt.wantIDs) {
				t.Fatalf("got %d rows %v, want %v", len(got), ids, tt.wantIDs)
			}
			for _, id := range tt.wantIDs {
				if !ids[id] {
					t.Fatalf("missing %s in %v", id, ids)
				}
			}
		})
	}
}

// nameLookupStubCluster drives the cluster ?name= branch without a real FSM.
// placementPages counts list-page reads: a name lookup must never reach the
// fan-out path.
type nameLookupStubCluster struct {
	*cluster.Noop
	id             string
	owner          cluster.OwnerInfo
	err            error
	gotOwnerRef    string
	gotName        string
	forwards       int
	forwardTarget  cluster.Endpoint
	placementPages int
}

func (c *nameLookupStubCluster) OwnerOfName(ownerRef, name string) (string, cluster.OwnerInfo, error) {
	c.gotOwnerRef, c.gotName = ownerRef, name
	return c.id, c.owner, c.err
}

func (c *nameLookupStubCluster) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, _ *http.Request) {
	c.forwards++
	c.forwardTarget = target
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `[{"id":"sb-remote","name":"agent"}]`)
}

func (c *nameLookupStubCluster) PlacementPage(req cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	c.placementPages++
	return c.Noop.PlacementPage(req)
}

var _ cluster.Client = (*nameLookupStubCluster)(nil)

func TestClusterListByName(t *testing.T) {
	remote := cluster.OwnerInfo{NodeID: "node-b", InternalURL: "https://node-b.internal", APIURL: "https://node-b"}
	tests := []struct {
		name        string
		stub        nameLookupStubCluster
		forwarded   bool
		wantStatus  int
		wantIDs     []string
		wantForward int
	}{
		{name: "owned by a peer forwards once", stub: nameLookupStubCluster{id: "sb-remote", owner: remote}, wantStatus: http.StatusOK, wantIDs: []string{"sb-remote"}, wantForward: 1},
		{name: "owned by self answers locally", stub: nameLookupStubCluster{id: "sb-a", owner: cluster.OwnerInfo{NodeID: "node-a", IsSelf: true}}, wantStatus: http.StatusOK, wantIDs: []string{"sb-a"}},
		{name: "unknown to the index answers locally", stub: nameLookupStubCluster{err: cluster.ErrUnknownSandbox}, wantStatus: http.StatusOK, wantIDs: []string{"sb-a"}},
		{name: "orphaned is retryable", stub: nameLookupStubCluster{id: "sb-x", err: cluster.ErrOrphaned}, wantStatus: http.StatusServiceUnavailable},
		{name: "control plane failure", stub: nameLookupStubCluster{err: errors.New("control plane down")}, wantStatus: http.StatusServiceUnavailable},
		{name: "owner url unknown", stub: nameLookupStubCluster{id: "sb-remote", owner: cluster.OwnerInfo{NodeID: "node-b"}}, wantStatus: http.StatusServiceUnavailable},
		{name: "forwarded request answers locally", stub: nameLookupStubCluster{id: "sb-remote", owner: remote}, forwarded: true, wantStatus: http.StatusOK, wantIDs: []string{"sb-a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, st := newNameLookupEnv(t)
			seedNamedSandbox(t, st, "sb-a", "acct-a", "agent", nil)
			stub := tt.stub
			stub.Noop = cluster.NewNoop("node-a", "http://node-a", "")
			h.deps.Service.AttachCluster(&stub)

			req := tenantRequest(httptest.NewRequest(http.MethodGet, "/v1/sandboxes?name=agent", nil), "acct-a")
			if tt.forwarded {
				req.Header.Set("X-Cluster-Forwarded", "1")
			}
			rr := httptest.NewRecorder()
			h.clusterListWrap(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if stub.forwards != tt.wantForward {
				t.Fatalf("forwards = %d, want %d", stub.forwards, tt.wantForward)
			}
			if stub.placementPages != 0 {
				t.Fatalf("a name lookup reached the list fan-out (%d placement pages)", stub.placementPages)
			}
			if !tt.forwarded && (stub.gotOwnerRef != "acct-a" || stub.gotName != "agent") {
				t.Fatalf("OwnerOfName(%q, %q), want (acct-a, agent)", stub.gotOwnerRef, stub.gotName)
			}
			if tt.wantStatus != http.StatusOK {
				return
			}
			got := decodeSandboxList(t, rr)
			if len(got) != len(tt.wantIDs) || (len(got) == 1 && got[0].ID != tt.wantIDs[0]) {
				t.Fatalf("rows = %+v, want %v", got, tt.wantIDs)
			}
		})
	}
}

// TestSingleNodeListHonorsLimit pins that ?limit= pages in single-node mode
// too (it used to be a cluster-only parameter), while a request with neither
// limit nor page_token still gets every row in one response.
func TestSingleNodeListHonorsLimit(t *testing.T) {
	h, st := newNameLookupEnv(t)
	for _, id := range []string{"sb-c", "sb-a", "sb-b"} {
		seedNamedSandbox(t, st, id, "", "", nil)
	}
	get := func(query string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.clusterListWrap(rr, tenantRequest(httptest.NewRequest(http.MethodGet, "/v1/sandboxes"+query, nil), ""))
		return rr
	}
	if all := decodeSandboxList(t, get("")); len(all) != 3 {
		t.Fatalf("unpaged list = %d rows, want 3", len(all))
	}
	var ids []string
	query := "?limit=2"
	for i := 0; i < 5; i++ {
		rr := get(query)
		for _, sb := range decodeSandboxList(t, rr) {
			ids = append(ids, sb.ID)
		}
		next := rr.Header().Get("X-Cluster-List-Next-Page-Token")
		if next == "" {
			break
		}
		query = "?limit=2&page_token=" + next
	}
	if len(ids) != 3 || ids[0] != "sb-a" || ids[1] != "sb-b" || ids[2] != "sb-c" {
		t.Fatalf("paged ids = %v, want [sb-a sb-b sb-c]", ids)
	}
	if rr := get("?limit=2&page_token=not-ours"); rr.Code != http.StatusBadRequest {
		t.Fatalf("foreign page token status = %d, want 400", rr.Code)
	}
}
