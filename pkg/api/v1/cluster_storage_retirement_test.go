package v1

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

type retirementMembersCluster struct {
	*cluster.Noop
	members []cluster.Member
}

func (c *retirementMembersCluster) Members() []cluster.Member {
	return append([]cluster.Member(nil), c.members...)
}
func (c *retirementMembersCluster) LocalMembers() []cluster.Member { return c.Members() }

func newRetirementHandlers(t *testing.T) *handlers {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(config.Config{DBPath: dbPath, EnableCluster: true}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&retirementMembersCluster{
		Noop: cluster.NewNoop("node-self", "http://node-self", ""),
		members: []cluster.Member{
			{NodeID: "node-self", Alive: true},
			{NodeID: "node-live", Alive: true},
			{NodeID: "node-gone", Alive: false},
		},
	})
	t.Cleanup(svc.CloseSecretAuditSink)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}
}

func asOperator(r *http.Request, operator bool) *http.Request {
	return r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.Access{
		Identity: controlplane.Identity{ExternalID: "op-1"},
		Operator: operator,
	}))
}

func retireReq(t *testing.T, method, id, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "/v1/cluster/nodes/"+id+"/storage-retired", nil)
	} else {
		r = httptest.NewRequest(method, "/v1/cluster/nodes/"+id+"/storage-retired", strings.NewReader(body))
	}
	r.SetPathValue("id", id)
	return r
}

// Discharging a deletion obligation without an ACK is the most consequential
// thing an operator can do to the evidence trail, so the endpoint is
// operator-only and refuses a node that is still alive.
func TestClusterStorageRetirementIsOperatorOnlyAndRefusesLiveNodes(t *testing.T) {
	h := newRetirementHandlers(t)

	tenant := httptest.NewRecorder()
	h.clusterRetireNodeStorage(tenant, asOperator(retireReq(t, http.MethodPost, "node-gone", ""), false))
	if tenant.Code != http.StatusForbidden {
		t.Fatalf("non-operator attestation = %d, want 403", tenant.Code)
	}

	live := httptest.NewRecorder()
	h.clusterRetireNodeStorage(live, asOperator(retireReq(t, http.MethodPost, "node-live", `{"reason":"oops"}`), true))
	if live.Code != http.StatusConflict {
		t.Fatalf("attesting a live node = %d, want 409", live.Code)
	}

	blank := httptest.NewRecorder()
	h.clusterRetireNodeStorage(blank, asOperator(retireReq(t, http.MethodPost, "", ""), true))
	if blank.Code != http.StatusBadRequest {
		t.Fatalf("blank node id = %d, want 400", blank.Code)
	}
}

// Record, list, revoke — the operator can always answer "why is this
// obligation gone?".
func TestClusterStorageRetirementRecordListRevoke(t *testing.T) {
	h := newRetirementHandlers(t)

	rr := httptest.NewRecorder()
	h.clusterRetireNodeStorage(rr, asOperator(retireReq(t, http.MethodPost, "node-gone", `{"reason":"disk destroyed"}`), true))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("attestation = %d body=%s", rr.Code, rr.Body.String())
	}

	listRR := httptest.NewRecorder()
	listReq := asOperator(httptest.NewRequest(http.MethodGet, "/v1/cluster/storage-retirements", nil), true)
	h.clusterListNodeStorageRetirements(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list = %d", listRR.Code)
	}
	var listed struct {
		Retirements []struct {
			NodeID string `json:"node_id"`
			Actor  string `json:"actor"`
			Reason string `json:"reason"`
		} `json:"retirements"`
	}
	if err := json.Unmarshal(listRR.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listed.Retirements) != 1 || listed.Retirements[0].NodeID != "node-gone" ||
		listed.Retirements[0].Actor != "op-1" || listed.Retirements[0].Reason != "disk destroyed" {
		t.Fatalf("listing = %+v; the attestation must name who attested and why", listed.Retirements)
	}

	// Re-attesting is idempotent.
	again := httptest.NewRecorder()
	h.clusterRetireNodeStorage(again, asOperator(retireReq(t, http.MethodPost, "node-gone", ""), true))
	if again.Code != http.StatusNoContent {
		t.Fatalf("re-attestation = %d", again.Code)
	}

	revoke := httptest.NewRecorder()
	h.clusterRevokeNodeStorageRetirement(revoke, asOperator(retireReq(t, http.MethodDelete, "node-gone", ""), true))
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d", revoke.Code)
	}
	// Revoking again is also idempotent.
	revokeAgain := httptest.NewRecorder()
	h.clusterRevokeNodeStorageRetirement(revokeAgain, asOperator(retireReq(t, http.MethodDelete, "node-gone", ""), true))
	if revokeAgain.Code != http.StatusNoContent {
		t.Fatalf("second revoke = %d", revokeAgain.Code)
	}

	after, err := h.deps.Service.ListNodeStorageRetirements(context.Background())
	if err != nil || len(after) != 0 {
		t.Fatalf("after revoke: %+v err=%v", after, err)
	}

	tenantList := httptest.NewRecorder()
	h.clusterListNodeStorageRetirements(tenantList, asOperator(httptest.NewRequest(http.MethodGet, "/v1/cluster/storage-retirements", nil), false))
	if tenantList.Code != http.StatusForbidden {
		t.Fatalf("non-operator list = %d, want 403", tenantList.Code)
	}
	tenantRevoke := httptest.NewRecorder()
	h.clusterRevokeNodeStorageRetirement(tenantRevoke, asOperator(retireReq(t, http.MethodDelete, "node-gone", ""), false))
	if tenantRevoke.Code != http.StatusForbidden {
		t.Fatalf("non-operator revoke = %d, want 403", tenantRevoke.Code)
	}
}
