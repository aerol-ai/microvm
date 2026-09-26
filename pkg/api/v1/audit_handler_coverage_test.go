package v1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

func TestParseSecretAuditQueryAndAuditHandlers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/x/audit?cursor=c1&kind=read&incarnation_id=inc-1&limit=7", nil)
	q := parseSecretAuditQuery(req)
	if q.Cursor != "c1" || q.Kind != "read" || q.IncarnationID != "inc-1" || q.Limit != 7 {
		t.Fatalf("query = %+v", q)
	}
	badLimit := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/x/audit?limit=nope", nil)
	if parseSecretAuditQuery(badLimit).Limit != 0 {
		t.Fatal("invalid limit must stay zero")
	}

	h, sbID := newAuditTestHandler(t, nil)
	missing := httptest.NewRecorder()
	h.getSandboxAudit(missing, httptest.NewRequest(http.MethodGet, "/v1/sandboxes//audit", nil))
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing id status = %d", missing.Code)
	}

	// Multiple members + no placement/ACL index is the incomplete-fanout refuse.
	multi := &membersStubCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "node-b", Alive: true, Role: config.NodeRoleWorker},
		},
	}
	h.deps.Service.AttachCluster(multi)
	incRR := httptest.NewRecorder()
	incReq := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/"+sbID+"/audit", nil)
	incReq.SetPathValue("id", sbID)
	h.getSandboxAudit(incRR, incReq)
	if incRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("incomplete index status = %d body=%s", incRR.Code, incRR.Body.String())
	}

	internalMissing := httptest.NewRecorder()
	h.clusterInternalSandboxAudit(internalMissing, httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/sandboxes//audit", nil))
	if internalMissing.Code != http.StatusBadRequest {
		t.Fatalf("internal missing id status = %d", internalMissing.Code)
	}

	alt := httptest.NewRequest(http.MethodGet, "/internal/audit", nil)
	alt.SetPathValue("sandboxID", sbID)
	h.deps.Service.ClearClusterForTest()
	altRR := httptest.NewRecorder()
	h.clusterInternalSandboxAudit(altRR, alt)
	if altRR.Code != http.StatusOK || !strings.Contains(altRR.Body.String(), `"local"`) {
		t.Fatalf("sandboxID path / nil cluster: status=%d body=%s", altRR.Code, altRR.Body.String())
	}
}
