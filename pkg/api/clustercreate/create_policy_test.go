package clustercreate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/createpolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestPrepareRefusesByCreatePolicyBeforePlacement: a create the operator's
// policy refuses gets 403 naming the rule even when no node has room for it.
// Live (UC-410, 2026-11-06) the router asked placement first and answered
// 503 "no placement target", so the caller never learned which rule it broke.
func TestPrepareRefusesByCreatePolicyBeforePlacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "create-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nlimits:\n  max_cpu: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), selectErr: cluster.ErrNoPlacementTarget}
	svc := testServiceWithCluster(stub)
	svc.SetCreatePolicy(createpolicy.NewWatcher(path, nil))

	var gotStatus int
	var gotCode string
	writeErr := func(w http.ResponseWriter, status int, code, message string) {
		gotStatus, gotCode = status, code
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
	}
	_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc,
		models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 64}, writeErr, PrepareOptions{})
	if ok || gotStatus != http.StatusForbidden || gotCode != models.ErrorCodeCreatePolicyDenied {
		t.Fatalf("Prepare = ok %v, %d %q; want 403 %q", ok, gotStatus, gotCode, models.ErrorCodeCreatePolicyDenied)
	}
	if len(stub.selectReqs) != 0 {
		t.Fatalf("placement ran for a create the policy refuses: %+v", stub.selectReqs)
	}

	// Inside the limits, placement decides as before (here: no room, 503).
	gotStatus = 0
	_, ok = Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc,
		models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1}, writeErr, PrepareOptions{})
	if ok || gotStatus != http.StatusServiceUnavailable || len(stub.selectReqs) != 1 {
		t.Fatalf("Prepare inside the limits = ok %v, %d, placements %d; want placement's 503", ok, gotStatus, len(stub.selectReqs))
	}
}
