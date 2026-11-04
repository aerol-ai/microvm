package daytona

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestResolveSandboxByNameStaysInCallerOwner pins D4 for the Daytona facade:
// names are unique per owner, so two tenants can hold the same name and each
// resolves its own. A tenant without the name gets 404, not a peek at
// another tenant's sandbox.
func TestResolveSandboxByNameStaysInCallerOwner(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	for id, ownerRef := range map[string]string{"sb-scope-a": "acct-a", "sb-scope-b": "acct-b"} {
		if err := st.Upsert(context.Background(), &models.Sandbox{
			ID: id, Name: "shared-name", OwnerRef: ownerRef, Status: models.SandboxStatusStarted,
			ToolboxEnabled: true, ContainerID: "ctr-" + id, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("Upsert %s: %v", id, err)
		}
	}
	get := func(ownerRef string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/shared-name", nil)
		req.SetPathValue("idOrName", "shared-name")
		req = req.WithContext(controlplane.ContextWithAccess(req.Context(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: ownerRef}}))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	for ownerRef, wantID := range map[string]string{"acct-a": "sb-scope-a", "acct-b": "sb-scope-b"} {
		rr := get(ownerRef)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status = %d body=%s", ownerRef, rr.Code, rr.Body.String())
		}
		var body struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: decode: %v", ownerRef, err)
		}
		if body.ID != wantID {
			t.Fatalf("%s resolved %q, want %q", ownerRef, body.ID, wantID)
		}
	}
	if rr := get("acct-c"); rr.Code != http.StatusNotFound {
		t.Fatalf("other tenant: status = %d, want 404 (body=%s)", rr.Code, rr.Body.String())
	}
}
