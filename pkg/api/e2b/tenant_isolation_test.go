package e2b

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// tenantRequest issues one E2B request as a validated user token for owner.
func tenantRequest(t *testing.T, handler http.Handler, owner, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{ExternalID: owner, OwnerRef: owner},
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// TestE2BDeterministicCreateIsTenantScoped pins the cross-tenant disclosure
// closed: two tenants sending a byte-identical create body must never share a
// deterministic sandbox ID, a create-idempotency key, or an envd access token.
//
// Cluster is disabled here on purpose — the original defect was reachable in
// single-node mode, where the Noop placement client accepts any preferred
// sandbox ID and CreateSandboxWithID answered from the local row.
func TestE2BDeterministicCreateIsTenantScoped(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)

	// secure:true makes the response carry envdAccessToken (the toolbox token).
	body := `{"templateID":"base","metadata":{"team":"sdk"},"timeout":120,"secure":true}`

	first := tenantRequest(t, handler, "tenant-a", http.MethodPost, "/e2b/sandboxes", body)
	if first.Code != http.StatusCreated {
		t.Fatalf("tenant-a create status = %d, want 201; body=%s", first.Code, first.Body.String())
	}
	var a sandboxResponse
	if err := json.NewDecoder(first.Body).Decode(&a); err != nil {
		t.Fatalf("decode tenant-a response error = %v", err)
	}
	if a.EnvdAccessToken == "" {
		t.Fatal("tenant-a response missing envdAccessToken; the test cannot prove isolation")
	}

	second := tenantRequest(t, handler, "tenant-b", http.MethodPost, "/e2b/sandboxes", body)
	if second.Code != http.StatusCreated {
		t.Fatalf("tenant-b create status = %d, want 201; body=%s", second.Code, second.Body.String())
	}
	var b sandboxResponse
	if err := json.NewDecoder(second.Body).Decode(&b); err != nil {
		t.Fatalf("decode tenant-b response error = %v", err)
	}

	if a.SandboxID == b.SandboxID {
		t.Fatalf("both tenants got sandbox id %q: the deterministic id is not owner-bound", a.SandboxID)
	}
	if b.EnvdAccessToken == a.EnvdAccessToken {
		t.Fatal("tenant-b was handed tenant-a's envd access token")
	}
}

// TestE2BSameTenantCreateStaysIdempotent guards the other direction: binding
// the fingerprint to the owner must not break replay for the tenant that owns
// the row. Two identical creates from one tenant still collapse to one sandbox.
func TestE2BSameTenantCreateStaysIdempotent(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)

	body := `{"templateID":"base","timeout":120,"secure":true}`

	first := tenantRequest(t, handler, "tenant-a", http.MethodPost, "/e2b/sandboxes", body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, want 201; body=%s", first.Code, first.Body.String())
	}
	var a sandboxResponse
	if err := json.NewDecoder(first.Body).Decode(&a); err != nil {
		t.Fatalf("decode first response error = %v", err)
	}

	second := tenantRequest(t, handler, "tenant-a", http.MethodPost, "/e2b/sandboxes", body)
	if second.Code != http.StatusCreated {
		t.Fatalf("replay create status = %d, want 201; body=%s", second.Code, second.Body.String())
	}
	var b sandboxResponse
	if err := json.NewDecoder(second.Body).Decode(&b); err != nil {
		t.Fatalf("decode replay response error = %v", err)
	}
	if a.SandboxID != b.SandboxID {
		t.Fatalf("replay returned %q, want the original %q", b.SandboxID, a.SandboxID)
	}
}
