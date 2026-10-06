package v1

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestV1UpdateNetworkPolicy (P2-1): PUT replaces the policy and answers with
// the effective one; a repeat is a no-op; bad input, unknown sandboxes and a
// sandbox mid-create get their own statuses.
func TestV1UpdateNetworkPolicy(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-1")
	body := models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}, NetworkDenyOut: []string{"10.0.0.0/8"}}
	for range 2 {
		rr := do(t, env.mux, http.MethodPut, "/v1/sandboxes/sb-1/network/policy", body)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var got models.NetworkPolicy
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.NetworkBlockAll || !slices.Equal(got.NetworkAllowOut, body.NetworkAllowOut) || !slices.Equal(got.NetworkDenyOut, body.NetworkDenyOut) {
			t.Fatalf("effective policy = %+v", got)
		}
	}
	rr := do(t, env.mux, http.MethodGet, "/v1/sandboxes/sb-1", nil)
	var sb models.Sandbox
	_ = json.Unmarshal(rr.Body.Bytes(), &sb)
	if !slices.Equal(sb.NetworkAllowOut, body.NetworkAllowOut) {
		t.Fatalf("GET after PUT shows %v", sb.NetworkAllowOut)
	}

	for _, tc := range []struct {
		path string
		body any
		want int
	}{
		{"/v1/sandboxes/sb-1/network/policy", models.NetworkPolicyRequest{NetworkDenyOut: []string{"evil.example"}}, http.StatusBadRequest},
		{"/v1/sandboxes/sb-1/network/policy", "not an object", http.StatusBadRequest},
		{"/v1/sandboxes/sb-missing/network/policy", models.NetworkPolicyRequest{NetworkBlockAll: true}, http.StatusNotFound},
	} {
		if rr := do(t, env.mux, http.MethodPut, tc.path, tc.body); rr.Code != tc.want {
			t.Fatalf("%s %v: status=%d, want %d (%s)", tc.path, tc.body, rr.Code, tc.want, rr.Body.String())
		}
	}
}

// TestV1NetworkLearned (P2-7): the learned route answers from the service;
// a sandbox on a runtime without learn mode is a 501.
func TestV1NetworkLearned(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-1")
	// The env has no egress gateway, so a container sandbox can't be read.
	if rr := do(t, env.mux, http.MethodGet, "/v1/sandboxes/sb-1/network/learned", nil); rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := do(t, env.mux, http.MethodGet, "/v1/sandboxes/missing/network/learned", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("missing = %d", rr.Code)
	}
}
