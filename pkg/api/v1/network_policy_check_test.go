package v1

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestV1NetworkPolicyCheck (P2-9): a pure answer from the shared matcher;
// bad input is a 400.
func TestV1NetworkPolicyCheck(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	for _, tc := range []struct {
		body    models.NetworkPolicyCheckRequest
		allowed bool
		rule    string
	}{
		{models.NetworkPolicyCheckRequest{NetworkAllowOut: []string{"*.github.com"}, Destination: "api.github.com"}, true, "*.github.com"},
		{models.NetworkPolicyCheckRequest{NetworkAllowOut: []string{"github.com:22"}, Destination: "github.com"}, false, ""},
		{models.NetworkPolicyCheckRequest{NetworkAllowOut: []string{"github.com:22"}, Destination: "github.com:22"}, true, "github.com:22"},
		{models.NetworkPolicyCheckRequest{NetworkDenyOut: []string{"10.0.0.0/8"}, Destination: "10.1.2.3:5432"}, false, "10.0.0.0/8"},
		{models.NetworkPolicyCheckRequest{Destination: "example.com"}, true, ""},
	} {
		rr := do(t, env.mux, http.MethodPost, "/v1/network/policy/check", tc.body)
		if rr.Code != http.StatusOK {
			t.Fatalf("%+v: status=%d body=%s", tc.body, rr.Code, rr.Body.String())
		}
		var got models.NetworkPolicyCheckResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Allowed != tc.allowed || got.MatchedRule != tc.rule {
			t.Fatalf("%+v: got %+v", tc.body, got)
		}
	}
	for _, bad := range []any{
		models.NetworkPolicyCheckRequest{Destination: ""},
		models.NetworkPolicyCheckRequest{NetworkDenyOut: []string{"evil.com"}, Destination: "x.com"},
		"not an object",
	} {
		if rr := do(t, env.mux, http.MethodPost, "/v1/network/policy/check", bad); rr.Code != http.StatusBadRequest {
			t.Fatalf("%v: status=%d, want 400", bad, rr.Code)
		}
	}
}
