package e2b

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// TestUpdateNetwork covers P2-5: E2B's PUT /sandboxes/{id}/network replaces
// the policy with the same mapping as create (D4, D11), repeats are no-ops,
// and GET echoes the E2B spelling.
func TestUpdateNetwork(t *testing.T) {
	svc, _, handler := newE2BHandlerTestEnv(t)
	ctx := context.Background()
	put := func(id, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/e2b/sandboxes/"+id+"/network", strings.NewReader(body)))
		return rr
	}
	create := httptest.NewRecorder()
	handler.ServeHTTP(create, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base"}`)))
	var created sandboxResponse
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil || created.SandboxID == "" {
		t.Fatalf("create: %v %s", err, create.Body.String())
	}
	id := created.SandboxID

	for _, tc := range []struct {
		name      string
		body      string
		blockAll  bool
		allow     []string
		deny      []string
		echoAllow []string
		echoDeny  []string
	}{
		{"portable allowlist", `{"allowOut":["1.1.1.0/24"],"denyOut":["0.0.0.0/0"]}`, false, []string{"1.1.1.0/24"}, []string{"0.0.0.0/0"}, []string{"1.1.1.0/24"}, []string{"0.0.0.0/0"}},
		{"allowOut alone stays an allowlist", `{"allowOut":["8.8.8.0/24"]}`, false, []string{"8.8.8.0/24"}, nil, []string{"8.8.8.0/24"}, nil},
		{"deny all alone is block-all", `{"denyOut":["0.0.0.0/0"]}`, true, nil, nil, nil, []string{"0.0.0.0/0"}},
		{"no internet", `{"allow_internet_access":false}`, true, nil, nil, nil, nil},
		{"empty body clears everything", `{}`, false, nil, nil, nil, nil},
	} {
		for range 2 { // a repeat of the same body is a no-op
			if rr := put(id, tc.body); rr.Code != http.StatusNoContent {
				t.Fatalf("%s: status = %d body=%s", tc.name, rr.Code, rr.Body.String())
			}
		}
		sb, err := svc.GetSandbox(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if sb.NetworkBlockAll != tc.blockAll || !slices.Equal(sb.NetworkAllowOut, tc.allow) || !slices.Equal(sb.NetworkDenyOut, tc.deny) {
			t.Fatalf("%s: native policy = block %v allow %v deny %v", tc.name, sb.NetworkBlockAll, sb.NetworkAllowOut, sb.NetworkDenyOut)
		}
		get := httptest.NewRecorder()
		handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes/"+id, nil))
		var detail struct {
			Network *sandboxNetworkPayload `json:"network"`
		}
		_ = json.Unmarshal(get.Body.Bytes(), &detail)
		var gotAllow, gotDeny []string
		if detail.Network != nil {
			gotAllow, gotDeny = detail.Network.AllowOut, detail.Network.DenyOut
		}
		if !slices.Equal(gotAllow, tc.echoAllow) || !slices.Equal(gotDeny, tc.echoDeny) {
			t.Fatalf("%s: GET echoes %v / %v", tc.name, gotAllow, gotDeny)
		}
	}

	for _, tc := range []struct {
		id, body string
		want     int
	}{
		{id, `{"rules":{"api.example.com":[{"transform":{"headers":{"X":"1"}}}]}}`, http.StatusNotImplemented},
		{id, `{"egressProxy":{"address":"proxy:3128"}}`, http.StatusNotImplemented},
		{id, `{"denyOut":["evil.example"]}`, http.StatusBadRequest},
		{id, `not json`, http.StatusBadRequest},
		{"sb-missing", `{}`, http.StatusNotFound},
	} {
		if rr := put(tc.id, tc.body); rr.Code != tc.want {
			t.Fatalf("%s: status = %d, want %d (%s)", tc.body, rr.Code, tc.want, rr.Body.String())
		}
	}
	create = httptest.NewRecorder()
	handler.ServeHTTP(create, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","network":{"rules":{"x.example":[{}]}}}`)))
	if create.Code != http.StatusNotImplemented {
		t.Fatalf("create with rules: status = %d", create.Code)
	}
	// Explicitly empty rules and proxy are "not set".
	if rr := put(id, `{"rules":{},"egressProxy":null}`); rr.Code != http.StatusNoContent {
		t.Fatalf("empty rules: status = %d", rr.Code)
	}
}
