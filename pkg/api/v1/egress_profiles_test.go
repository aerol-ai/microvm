package v1

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestV1EgressProfiles (P2-6): PUT/GET/list/DELETE, a profile in use is a
// 409, and a sandbox's policy can reference it.
func TestV1EgressProfiles(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-1")
	put := func(name string, body any) models.EgressProfile {
		rr := do(t, env.mux, http.MethodPut, "/v1/egress-profiles/"+name, body)
		if rr.Code != http.StatusOK {
			t.Fatalf("PUT %s: %d %s", name, rr.Code, rr.Body.String())
		}
		var p models.EgressProfile
		_ = json.Unmarshal(rr.Body.Bytes(), &p)
		return p
	}
	if p := put("cidrs", models.EgressProfileRequest{AllowOut: []string{"1.1.1.0/24"}, Description: "dns"}); p.Generation != 1 || p.Description != "dns" {
		t.Fatalf("created = %+v", p)
	}
	put("other", models.EgressProfileRequest{AllowOut: []string{"8.8.8.0/24"}})
	rr := do(t, env.mux, http.MethodGet, "/v1/egress-profiles/cidrs", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET: %d", rr.Code)
	}
	rr = do(t, env.mux, http.MethodGet, "/v1/egress-profiles?limit=1", nil)
	var page models.EgressProfileList
	_ = json.Unmarshal(rr.Body.Bytes(), &page)
	if rr.Code != http.StatusOK || len(page.Profiles) != 1 || page.NextCursor != "cidrs" {
		t.Fatalf("list: %d %+v", rr.Code, page)
	}
	rr = do(t, env.mux, http.MethodGet, "/v1/egress-profiles?cursor=cidrs", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &page)
	if len(page.Profiles) != 1 || page.Profiles[0].Name != "other" {
		t.Fatalf("page 2 = %+v", page)
	}

	rr = do(t, env.mux, http.MethodPut, "/v1/sandboxes/sb-1/network/policy", models.NetworkPolicyRequest{EgressProfiles: []string{"cidrs"}})
	var pol models.NetworkPolicy
	_ = json.Unmarshal(rr.Body.Bytes(), &pol)
	if rr.Code != http.StatusOK || !slices.Equal(pol.EgressProfiles, []string{"cidrs"}) {
		t.Fatalf("policy with a profile: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(t, env.mux, http.MethodGet, "/v1/sandboxes/sb-1", nil)
	var sb models.Sandbox
	_ = json.Unmarshal(rr.Body.Bytes(), &sb)
	if !slices.Equal(sb.EgressProfiles, []string{"cidrs"}) || len(sb.NetworkAllowOut) != 0 || len(sb.EgressProfilesApplied) != 1 {
		t.Fatalf("GET shows inline list and references: %+v", sb)
	}

	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodDelete, "/v1/egress-profiles/cidrs", nil, http.StatusConflict},
		{http.MethodGet, "/v1/egress-profiles/missing", nil, http.StatusNotFound},
		// Built-ins are global and read-only (P2-8).
		{http.MethodGet, "/v1/egress-profiles/builtin:pypi", nil, http.StatusOK},
		{http.MethodGet, "/v1/egress-profiles/builtin:nope", nil, http.StatusNotFound},
		// Org profiles come only from the operator file (P2-10).
		{http.MethodGet, "/v1/egress-profiles/org:mirrors", nil, http.StatusNotFound},
		{http.MethodPut, "/v1/egress-profiles/org:mirrors", models.EgressProfileRequest{AllowOut: []string{"x.example"}}, http.StatusBadRequest},
		{http.MethodPut, "/v1/egress-profiles/builtin:pypi", models.EgressProfileRequest{AllowOut: []string{"x.example"}}, http.StatusBadRequest},
		{http.MethodDelete, "/v1/egress-profiles/builtin:pypi", nil, http.StatusBadRequest},
		{http.MethodPut, "/v1/egress-profiles/Bad", models.EgressProfileRequest{}, http.StatusBadRequest},
		{http.MethodPut, "/v1/egress-profiles/ok", "not an object", http.StatusBadRequest},
		{http.MethodGet, "/v1/egress-profiles?limit=x", nil, http.StatusBadRequest},
		{http.MethodDelete, "/v1/egress-profiles/other", nil, http.StatusNoContent},
		{http.MethodDelete, "/v1/egress-profiles/other", nil, http.StatusNoContent},
	} {
		if rr := do(t, env.mux, tc.method, tc.path, tc.body); rr.Code != tc.want {
			t.Fatalf("%s %s: %d, want %d (%s)", tc.method, tc.path, rr.Code, tc.want, rr.Body.String())
		}
	}
}
