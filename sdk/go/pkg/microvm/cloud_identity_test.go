package microvm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestIdentityRoleWrappers(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		switch r.Method {
		case http.MethodPut:
			_, _ = w.Write([]byte(`{"tag":"deploy","min_role":"runner","team":"payments"}`))
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"roles":[{"tag":"deploy","min_role":"runner"}]}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	role, err := client.PutIdentityRole(ctx, "deploy", sdktypes.IdentityRoleOptions{MinRole: "runner", Team: "payments"})
	if err != nil || role.MinRole != "runner" || role.Team != "payments" {
		t.Fatalf("put = %+v %v", role, err)
	}
	list, err := client.ListIdentityRoles(ctx, sdktypes.ListIdentityRolesOptions{Team: "payments"})
	if err != nil || len(list.Roles) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := client.DeleteIdentityRole(ctx, "deploy", "payments"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"PUT /v1/identity/roles/deploy?team=payments",
		"GET /v1/identity/roles?team=payments",
		"DELETE /v1/identity/roles/deploy?team=payments",
	}
	if len(requests) != len(want) {
		t.Fatalf("requests = %v", requests)
	}
	for i := range want {
		if requests[i] != want[i] {
			t.Fatalf("request %d = %s, want %s", i, requests[i], want[i])
		}
	}
}
