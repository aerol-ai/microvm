package microvm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestClientNameLookup(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		switch r.URL.Query().Get("name") {
		case "agent":
			_ = json.NewEncoder(w).Encode([]models.Sandbox{{ID: "sb-1", Name: "agent"}})
		case "conflict":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"sandbox name already in use"}`))
		default:
			_, _ = w.Write([]byte("[]"))
		}
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	ctx := context.Background()

	got, err := client.GetByName(ctx, "agent", WithGetIncludeEnv())
	if err != nil || got.ID != "sb-1" || got.client != client {
		t.Fatalf("GetByName = (%+v, %v)", got, err)
	}
	if _, err := client.GetByName(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByName(missing) error = %v, want ErrNotFound", err)
	}
	_, err = client.GetByName(ctx, "conflict")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || !errors.Is(err, ErrConflict) {
		t.Fatalf("GetByName(conflict) error = %v", err)
	}
	items, err := client.List(ctx, WithName(" agent "))
	if err != nil || len(items) != 1 {
		t.Fatalf("List(WithName) = (%d, %v)", len(items), err)
	}
	if _, _, err := client.ListPage(ctx, "", WithName("agent"), WithTags(map[string]string{"t": "v"})); err != nil {
		t.Fatalf("ListPage(WithName): %v", err)
	}
	want := []string{"include_env=true&name=agent", "name=missing", "name=conflict", "name=agent", "tag.t=v&name=agent"}
	if len(queries) != len(want) {
		t.Fatalf("queries = %q, want %q", queries, want)
	}
	for i := range want {
		if queries[i] != want[i] {
			t.Fatalf("query %d = %q, want %q", i, queries[i], want[i])
		}
	}
}
