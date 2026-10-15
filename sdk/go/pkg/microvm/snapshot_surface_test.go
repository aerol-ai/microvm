package microvm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// TestSnapshotSurfaceHitsV1 verifies the read/list/delete snapshot wrappers
// thread through to the v1 snapshot surface: GetSnapshot/DeleteSnapshot hit
// /v1/snapshots/<name>, and ListSnapshots forwards limit + starting_after and
// parses {snapshots, has_more} back into SnapshotList.
func TestSnapshotSurfaceHitsV1(t *testing.T) {
	ctx := context.Background()
	var (
		gotGetPath    string
		gotListQuery  string
		gotDeletePath string
		gotDeleteVerb string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/snapshots/py-base":
			gotGetPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(models.SandboxSnapshot{
				Name:      "py-base",
				Image:     "python:3.12-slim",
				MemoryMB:  4096,
				CreatedAt: time.Now().UTC(),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/snapshots":
			gotListQuery = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(map[string]any{
				"snapshots": []models.SandboxSnapshot{
					{Name: "py-base", Image: "python:3.12-slim"},
				},
				"has_more": true,
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/snapshots/py-base":
			gotDeletePath = r.URL.Path
			gotDeleteVerb = r.Method
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
		APIUrl:     server.URL,
		PATToken:   "pat",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}

	// GetSnapshot → GET /v1/snapshots/<name>
	snap, err := client.GetSnapshot(ctx, "py-base")
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if gotGetPath != "/v1/snapshots/py-base" {
		t.Fatalf("GetSnapshot path = %q", gotGetPath)
	}
	if snap.Name != "py-base" || snap.Image != "python:3.12-slim" || snap.MemoryMB != 4096 {
		t.Fatalf("GetSnapshot result = %+v", snap)
	}

	// ListSnapshots → GET /v1/snapshots?limit=&starting_after=, parses has_more.
	page, err := client.ListSnapshots(ctx, sdktypes.ListSnapshotsOptions{
		Limit:         1,
		StartingAfter: "cursor",
	})
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if gotListQuery != "limit=1&starting_after=cursor" {
		t.Fatalf("ListSnapshots query = %q", gotListQuery)
	}
	if !page.HasMore {
		t.Fatalf("ListSnapshots HasMore = false, want true")
	}
	if len(page.Snapshots) != 1 || page.Snapshots[0].Name != "py-base" {
		t.Fatalf("ListSnapshots snapshots = %+v", page.Snapshots)
	}

	// DeleteSnapshot → DELETE /v1/snapshots/<name>
	if err := client.DeleteSnapshot(ctx, "py-base"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if gotDeleteVerb != http.MethodDelete || gotDeletePath != "/v1/snapshots/py-base" {
		t.Fatalf("DeleteSnapshot = %s %s", gotDeleteVerb, gotDeletePath)
	}
}

// TestListSnapshotsNoOptsOmitsQuery verifies a bare ListSnapshots sends no
// query string and that a null `snapshots` wire array decodes to an empty,
// non-nil slice.
func TestListSnapshotsNoOptsOmitsQuery(t *testing.T) {
	ctx := context.Background()
	var gotRawQuery string
	queried := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/snapshots" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		queried = true
		gotRawQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{
			"snapshots": nil,
			"has_more":  false,
		})
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
		APIUrl:     server.URL,
		PATToken:   "pat",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}

	page, err := client.ListSnapshots(ctx, sdktypes.ListSnapshotsOptions{})
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if !queried {
		t.Fatalf("server never saw the list request")
	}
	if gotRawQuery != "" {
		t.Fatalf("ListSnapshots query = %q, want empty", gotRawQuery)
	}
	if page.HasMore {
		t.Fatalf("ListSnapshots HasMore = true, want false")
	}
	if page.Snapshots == nil {
		t.Fatalf("ListSnapshots Snapshots = nil, want non-nil empty slice")
	}
	if len(page.Snapshots) != 0 {
		t.Fatalf("ListSnapshots Snapshots = %+v, want empty", page.Snapshots)
	}
}
