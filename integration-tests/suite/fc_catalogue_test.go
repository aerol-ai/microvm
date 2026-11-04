//go:build integration

package suite

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

type e2bSnapshotInfo struct {
	Names      []string `json:"names"`
	SnapshotID string   `json:"snapshotID"`
}

type daytonaSnapshotPage struct {
	Items []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"items"`
	Total      float32 `json:"total"`
	Page       float32 `json:"page"`
	TotalPages float32 `json:"totalPages"`
}

// UC-243 — a v1-registered snapshot is visible through the Daytona facade
// (shared catalogue, no separate per-facade table). Daytona's snapshot id is
// the name, so a get-by-id for the v1 name must resolve.
func TestCatalogueSharedWithDaytona(t *testing.T) {
	harness.Require(t, sc, "UC-243")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	name := registerImageSnapshot(t, c, ctx, "dt-shared")
	st, body := fcDo(t, ctx, http.MethodGet, "", "/daytona/snapshots/"+name, nil, nil)
	if st != http.StatusOK {
		t.Fatalf("Daytona get of v1-registered snapshot = %d, want 200; body=%s", st, string(body))
	}
	if !strings.Contains(string(body), name) {
		t.Fatalf("Daytona get response does not mention %q: %s", name, string(body))
	}
}

// UC-244 — a v1-registered snapshot is visible through the E2B snapshot list.
func TestCatalogueSharedWithE2B(t *testing.T) {
	harness.Require(t, sc, "UC-244")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	name := registerImageSnapshot(t, c, ctx, "e2b-shared")
	st, body := fcDo(t, ctx, http.MethodGet, "", "/e2b/snapshots?limit=500", nil, nil)
	if st != http.StatusOK {
		t.Fatalf("E2B snapshot list = %d, want 200; body=%s", st, string(body))
	}
	var items []e2bSnapshotInfo
	fcDecode(t, body, &items)
	found := false
	for _, it := range items {
		for _, n := range it.Names {
			// E2B canonicalizes a tagless name to name:default, so the
			// registered name is a prefix of what the list reports.
			if strings.Contains(n, name) {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("v1-registered snapshot %q not visible in E2B list (%d items)", name, len(items))
	}
}

// UC-245 — the Daytona snapshot list paginates (page + limit).
func TestDaytonaSnapshotListPaginates(t *testing.T) {
	harness.Require(t, sc, "UC-245")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	registerImageSnapshot(t, c, ctx, "dtpg1")
	registerImageSnapshot(t, c, ctx, "dtpg2")

	st, body := fcDo(t, ctx, http.MethodGet, "", "/daytona/snapshots?page=1&limit=1", nil, nil)
	if st != http.StatusOK {
		t.Fatalf("Daytona list = %d, want 200; body=%s", st, string(body))
	}
	var page daytonaSnapshotPage
	fcDecode(t, body, &page)
	if len(page.Items) != 1 {
		t.Fatalf("limit=1 returned %d items, want 1", len(page.Items))
	}
	if page.Total < 2 || page.TotalPages < 2 {
		t.Fatalf("pagination totals = total %v / pages %v, want >=2 each", page.Total, page.TotalPages)
	}
}

// UC-246 — the E2B snapshot list returns the catalogue.
func TestE2BSnapshotListReturnsCatalogue(t *testing.T) {
	harness.Require(t, sc, "UC-246")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	name := registerImageSnapshot(t, c, ctx, "e2blist")
	st, body := fcDo(t, ctx, http.MethodGet, "", "/e2b/snapshots?limit=500", nil, nil)
	if st != http.StatusOK {
		t.Fatalf("E2B list = %d, want 200; body=%s", st, string(body))
	}
	var items []e2bSnapshotInfo
	fcDecode(t, body, &items)
	if len(items) == 0 {
		t.Fatalf("E2B list empty after registering %q", name)
	}
}
