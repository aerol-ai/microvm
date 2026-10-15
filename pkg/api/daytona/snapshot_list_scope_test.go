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

// The snapshot list must return only the caller's snapshots. Before the D9 fix
// the handler loaded every tenant's rows via ListSnapshots and filtered in Go;
// now it pages the caller's rows in the store (ListOwnedSnapshots). This seeds
// two tenants and proves tenant-a never sees tenant-b's snapshot, and that the
// sort + page-number pagination still work over the scoped set.
func TestDaytonaListSnapshotsIsTenantScoped(t *testing.T) {
	_, st, _, handler := newSnapshotHandlerTestEnv(t)
	now := time.Now().UTC()

	seed := func(name, owner string) {
		if err := st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{
			Name: name, Image: "snapshots/" + name + ":v1", OwnerRef: owner, CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	seed("a-one", "tenant-a")
	seed("a-two", "tenant-a")
	seed("b-one", "tenant-b")

	req := httptest.NewRequest(http.MethodGet, "/daytona/snapshots?sort=name&order=asc", nil)
	req = req.WithContext(controlplane.ContextWithAccess(req.Context(),
		controlplane.Access{Identity: controlplane.Identity{OwnerRef: "tenant-a"}}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp paginatedSnapshotsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if resp.Total != 2 {
		t.Fatalf("tenant-a total = %v, want 2 (no cross-tenant leak); items=%+v", resp.Total, resp.Items)
	}
	for _, item := range resp.Items {
		if item.Name == "b-one" {
			t.Fatalf("tenant-a saw tenant-b snapshot %q", item.Name)
		}
	}
}
