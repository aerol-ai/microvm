package e2b

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The snapshot list must return only the caller's snapshots. Before the D9 fix
// the handler loaded every tenant's rows via ListSnapshots and filtered in Go;
// now it pages the caller's rows in the store (ListOwnedSnapshots). This seeds
// two tenants and proves tenant-a never sees tenant-b's snapshot.
func TestE2BListSnapshotsIsTenantScoped(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	now := time.Now().UTC()

	seed := func(name, owner string) {
		if err := st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{
			Name: name, Image: "img:" + name, OwnerRef: owner, CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	seed("e2b/a-one:default", "tenant-a")
	seed("e2b/a-two:default", "tenant-a")
	seed("e2b/b-one:default", "tenant-b")

	rr := tenantRequest(t, handler, "tenant-a", http.MethodGet, "/e2b/snapshots", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var snapshots []snapshotInfoResponse
	if err := json.NewDecoder(rr.Body).Decode(&snapshots); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(snapshots) != 2 {
		t.Fatalf("tenant-a list len = %d, want 2 (no cross-tenant leak); got %+v", len(snapshots), snapshots)
	}
	for _, s := range snapshots {
		for _, name := range s.Names {
			if name == "b-one" {
				t.Fatalf("tenant-a saw tenant-b snapshot %q", name)
			}
		}
	}
}
