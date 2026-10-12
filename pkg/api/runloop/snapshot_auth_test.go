package runloop

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func tenantContext(owner string) context.Context {
	return controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: owner, ExternalID: owner},
	})
}

// A tenant cannot reach another tenant's snapshot through names of its own.
// Registering a name for it is refused, and a chain of names that already
// leads there (rows from before registration checked) is refused at create,
// however many hops it has and however many times the create path resolves
// the request: the runtime never receives the other tenant's image.
func TestRegisteredNamesCannotReachAnotherTenantsSnapshot(t *testing.T) {
	env := newTestEnv(t)
	var source devboxView
	expectStatus(t, env.asTenant(t, "a", http.MethodPost, "/create_and_await_running", `{}`, &source), http.StatusOK)
	if _, err := env.svc.CreateSnapshot(tenantContext("a"), source.ID, models.CreateSandboxSnapshotRequest{Name: "private-source"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.RegisterSnapshot(tenantContext("b"), &models.SandboxSnapshot{Name: "b-alias", Image: "private-source"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("registering a name for another tenant's snapshot = %v; want not found", err)
	}

	now := time.Now().UTC()
	for _, row := range []*models.SandboxSnapshot{
		{Name: "b-alias", Image: "private-source", OwnerRef: "b", CreatedAt: now},
		{Name: "b-outer", Image: "b-alias", OwnerRef: "b", CreatedAt: now},
	} {
		if err := env.store.CreateSnapshot(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	}
	env.runtime.mu.Lock()
	before := env.runtime.lastReq.Image
	env.runtime.mu.Unlock()
	for _, name := range []string{"b-alias", "b-outer"} {
		if rr := env.asTenant(t, "b", http.MethodPost, "/create_and_await_running", `{"snapshot_id":"`+name+`"}`, nil); rr.Code < 300 {
			t.Fatalf("tenant b created from %s: HTTP %d", name, rr.Code)
		}
	}
	env.runtime.mu.Lock()
	defer env.runtime.mu.Unlock()
	if env.runtime.lastReq.Image != before {
		t.Fatalf("the runtime was asked to start %q for tenant b", env.runtime.lastReq.Image)
	}
}

// With the snapshot catalog unreadable, a name cannot be told apart from a
// private snapshot's, so the create fails rather than starting the name as
// a plain image.
func TestUnreadableSnapshotCatalogFailsCreatesClosed(t *testing.T) {
	env := newTestEnv(t)
	var source devboxView
	expectStatus(t, env.asTenant(t, "a", http.MethodPost, "/create_and_await_running", `{}`, &source), http.StatusOK)
	if _, err := env.svc.CreateSnapshot(tenantContext("a"), source.ID, models.CreateSandboxSnapshotRequest{Name: "private-on-read-error"}); err != nil {
		t.Fatal(err)
	}
	execSQL(t, env.store, "ALTER TABLE sandbox_snapshots RENAME TO snapshot_catalog_unavailable")
	defer execSQL(t, env.store, "ALTER TABLE snapshot_catalog_unavailable RENAME TO sandbox_snapshots")
	if _, err := env.svc.CreateSandbox(tenantContext("b"), models.CreateSandboxRequest{Image: "private-on-read-error"}); err == nil {
		t.Fatal("with the catalog unreadable, another tenant's private snapshot started as a plain image")
	}
}
