package runloop

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func tenantContext(owner string) context.Context {
	return controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: owner, ExternalID: owner},
	})
}

// A tenant cannot reach another tenant's snapshot through names of its own.
// The snapshot's image lives under a tag of its own, so naming the snapshot
// (directly or through a registered alias) reaches only an ordinary image of
// that name. Naming the image's tag is refused, at registration and at
// create, and so is a chain of names that already leads to it (rows from
// before registration checked), however many hops it has and however many
// times the create path resolves the request: the runtime never receives
// the other tenant's image.
func TestRegisteredNamesCannotReachAnotherTenantsSnapshot(t *testing.T) {
	env := newTestEnv(t)
	var source devboxView
	expectStatus(t, env.asTenant(t, "a", http.MethodPost, "/create_and_await_running", `{}`, &source), http.StatusOK)
	snap, err := env.svc.CreateSnapshot(tenantContext("a"), source.ID, models.CreateSandboxSnapshotRequest{Name: "private-source"})
	if err != nil {
		t.Fatal(err)
	}
	private := snap.Image
	if private != docker.SnapshotImageTag("private-source") {
		t.Fatalf("snapshot committed as %q", private)
	}

	req := models.CreateSandboxRequest{Image: "private-source"}
	if err := env.svc.NormalizeCreateImageDistribution(tenantContext("b"), &req); err != nil || req.Image != "private-source" {
		t.Fatalf("tenant b's private-source = %q, %v; want the ordinary image of that name", req.Image, err)
	}
	if _, err := env.svc.RegisterSnapshot(tenantContext("b"), &models.SandboxSnapshot{Name: "b-tag", Image: private}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("registering a name for another tenant's image = %v; want not found", err)
	}

	now := time.Now().UTC()
	for _, row := range []*models.SandboxSnapshot{
		{Name: "b-alias", Image: private, OwnerRef: "b", CreatedAt: now},
		{Name: "b-outer", Image: "b-alias", OwnerRef: "b", CreatedAt: now},
	} {
		if err := env.store.CreateSnapshot(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	}
	for _, image := range []string{private, "docker.io/" + private, "b-alias", "b-outer"} {
		if _, err := env.svc.CreateSandbox(tenantContext("b"), models.CreateSandboxRequest{Image: image}); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("tenant b created from %q: %v; want not found", image, err)
		}
	}
	for _, name := range []string{"b-alias", "b-outer"} {
		if rr := env.asTenant(t, "b", http.MethodPost, "/create_and_await_running", `{"snapshot_id":"`+name+`"}`, nil); rr.Code < 300 {
			t.Fatalf("tenant b created from %s: HTTP %d", name, rr.Code)
		}
	}
	env.runtime.mu.Lock()
	defer env.runtime.mu.Unlock()
	if env.runtime.lastReq.Image == private {
		t.Fatalf("the runtime was asked to start tenant a's image for tenant b")
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
